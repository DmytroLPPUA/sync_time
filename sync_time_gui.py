"""GUI utility for synchronizing remote Windows time via WMI."""

from __future__ import annotations

import base64
import datetime as _dt
import os
import re
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from typing import Callable, List, Optional, Tuple, TypeVar


SYNC_TOLERANCE = _dt.timedelta(minutes=5)
WMI_VERIFICATION_DELAY_SECONDS = 5
DEFAULT_USERNAME = "Administrator"
PASSWORD_FILE_NAME = "pass.txt"
ResultT = TypeVar("ResultT")


class RemoteProcessTimeoutError(RuntimeError):
    """Raised when the remote WMI process fails to finish in time."""


class TimeSyncApp:
    """Tkinter-based application for syncing time to a remote Windows host."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Синхронізація часу")
        self.root.resizable(False, False)

        self.host_var = tk.StringVar()

        self._build_ui()

    def _build_ui(self) -> None:
        padding = {"padx": 10, "pady": 5}
        main_frame = ttk.Frame(self.root)
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.columnconfigure(1, weight=1)

        ttk.Label(main_frame, text="Віддалений хост / IP:").grid(row=0, column=0, sticky="w", **padding)
        host_entry = ttk.Entry(main_frame, textvariable=self.host_var, width=45)
        host_entry.grid(row=0, column=1, sticky="ew", **padding)

        ttk.Label(
            main_frame,
            text=(
                "Аутентифікація виконується обліковим записом Administrator. "
                "Паролі зчитуються з pass.txt (кожний у новому рядку)."
            ),
            wraplength=460,
            justify="left",
        ).grid(row=1, column=0, columnspan=2, sticky="w", padx=10, pady=(0, 5))

        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, sticky="ew", padx=10, pady=(5, 0))
        button_frame.columnconfigure((0, 1), weight=1)

        self.check_button = ttk.Button(button_frame, text="Перевірити віддалений час", command=self.check_remote_time)
        self.check_button.grid(row=0, column=0, sticky="ew", padx=(0, 5))

        self.sync_button = ttk.Button(button_frame, text="Синхронізувати", command=self.sync_remote_time)
        self.sync_button.grid(row=0, column=1, sticky="ew", padx=(5, 0))

        self.output = ScrolledText(main_frame, width=70, height=15, state="disabled")
        self.output.grid(row=3, column=0, columnspan=2, padx=10, pady=(10, 10))
        self.output.tag_configure("error", foreground="red")
        self.output.tag_configure("warning", foreground="red")

        # Accessibility: focus first field
        host_entry.focus_set()

    # ------------------------------------------------------------------
    # UI helpers
    def _append_output(self, message: str, *, tag: Optional[str] = None) -> None:
        self.output.configure(state="normal")
        text = message if message.endswith("\n") else f"{message}\n"
        if tag:
            self.output.insert(tk.END, text, tag)
        else:
            self.output.insert(tk.END, text)
        self.output.see(tk.END)
        self.output.configure(state="disabled")

    def log_message(self, message: str, *, tag: Optional[str] = None) -> None:
        self.root.after(0, lambda msg=message, tg=tag: self._append_output(msg, tag=tg))

    def _set_buttons_state(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        self.root.after(0, lambda: (self.check_button.config(state=state), self.sync_button.config(state=state)))

    def _show_error(self, message: str) -> None:
        self.log_message(f"ПОМИЛКА: {message}", tag="error")

    def _show_info(self, message: str) -> None:
        self.log_message(message)

    def _run_in_thread(self, target) -> None:
        def worker():
            self._set_buttons_state(False)
            try:
                target()
            finally:
                self._set_buttons_state(True)

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------
    # Validation & command helpers
    def _get_connection_details(self) -> Tuple[str, str, List[str]]:
        host = self.host_var.get().strip()
        if not host:
            raise ValueError("Поле віддаленого хоста / IP не може бути порожнім.")

        passwords = self._load_passwords()
        return host, DEFAULT_USERNAME, passwords

    def _password_file_path(self) -> str:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(script_dir, PASSWORD_FILE_NAME)

    def _load_passwords(self) -> List[str]:
        path = self._password_file_path()
        if not os.path.isfile(path):
            raise FileNotFoundError(
                "Не знайдено файл паролів pass.txt поруч із програмою."
            )

        with open(path, "r", encoding="utf-8") as handle:
            passwords = [line.strip() for line in handle if line.strip()]

        if not passwords:
            raise ValueError("Файл pass.txt не містить жодного пароля.")

        return passwords

    @staticmethod
    def _is_authentication_error(message: str) -> bool:
        normalized = message.lower()
        tokens = [
            "access is denied",
            "логон відхилено",
            "logon failure",
            "authentication failure",
            "недійсні облікові дані",
            "bad username or password",
        ]
        return any(token in normalized for token in tokens)

    def _attempt_with_passwords(self, passwords: List[str], action: Callable[[str], ResultT]) -> ResultT:
        last_auth_error: Optional[Exception] = None
        for index, password in enumerate(passwords, start=1):
            self.log_message(
                f"Спроба використати пароль {index} з {len(passwords)}."
            )
            try:
                return action(password)
            except RuntimeError as exc:
                if self._is_authentication_error(str(exc)):
                    self.log_message("Пароль не підійшов, пробуємо наступний...", tag="warning")
                    last_auth_error = exc
                    continue
                raise
        if last_auth_error is not None:
            raise last_auth_error
        raise RuntimeError("Не знайдено жодного дійсного пароля у pass.txt.")

    @staticmethod
    def _ps_single_quote(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    @staticmethod
    def _encode_powershell_script(script: str) -> str:
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        return encoded

    def _run_local_powershell(self, script: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", script], capture_output=True, text=True
        )

    @staticmethod
    def _enhance_wmi_error(stderr: str) -> str:
        message = stderr.strip() or "PowerShell повідомив про невідому помилку."
        normalized = message.lower()
        hints = []

        access_denied_tokens = ["access is denied", "0x80070005"]
        if any(token in normalized for token in access_denied_tokens):
            hints.append(
                "WMI повідомив про відмову у доступі. Переконайтеся, що надані облікові дані належать до групи "
                "адміністраторів віддаленого комп'ютера, що Remote UAC дозволяє віддалені адміністративні дії, а також "
                "вказуйте ім'я комп'ютера під час автентифікації локальним обліковим записом (наприклад, HOST\\Administrator або .\\Administrator)."
            )

        rpc_unavailable_tokens = ["the rpc server is unavailable", "0x800706ba"]
        if any(token in normalized for token in rpc_unavailable_tokens):
            hints.append(
                "Не вдалося зв'язатися із сервером RPC. Перевірте мережеве з'єднання, "
                "що служба Windows Management Instrumentation працює, та що брандмауер дозволяє трафік WMI/DCOM."
            )

        if hints:
            message = message + "\n\n" + " ".join(hints)

        return message

    def _invoke_wmi_process(
        self,
        host: str,
        username: str,
        password: str,
        script: str,
        *,
        wait_for_completion: bool = True,
    ) -> None:
        encoded = self._encode_powershell_script(script)
        remote_command = f"powershell.exe -NoProfile -EncodedCommand {encoded}"
        host_q = self._ps_single_quote(host)
        user_q = self._ps_single_quote(username)
        pass_q = self._ps_single_quote(password)
        command_parts = [
            "$ErrorActionPreference='Stop'; ",
            f"$sec = ConvertTo-SecureString {pass_q} -AsPlainText -Force; ",
            f"$cred = New-Object System.Management.Automation.PSCredential({user_q}, $sec); ",
            f"$cmd = {self._ps_single_quote(remote_command)}; ",
            f"$result = Invoke-WmiMethod -Class Win32_Process -ComputerName {host_q} -Credential $cred -Name Create -ArgumentList $cmd; ",
            "if ($null -eq $result) { throw 'Invoke-WmiMethod не повернув дані.' } ",
            "if ($result.ReturnValue -ne 0) { throw (\"Віддалений процес завершився з кодом {0}\" -f $result.ReturnValue) } ",
            "$remotePid = $result.ProcessId; ",
            "if (-not $remotePid) { throw 'Віддалений процес не повернув ідентифікатор.' } ",
        ]
        if wait_for_completion:
            max_attempts = 150
            sleep_ms = 200
            timeout_seconds = max_attempts * sleep_ms / 1000
            timeout_message = self._ps_single_quote(
                f"Перевищено час очікування завершення віддаленого процесу після {timeout_seconds:.1f} с."
            )
            command_parts.extend(
                [
                    f"$maxAttempts = {max_attempts}; ",
                    "$attempts = 0; ",
                    "while ($attempts -lt $maxAttempts) { ",
                    f"    $proc = Get-WmiObject -Class Win32_Process -ComputerName {host_q} -Credential $cred -Filter (\"ProcessId = {0}\" -f $remotePid); ",
                    "    if (-not $proc) { break } ; ",
                    f"    Start-Sleep -Milliseconds {sleep_ms}; ",
                    "    $attempts++; ",
                    "}; ",
                    f"if ($attempts -eq $maxAttempts) {{ throw {timeout_message} }}",
                ]
            )

        command = "".join(command_parts)

        self.log_message(f"Виконання команди WMI для {host} ...")
        completed = self._run_local_powershell(command)
        if completed.returncode != 0:
            stderr = completed.stderr.strip() or "PowerShell повідомив про невідому помилку."
            if "Перевищено час очікування завершення віддаленого процесу" in stderr:
                raise RemoteProcessTimeoutError(stderr)
            raise RuntimeError(self._enhance_wmi_error(stderr))

    def _get_remote_time_via_wmi(
        self, host: str, username: str, password: str
    ) -> Tuple[Optional[_dt.datetime], Optional[str]]:
        host_q = self._ps_single_quote(host)
        user_q = self._ps_single_quote(username)
        pass_q = self._ps_single_quote(password)
        command = (
            "$ErrorActionPreference='Stop'; "
            f"$sec = ConvertTo-SecureString {pass_q} -AsPlainText -Force; "
            f"$cred = New-Object System.Management.Automation.PSCredential({user_q}, $sec); "
            f"$os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName {host_q} -Credential $cred; "
            "if ($null -eq $os) { throw 'Не вдалося отримати дані про віддалену операційну систему через WMI.' } "
            "$os.LocalDateTime"
        )

        self.log_message(f"Отримання віддаленого часу через WMI на {host} ...")
        completed = self._run_local_powershell(command)
        if completed.returncode != 0:
            stderr = completed.stderr.strip() or "PowerShell повідомив про невідому помилку."
            raise RuntimeError(self._enhance_wmi_error(stderr))

        stdout = completed.stdout.strip()
        remote_dt, parsed = self._parse_wmi_datetime(stdout)
        return remote_dt, parsed or stdout or None

    @staticmethod
    def _parse_wmi_datetime(value: str) -> Tuple[Optional[_dt.datetime], Optional[str]]:
        if not value:
            return None, None

        first_line = value.splitlines()[0].strip()
        match = re.fullmatch(r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.(\d{6})([+-])(\d{3}|\*\*\*)", first_line)
        if not match:
            return None, first_line

        year, month, day, hour, minute, second, micros, sign, offset = match.groups()
        dt = _dt.datetime(
            int(year),
            int(month),
            int(day),
            int(hour),
            int(minute),
            int(second),
            int(micros),
        )

        if offset == "***":
            tzinfo = _dt.datetime.now(_dt.timezone.utc).astimezone().tzinfo
        else:
            minutes = int(offset)
            delta = _dt.timedelta(minutes=minutes)
            if sign == "-":
                delta = -delta
            tzinfo = _dt.timezone(delta)

        return dt.replace(tzinfo=tzinfo), first_line

    def _sync_remote_time_via_wmi(
        self, host: str, username: str, password: str, iso_time: str
    ) -> Tuple[Optional[_dt.datetime], Optional[str]]:
        script = (
            "$ErrorActionPreference='Stop'; "
            f"$target = Get-Date '{iso_time}'; "
            "Set-Date -Date $target | Out-Null"
        )
        self._invoke_wmi_process(
            host, username, password, script, wait_for_completion=False
        )
        self.log_message("Команду зміни віддаленого часу надіслано; очікується перевірка.")
        wait_seconds = WMI_VERIFICATION_DELAY_SECONDS
        self.log_message(
            f"Очікування {wait_seconds} с перед перевіркою стану віддаленого годинника..."
        )
        time.sleep(wait_seconds)
        # Confirm the updated time via WMI
        remote_dt, parsed = self._get_remote_time_via_wmi(host, username, password)
        return remote_dt, parsed

    @staticmethod
    def _parse_remote_time(output: str) -> Tuple[Optional[_dt.datetime], Optional[str]]:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        for line in reversed(lines):
            try:
                return _dt.datetime.fromisoformat(line), line
            except ValueError:
                continue
        if lines:
            return None, "\n".join(lines)
        return None, None

    @staticmethod
    def _format_timedelta(delta: _dt.timedelta) -> str:
        total_seconds = delta.total_seconds()
        sign = "-" if total_seconds < 0 else ""
        abs_seconds = abs(total_seconds)
        hours, remainder = divmod(abs_seconds, 3600)
        minutes, remainder = divmod(remainder, 60)
        seconds = int(remainder)
        milliseconds = int(round((remainder - seconds) * 1000))
        return f"{sign}{int(hours):02d}:{int(minutes):02d}:{seconds:02d}.{milliseconds:03d}"

    # ------------------------------------------------------------------
    # Actions
    def check_remote_time(self) -> None:
        self._run_in_thread(self._check_remote_time_impl)

    def _check_remote_time_impl(self) -> None:
        try:
            host, username, passwords = self._get_connection_details()

            def action(password: str) -> Tuple[Optional[_dt.datetime], Optional[str]]:
                return self._get_remote_time_via_wmi(host, username, password)

            remote_dt, parsed = self._attempt_with_passwords(passwords, action)
        except Exception as exc:  # pylint: disable=broad-except
            self._show_error(str(exc))
            return

        if remote_dt is None:
            message = "Отримано неочікувану відповідь під час розбору віддаленого часу."
            details = parsed or "<немає виводу>"
            self._show_error(f"{message}\nВивід:\n{details}")
            return

        local_dt = _dt.datetime.now(_dt.timezone.utc).astimezone()
        delta = remote_dt - local_dt
        diff_message = self._format_timedelta(delta)

        self.log_message(f"Віддалений час: {remote_dt.isoformat()}")
        self.log_message(f"Локальний час:  {local_dt.isoformat()}")
        diff_tag = "warning" if abs(delta.total_seconds()) > SYNC_TOLERANCE.total_seconds() else None
        self.log_message(f"Різниця:       {diff_message}", tag=diff_tag)
        self._show_info("Віддалений час успішно отримано.")

    def sync_remote_time(self) -> None:
        self._run_in_thread(self._sync_remote_time_impl)

    def _sync_remote_time_impl(self) -> None:
        try:
            host, username, passwords = self._get_connection_details()
            local_dt = _dt.datetime.now(_dt.timezone.utc).astimezone()
            iso_time = local_dt.isoformat()

            def action(password: str) -> Tuple[Optional[_dt.datetime], Optional[str]]:
                return self._sync_remote_time_via_wmi(host, username, password, iso_time)

            remote_dt, parsed = self._attempt_with_passwords(passwords, action)
        except Exception as exc:  # pylint: disable=broad-except
            self._show_error(str(exc))
            return

        if remote_dt is None:
            message = "Не вдалося підтвердити оновлений віддалений час."
            details = parsed or "<немає виводу>"
            self._show_error(f"{message}\nВивід:\n{details}")
            return

        delta = remote_dt - _dt.datetime.now(_dt.timezone.utc).astimezone()
        diff_message = self._format_timedelta(delta)
        self.log_message(f"Віддалений час після синхронізації: {remote_dt.isoformat()}")
        self.log_message(f"Локальний час під час синхронізації: {iso_time}")
        diff_tag = "warning" if abs(delta.total_seconds()) > SYNC_TOLERANCE.total_seconds() else None
        self.log_message(f"Різниця після синхронізації: {diff_message}", tag=diff_tag)

        if abs(delta.total_seconds()) > SYNC_TOLERANCE.total_seconds():
            tolerance_message = self._format_timedelta(SYNC_TOLERANCE)
            self._show_error(
                "Різниця годинника після синхронізації перевищує допустиме "
                f"відхилення {tolerance_message} (зафіксовано {diff_message})."
            )
            return

        self._show_info("Віддалений годинник успішно синхронізовано.")

    # ------------------------------------------------------------------
    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    root = tk.Tk()
    app = TimeSyncApp(root)
    app.run()


if __name__ == "__main__":
    main()
