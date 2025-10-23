"""GUI utility for synchronizing remote Windows time via PsExec or WMI."""

from __future__ import annotations

import base64
import datetime as _dt
import os
import re
import shutil
import subprocess
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Optional, Tuple


SYNC_TOLERANCE = _dt.timedelta(minutes=5)
WMI_VERIFICATION_DELAY_SECONDS = 5


class RemoteProcessTimeoutError(RuntimeError):
    """Raised when the remote WMI process fails to finish in time."""


class TimeSyncApp:
    """Tkinter-based application for syncing time to a remote Windows host."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Remote Time Sync")
        self.root.resizable(False, False)

        self.psexec_var = tk.StringVar(value="PsExec.exe")
        self.host_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.method_var = tk.StringVar(value="psexec")
        self.settings_window: Optional[tk.Toplevel] = None

        self._build_ui()

    def _build_ui(self) -> None:
        padding = {"padx": 10, "pady": 5}
        main_frame = ttk.Frame(self.root)
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.columnconfigure(1, weight=1)

        ttk.Label(main_frame, text="Remote host/IP:").grid(row=0, column=0, sticky="w", **padding)
        host_entry = ttk.Entry(main_frame, textvariable=self.host_var, width=45)
        host_entry.grid(row=0, column=1, sticky="ew", **padding)
        settings_button = ttk.Button(main_frame, text="Settings...", command=self._open_settings_dialog)
        settings_button.grid(row=0, column=2, sticky="ew", **padding)

        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, columnspan=3, sticky="ew", padx=10, pady=(5, 0))
        button_frame.columnconfigure((0, 1), weight=1)

        self.check_button = ttk.Button(button_frame, text="Check remote time", command=self.check_remote_time)
        self.check_button.grid(row=0, column=0, sticky="ew", padx=(0, 5))

        self.sync_button = ttk.Button(button_frame, text="Sync now", command=self.sync_remote_time)
        self.sync_button.grid(row=0, column=1, sticky="ew", padx=(5, 0))

        self.output = ScrolledText(main_frame, width=70, height=15, state="disabled")
        self.output.grid(row=2, column=0, columnspan=3, padx=10, pady=(10, 10))

        # Accessibility: focus first field
        host_entry.focus_set()

    def _open_settings_dialog(self) -> None:
        if self.settings_window is not None and self.settings_window.winfo_exists():
            self.settings_window.lift()
            self.settings_window.focus_set()
            return

        window = tk.Toplevel(self.root)
        window.title("Connection Settings")
        window.resizable(False, False)
        window.transient(self.root)
        self.settings_window = window

        window.protocol("WM_DELETE_WINDOW", self._close_settings_dialog)

        settings_frame = ttk.Frame(window, padding=10)
        settings_frame.grid(row=0, column=0, sticky="nsew")
        settings_frame.columnconfigure(1, weight=1)

        padding = {"padx": 5, "pady": 5}

        ttk.Label(settings_frame, text="PsExec path:").grid(row=0, column=0, sticky="w", **padding)
        psexec_entry = ttk.Entry(settings_frame, textvariable=self.psexec_var, width=45)
        psexec_entry.grid(row=0, column=1, sticky="ew", **padding)
        browse_button = ttk.Button(settings_frame, text="Browse", command=self._browse_psexec)
        browse_button.grid(row=0, column=2, sticky="ew", **padding)

        ttk.Label(settings_frame, text="Username:").grid(row=1, column=0, sticky="w", **padding)
        username_entry = ttk.Entry(settings_frame, textvariable=self.username_var, width=45)
        username_entry.grid(row=1, column=1, columnspan=2, sticky="ew", **padding)

        ttk.Label(settings_frame, text="Password:").grid(row=2, column=0, sticky="w", **padding)
        password_entry = ttk.Entry(settings_frame, textvariable=self.password_var, width=45, show="*")
        password_entry.grid(row=2, column=1, columnspan=2, sticky="ew", **padding)

        ttk.Label(settings_frame, text="Execution method:").grid(row=3, column=0, sticky="w", **padding)
        method_frame = ttk.Frame(settings_frame)
        method_frame.grid(row=3, column=1, columnspan=2, sticky="w", **padding)
        ttk.Radiobutton(
            method_frame,
            text="PsExec",
            variable=self.method_var,
            value="psexec",
        ).grid(row=0, column=0, sticky="w", padx=(0, 10))
        ttk.Radiobutton(
            method_frame,
            text="WMI (Invoke-WmiMethod)",
            variable=self.method_var,
            value="wmi",
        ).grid(row=0, column=1, sticky="w")

        close_frame = ttk.Frame(settings_frame)
        close_frame.grid(row=4, column=0, columnspan=3, sticky="e", pady=(10, 0))
        close_button = ttk.Button(close_frame, text="Close", command=self._close_settings_dialog)
        close_button.grid(row=0, column=0, sticky="e")

        psexec_entry.focus_set()
        window.lift()

    def _close_settings_dialog(self) -> None:
        if self.settings_window is not None:
            window = self.settings_window
            self.settings_window = None
            window.destroy()

    # ------------------------------------------------------------------
    # UI helpers
    def _browse_psexec(self) -> None:
        path = filedialog.askopenfilename(
            title="Select PsExec.exe",
            filetypes=[("PsExec", "PsExec.exe"), ("Executable", "*.exe"), ("All files", "*.*")],
        )
        if path:
            self.psexec_var.set(path)

    def _append_output(self, message: str) -> None:
        self.output.configure(state="normal")
        self.output.insert(tk.END, f"{message}\n")
        self.output.see(tk.END)
        self.output.configure(state="disabled")

    def log_message(self, message: str) -> None:
        self.root.after(0, lambda: self._append_output(message))

    def _set_buttons_state(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        self.root.after(0, lambda: (self.check_button.config(state=state), self.sync_button.config(state=state)))

    def _show_error(self, message: str) -> None:
        self.log_message(f"ERROR: {message}")
        self.root.after(0, lambda: messagebox.showerror("Remote Time Sync", message))

    def _show_info(self, message: str) -> None:
        self.log_message(message)
        self.root.after(0, lambda: messagebox.showinfo("Remote Time Sync", message))

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
    def _resolve_psexec_path(self) -> str:
        path = self.psexec_var.get().strip()
        if not path:
            path = "PsExec.exe"

        if os.path.isfile(path):
            return path

        resolved = shutil.which(path)
        if resolved:
            return resolved

        raise FileNotFoundError(
            "Could not locate PsExec executable. Specify the full path or ensure it is available in PATH."
        )

    def _get_connection_details(self) -> Tuple[str, str, str]:
        host = self.host_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()

        if not host:
            raise ValueError("Remote host/IP cannot be empty.")
        if not username:
            raise ValueError("Username cannot be empty.")
        if not password:
            raise ValueError("Password cannot be empty.")

        return host, username, password

    def _execute_psexec(self, host: str, username: str, password: str, command: str) -> subprocess.CompletedProcess:
        psexec_path = self._resolve_psexec_path()
        cmd = [
            psexec_path,
            f"\\\\{host}",
            "-u",
            username,
            "-p",
            password,
            "-accepteula",
            "-nobanner",
            "powershell.exe",
            "-NoProfile",
            "-Command",
            command,
        ]

        self.log_message(f"Executing PsExec command against {host} ...")
        completed = subprocess.run(cmd, capture_output=True, text=True)
        if completed.returncode != 0:
            stderr = completed.stderr.strip() or "PsExec reported an unknown error."
            raise RuntimeError(stderr)
        return completed

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
            f"$sec = ConvertTo-SecureString {pass_q} -AsPlainText -Force; ",
            f"$cred = New-Object System.Management.Automation.PSCredential({user_q}, $sec); ",
            f"$cmd = {self._ps_single_quote(remote_command)}; ",
            f"$result = Invoke-WmiMethod -Class Win32_Process -ComputerName {host_q} -Credential $cred -Name Create -ArgumentList $cmd; ",
            "if ($null -eq $result) { throw 'Invoke-WmiMethod returned no data.' } ",
            "if ($result.ReturnValue -ne 0) { throw (\"Remote process failed with exit code {0}\" -f $result.ReturnValue) } ",
            "$remotePid = $result.ProcessId; ",
            "if (-not $remotePid) { throw 'Remote process did not return an identifier.' } ",
        ]
        if wait_for_completion:
            max_attempts = 150
            sleep_ms = 200
            timeout_seconds = max_attempts * sleep_ms / 1000
            timeout_message = self._ps_single_quote(
                f"Timed out waiting for remote process completion after {timeout_seconds:.1f} seconds."
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

        self.log_message(f"Executing WMI command against {host} ...")
        completed = self._run_local_powershell(command)
        if completed.returncode != 0:
            stderr = completed.stderr.strip() or "PowerShell reported an unknown error."
            if "Timed out waiting for remote process completion" in stderr:
                raise RemoteProcessTimeoutError(stderr)
            raise RuntimeError(stderr)

    def _get_remote_time_via_wmi(
        self, host: str, username: str, password: str
    ) -> Tuple[Optional[_dt.datetime], Optional[str]]:
        host_q = self._ps_single_quote(host)
        user_q = self._ps_single_quote(username)
        pass_q = self._ps_single_quote(password)
        command = (
            f"$sec = ConvertTo-SecureString {pass_q} -AsPlainText -Force; "
            f"$cred = New-Object System.Management.Automation.PSCredential({user_q}, $sec); "
            f"$os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName {host_q} -Credential $cred; "
            "if ($null -eq $os) { throw 'Failed to query remote operating system via WMI.' } "
            "$os.LocalDateTime"
        )

        self.log_message(f"Querying remote time via WMI on {host} ...")
        completed = self._run_local_powershell(command)
        if completed.returncode != 0:
            stderr = completed.stderr.strip() or "PowerShell reported an unknown error."
            raise RuntimeError(stderr)

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
        self.log_message("Remote time change command dispatched; verification pending.")
        wait_seconds = WMI_VERIFICATION_DELAY_SECONDS
        self.log_message(
            f"Waiting {wait_seconds} seconds before verifying the remote clock state..."
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
            host, username, password = self._get_connection_details()
            method = self.method_var.get()
            if method == "psexec":
                command = "Get-Date -Format o"
                completed = self._execute_psexec(host, username, password, command)
                stdout = completed.stdout.strip()
                remote_dt, parsed = self._parse_remote_time(stdout)
            else:
                remote_dt, parsed = self._get_remote_time_via_wmi(host, username, password)
        except Exception as exc:  # pylint: disable=broad-except
            self._show_error(str(exc))
            return

        if remote_dt is None:
            message = "Received unexpected response when parsing remote time."
            details = parsed or "<no output>"
            self._show_error(f"{message}\nOutput:\n{details}")
            return

        local_dt = _dt.datetime.now(_dt.timezone.utc).astimezone()
        delta = remote_dt - local_dt
        diff_message = self._format_timedelta(delta)

        log = [
            f"Remote time: {remote_dt.isoformat()}",
            f"Local time:  {local_dt.isoformat()}",
            f"Difference:  {diff_message}",
        ]
        self.log_message("\n".join(log))
        self._show_info("Remote time retrieved successfully.")

    def sync_remote_time(self) -> None:
        self._run_in_thread(self._sync_remote_time_impl)

    def _sync_remote_time_impl(self) -> None:
        try:
            host, username, password = self._get_connection_details()
            local_dt = _dt.datetime.now(_dt.timezone.utc).astimezone()
            iso_time = local_dt.isoformat()
            method = self.method_var.get()
            if method == "psexec":
                command = (
                    "$ErrorActionPreference='Stop'; "
                    f"$target = Get-Date '{iso_time}'; "
                    "Set-Date -Date $target | Out-Null; "
                    "Get-Date -Format o"
                )
                completed = self._execute_psexec(host, username, password, command)
                stdout = completed.stdout.strip()
                remote_dt, parsed = self._parse_remote_time(stdout)
            else:
                remote_dt, parsed = self._sync_remote_time_via_wmi(host, username, password, iso_time)
        except Exception as exc:  # pylint: disable=broad-except
            self._show_error(str(exc))
            return

        if remote_dt is None:
            message = "Failed to confirm the updated remote time."
            details = parsed or "<no output>"
            self._show_error(f"{message}\nOutput:\n{details}")
            return

        delta = remote_dt - _dt.datetime.now(_dt.timezone.utc).astimezone()
        diff_message = self._format_timedelta(delta)
        log = [
            f"Remote time after sync: {remote_dt.isoformat()}",
            f"Local time during sync: {iso_time}",
            f"Difference after sync:  {diff_message}",
        ]
        self.log_message("\n".join(log))

        if abs(delta.total_seconds()) > SYNC_TOLERANCE.total_seconds():
            tolerance_message = self._format_timedelta(SYNC_TOLERANCE)
            self._show_error(
                "Remote clock difference after sync exceeds the allowable "
                f"tolerance of {tolerance_message} (observed {diff_message})."
            )
            return

        self._show_info("Remote clock synchronized successfully.")

    # ------------------------------------------------------------------
    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    root = tk.Tk()
    app = TimeSyncApp(root)
    app.run()


if __name__ == "__main__":
    main()
