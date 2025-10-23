"""GUI utility for synchronizing remote Windows time via PsExec."""

from __future__ import annotations

import datetime as _dt
import os
import shutil
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Optional, Tuple


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

        self._build_ui()

    def _build_ui(self) -> None:
        padding = {"padx": 10, "pady": 5}
        main_frame = ttk.Frame(self.root)
        main_frame.grid(row=0, column=0, sticky="nsew")

        ttk.Label(main_frame, text="PsExec path:").grid(row=0, column=0, sticky="w", **padding)
        psexec_entry = ttk.Entry(main_frame, textvariable=self.psexec_var, width=45)
        psexec_entry.grid(row=0, column=1, sticky="ew", **padding)
        browse_button = ttk.Button(main_frame, text="Browse", command=self._browse_psexec)
        browse_button.grid(row=0, column=2, sticky="ew", **padding)

        ttk.Label(main_frame, text="Remote host/IP:").grid(row=1, column=0, sticky="w", **padding)
        host_entry = ttk.Entry(main_frame, textvariable=self.host_var, width=45)
        host_entry.grid(row=1, column=1, columnspan=2, sticky="ew", **padding)

        ttk.Label(main_frame, text="Username:").grid(row=2, column=0, sticky="w", **padding)
        username_entry = ttk.Entry(main_frame, textvariable=self.username_var, width=45)
        username_entry.grid(row=2, column=1, columnspan=2, sticky="ew", **padding)

        ttk.Label(main_frame, text="Password:").grid(row=3, column=0, sticky="w", **padding)
        password_entry = ttk.Entry(main_frame, textvariable=self.password_var, width=45, show="*")
        password_entry.grid(row=3, column=1, columnspan=2, sticky="ew", **padding)

        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=3, sticky="ew", padx=10, pady=(5, 0))
        button_frame.columnconfigure((0, 1), weight=1)

        self.check_button = ttk.Button(button_frame, text="Check remote time", command=self.check_remote_time)
        self.check_button.grid(row=0, column=0, sticky="ew", padx=(0, 5))

        self.sync_button = ttk.Button(button_frame, text="Sync now", command=self.sync_remote_time)
        self.sync_button.grid(row=0, column=1, sticky="ew", padx=(5, 0))

        self.output = ScrolledText(main_frame, width=70, height=15, state="disabled")
        self.output.grid(row=5, column=0, columnspan=3, padx=10, pady=(10, 10))

        # Accessibility: focus first field
        host_entry.focus_set()

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
            command = "Get-Date -Format o"
            completed = self._execute_psexec(host, username, password, command)
        except Exception as exc:  # pylint: disable=broad-except
            self._show_error(str(exc))
            return

        stdout = completed.stdout.strip()
        remote_dt, parsed = self._parse_remote_time(stdout)

        if remote_dt is None:
            message = "Received unexpected response when parsing remote time."
            details = parsed or stdout or "<no output>"
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
            command = (
                "$ErrorActionPreference='Stop'; "
                f"$target = Get-Date '{iso_time}'; "
                "Set-Date -Date $target | Out-Null; "
                "Get-Date -Format o"
            )
            completed = self._execute_psexec(host, username, password, command)
        except Exception as exc:  # pylint: disable=broad-except
            self._show_error(str(exc))
            return

        stdout = completed.stdout.strip()
        remote_dt, parsed = self._parse_remote_time(stdout)
        if remote_dt is None:
            message = "Failed to confirm the updated remote time."
            details = parsed or stdout or "<no output>"
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
