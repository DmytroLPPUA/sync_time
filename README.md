# sync_time

Tkinter-based helper application for synchronising the clock of a remote Windows PC with the local machine via [PsExec](https://learn.microsoft.com/sysinternals/downloads/psexec).

## Requirements

* Windows host where the utility will run.
* Python 3.9 or newer (ships with Tkinter).
* `PsExec.exe` from the Microsoft Sysinternals suite (copy it next to the script or make sure it is available through the `PATH`).
* Administrative credentials for the remote Windows machine.

## Usage

1. Download `PsExec.exe` from Microsoft Sysinternals and place it next to `sync_time_gui.py` (or add the directory to the `PATH`).
2. Run the script:

   ```powershell
   python sync_time_gui.py
   ```

3. Configure the connection details as described in the [Settings](#settings) section below.

4. Click **Check remote time** to display the remote clock, the local clock, and the time difference.
5. Click **Sync now** to set the remote clock to the local time. The tool automatically confirms the new time afterwards.

## Settings

The GUI stores the parameters needed for PsExec in a small form:

* **PsExec path** – Provide the path to `PsExec.exe` (pre-filled with `PsExec.exe` for convenience).
* **Remote computer** – Enter the remote computer name or IP address.
* **Credentials** – Enter the administrator username and password for the remote computer.

The application logs every action in the lower text area. Errors are shown in the log and via pop-up dialogs.

> **Note**
> * The utility invokes PsExec with the `-accepteula` flag. The first execution may still prompt for elevation depending on local policies.
> * PsExec transmits credentials over the network. Ensure you trust the network path before using it.
