# sync_time

Tkinter-based helper application for synchronising the clock of a remote Windows PC with the local machine via Windows Management Instrumentation (WMI).

## Requirements

* Windows host where the utility will run.
* Python 3.9 or newer (ships with Tkinter).
* Network access to the target Windows machine with WMI enabled for the built-in `Administrator` account.
* A `pass.txt` file located next to `sync_time_gui.py` that contains one possible Administrator password per line.

## Usage

1. Create `pass.txt` in the same folder as `sync_time_gui.py` and list every possible password for the remote `Administrator` account (each on its own line). The application will try them sequentially until the connection succeeds.
2. Run the script:

   ```powershell
   python sync_time_gui.py
   ```

3. Enter the remote computer name or IP address in the main window.
4. Click **Перевірити віддалений час** to display the remote clock, the local clock, and the time difference.
5. Click **Синхронізувати** to set the remote clock to the local time. The tool automatically confirms the new time afterwards.

The application logs every action in the lower text area. Errors are shown in the log and via pop-up dialogs.

> **Note**
> * Ensure that the remote firewall allows WMI/DCOM traffic and that the `Administrator` account is permitted for remote WMI calls.
