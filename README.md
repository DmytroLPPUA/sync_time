# sync_time

Tkinter-based helper application for synchronising the clock of a remote Windows PC with the local machine via Windows Management Instrumentation (WMI).

## Requirements

* Windows host where the utility will run.
* Python 3.9 or newer (ships with Tkinter).
* Network access to the target Windows machine with WMI enabled for the built-in `Administrator` account.
* An encrypted password vault (`pass.enc`) located next to `sync_time_gui.py`. Use the built-in password manager to populate it with potential `Administrator` passwords.

## Usage

1. Run the script:

   ```powershell
   python sync_time_gui.py
   ```

2. Click **Керування паролями** in the main window to add or remove possible passwords for the remote `Administrator` account. The entries are stored encrypted in `pass.enc` next to the script. Changes are saved automatically.
3. Enter the remote computer name or IP address in the main window.
4. Click **Перевірити віддалений час** to display the remote clock, the local clock, and the time difference.
5. Click **Синхронізувати** to set the remote clock to the local time. The tool automatically confirms the new time afterwards.

The application logs every action in the lower text area. Errors are shown in the log and via pop-up dialogs.

> **Note**
> * Ensure that the remote firewall allows WMI/DCOM traffic and that the `Administrator` account is permitted for remote WMI calls.

## Building a Windows executable

To distribute the tool without requiring Python on the target machine, package it into a standalone executable with [PyInstaller](https://pyinstaller.org/):

1. Open a PowerShell prompt in the project directory and (optionally) create and activate a virtual environment.
2. Install PyInstaller:

   ```powershell
   py -3 -m pip install pyinstaller
   ```

3. Build the executable:

   ```powershell
   py -3 -m PyInstaller --noconsole --onefile --name sync_time sync_time_gui.py
   ```

   The binary will be created at `dist\sync_time.exe`. Copy `pass.enc` next to this file so the password manager can access the encrypted vault.

4. Optionally copy any additional resources (e.g., README) into the distribution folder before handing it over to end users.
