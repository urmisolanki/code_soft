# Advanced File Integrity Monitoring System

## Features
- Reuses the existing `baseline.json` format (`created_at` + `files`).
- SHA-256 hashes for file integrity checking.
- Real-time monitoring for created, modified, deleted, and moved files.
- Console security alerts.
- SQLite audit log stored in `file_integrity.db`.
- View recent events from the menu.

## Windows setup
Open PowerShell and run:

```powershell
cd D:\sem3\code_soft\Task4_File_Integrity_Monitor
py -m pip install -r requirements.txt
```

Copy `realtime_file_monitor.py`, `database.py`, and `requirements.txt` into your existing
`Task4_File_Integrity_Monitor` folder. Keep your existing `baseline.json` in that same folder.
Do not delete your existing `file_integrity_monitor.py`; this upgrade uses a separate script.

Run:

```powershell
py realtime_file_monitor.py
```

Enter the monitored folder, for example:

```text
D:\sem3\BD
```

Choose:
1. Create/update baseline
2. Start real-time monitoring and alerts
3. View recent security events

## Safe test procedure
1. Make sure you have a backup of important files. Use a test folder with copies, not important system folders.
2. Run option 1 once to create a fresh baseline for the test folder.
3. Run the program again and choose option 2.
4. While monitoring is running, create `new_test.txt` in the monitored folder. Expect an `ADDED` alert.
5. Edit and save an existing baseline file. Expect a `MODIFIED` alert.
6. Delete a disposable test file that was included in the baseline. Expect a `DELETED` alert.
7. Press Ctrl+C to stop monitoring.
8. Run the program and choose option 3 to view the SQLite audit log.

## Important notes
- The trusted baseline is not automatically changed when a file changes.
- A changed file is not automatically evidence of an attack.
- This is a learning project, not a replacement for enterprise endpoint detection.
- For the most reliable test, monitor a small folder that contains only disposable test files.
- The baseline uses relative paths, so run the baseline and monitor against the same root folder.
