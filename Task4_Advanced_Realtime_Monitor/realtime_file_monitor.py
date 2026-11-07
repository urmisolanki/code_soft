
import hashlib
import json
import time
from datetime import datetime
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from plyer import notification

import database


# Application files excluded from monitoring
BASELINE_FILE = "baseline.json"
DATABASE_FILE = "file_integrity.db"


# -----------------------------------------
# 1. CURRENT DATE AND TIME
# -----------------------------------------

def current_time():
    return datetime.now().astimezone().isoformat(
        timespec="seconds"
    )


# -----------------------------------------
# 2. WINDOWS DESKTOP POPUP NOTIFICATION
# -----------------------------------------

def show_popup(title, message):

    try:
        notification.notify(
            title=title,
            message=message,
            app_name="File Integrity Monitor",
            timeout=5
        )

    except Exception as error:
        print(f"[POPUP ERROR] {error}")


# -----------------------------------------
# 3. SHA-256 HASH GENERATION
# -----------------------------------------

def calculate_hash(file_path):

    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:

            for chunk in iter(
                lambda: file.read(1024 * 1024), b""
            ):
                sha256.update(chunk)

        return sha256.hexdigest()

    except OSError:
        return None


# -----------------------------------------
# 4. IGNORE APPLICATION FILES
# -----------------------------------------

def should_ignore(path, root):

    try:
        relative = Path(path).resolve().relative_to(
            root.resolve()
        )

    except (ValueError, OSError):
        return True

    if not relative.parts:
        return True

    if len(relative.parts) == 1:

        if relative.name in {
            BASELINE_FILE,
            DATABASE_FILE,
            BASELINE_FILE + ".tmp"
        }:
            return True

    return False


# -----------------------------------------
# 5. CREATE BASELINE
# -----------------------------------------

def create_baseline(root):

    files = {}

    for path in root.rglob("*"):

        if not path.is_file():
            continue

        if should_ignore(path, root):
            continue

        fingerprint = calculate_hash(path)

        if fingerprint is not None:

            relative = path.relative_to(root).as_posix()

            files[relative] = fingerprint

    baseline = {
        "created_at": current_time(),
        "files": files
    }

    baseline_path = root / BASELINE_FILE
    temp_path = root / (BASELINE_FILE + ".tmp")

    try:

        temp_path.write_text(
            json.dumps(baseline, indent=4),
            encoding="utf-8"
        )

        temp_path.replace(baseline_path)

    except OSError as error:

        print(f"[ERROR] Could not save baseline: {error}")
        return

    print("\n[SUCCESS] Baseline created successfully.")
    print(f"Folder: {root}")
    print(f"Files recorded: {len(files)}")
    print(f"Baseline: {baseline_path}")


# -----------------------------------------
# 6. LOAD BASELINE
# -----------------------------------------

def load_baseline(root):

    baseline_path = root / BASELINE_FILE

    if not baseline_path.is_file():

        print("\n[ERROR] No baseline found.")
        print("Choose option 1 first.")
        return None

    try:

        data = json.loads(
            baseline_path.read_text(encoding="utf-8")
        )

        if not isinstance(data.get("files"), dict):
            raise ValueError("Invalid baseline format.")

        return data["files"]

    except (OSError, json.JSONDecodeError, ValueError) as error:

        print(f"[ERROR] Could not read baseline: {error}")
        return None


# -----------------------------------------
# 7. REAL-TIME FILE MONITOR
# -----------------------------------------

class IntegrityMonitor(FileSystemEventHandler):

    def __init__(self, root, baseline):

        super().__init__()

        self.root = root
        self.baseline = baseline

        self.db_path = root / DATABASE_FILE

        # Duplicate event prevention
        self.last_events = {}

    # -------------------------------------
    # Convert absolute path to relative path
    # -------------------------------------

    def relative_path(self, path):

        return Path(path).resolve().relative_to(
            self.root.resolve()
        ).as_posix()

    # -------------------------------------
    # Record Security Event
    # -------------------------------------

    def record_event(
        self,
        event_type,
        path,
        fingerprint=None
    ):

        event_time = current_time()

        print("\n" + "=" * 65)
        print(f"[SECURITY ALERT] {event_type}")
        print(f"Time: {event_time}")
        print(f"File: {path}")

        if fingerprint:
            print(f"SHA-256: {fingerprint}")

        print("=" * 65)

        # Save event in SQLite database
        try:

            database.log_event(
                self.db_path,
                event_time,
                event_type,
                str(path),
                fingerprint or ""
            )

        except Exception as error:

            print(f"[DATABASE ERROR] {error}")

        # NEW: Windows desktop popup
        show_popup(
            f"Security Alert: {event_type}",
            f"File: {Path(path).name}\n"
            f"Event: {event_type}\n"
            "Please review this file."
        )

    # -------------------------------------
    # Process New or Modified Files
    # -------------------------------------

    def process_created_or_modified(self, path):

        if should_ignore(path, self.root):
            return

        file_path = Path(path)

        if not file_path.is_file():
            return

        # Wait for file writing to finish
        time.sleep(0.2)

        fingerprint = calculate_hash(file_path)

        if fingerprint is None:
            return

        relative = self.relative_path(file_path)

        previous = self.baseline.get(relative)

        if previous is None:

            event_type = "ADDED"

        elif previous != fingerprint:

            event_type = "MODIFIED"

        else:

            return

        # Prevent duplicate notifications for the same content
        event_key = (relative, event_type)

        if self.last_events.get(event_key) == fingerprint:
            return

        self.record_event(
            event_type,
            file_path,
            fingerprint
        )

        # Update memory, not the original JSON baseline
        self.baseline[relative] = fingerprint

        self.last_events[event_key] = fingerprint

    # -------------------------------------
    # File Created
    # -------------------------------------

    def on_created(self, event):

        if not event.is_directory:

            self.process_created_or_modified(
                event.src_path
            )

    # -------------------------------------
    # File Modified
    # -------------------------------------

    def on_modified(self, event):

        if not event.is_directory:

            self.process_created_or_modified(
                event.src_path
            )

    # -------------------------------------
    # File Deleted
    # -------------------------------------

    def on_deleted(self, event):

        if event.is_directory:
            return

        if should_ignore(event.src_path, self.root):
            return

        try:

            relative = self.relative_path(event.src_path)

        except (ValueError, OSError):
            return

        if relative in self.baseline:

            self.record_event(
                "DELETED",
                event.src_path
            )

            self.baseline.pop(relative, None)

    # -------------------------------------
    # File Moved or Renamed
    # -------------------------------------

    def on_moved(self, event):

        if event.is_directory:
            return

        source = event.src_path
        destination = event.dest_path

        if should_ignore(source, self.root):
            return

        try:

            relative_source = self.relative_path(source)

        except (ValueError, OSError):
            return

        if relative_source not in self.baseline:
            return

        # Wait for destination file to become available
        time.sleep(0.2)

        fingerprint = calculate_hash(destination)

        if fingerprint is None:
            return

        self.record_event(
            "MOVED",
            destination,
            fingerprint
        )

        self.baseline.pop(relative_source, None)

        if not should_ignore(destination, self.root):

            relative_destination = self.relative_path(
                destination
            )

            self.baseline[relative_destination] = fingerprint


# -----------------------------------------
# 8. START REAL-TIME MONITORING
# -----------------------------------------

def start_monitoring(root):

    baseline = load_baseline(root)

    if baseline is None:
        return

    db_path = root / DATABASE_FILE

    try:

        database.init_database(db_path)

    except Exception as error:

        print(f"[DATABASE ERROR] {error}")
        return

    handler = IntegrityMonitor(root, baseline)

    observer = Observer()

    try:

        observer.schedule(
            handler,
            str(root),
            recursive=True
        )

        observer.start()

        print("\n[MONITORING STARTED]")
        print(f"Watching: {root}")
        print("Monitoring subfolders as well.")
        print("Desktop Popup Notifications: ENABLED")
        print("Press Ctrl+C to stop monitoring.")

        while True:

            time.sleep(1)

    except KeyboardInterrupt:

        print("\n[STOPPING] Shutting down monitor...")

    except OSError as error:

        print(f"\n[ERROR] Monitoring failed: {error}")

    finally:

        if observer.is_alive():

            observer.stop()
            observer.join()

    print("[STOPPED] Monitoring has ended.")


# -----------------------------------------
# 9. SELECT MONITORING FOLDER
# -----------------------------------------

def choose_folder():

    raw_path = input(
        "\nEnter the folder path to monitor:\n> "
    ).strip().strip('"')

    if not raw_path:

        print("[ERROR] Folder path cannot be empty.")
        return None

    root = Path(raw_path).expanduser()

    try:

        root = root.resolve()

    except OSError as error:

        print(f"[ERROR] Invalid path: {error}")
        return None

    if not root.is_dir():

        print("[ERROR] This folder does not exist.")
        return None

    return root


# -----------------------------------------
# 10. MAIN MENU
# -----------------------------------------

def main():

    while True:

        print("\n" + "=" * 55)
        print(" ADVANCED REAL-TIME FILE INTEGRITY MONITOR")
        print("=" * 55)

        print("1. Create/update baseline")
        print("2. Start real-time monitoring and alerts")
        print("3. View recent security events")
        print("4. Exit")

        print("=" * 55)

        choice = input(
            "Enter your choice (1-4): "
        ).strip()

        if choice == "4":

            print("Exiting program. Goodbye!")
            break

        if choice not in {"1", "2", "3"}:

            print("[ERROR] Please enter 1, 2, 3, or 4.")
            continue

        root = choose_folder()

        if root is None:
            continue

        if choice == "1":

            create_baseline(root)

        elif choice == "2":

            start_monitoring(root)

        elif choice == "3":

            try:

                database.init_database(
                    root / DATABASE_FILE
                )

                database.show_recent_events(
                    root / DATABASE_FILE
                )

            except Exception as error:

                print(f"[ERROR] Could not read events: {error}")


# -----------------------------------------
# 11. RUN APPLICATION
# -----------------------------------------

if __name__ == "__main__":

    main()
