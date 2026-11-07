"""SQLite storage for file integrity security events."""
import sqlite3
from pathlib import Path


def connect(db_path: Path):
    connection = sqlite3.connect(str(db_path))
    connection.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT NOT NULL,
            event_type TEXT NOT NULL,
            file_path TEXT NOT NULL,
            fingerprint TEXT
        )
    """)
    connection.commit()
    return connection


def init_database(db_path: Path) -> None:
    connection = connect(db_path)
    connection.close()


def log_event(db_path: Path, event_time: str, event_type: str,
              file_path: str, fingerprint: str) -> None:
    connection = connect(db_path)
    with connection:
        connection.execute(
            """INSERT INTO security_events
               (event_time, event_type, file_path, fingerprint)
               VALUES (?, ?, ?, ?)""",
            (event_time, event_type, file_path, fingerprint)
        )
    connection.close()


def show_recent_events(db_path: Path, limit: int = 20) -> None:
    connection = connect(db_path)
    rows = connection.execute(
        """SELECT event_time, event_type, file_path
           FROM security_events ORDER BY id DESC LIMIT ?""",
        (limit,)
    ).fetchall()
    connection.close()

    print("\n" + "=" * 78)
    print(f" RECENT SECURITY EVENTS (latest {limit})")
    print("=" * 78)
    if not rows:
        print("No events have been recorded yet.")
        return
    for event_time, event_type, file_path in rows:
        print(f"{event_time} | {event_type:<8} | {file_path}")
