
import sqlite3
from pathlib import Path


def connect(db_path):
    connection = sqlite3.connect(str(db_path), timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def init_db(db_path):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    with connect(db_path) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS log_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                event_type TEXT NOT NULL,
                status TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                severity TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                username TEXT,
                source_ip TEXT,
                event_timestamp TEXT,
                details TEXT
            )
        """)


def save_analysis(db_path, rows, alerts):
    with connect(db_path) as connection:
        connection.executemany("""
            INSERT INTO log_events
            (timestamp, username, source_ip, event_type, status)
            VALUES (?, ?, ?, ?, ?)
        """, [
            (
                row.get("timestamp", ""),
                row.get("username", ""),
                row.get("source_ip", ""),
                row.get("event_type", ""),
                row.get("status", "").lower(),
            )
            for row in rows
        ])

        connection.executemany("""
            INSERT INTO alerts
            (
                severity, alert_type, username,
                source_ip, event_timestamp, details
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, [
            (
                alert.get("severity", "MEDIUM"),
                alert.get("type", "Suspicious Activity"),
                alert.get("username", "Unknown"),
                alert.get("ip", alert.get("source_ip", "Unknown")),
                alert.get("timestamp", ""),
                alert.get("details", ""),
            )
            for alert in alerts
        ])


def dashboard_data(db_path):
    with connect(db_path) as connection:
        total = connection.execute(
            "SELECT COUNT(*) FROM log_events"
        ).fetchone()[0]

        failed = connection.execute("""
            SELECT COUNT(*)
            FROM log_events
            WHERE LOWER(TRIM(status)) IN (
                'failed', 'failure', 'denied', 'unsuccessful'
            )
        """).fetchone()[0]

        alert_count = connection.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        high_count = connection.execute("""
            SELECT COUNT(*)
            FROM alerts
            WHERE UPPER(TRIM(severity)) = 'HIGH'
        """).fetchone()[0]

        recent_alerts = connection.execute("""
            SELECT *
            FROM alerts
            ORDER BY id DESC
            LIMIT 50
        """).fetchall()

        top_ips = connection.execute("""
            SELECT source_ip, COUNT(*) AS total
            FROM log_events
            WHERE TRIM(source_ip) != ''
            GROUP BY source_ip
            ORDER BY total DESC, source_ip ASC
            LIMIT 5
        """).fetchall()

    alerts = [dict(row) for row in recent_alerts]

    return {
        "total_events": total,
        "failed_events": failed,
        "failed_logins": failed,
        "alert_count": alert_count,
        "total_alerts": alert_count,
        "high_count": high_count,
        "high_severity": high_count,
        "alerts": alerts,
        "recent_alerts": alerts,
        "top_ips": [dict(row) for row in top_ips],
    }


def clear_history(db_path):
    with connect(db_path) as connection:
        connection.execute("DELETE FROM log_events")
        connection.execute("DELETE FROM alerts")
