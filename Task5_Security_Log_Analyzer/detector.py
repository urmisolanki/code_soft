
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone


FAILED_STATUSES = {
    "failed", "failure", "denied", "unsuccessful"
}

SUCCESS_STATUSES = {
    "success", "successful", "accepted", "ok"
}

PRIVILEGED_USERS = {
    "admin", "administrator", "root", "sysadmin"
}


def parse_timestamp(value):
    timestamp = datetime.fromisoformat(value.strip())

    # Normalize timezone-aware values so comparisons are consistent.
    if timestamp.tzinfo is not None:
        timestamp = timestamp.astimezone(timezone.utc).replace(
            tzinfo=None
        )

    return timestamp


def analyze_logs(rows):
    alerts = []
    failed_logins = defaultdict(list)
    parsed_rows = []

    for row in rows:
        timestamp_text = str(row.get("timestamp") or "").strip()
        username = str(row.get("username") or "unknown").strip()
        ip = str(row.get("source_ip") or "unknown").strip()
        status = str(row.get("status") or "").strip().lower()

        username = username or "unknown"
        ip = ip or "unknown"

        try:
            timestamp = parse_timestamp(timestamp_text)
        except (ValueError, TypeError):
            continue

        item = {
            "timestamp": timestamp,
            "timestamp_text": timestamp_text,
            "username": username,
            "source_ip": ip,
            "status": status,
        }

        parsed_rows.append(item)

        key = (ip, username.lower())

        if status in FAILED_STATUSES:
            failed_logins[key].append(timestamp)

        if (
            status in SUCCESS_STATUSES
            and username.lower() in PRIVILEGED_USERS
        ):
            alerts.append({
                "severity": "MEDIUM",
                "type": "Privileged Account Login",
                "username": username,
                "ip": ip,
                "timestamp": timestamp_text,
                "details": (
                    f"Successful login for privileged account "
                    f"{username}."
                ),
            })

    # Detect five or more failures in a 10-minute window.
    for (ip, username), times in failed_logins.items():
        times.sort()
        window = deque()

        for current in times:
            window.append(current)

            while (
                window
                and current - window[0] > timedelta(minutes=10)
            ):
                window.popleft()

            if len(window) >= 5:
                alerts.append({
                    "severity": "HIGH",
                    "type": "Possible Brute-Force Activity",
                    "username": username,
                    "ip": ip,
                    "timestamp": window[0].isoformat(sep=" "),
                    "details": (
                        f"{len(window)} failed logins for {username} "
                        f"from {ip} within 10 minutes."
                    ),
                })
                break

    # Detect success after at least three earlier failures.
    for item in parsed_rows:
        if item["status"] not in SUCCESS_STATUSES:
            continue

        key = (
            item["source_ip"],
            item["username"].lower(),
        )

        login_time = item["timestamp"]

        earlier_failures = [
            failure_time
            for failure_time in failed_logins.get(key, [])
            if login_time - timedelta(minutes=10)
            <= failure_time < login_time
        ]

        if len(earlier_failures) >= 3:
            alerts.append({
                "severity": "HIGH",
                "type": "Login Success After Failures",
                "username": item["username"],
                "ip": item["source_ip"],
                "timestamp": item["timestamp_text"],
                "details": (
                    f"Successful login after "
                    f"{len(earlier_failures)} failed attempts "
                    f"within the preceding 10 minutes."
                ),
            })

    failed_count = sum(
        item["status"] in FAILED_STATUSES
        for item in parsed_rows
    )

    success_count = sum(
        item["status"] in SUCCESS_STATUSES
        for item in parsed_rows
    )

    return {
        "total_events": len(rows),
        "valid_events": len(parsed_rows),
        "failed_events": failed_count,
        "successful_events": success_count,
        "alerts": alerts,
    }
