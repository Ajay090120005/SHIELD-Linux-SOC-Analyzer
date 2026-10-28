from pathlib import Path
from datetime import datetime
from collections import defaultdict
import re

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "export" / "kali_journal.log"

WINDOW_SECONDS = 60
THRESHOLD = 3

# Rule 1: PAM authentication failures
PAM_FAILURE = re.compile(
    r"pam_unix\(([^:)]*):auth\): authentication failure.*?"
    r"\buser=([^\s;]+)",
    re.IGNORECASE,
)

# Rule 2: SSH failed-password events
SSH_FAILURE = re.compile(
    r"Failed password for (?:invalid user )?(\S+)\s+from\s+(\S+)",
    re.IGNORECASE,
)

# Rule 3: SSH invalid-user events
SSH_INVALID_USER = re.compile(
    r"Invalid user\s+(\S+)\s+from\s+(\S+)",
    re.IGNORECASE,
)


def parse_timestamp(line):
    """Parse the timestamp at the start of a short-iso journal line."""
    parts = line.split(maxsplit=1)

    if not parts:
        return None

    try:
        return datetime.fromisoformat(parts[0])
    except (ValueError, TypeError):
        return None


def detect_events(log_file=LOG_FILE):
    if not Path(log_file).is_file():
        raise FileNotFoundError(f"Log file not found: {log_file}")

    # Keep timestamp and evidence for every matching event.
    events = defaultdict(list)

    with Path(log_file).open(
        "r", encoding="utf-8", errors="replace"
    ) as file:
        for line_number, raw_line in enumerate(file, start=1):
            line = raw_line.rstrip("\r\n")

            if not line.strip():
                continue

            timestamp = parse_timestamp(line)

            if timestamp is None:
                continue

            pam_match = PAM_FAILURE.search(line)

            if pam_match:
                service, user = pam_match.groups()
                events[("PAM authentication failure", user, service)].append({
                    "timestamp": timestamp,
                    "line_number": line_number,
                    "raw": line,
                })
                continue

            ssh_match = SSH_FAILURE.search(line)

            if ssh_match:
                user, source_ip = ssh_match.groups()
                events[("SSH failed password", user, source_ip)].append({
                    "timestamp": timestamp,
                    "line_number": line_number,
                    "raw": line,
                })
                continue

            invalid_match = SSH_INVALID_USER.search(line)

            if invalid_match:
                user, source_ip = invalid_match.groups()
                events[("SSH invalid user", user, source_ip)].append({
                    "timestamp": timestamp,
                    "line_number": line_number,
                    "raw": line,
                })

    alerts = []

    for (event_type, user, source), records in events.items():
        records.sort(key=lambda item: item["timestamp"])

        left = 0

        for right, current in enumerate(records):
            while (
                left < right
                and (
                    current["timestamp"] - records[left]["timestamp"]
                ).total_seconds() > WINDOW_SECONDS
            ):
                left += 1

            count = right - left + 1

            if count < THRESHOLD:
                continue

            window_records = records[left:right + 1]

            alerts.append({
                "user": user,
                "service": source if event_type == "PAM authentication failure" else "sshd",
                "source_ip": source if event_type != "PAM authentication failure" else "",
                "count": count,
                "start": window_records[0]["timestamp"].isoformat(),
                "end": current["timestamp"].isoformat(),
                "severity": "Potentially suspicious",
                "event_type": event_type,
                "reason": (
                    f"{count} events of type '{event_type}' "
                    f"within {WINDOW_SECONDS} seconds"
                ),
                "evidence": (
                    f"{count} matching log lines; "
                    f"source: {source}"
                ),
                "log_lines": [
                    record["line_number"] for record in window_records
                ],
                "sample_evidence": [
                    record["raw"] for record in window_records[:5]
                ],
            })

            # One alert for this group/window, not one alert per line.
            break

    return alerts


if __name__ == "__main__":
    try:
        results = detect_events()

        print("=== SHIELD Detection Engine ===")
        print(f"Log file: {LOG_FILE}")
        print(f"Detection patterns: {len(results)}")

        for index, alert in enumerate(results, start=1):
            print(f"\n--- Detection {index} ---")
            print(f"Type: {alert['event_type']}")
            print(f"Severity: {alert['severity']}")
            print(f"User: {alert['user']}")
            print(f"Service/source: {alert['service']}")
            print(f"Events in window: {alert['count']}")
            print(f"Window: {alert['start']} -> {alert['end']}")
            print(f"Reason: {alert['reason']}")

            for evidence in alert["sample_evidence"]:
                print(f"Evidence: {evidence}")

        print(
            "\nNote: These are rule-based indicators for investigation, "
            "not proof of an attack."
        )

    except (FileNotFoundError, OSError) as error:
        print(f"ERROR: {error}")
