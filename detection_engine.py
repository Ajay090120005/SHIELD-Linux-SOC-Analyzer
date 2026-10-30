from pathlib import Path
from datetime import datetime
from collections import defaultdict
import json
import re

from log_parser import parse_windows_timestamp

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "export" / "kali_journal.log"

WINDOW_SECONDS = 60
THRESHOLD = 3

PAM_FAILURE = re.compile(
    r"pam_unix\(([^:)]*):auth\): authentication failure.*?"
    r"\buser=([^\s;]+)", re.IGNORECASE
)

SSH_FAILURE = re.compile(
    r"Failed password for (?:invalid user )?(\S+)\s+from\s+(\S+)",
    re.IGNORECASE
)

SSH_INVALID_USER = re.compile(
    r"Invalid user\s+(\S+)\s+from\s+(\S+)", re.IGNORECASE
)


def parse_timestamp(line):
    parts = line.split(maxsplit=1)
    if not parts:
        return None
    try:
        return datetime.fromisoformat(parts[0])
    except (ValueError, TypeError):
        return None


def make_alert(event_type, records, user, source, severity, reason):
    return {
        "user": user,
        "service": "Windows Security" if event_type.startswith("Windows") else "sshd",
        "source_ip": source,
        "count": len(records),
        "start": records[0]["timestamp"].isoformat(),
        "end": records[-1]["timestamp"].isoformat(),
        "severity": severity,
        "event_type": event_type,
        "reason": reason,
        "evidence": f"{len(records)} matching Windows event(s)",
        "log_lines": [r["line_number"] for r in records],
        "sample_evidence": [r["raw"] for r in records[:5]],
    }


def extract_windows_field(message, pattern):
    match = re.search(pattern, message, re.IGNORECASE)
    return match.group(1).strip() if match else "Unknown"


def detect_windows_events(log_file):
    with Path(log_file).open("r", encoding="utf-8-sig") as file:
        data = json.load(file)

    if isinstance(data, dict):
        data = [data]

    if not isinstance(data, list):
        raise ValueError("Invalid Windows event JSON format")

    failed_logons = defaultdict(list)
    alerts = []

    for line_number, event in enumerate(data, start=1):
        if not isinstance(event, dict):
            continue

        try:
            event_id = int(event.get("Id", event.get("EventID", 0)))
        except (ValueError, TypeError):
            continue

        timestamp_text = parse_windows_timestamp(event.get("TimeCreated"))
        try:
            timestamp = datetime.fromisoformat(timestamp_text)
        except (ValueError, TypeError):
            continue

        message = str(event.get("Message") or "")
        raw = f"Event ID: {event_id} | {message}"

        record = {
            "timestamp": timestamp,
            "line_number": line_number,
            "raw": raw,
        }

        if event_id == 4625:
            user = extract_windows_field(
                message,
                r"Account Name:\s*([^\r\n]+)"
            )
            source_ip = extract_windows_field(
                message,
                r"Source Network Address:\s*([^\r\n]+)"
            )
            failed_logons[(user, source_ip)].append(record)

        elif event_id == 1102:
            alerts.append(make_alert(
                "Windows Security Log Cleared",
                [record],
                "Unknown",
                "",
                "High",
                "Windows Security audit log was cleared. Investigate who performed this action."
            ))

        elif event_id == 4740:
            user = extract_windows_field(
                message,
                r"Account Name:\s*([^\r\n]+)"
            )
            alerts.append(make_alert(
                "Windows Account Locked",
                [record],
                user,
                "",
                "Medium",
                "Windows account lockout detected. Investigate possible repeated failed logons."
            ))

    for (user, source_ip), records in failed_logons.items():
        records.sort(key=lambda r: r["timestamp"])
        left = 0

        for right, current in enumerate(records):
            while (
                left < right
                and (current["timestamp"] - records[left]["timestamp"])
                .total_seconds() > WINDOW_SECONDS
            ):
                left += 1

            window_records = records[left:right + 1]

            if len(window_records) >= THRESHOLD:
                alerts.append(make_alert(
                    "Windows Failed Logon Burst",
                    window_records,
                    user,
                    source_ip,
                    "High",
                    f"{len(window_records)} failed logons within {WINDOW_SECONDS} seconds. Investigate possible brute-force activity."
                ))
                break

    return alerts


def detect_linux_events(log_file):
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
                and (current["timestamp"] - records[left]["timestamp"])
                .total_seconds() > WINDOW_SECONDS
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
                "reason": f"{count} events within {WINDOW_SECONDS} seconds",
                "evidence": f"{count} matching log lines; source: {source}",
                "log_lines": [r["line_number"] for r in window_records],
                "sample_evidence": [r["raw"] for r in window_records[:5]],
            })
            break

    return alerts


def detect_events(log_file=LOG_FILE):
    path = Path(log_file)

    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")

    if path.suffix.lower() == ".json":
        return detect_windows_events(path)

    return detect_linux_events(path)


if __name__ == "__main__":
    try:
        results = detect_events()
        print("=== SHIELD Detection Engine ===")
        print(f"Detections: {len(results)}")

        for index, alert in enumerate(results, start=1):
            print(f"\nDetection {index}: {alert['event_type']}")
            print(f"Severity: {alert['severity']}")
            print(f"User: {alert['user']}")
            print(f"Reason: {alert['reason']}")

    except (FileNotFoundError, OSError, ValueError) as error:
        print(f"ERROR: {error}")