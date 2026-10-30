import json
import re
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter

LOG_FILE = Path("export/kali_journal.log")

PATTERNS = [
    ("ssh_login_failure", re.compile(
        r"failed password for (?:invalid user )?.+? from \S+", re.I
    )),
    ("ssh_invalid_user", re.compile(
        r"invalid user \S+ from \S+", re.I
    )),
    ("ssh_login_success", re.compile(
        r"accepted (?:password|publickey) for \S+ from \S+", re.I
    )),
    ("pam_authentication_failure", re.compile(
        r"pam_[\w-]+\([^)]*auth[^)]*\): authentication failure", re.I
    )),
    ("sudo_command", re.compile(
        r"\bsudo\[\d+\]:\s+.*COMMAND=", re.I
    )),
    ("sudo_session_opened", re.compile(
        r"pam_unix\(sudo:session\): session opened", re.I
    )),
    ("sudo_session_closed", re.compile(
        r"pam_unix\(sudo:session\): session closed", re.I
    )),
]

WINDOWS_EVENT_TYPES = {
    4624: "windows_successful_logon",
    4625: "windows_failed_logon",
    4688: "windows_process_creation",
    4672: "windows_special_privileges_assigned",
    4740: "windows_account_locked",
    1102: "windows_security_log_cleared",
}


def classify(line):
    for event_type, pattern in PATTERNS:
        if pattern.search(line):
            return event_type

    lower_line = line.lower()

    if "authentication failed" in lower_line and (
        "virtualbox" in lower_line
        or "vbox" in lower_line
        or "drmipc" in lower_line
    ):
        return "virtualbox_ipc_auth_error"

    if "session opened" in lower_line:
        return "session_opened"

    if "session closed" in lower_line:
        return "session_closed"

    return "other"


def parse_windows_timestamp(value):
    if value is None:
        return "Unknown"

    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(
            value / 1000, tz=timezone.utc
        ).astimezone().isoformat(sep=" ")

    value = str(value)

    match = re.search(r"/Date\((-?\d+)(?:[+-]\d+)?\)/", value)
    if match:
        milliseconds = int(match.group(1))
        return datetime.fromtimestamp(
            milliseconds / 1000, tz=timezone.utc
        ).astimezone().isoformat(sep=" ")

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        ).astimezone().isoformat(sep=" ")
    except ValueError:
        return value


def classify_windows_event(event_id):
    try:
        event_id = int(event_id)
    except (TypeError, ValueError):
        return "windows_unknown_event"

    return WINDOWS_EVENT_TYPES.get(
        event_id, f"windows_event_{event_id}"
    )


def load_windows_json(path):
    """Read Windows Event Log JSON exported through PowerShell."""
    path = Path(path)

    with path.open("r", encoding="utf-8-sig") as file:
        data = json.load(file)

    if isinstance(data, dict):
        data = [data]

    if not isinstance(data, list):
        raise ValueError("Expected a JSON object or array of events.")

    records = []

    for line_number, event in enumerate(data, start=1):
        if not isinstance(event, dict):
            continue

        event_id = event.get("Id", event.get("EventID", "Unknown"))
        provider = event.get("ProviderName", "Unknown")
        timestamp = parse_windows_timestamp(
            event.get("TimeCreated")
        )
        level = event.get("LevelDisplayName", "Unknown")
        message = str(event.get("Message") or "")

        records.append({
            "Line": line_number,
            "Timestamp": timestamp,
            "Event ID": event_id,
            "Event Type": classify_windows_event(event_id),
            "Level": level,
            "Provider": provider,
            "Raw Log": (
                f"Event ID: {event_id} | Provider: {provider} | "
                f"Level: {level} | {message}"
            ),
            "Message": message,
        })

    return records


if __name__ == "__main__":
    print("Windows event parser module loaded.")