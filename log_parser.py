from pathlib import Path
import re
from collections import Counter

LOG_FILE = Path("export/kali_journal.log")

PATTERNS = [
    ("ssh_login_failure", re.compile(
        r"failed password for (?:invalid user )?.+? from \S+",
        re.I
    )),
    ("ssh_invalid_user", re.compile(
        r"invalid user \S+ from \S+",
        re.I
    )),
    ("ssh_login_success", re.compile(
        r"accepted (?:password|publickey) for \S+ from \S+",
        re.I
    )),
    ("pam_authentication_failure", re.compile(
        r"pam_[\w-]+\([^)]*auth[^)]*\): authentication failure",
        re.I
    )),
    ("sudo_command", re.compile(
        r"\bsudo\[\d+\]:\s+.*COMMAND=",
        re.I
    )),
    ("sudo_session_opened", re.compile(
        r"pam_unix\(sudo:session\): session opened",
        re.I
    )),
    ("sudo_session_closed", re.compile(
        r"pam_unix\(sudo:session\): session closed",
        re.I
    )),
]

def classify(line):
    for event_type, pattern in PATTERNS:
        if pattern.search(line):
            return event_type

    if "authentication failed" in line.lower() and (
        "virtualbox" in line.lower()
        or "vbox" in line.lower()
        or "drmipc" in line.lower()
    ):
        return "virtualbox_ipc_auth_error"

    if "session opened" in line.lower():
        return "session_opened"

    if "session closed" in line.lower():
        return "session_closed"

    return "other"


def main():
    if not LOG_FILE.is_file():
        print(f"ERROR: File not found: {LOG_FILE}")
        return

    counts = Counter()
    total_lines = 0
    unmatched_lines = 0

    with LOG_FILE.open(
        "r", encoding="utf-8", errors="replace"
    ) as log_file:
        for line in log_file:
            total_lines += 1
            event_type = classify(line)
            counts[event_type] += 1

            if not line.strip():
                unmatched_lines += 1

    print("\n=== Linux SOC Log Analyzer ===")
    print(f"Input file: {LOG_FILE}")
    print(f"Total lines read: {total_lines}")
    print(f"Blank lines: {unmatched_lines}")

    print("\n=== Classified Events ===")
    for event_type, count in sorted(counts.items()):
        print(f"{event_type}: {count}")

    print("\nNote:")
    print("- Counts represent matching log lines, not necessarily unique incidents.")
    print("- A matched event is not proof of a successful attack.")
    print("- 'other' means no current rule matched the line.")


if __name__ == "__main__":
    main()
