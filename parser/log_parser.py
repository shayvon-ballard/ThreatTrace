import re
from datetime import datetime

def parse_line(line):
    try:
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 5:
            return None
        return {
            "timestamp": parts[0],
            "ip": parts[1],
            "username": parts[2],
            "action": parts[3],
            "description": parts[4]
        }
    except Exception:
        return None

def parse_log_file(filepath):
    parsed = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                entry = parse_line(line)
                if entry:
                    parsed.append(entry)
    print(f"Parsed {len(parsed)} log entries from {filepath}")
    return parsed

if __name__ == "__main__":
    entries = parse_log_file("logs/auth.log")
    print("\nSample entries:")
    for entry in entries[:5]:
        print(entry)