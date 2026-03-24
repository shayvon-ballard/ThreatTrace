import csv
import os
from datetime import datetime

REPORTS_DIR = "reports"

def export_to_csv(alerts):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{REPORTS_DIR}/threattrace_report_{timestamp}.csv"

    with open(filename, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow([
            "Rule",
            "Severity",
            "IP Address",
            "Username",
            "Description",
            "Timestamp"
        ])

        for alert in alerts:
            writer.writerow([
                alert["rule"],
                alert["severity"],
                alert["ip"],
                alert["username"],
                alert["description"],
                alert["timestamp"]
            ])

    print(f"Report exported to: {filename}")
    return filename

if __name__ == "__main__":
    from parser.log_parser import parse_log_file
    from parser.detection_rules import run_all_rules
    entries = parse_log_file("logs/auth.log")
    alerts = run_all_rules(entries)
    export_to_csv(alerts)