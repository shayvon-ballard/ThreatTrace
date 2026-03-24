from datetime import datetime

def triage_alerts(alerts):
    critical = [a for a in alerts if a["severity"] == "CRITICAL"]
    high = [a for a in alerts if a["severity"] == "HIGH"]
    medium = [a for a in alerts if a["severity"] == "MEDIUM"]
    low = [a for a in alerts if a["severity"] == "LOW"]

    return {
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low
    }

def print_triage_report(alerts):
    triaged = triage_alerts(alerts)
    print("\n" + "=" * 50)
    print("THREATTRACE — ALERT TRIAGE REPORT")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)

    for severity in ["critical", "high", "medium", "low"]:
        group = triaged[severity]
        if group:
            print(f"\n=== {severity.upper()} ALERTS ({len(group)}) ===")
            for alert in group:
                print(f"  - {alert['rule']} | {alert['username']} | {alert['ip']}")
                print(f"    {alert['description']}")
                print(f"    Timestamp: {alert['timestamp']}")

    print("\n" + "=" * 50)
    print(f"SUMMARY: {len(alerts)} total alerts requiring attention")
    print(f"  Critical: {len(triaged['critical'])}")
    print(f"  High:     {len(triaged['high'])}")
    print(f"  Medium:   {len(triaged['medium'])}")
    print(f"  Low:      {len(triaged['low'])}")
    print("=" * 50)

if __name__ == "__main__":
    from parser.log_parser import parse_log_file
    from parser.detection_rules import run_all_rules
    entries = parse_log_file("logs/auth.log")
    alerts = run_all_rules(entries)
    print_triage_report(alerts)