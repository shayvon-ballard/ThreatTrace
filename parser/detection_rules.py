from datetime import datetime, timedelta
from collections import defaultdict

INTERNAL_IPS = ["192.168.1.10", "192.168.1.20", "10.0.0.5"]
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 60

def detect_brute_force(entries):
    alerts = []
    failed_logins = defaultdict(list)

    for entry in entries:
        if entry["action"] == "LOGIN_FAILED":
            key = (entry["ip"], entry["username"])
            failed_logins[key].append(entry["timestamp"])

    for (ip, username), timestamps in failed_logins.items():
        times = [datetime.strptime(t, "%Y-%m-%d %H:%M:%S") for t in timestamps]
        times.sort()

        for i in range(len(times)):
            window = [t for t in times if times[i] <= t <= times[i] + timedelta(seconds=BRUTE_FORCE_WINDOW)]
            if len(window) >= BRUTE_FORCE_THRESHOLD:
                alerts.append({
                    "rule": "Brute Force Attack",
                    "severity": "HIGH",
                    "ip": ip,
                    "username": username,
                    "description": f"{len(window)} failed login attempts in {BRUTE_FORCE_WINDOW} seconds",
                    "timestamp": timestamps[i]
                })
                break

    return alerts

def detect_privilege_escalation(entries):
    alerts = []
    for entry in entries:
        if entry["action"] == "PRIVILEGE_ESCALATION":
            alerts.append({
                "rule": "Privilege Escalation",
                "severity": "CRITICAL",
                "ip": entry["ip"],
                "username": entry["username"],
                "description": f"User {entry['username']} performed privilege escalation",
                "timestamp": entry["timestamp"]
            })
    return alerts

def detect_suspicious_ip(entries):
    alerts = []
    for entry in entries:
        if entry["ip"] not in INTERNAL_IPS and entry["action"] == "LOGIN_SUCCESS":
            alerts.append({
                "rule": "Suspicious External IP",
                "severity": "MEDIUM",
                "ip": entry["ip"],
                "username": entry["username"],
                "description": f"Successful login from external IP {entry['ip']}",
                "timestamp": entry["timestamp"]
            })
    return alerts

def detect_root_activity(entries):
    alerts = []
    for entry in entries:
        if entry["username"] == "root":
            alerts.append({
                "rule": "Root Account Activity",
                "severity": "HIGH",
                "ip": entry["ip"],
                "username": entry["username"],
                "description": f"Root account performed {entry['action']}",
                "timestamp": entry["timestamp"]
            })
    return alerts

def run_all_rules(entries):
    all_alerts = []
    all_alerts.extend(detect_brute_force(entries))
    all_alerts.extend(detect_privilege_escalation(entries))
    all_alerts.extend(detect_suspicious_ip(entries))
    all_alerts.extend(detect_root_activity(entries))
    print(f"Detection complete — {len(all_alerts)} alerts generated!")
    return all_alerts

if __name__ == "__main__":
    from parser.log_parser import parse_log_file
    entries = parse_log_file("logs/auth.log")
    alerts = run_all_rules(entries)
    for alert in alerts[:5]:
        print(alert)