from flask import Flask, render_template, redirect, url_for
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

app = Flask(__name__)

def get_alerts():
    from parser.log_parser import parse_log_file
    from parser.detection_rules import run_all_rules
    entries = parse_log_file("logs/auth.log")
    alerts = run_all_rules(entries)
    return alerts

def get_stats(alerts):
    total = len(alerts)
    critical = sum(1 for a in alerts if a["severity"] == "CRITICAL")
    high = sum(1 for a in alerts if a["severity"] == "HIGH")
    medium = sum(1 for a in alerts if a["severity"] == "MEDIUM")
    brute_force = sum(1 for a in alerts if a["rule"] == "Brute Force Attack")
    privilege = sum(1 for a in alerts if a["rule"] == "Privilege Escalation")
    suspicious_ip = sum(1 for a in alerts if a["rule"] == "Suspicious External IP")
    root = sum(1 for a in alerts if a["rule"] == "Root Account Activity")

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "brute_force": brute_force,
        "privilege": privilege,
        "suspicious_ip": suspicious_ip,
        "root": root
    }

@app.route("/")
def index():
    alerts = get_alerts()
    stats = get_stats(alerts)
    return render_template("index.html", alerts=alerts, stats=stats)

@app.route("/export")
def export():
    from reports.exporter import export_to_csv
    alerts = get_alerts()
    export_to_csv(alerts)
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)