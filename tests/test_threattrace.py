import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from parser.detection_rules import (
    detect_brute_force,
    detect_privilege_escalation,
    detect_suspicious_ip,
    detect_root_activity
)

# --- Route Tests ---

def test_homepage_loads(client):
    response = client.get("/")
    assert response.status_code == 200

def test_export_route_exists(client):
    response = client.get("/export")
    assert response.status_code in [200, 302, 500]

def test_404_for_unknown_route(client):
    response = client.get("/this-does-not-exist")
    assert response.status_code == 404

# --- Detection Rule Tests ---

def test_brute_force_detected():
    entries = [
        {"ip": "10.10.10.10", "username": "admin", "action": "LOGIN_FAILED", "timestamp": "2024-01-01 00:00:01"},
        {"ip": "10.10.10.10", "username": "admin", "action": "LOGIN_FAILED", "timestamp": "2024-01-01 00:00:10"},
        {"ip": "10.10.10.10", "username": "admin", "action": "LOGIN_FAILED", "timestamp": "2024-01-01 00:00:20"},
        {"ip": "10.10.10.10", "username": "admin", "action": "LOGIN_FAILED", "timestamp": "2024-01-01 00:00:30"},
        {"ip": "10.10.10.10", "username": "admin", "action": "LOGIN_FAILED", "timestamp": "2024-01-01 00:00:40"},
    ]
    alerts = detect_brute_force(entries)
    assert len(alerts) > 0
    assert alerts[0]["rule"] == "Brute Force Attack"
    assert alerts[0]["severity"] == "HIGH"

def test_brute_force_not_triggered_below_threshold():
    entries = [
        {"ip": "10.10.10.10", "username": "admin", "action": "LOGIN_FAILED", "timestamp": "2024-01-01 00:00:01"},
        {"ip": "10.10.10.10", "username": "admin", "action": "LOGIN_FAILED", "timestamp": "2024-01-01 00:00:10"},
    ]
    alerts = detect_brute_force(entries)
    assert len(alerts) == 0

def test_privilege_escalation_detected():
    entries = [
        {"ip": "192.168.1.10", "username": "jdoe", "action": "PRIVILEGE_ESCALATION", "timestamp": "2024-01-01 00:01:00"},
    ]
    alerts = detect_privilege_escalation(entries)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "CRITICAL"

def test_suspicious_ip_detected():
    entries = [
        {"ip": "8.8.8.8", "username": "jdoe", "action": "LOGIN_SUCCESS", "timestamp": "2024-01-01 00:02:00"},
    ]
    alerts = detect_suspicious_ip(entries)
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "Suspicious External IP"

def test_internal_ip_not_flagged():
    entries = [
        {"ip": "192.168.1.10", "username": "jdoe", "action": "LOGIN_SUCCESS", "timestamp": "2024-01-01 00:02:00"},
    ]
    alerts = detect_suspicious_ip(entries)
    assert len(alerts) == 0

def test_root_activity_detected():
    entries = [
        {"ip": "192.168.1.10", "username": "root", "action": "LOGIN_SUCCESS", "timestamp": "2024-01-01 00:03:00"},
    ]
    alerts = detect_root_activity(entries)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "HIGH"