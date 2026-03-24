import random
from datetime import datetime, timedelta

USERNAMES = ["admin", "jsmith", "arogers", "mwilliams", "guest", "root"]
IPS = ["192.168.1.10", "192.168.1.20", "10.0.0.5", "185.220.101.5", "45.33.32.156", "192.168.1.10"]
ACTIONS = ["LOGIN_SUCCESS", "LOGIN_FAILED", "LOGOUT", "FILE_ACCESS", "PRIVILEGE_ESCALATION"]

def generate_logs(num_lines=200):
    logs = []
    base_time = datetime.now() - timedelta(hours=6)

    for i in range(num_lines):
        timestamp = base_time + timedelta(seconds=i*30)
        username = random.choice(USERNAMES)
        ip = random.choice(IPS)
        action = random.choice(ACTIONS)

        if i % 15 == 0:
            for j in range(10):
                t = timestamp + timedelta(seconds=j*2)
                logs.append(f"{t.strftime('%Y-%m-%d %H:%M:%S')} | {ip} | {username} | LOGIN_FAILED | Invalid password attempt")

        logs.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} | {ip} | {username} | {action} | User performed {action.lower()}")

    with open("logs/auth.log", "w") as f:
        f.write("\n".join(logs))

    print(f"Generated {len(logs)} log entries in logs/auth.log")

if __name__ == "__main__":
    generate_logs()