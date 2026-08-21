import csv
from datetime import datetime

def log_api_call(user, api_name):

    with open("api_logs.csv", "a", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([user, api_name, datetime.now()])


def log_security_event(user, api_name, analysis, prevention):

    with open("security_events.csv", "a", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            user,
            api_name,
            analysis["title"],
            analysis["risk"],
            analysis["risk_score"],
            prevention["action"],
            prevention["trust_score"],
            prevention["violations"],
            datetime.now()
        ])


def log_user_activity(user, action, status, role="user"):

    with open("user_activity.csv", "a", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([user, role, action, status, datetime.now()])
