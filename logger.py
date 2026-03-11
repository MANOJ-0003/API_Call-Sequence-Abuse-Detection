import csv
from datetime import datetime

def log_api_call(user, api_name):

    with open("api_logs.csv", "a", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([user, api_name, datetime.now()])