import csv
import re

# Logs provided as a string
logs = ''

# Pattern to extract data from each alert
pattern = re.compile(r"""\*\* Alert (?P<alert_id>\S+): - (?P<categories>.+?),\n(?P<alert_time>\d{4} \w{3} \d{2} \d{2}:\d{2}:\d{2}) \((?P<source_agent>.+?)\) (?P<source_ip>.+?)->(?P<log_path>.+)\nRule: (?P<rule_id>\d+) \(level (?P<rule_level>\d+)\) -> '(?P<rule_description>.+?)'(?:\nUser: (?P<user>.+))?\n(?P<log_details>.+)""", re.DOTALL)

# Extract data
matches = pattern.finditer(logs)
data = []

for match in matches:
    data.append(match.groupdict())

# Write to CSV
csv_file = "logs.csv"
fields = ["alert_id", "categories", "alert_time", "source_agent", "source_ip", "log_path", "rule_id", "rule_level", "rule_description", "user", "log_details"]

with open(csv_file, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(data)

print(f"Data has been written to {csv_file}")
