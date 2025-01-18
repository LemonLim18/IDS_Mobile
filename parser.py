import re
import json
import csv

logFileName = 'input/ossec_logs_20250118_165454.log'
jsonFileName = 'output/testLogs.json'
csvFileName = 'output/testLogs.csv'

with open(logFileName, 'r') as f:
    log_data = f.read()


# Regular expressions to extract the required fields
patterns = {
    "alert_id": r"Alert (\d+)",
    "categories": r"(\w+,\w+,\w+)",
    "alert_time": r"(\d{4} \w{3} \d{2} \d{2}:\d{2}:\d{2})",
    "source_agent": r"\(([^)]+)\)",
    "source_ip": r"(\d+\.\d+\.\d+\.\d+)->",
    "log_path": r"->([^\s]+)",
    "rule_id": r"Rule: (\d+)",
    "rule_level": r"level (\d+)",
    "rule_description": r"-> '([^']+)'",
    "user": r"User: (\w+)",
    "log_details": r"(\d{4}-\d{2}-\d{2}T[\d:.+]+[\w-]+ sshd\[\d+\]: .+)"
}

# Split the logs into individual alert entries
alerts = log_data.strip().split('\n\n** Alert')

# List to store extracted data for each alert
extracted_alerts = []

# Iterate through each alert and extract the data
for alert in alerts:
    alert = '** Alert' + alert  # Add '** Alert' back at the start of each alert
    extracted_data = {}

    for key, pattern in patterns.items():
        match = re.search(pattern, alert)
        if match:
            extracted_data[key] = match.group(1)

    if extracted_data:
        extracted_alerts.append(extracted_data)

# Convert to JSON format
json_output = json.dumps(extracted_alerts, indent=4)

# Write to testLogs.json file
with open(jsonFileName, 'w') as f:
    f.write(json_output)

print("Data has been read from " + logFileName + " and written to testLogs.json")


# Write to CSV
with open(jsonFileName, 'r') as f:
    alerts_data = json.load(f)

# Open CSV file for writing
with open(csvFileName, "w", newline="") as csvFile:
     # Define the CSV fieldnames (columns)
    fieldnames = ['alert_id', 'categories', 'alert_time', 'source_agent', 'source_ip', 'log_path', 'rule_id', 'rule_level', 'rule_description', 'user', 'log_details']
    
    # Create a CSV DictWriter object
    writer = csv.DictWriter(csvFile, fieldnames=fieldnames)
    
    # Write the header (column names) to the CSV
    writer.writeheader()
    
    # Write the rows from the JSON data to the CSV
    for alert in alerts_data:
        writer.writerow(alert)

print(f"Data has been written to {csvFileName}")