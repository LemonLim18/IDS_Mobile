import paramiko
import datetime

# SSH connection details
hostname = '192.168.25.43'
port = 22
username = 'miinning'
password = 'kali'
sudo_password = 'kali'

# Path to OSSEC alert log file on Kali Linux
log_file_path = '/var/ossec/logs/alerts/alerts.log'

def get_ossec_logs_via_ssh():
    try:
        # Initialize the SSH client
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Auto accept host keys

        # Attempt to connect to the server
        print(f"Attempting to connect to {hostname}...")
        client.connect(hostname, port, username, password)
        # If successful, print a success message
        print(f"Successfully connected to {hostname}")

        command = f"sudo -S cat {log_file_path}"

        # Execute the command to retrieve the log file
        stdin, stdout, stderr = client.exec_command(command)
        stdin.write(f"{sudo_password}\n")
        stdin.flush()  # Ensure the password is sent

        # Read the output (logs)
        logs = stdout.read().decode('utf-8')
        errors = stderr.read().decode('utf-8')

        # Check if there is any output
        if logs:
            print("Logs retrieved successfully:")
            print(logs)
            # Write logs to a local file
            with open(f"ossec_logs_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log", 'w') as log_file:
                log_file.write(logs)
        else:
            print("No logs available or empty output.")

        # if errors:
        #     print("Errors:")
        #     print(errors)

        # Close the SSH connection
        client.close()

    except Exception as e:
        print(f"Error: {e}")

# Call the function
get_ossec_logs_via_ssh()
