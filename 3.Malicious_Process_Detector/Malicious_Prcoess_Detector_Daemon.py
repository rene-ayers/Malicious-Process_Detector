import psutil
import json
import logging
import time
from datetime import datetime

# This script continuously monitors running processes on a system, identifies suspicious ones
# (e.g., based on a blacklist or unusual behavior like high CPU usage), and logs all findings
# to both a JSON file and a log file.



# ----------------- CONFIGURATION -----------------
BLACKLISTED_PROCESSES = {"mimikatz.exe", "powershell.exe", "unknown.exe"}  # Modify as needed
CPU_THRESHOLD = 50  # Flag processes using more than 50% CPU
MEMORY_THRESHOLD = 500  # Flag processes using more than 500MB RAM
LOG_FILE = "suspicious_process_monitor.log"
JSON_FILE = "suspicious_processes.json"

# ----------------- SET UP LOGGING -----------------
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# ----------------- FUNCTION TO GET PROCESS INFO -----------------
def get_running_processes():
    """Retrieve list of currently running processes with details."""
    processes = []
    for process in psutil.process_iter(attrs=["pid", "name", "cpu_percent", "memory_info"]):
        try:
            proc_info = process.info
            proc_info["memory_info"] = proc_info["memory_info"].rss // (1024 * 1024)  # Convert to MB
            processes.append(proc_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return processes

# ----------------- FUNCTION TO DETECT SUSPICIOUS PROCESSES -----------------
def detect_suspicious_processes():
    """Check running processes for suspicious activity and log results."""
    suspicious = []
    all_processes = get_running_processes()
    
    for process in all_processes:
        pid = process["pid"]
        name = process["name"]
        cpu_usage = process["cpu_percent"]
        memory_usage = process["memory_info"]
        
        if (
            name.lower() in BLACKLISTED_PROCESSES or
            cpu_usage > CPU_THRESHOLD or
            memory_usage > MEMORY_THRESHOLD
        ):
            suspicious_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "pid": pid,
                "name": name,
                "cpu_usage": cpu_usage,
                "memory_usage": memory_usage,
            }
            suspicious.append(suspicious_entry)
            logging.warning(f"Suspicious process detected: {suspicious_entry}")

    return suspicious

# ----------------- FUNCTION TO SAVE TO JSON -----------------
def save_to_json(data):
    """Save suspicious process data to a JSON file."""
    try:
        with open(JSON_FILE, "a") as file:
            json.dump(data, file, indent=4)
            file.write("\n")
        logging.info(f"Suspicious processes saved to {JSON_FILE}")
    except Exception as e:
        logging.error(f"Error writing to JSON file: {e}")

# ----------------- MAIN FUNCTION -----------------
def main():
    """Continuously monitor and log suspicious processes."""
    while True:
        logging.info("Scanning for suspicious processes...")
        suspicious_processes = detect_suspicious_processes()
        
        if suspicious_processes:
            print("[!] Suspicious Processes Detected! Check logs and JSON file.")
            save_to_json(suspicious_processes)
        else:
            print("[✓] No suspicious processes detected.")

        time.sleep(10)  # Scan every 10 seconds

# ----------------- RUN SCRIPT -----------------
if __name__ == "__main__":
    main()
