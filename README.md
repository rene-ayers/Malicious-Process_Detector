# Suspicious Process Monitoring Tool

This Python tool monitors all running processes on a system and flags suspicious activity - such as high CPU usage, large memory consumption, or blacklisted programs. 
It logs the findings in both JSON file and a log file.

---

## Features

- Scans all currently running system processes
- Flags any process that:
    - Mactches a blacklisted name
    - Uses too much CPU (over 50%)
    - Uses too much memory (over 500 MB)
- Logs warnings to a '.log' file
- Saves detailed reports to a '.json' file
- Automatically rescans every 10 seconds

---

## File Descriptions

| File Name                        | Purpose                                   |
| ---------------------------------| ------------------------------------------|
| 'suspicious_process_monitor.py'  | Main Python script                        |
| 'suspicious_process_monitor.log' | Log file recording of flagged processes   |
| 'suspicious_processes.json'      | JSON report of suspicious processes       |

---

## Configuration

- 'BLACKLISTED_PROCESSES' : Add or remove blacklisted process names
- 'CPU_THRESHOLD' : Max allowed CPU  % per process (default is 50)
- 'MEMORY_THRESHOLD" : Max allowed memory in MB per process (default is 500)

---

## How to Use

1. Python 3 must be installed.
2. Install the 'psutil' library:
   ```bash
   pip install psutil
3. Run the script:
   ```bash
   python suspicious_process_monitor.py
4. Let it run in the background and it will alert you when something suspicious is found.
