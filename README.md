# Fishnet

Fishnet is a Python-based network monitoring tool designed to list active network connections on your system with an added layer of security analysis. It intends to trace processes back to their executable files, calculates their SHA-256 hashe, and check these against the VirusTotal database to detect potential malware.

## Features

- **Real-time Connection Monitoring**: Continuously displays network connections with details such as local and remote addresses, status, PID, PPID, owner, and process name.
- **Malware Detection**: Integrates with VirusTotal to check file hashes for known malicious signatures.
- **Color-Coded Output**: Highlights remote addresses based on malware detection:
  - **Green**: No malicious detections or no data available.
  - **Orange**: Some malicious detections (less than 5).
  - **Red**: High likelihood of malware (5 or more detections).
- **Customizable Filters**: Filter connections by type (e.g., `inet`, `tcp`, `udp`) and status (e.g., `ESTABLISHED`, `LISTEN`).
- **Verbose Mode**: Optional detailed error reporting.

## Prerequisites

- Python 3.x
- Required Python packages:
  - `psutil`
  - `tabulate`
  - `requests`

Install dependencies using:
```bash
pip install psutil tabulate requests
