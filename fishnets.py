import psutil
import sys
from tabulate import tabulate as tb
import argparse
import time
import pwd
import hashlib
import requests
from collections import defaultdict
from datetime import datetime, timedelta

def color_background(text, color):
    """Helper function to add background color to text in terminal."""
    colors = {
        'green': '\033[42m{}\033[0m',
        'yellow_green': '\033[48;2;43;212;0m{}\033[0m',
        'chartreuse': '\033[48;2;85;170;0m{}\033[0m',
        'yellow': '\033[48;2;127;127;0m{}\033[0m',
        'orange': '\033[48;2;170;85;0m{}\033[0m',
        'red_orange': '\033[48;2;212;42;0m{}\033[0m',
        'red': '\033[41m{}\033[0m'
    }
    return colors.get(color, '{}').format(text)

def get_file_hash(file_path, cache=None):
    """Calculate SHA-256 hash of a file with caching."""
    if cache and file_path in cache:
        return cache[file_path]
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    hash_value = hash_sha256.hexdigest()
    if cache is not None:
        cache[file_path] = hash_value
    return hash_value

def check_with_virustotal(file_hashes, api_key, cache=None, last_request_time=None, min_interval=15):
    """Check SHA-256 hashes against VirusTotal with caching and rate limiting."""
    results = {}
    now = datetime.now()
    
    if last_request_time and (now - last_request_time) < timedelta(seconds=min_interval):
        time_to_wait = min_interval - (now - last_request_time).total_seconds()
        time.sleep(time_to_wait)

    hashes_to_check = [h for h in file_hashes if cache is None or h not in cache]
    if not hashes_to_check:
        return {h: cache[h] if h in cache else {"detections": "N/A", "malicious": False} for h in file_hashes}

    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": api_key}
    
    for file_hash in hashes_to_check:
        try:
            response = requests.get(f"{url}/{file_hash}", headers=headers, timeout=5)
            response.raise_for_status()
            data = response.json()
            result = {
                "detections": data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}),
                "malicious": data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0
            }
            if cache is not None:
                cache[file_hash] = result
            results[file_hash] = result
            time.sleep(15)  # Enforce delay for free tier
        except requests.RequestException as e:
            results[file_hash] = {"error": str(e), "malicious": False}
            if cache is not None:
                cache[file_hash] = results[file_hash]

    for h in file_hashes:
        if h not in results:
            results[h] = cache[h] if cache and h in cache else {"detections": "N/A", "malicious": False}
    
    return results, now

def list_connections_with_malware_detection(kind='inet', filter_status=None, api_key=None, refresh_interval=2, 
                                            ignore_loopback=False, ignore_blank=False):
    headers = ['Local Address', 'Remote Address', 'Status', 'PID', 'PPID', 'Owner', 'Process Name', 'File Path', 'SHA-256', 'VT Malicious']
    print(tb([headers], headers="firstrow", tablefmt="grid"))
    
    hash_cache = {}
    vt_cache = {}
    last_connections = set()
    last_vt_request_time = None

    while True:
        try:
            table = []
            connections = psutil.net_connections(kind=kind)
            current_connections = set()

            # Gathering hashes first, then filtering
            hashes_to_check = set()
            for conn in connections:
                if filter_status and conn.status != filter_status:
                    continue
                
                # Checking for loopback addresses
                if ignore_loopback:
                    if conn.laddr and (conn.laddr.ip in ('127.0.0.1', '::1')):
                        continue
                    if conn.raddr and (conn.raddr.ip in ('127.0.0.1', '::1')):
                        continue
                
                # Checking for blank/unspecified remote addresses
                if ignore_blank and (not conn.raddr or conn.raddr.ip == ''):
                    continue
                
                current_connections.add((conn.pid, conn.laddr, conn.raddr, conn.status))
                if conn.pid:
                    try:
                        p = psutil.Process(conn.pid)
                        file_path = p.exe()
                        file_hash = get_file_hash(file_path, hash_cache)
                        hashes_to_check.add(file_hash)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, IOError):
                        continue

            if current_connections == last_connections and last_connections:
                time.sleep(refresh_interval)
                continue

            last_connections = current_connections

            # Batch check with VirusTotal if API key provided
            if api_key and hashes_to_check:
                vt_results, last_vt_request_time = check_with_virustotal(hashes_to_check, api_key, vt_cache, last_vt_request_time)
            else:
                vt_results = {h: {"detections": "API key not provided", "malicious": False} for h in hashes_to_check}

            # Process connections with results
            for conn in connections:
                if filter_status and conn.status != filter_status:
                    continue
                
                # Apply loopback filter
                if ignore_loopback:
                    if conn.laddr and (conn.laddr.ip in ('127.0.0.1', '::1')):
                        continue
                    if conn.raddr and (conn.raddr.ip in ('127.0.0.1', '::1')):
                        continue
                
                # Apply blank filter
                if ignore_blank and (not conn.raddr or conn.raddr.ip == ''):
                    continue
                
                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                
                if conn.pid:
                    try:
                        p = psutil.Process(conn.pid)
                        process_name = p.name()
                        owner = pwd.getpwuid(p.uids().real).pw_name
                        ppid = p.ppid()
                        file_path = p.exe()
                        file_hash = get_file_hash(file_path, hash_cache)
                        vt_result = vt_results.get(file_hash, {"detections": "Could not access file", "malicious": False})
                    except (psutil.NoSuchProcess, psutil.AccessDenied, IOError):
                        process_name = 'N/A'
                        owner = 'N/A'
                        ppid = 'N/A'
                        file_path = "N/A"
                        file_hash = "N/A"
                        vt_result = {"detections": "Could not access file", "malicious": False}
                else:
                    process_name = 'N/A'
                    owner = 'N/A'
                    ppid = 'N/A'
                    file_path = 'N/A'
                    file_hash = 'N/A'
                    vt_result = {"detections": "No PID", "malicious": False}
                
                # Determine color
                if 'detections' in vt_result:
                    if vt_result['malicious']:
                        if vt_result['detections'].get('malicious', 0) >= 5:
                            color = 'red'
                        else:
                            color = 'orange'
                    else:
                        color = 'green'
                else:
                    color = 'green'

                remote_addr = color_background(remote_addr, color)
                
                table.append([local_addr, remote_addr, conn.status, conn.pid, ppid, owner, process_name, file_path, file_hash, 
                              'Yes' if vt_result.get('malicious', False) else 'No' if not vt_result.get('error') else 'Error'])
            
            sys.stdout.write("\033[2J\033[2H")
            print(tb(table, tablefmt="grid"))
            time.sleep(refresh_interval)
        
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"An error occurred: {e}")
            time.sleep(refresh_interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="List network connections with malware detection capabilities.",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog="""Examples:
  python fishnet.py -t inet -s ESTABLISHED -k YOUR_API_KEY --ignore-loopback
  python fishnet.py -t tcp --status LISTEN --ignore-blank
  python fishnet.py --type udp --ignore-loopback --ignore-blank
""")
    parser.add_argument('-t', '--type', default='inet', help='Type of network connection (default: inet)')
    parser.add_argument('-s', '--status', help='Filter connections by status')
    parser.add_argument('-k', '--api-key', help='VirusTotal API key for malware detection')
    parser.add_argument('-r', '--refresh-interval', type=float, default=2, help='Refresh interval in seconds (default: 2)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--ignore-loopback', action='store_true', help='Ignore loopback addresses (127.0.0.1, ::1)')
    parser.add_argument('--ignore-blank', action='store_true', help='Ignore connections with blank or unspecified remote addresses')

    args = parser.parse_args()
    list_connections_with_malware_detection(
        kind=args.type, 
        filter_status=args.status, 
        api_key=args.api_key, 
        refresh_interval=args.refresh_interval,
        ignore_loopback=args.ignore_loopback,
        ignore_blank=args.ignore_blank
    )
