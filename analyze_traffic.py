import re
from collections import Counter, defaultdict
import datetime
import time
import os

def parse_log_line(line):
    """Parse a log line into its components."""
    try:
        # Regular expression to match log format
        pattern = r'(\d+\.\d+\.\d+\.\d+) - (\w+) - \[(\d+/\d+/\d+):(\d+:\d+:\d+)\] "(.*?)" (\d+) (\d+) "-" "(.*?)" (\d+)'
        match = re.search(pattern, line)
        
        if match:
            ip = match.group(1)
            country = match.group(2)
            date_str = match.group(3)
            time_str = match.group(4)
            request = match.group(5)
            status = int(match.group(6))
            response_time = int(match.group(9))
            
            # Extract HTTP method and URL from request
            req_parts = request.split(' ')
            method = req_parts[0] if len(req_parts) >= 2 else "UNKNOWN"
            url = req_parts[1] if len(req_parts) >= 2 else "UNKNOWN"
            
            # Parse the date
            day, month, year = map(int, date_str.split('/'))
            hour, minute, second = map(int, time_str.split(':'))
            
            return {
                'ip': ip,
                'hour': hour,
                'url': url,
                'method': method,
                'country': country,
                'response_time': response_time
            }
    except Exception as e:
        pass
    
    return None

def analyze_log_file(log_file_path):
    """Analyze the log file for suspicious traffic patterns."""
    print(f"Analyzing log file: {log_file_path}")
    
    # Data structures to store analysis info
    ip_request_counts = Counter()
    ip_urls = defaultdict(list)
    ip_request_times = defaultdict(list)
    hourly_traffic = Counter()
    suspicious_ips = set()
    
    # Parse log file
    start_time = time.time()
    line_count = 0
    valid_entries = 0
    
    with open(log_file_path, 'r', encoding='utf-8') as f:
        # Process the file in chunks to handle large files efficiently
        prev_time = {}
        for line in f:
            line_count += 1
            entry = parse_log_line(line)
            
            if entry:
                valid_entries += 1
                ip = entry['ip']
                
                # Count requests per IP
                ip_request_counts[ip] += 1
                
                # Track URLs requested by this IP
                ip_urls[ip].append(entry['url'])
                
                # Track request timing for this IP
                curr_time = time.time()
                if ip in prev_time:
                    time_diff = curr_time - prev_time[ip]
                    ip_request_times[ip].append(time_diff)
                prev_time[ip] = curr_time
                
                # Count hourly traffic
                hourly_traffic[entry['hour']] += 1
                
                # Print progress for large files
                if line_count % 50000 == 0:
                    print(f"Processed {line_count} lines...")
    
    # Identify suspicious IPs based on simple criteria
    for ip, count in ip_request_counts.items():
        # Criterion 1: High number of requests (potential DoS)
        if count > 100:
            suspicious_ips.add(ip)
            continue
            
        # Criterion 2: Same URL repeatedly requested
        url_counter = Counter(ip_urls[ip])
        most_common_url, most_common_count = url_counter.most_common(1)[0] if url_counter else (None, 0)
        if most_common_count > 20:
            suspicious_ips.add(ip)
            continue
            
        # Criterion 3: Very regular timing between requests (potential bot)
        if len(ip_request_times[ip]) > 10:
            time_diffs = ip_request_times[ip]
            if time_diffs and max(time_diffs) - min(time_diffs) < 0.1:  # Very consistent timing
                suspicious_ips.add(ip)
    
    # Summarize results
    print(f"\nAnalysis completed in {time.time() - start_time:.2f} seconds.")
    print(f"Processed {line_count} lines, found {valid_entries} valid log entries.")
    print(f"Identified {len(suspicious_ips)} suspicious IPs out of {len(ip_request_counts)} total IPs.")
    
    # Show peak traffic hours
    peak_hour = max(hourly_traffic.items(), key=lambda x: x[1])[0]
    print(f"\nPeak traffic hour: {peak_hour:02d}:00 with {hourly_traffic[peak_hour]} requests")
    
    # Show top suspicious IPs
    print("\nTop 5 suspicious IPs by request count:")
    suspicious_ips_by_count = [(ip, count) for ip, count in ip_request_counts.items() if ip in suspicious_ips]
    for ip, count in sorted(suspicious_ips_by_count, key=lambda x: x[1], reverse=True)[:5]:
        url_counter = Counter(ip_urls[ip])
        most_requested = url_counter.most_common(1)[0] if url_counter else ("unknown", 0)
        print(f"  IP: {ip} - {count} requests - Most requested: {most_requested[0]} ({most_requested[1]} times)")

if __name__ == "__main__":
    log_file_path = "sample-log.log"
    analyze_log_file(log_file_path)
