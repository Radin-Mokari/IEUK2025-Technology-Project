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
    """Analyze the log file for suspicious traffic patterns using comprehensive methods."""
    print(f"Analyzing log file: {log_file_path}")
    
    # Data structures to store analysis info
    ip_request_counts = Counter()
    ip_urls = defaultdict(list)
    ip_methods = defaultdict(Counter)
    ip_user_agents = defaultdict(set)
    ip_status_codes = defaultdict(Counter)
    ip_session_data = defaultdict(list)  # Store [timestamp, url, method] for sequence analysis
    ip_countries = defaultdict(str)
    ip_response_times = defaultdict(list)
    hourly_traffic = Counter()
    
    # Track suspicious IPs and reasons
    suspicious_ips = set()
    suspicious_reasons = defaultdict(list)
    
    # Parse log file
    start_time = time.time()
    line_count = 0
    valid_entries = 0
    
    # Process the first pass to gather data
    print("First pass: Gathering traffic data...")
    with open(log_file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line_count += 1
            entry = parse_log_line(line)
            
            if entry:
                valid_entries += 1
                ip = entry['ip']
                
                # Collect comprehensive data about this IP
                ip_request_counts[ip] += 1
                ip_urls[ip].append(entry['url'])
                ip_methods[ip][entry['method']] += 1
                ip_countries[ip] = entry['country']
                ip_response_times[ip].append(entry['response_time'])
                
                # Add timestamp, URL and method for sequence analysis
                hour_timestamp = entry['hour'] * 3600  # Convert to seconds for simpler calculation
                ip_session_data[ip].append((hour_timestamp, entry['url'], entry['method']))
                
                # Count hourly traffic
                hourly_traffic[entry['hour']] += 1
                
                # Print progress for large files
                if line_count % 50000 == 0:
                    print(f"Processed {line_count} lines...")
    
    # Process the data to identify suspicious patterns
    print("\nSecond pass: Analyzing for suspicious patterns...")
    
    # Calculate baseline metrics for comparison
    avg_requests_per_ip = sum(ip_request_counts.values()) / len(ip_request_counts) if ip_request_counts else 0
    std_dev_threshold = 2.5  # IPs with request counts > mean + 2.5*std_dev are suspicious
    
    # Calculate standard deviation of request counts
    if len(ip_request_counts) > 1:
        variance = sum((count - avg_requests_per_ip) ** 2 for count in ip_request_counts.values()) / len(ip_request_counts)
        std_dev = variance ** 0.5
        high_request_threshold = avg_requests_per_ip + (std_dev * std_dev_threshold)
    else:
        high_request_threshold = 100  # Fallback if not enough data
    
    print(f"Average requests per IP: {avg_requests_per_ip:.2f}")
    print(f"High request threshold: {high_request_threshold:.2f}")
    
    # Identify suspicious IPs based on comprehensive criteria
    for ip, count in ip_request_counts.items():
        reasons = []
        
        # Criterion 1: Abnormally high number of requests (statistical outlier)
        if count > high_request_threshold:
            reasons.append(f"High request volume: {count} requests (threshold: {high_request_threshold:.2f})")
        
        # Criterion 2: Request rate analysis
        if len(ip_session_data[ip]) > 10:
            # Sort by timestamp
            sessions = sorted(ip_session_data[ip], key=lambda x: x[0])
            
            # Calculate time differences between consecutive requests
            time_diffs = [(sessions[i+1][0] - sessions[i][0]) for i in range(len(sessions)-1)]
            
            if time_diffs:
                # Check for suspiciously regular timing
                if len(time_diffs) >= 5:
                    avg_diff = sum(time_diffs) / len(time_diffs)
                    # Calculate standard deviation of time differences
                    if avg_diff > 0:
                        variance = sum((diff - avg_diff) ** 2 for diff in time_diffs) / len(time_diffs)
                        std_dev = variance ** 0.5
                        
                        # Very regular timing (low standard deviation relative to average)
                        regularity = std_dev / avg_diff if avg_diff > 0 else 999
                        if regularity < 0.2 and len(time_diffs) >= 10:
                            reasons.append(f"Machine-like request timing (regularity: {regularity:.3f})")
                
                # Check for extremely rapid requests
                min_time_diff = min(time_diffs)
                if min_time_diff < 1 and len(time_diffs) > 5:
                    fast_requests = sum(1 for diff in time_diffs if diff < 1)
                    if fast_requests > 5:
                        reasons.append(f"Rapid-fire requests: {fast_requests} requests with <1s intervals")
        
        # Criterion 3: URL pattern analysis
        url_counter = Counter(ip_urls[ip])
        url_count = len(url_counter)
        unique_url_ratio = url_count / count if count > 0 else 1
        
        # Same URL requested repeatedly
        most_common_url, most_common_count = url_counter.most_common(1)[0] if url_counter else (None, 0)
        if most_common_count > 20:
            reasons.append(f"URL hammering: requested '{most_common_url}' {most_common_count} times")
            
        # Too many unique URLs in short time (crawler behavior)
        if url_count > 50 and count > 100:
            reasons.append(f"Crawler pattern: {url_count} unique URLs in {count} requests")
        
        # Very low URL diversity (suspicious focus)
        elif url_count == 1 and count > 10:
            reasons.append(f"Single-target focus: only requesting '{most_common_url}'")
            
        # Very high URL diversity (potential scanner)
        elif unique_url_ratio > 0.9 and count > 20:
            reasons.append(f"Scanner pattern: {url_count} unique URLs in {count} requests (ratio: {unique_url_ratio:.2f})")
        
        # Criterion 4: HTTP method distribution analysis
        if len(ip_methods[ip]) > 0:
            # Unusual HTTP methods or suspicious combinations
            if 'OPTIONS' in ip_methods[ip] and ip_methods[ip]['OPTIONS'] > 5:
                reasons.append(f"Suspicious HTTP methods: {ip_methods[ip]['OPTIONS']} OPTIONS requests")
            
            if 'HEAD' in ip_methods[ip] and ip_methods[ip]['HEAD'] > 10:
                reasons.append(f"Potential reconnaissance: {ip_methods[ip]['HEAD']} HEAD requests")
            
            # Excessive POST requests to different URLs suggests automation
            if 'POST' in ip_methods[ip] and ip_methods[ip]['POST'] > 10:
                post_urls = set(url for ts, url, method in ip_session_data[ip] if method == 'POST')
                if len(post_urls) > 5:
                    reasons.append(f"Form submission automation: POSTing to {len(post_urls)} different URLs")
        
        # Criterion 5: Response time analysis
        if ip_response_times[ip]:
            avg_response = sum(ip_response_times[ip]) / len(ip_response_times[ip])
            # Unusually low response times may indicate cached responses or non-browser clients
            if avg_response < 50 and len(ip_response_times[ip]) > 10:
                reasons.append(f"Suspiciously fast responses: avg {avg_response:.2f}ms")
        
        # Add to suspicious IPs if any criteria were met
        if reasons:
            suspicious_ips.add(ip)
            suspicious_reasons[ip] = reasons
    
    # Summarize results
    print(f"\nAnalysis completed in {time.time() - start_time:.2f} seconds.")
    print(f"Processed {line_count} lines, found {valid_entries} valid log entries.")
    print(f"Identified {len(suspicious_ips)} suspicious IPs out of {len(ip_request_counts)} total IPs.")
    
    # Show peak traffic hours
    peak_hour = max(hourly_traffic.items(), key=lambda x: x[1])[0] if hourly_traffic else 0
    print(f"\nPeak traffic hour: {peak_hour:02d}:00 with {hourly_traffic[peak_hour]} requests")
    
    # Show hourly distribution to identify suspicious patterns
    print("\nHourly traffic distribution:")
    for hour in sorted(hourly_traffic.keys()):
        hour_percent = (hourly_traffic[hour] / valid_entries) * 100 if valid_entries > 0 else 0
        print(f"  Hour {hour:02d}: {hourly_traffic[hour]} requests ({hour_percent:.1f}%)")
    
    # Show top suspicious IPs with detailed reasons
    print("\nTop suspicious IPs with detection reasons:")
    suspicious_ips_by_count = [(ip, ip_request_counts[ip]) for ip in suspicious_ips]
    for i, (ip, count) in enumerate(sorted(suspicious_ips_by_count, key=lambda x: x[1], reverse=True)[:10]):
        country = ip_countries[ip]
        url_counter = Counter(ip_urls[ip])
        most_requested = url_counter.most_common(1)[0] if url_counter else ("unknown", 0)
        
        print(f"{i+1}. IP: {ip} ({country}) - {count} requests")
        print(f"   Most requested: {most_requested[0]} ({most_requested[1]} times)")
        print(f"   HTTP Methods: {dict(ip_methods[ip])}")
        
        print("   Detection reasons:")
        for reason in suspicious_reasons[ip]:
            print(f"    - {reason}")
        print("")

if __name__ == "__main__":
    log_file_path = "sample-log.log"
    analyze_log_file(log_file_path)
    
    print("\nSUMMARY OF ANALYSIS:")
    print("1. The analysis detected suspicious traffic using multiple criteria")
    print("2. Bot detection is based on statistical patterns and behavioral indicators")
    print("3. Peak hours have been identified for potential server scaling")
    print("4. Country-based patterns may indicate targeted campaigns")
    print("5. HTTP method distribution helps identify automation tools")
