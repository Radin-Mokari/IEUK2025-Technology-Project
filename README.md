# ieuk-task-2025
This repo contains the log file for completing the 2025 IEUK Engineering task! The log file is too big to view in browser so you'll need to download it to your local machine. 

## Download Task
### Via Github UI 
https://github.com/user-attachments/assets/81972137-bf32-42c1-bc7d-dc65a0b9398f

### Via Git
You'll need to install Git and the Git LFS extension (which can be found [here](https://git-lfs.com/)). If you're unfamiliar with Git, I wouldn't worry about this—just download the log file via the UI. Using Git is not part of the task, so it's not worth spending too much time on it.

## Traffic Analysis Solution

### Task Overview
This solution performs advanced analysis of web server logs to detect sophisticated non-human traffic patterns that may be causing server overloading. The Python script uses statistical methods and behavioral analysis to identify bots, crawlers, and other automated traffic with high precision.

### Solution Approach
The `analyze_traffic.py` script:

1. Performs multi-pass analysis of log data:
   - First pass collects comprehensive metrics about each IP
   - Second pass applies statistical and behavioral analysis algorithms

2. Identifies suspicious traffic using advanced detection methods:
   - Statistical outlier detection (uses mean + standard deviation)
   - Machine-like request timing patterns (regularity analysis)
   - URL diversity ratio analysis (for crawler/scanner detection)
   - HTTP method distribution analysis
   - Response time anomaly detection

3. Provides detailed analysis reports:
   - Hourly traffic distribution with percentage breakdown
   - Country-based traffic patterns
   - HTTP method usage statistics
   - Comprehensive reasons for each flagged IP

### Results
When executed, the script will:

- Display statistical baseline metrics (average requests per IP, thresholds)
- Provide hourly traffic distribution with percentage breakdowns
- Show peak traffic periods for capacity planning
- List the top 10 most suspicious IPs with:
  - Country of origin
  - Request volume statistics
  - Most requested URLs
  - HTTP method distribution
  - Detailed reasons for flagging each IP with specific metrics

### How to Run

#### Requirements
- Python 3.7 or higher
- The log file (`sample-log.log`) in the same directory as the script

#### Execution
1. Ensure the log file is in the same directory as the script
2. Run the script:
   ```
   python analyze_traffic.py
   ```
3. Review the comprehensive output for traffic analysis insights

The script is optimized for large log files (>50MB) and provides sophisticated analysis without external dependencies. The enhanced detection algorithms can identify a wide range of automated traffic patterns including bots, crawlers, scanners, and DoS attempts.
