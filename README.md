# ieuk-task-2025
This repo contains the log file for completing the 2025 IEUK Engineering task! The log file is too big to view in browser so you'll need to download it to your local machine. 

## Download Task
### Via Github UI 
https://github.com/user-attachments/assets/81972137-bf32-42c1-bc7d-dc65a0b9398f

### Via Git
You'll need to install Git and the Git LFS extension (which can be found [here](https://git-lfs.com/)). If you're unfamiliar with Git, I wouldn't worry about this—just download the log file via the UI. Using Git is not part of the task, so it's not worth spending too much time on it.

## Traffic Analysis Solution

### Task Overview
This solution analyzes a large web server log file to identify suspicious non-human traffic that may be causing server overloading. The Python script detects patterns consistent with bots or automated traffic and provides actionable insights to improve server performance.

### Solution Approach
The `analyze_traffic.py` script:
1. Parses web server log entries using regex to extract key information
2. Identifies suspicious IPs based on three key criteria:
   - IPs making excessive requests (>100)
   - IPs repeatedly requesting the same URL (>20 times)
   - IPs showing machine-like request timing patterns
3. Analyzes traffic patterns including peak hours and distribution
4. Generates a report of suspicious activities

### Results
When executed, the script will:
- Display overall traffic statistics
- Identify the peak traffic hours
- List the top suspicious IPs with their activity patterns
- Show the most commonly requested URLs by suspicious IPs

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
3. Review the output for traffic analysis insights

The script is designed to work efficiently with large log files (>50MB) and provides focused insights without unnecessary visualizations or dependencies.
