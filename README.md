# VRV_Python_Assignment
Sure! Here is the full content for the README file in a single paragraph for easy copying:

---

# Log Analysis Script

This Python script processes a log file to extract and analyze information such as IP request counts, frequently accessed endpoints, and suspicious login activity. It performs the following tasks: 1) Counts the number of requests made by each IP address. 2) Identifies the most frequently accessed endpoint. 3) Detects suspicious activity (e.g., brute force login attempts). The script reads the provided log file, processes the data, and outputs the results in the terminal. The results are also saved in a CSV file named `log_analysis_results.csv` with sections for **Requests per IP** (IP Address, Request Count), **Most Accessed Endpoint** (Endpoint, Access Count), and **Suspicious Activity** (IP Address, Failed Login Count). To use the script, save your log file as `sample.log` and run the script with the command `python log_analysis.py sample.log`. The output will display in the terminal and be saved to a CSV file. You can customize the threshold for detecting suspicious activity (failed login attempts) directly in the script. The script is efficient for large files and provides valuable insights into log data related to security and web traffic.
