import re
import csv
from collections import defaultdict, Counter

# Configurable threshold for failed login attempts
FAILED_LOGIN_THRESHOLD = 10

# File paths
LOG_FILE = 'sample.log'
OUTPUT_CSV = 'log_analysis_results.csv'

def parse_log_file(log_file):
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = defaultdict(int)

    with open(log_file, 'r') as file:
        for line in file:
            # Extract IP, endpoint, and status code using regex
            match = re.match(r'(\d+\.\d+\.\d+\.\d+) .* "(GET|POST) (\S+) HTTP/1\.1" (\d+)', line)
            if match:
                ip, method, endpoint, status_code = match.groups()
                ip_requests[ip] += 1
                endpoint_requests[endpoint] += 1

                # Detect failed logins (status 401)
                if int(status_code) == 401:
                    failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins

def save_to_csv(ip_requests, most_accessed_endpoint, failed_logins, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write IP requests
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint', 'Access Count'])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write suspicious activity
        writer.writerow([])
        writer.writerow(['Suspicious Activity', 'Failed Login Count'])
        for ip, count in failed_logins.items():
            if count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip, count])

def main():
    print("Processing log file...")
    ip_requests, endpoint_requests, failed_logins = parse_log_file(LOG_FILE)

    # Sort and display IP requests
    print("\nIP Address Request Counts:")
    for ip, count in ip_requests.most_common():
        print(f"{ip:20} {count}")

    # Most frequently accessed endpoint
    most_accessed_endpoint = endpoint_requests.most_common(1)[0]
    print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    # Suspicious activity
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':20} {'Failed Login Attempts'}")
    for ip, count in failed_logins.items():
        if count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip:20} {count}")

    # Save results to CSV
    save_to_csv(ip_requests, most_accessed_endpoint, failed_logins, OUTPUT_CSV)
    print(f"\nResults saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
