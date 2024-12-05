import re
import csv
from collections import defaultdict

# Constants
LOG_FILE = 'sample.log'
OUTPUT_CSV = 'log_analysis_results.csv'
FAILED_LOGIN_THRESHOLD = 10


def parse_log_file(log_file):
    ip_requests = defaultdict(int)
    endpoint_access = defaultdict(int)
    failed_logins = defaultdict(int)

    with open(log_file, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.match(r'(\S+) - -', line)
            if ip_match:
                ip_address = ip_match.group(1)
                ip_requests[ip_address] += 1

            # Extract endpoint and status code
            endpoint_match = re.search(r'"(GET|POST) (\S+) HTTP/\d\.\d" (\d{3})', line)
            if endpoint_match:
                endpoint = endpoint_match.group(2)
                status_code = endpoint_match.group(3)
                endpoint_access[endpoint] += 1

                # Check for failed login attempts
                if status_code == '401' or 'Invalid credentials' in line:
                    failed_logins[ip_address] += 1

    return ip_requests, endpoint_access, failed_logins


def analyze_data(ip_requests, endpoint_access, failed_logins):
    # Sort IP requests
    sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)

    # Find most accessed endpoint
    most_accessed_endpoint = max(endpoint_access.items(), key=lambda x: x[1], default=(None, 0))

    # Detect suspicious activity
    suspicious_activity = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}

    return sorted_ip_requests, most_accessed_endpoint, suspicious_activity


def save_results_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity):
    with open(OUTPUT_CSV, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_requests:
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint', 'Access Count'])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(['IP Address', 'Failed Login Attempts'])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])


def main():
    ip_requests, endpoint_access, failed_logins = parse_log_file(LOG_FILE)
    sorted_ip_requests, most_accessed_endpoint, suspicious_activity = analyze_data(ip_requests, endpoint_access,
                                                                                   failed_logins)

    # Output results to terminal
    print("IP Address           Request Count")
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")


    print("### Suspicious Activity Detected ###")
    if suspicious_activity:
        print("IP Address".ljust(20), "Failed Login Attempts")
        print("-" * 40)
        for ip, count in suspicious_activity:
            print(f"{ip.ljust(20)} {count}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    save_results_to_csv(sorted_ip_requests, most_accessed_endpoint, suspicious_activity)


if __name__ == "__main__":
    main()