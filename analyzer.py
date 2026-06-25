# ==============================================================================
# PROJECT: Automated Physical Security Incident & Log Analyzer
# AUTHOR: Christian Udodi Chinedu
# DESCRIPTION: A Python script applying statistical logic to parse facility 
#              access logs and isolate operational security anomalies.
# ==============================================================================

import math

# Simulated raw facility log data: [Timestamp, Employee ID, Access Point, Status]
# Status codes: 200 = Success, 403 = Unauthorized Attempt
security_logs = [
    ["08:15", "EMP023", "Main Lobby", 200],
    ["08:22", "EMP104", "Server Room", 403],  # Anomaly
    ["09:00", "EMP088", "Main Lobby", 200],
    ["23:15", "EMP999", "Back Exit", 403],    # Anomaly (Late night)
    ["09:30", "EMP104", "Server Room", 200],
    ["11:45", "EMP211", "Finance Vault", 403], # Anomaly
    ["13:00", "EMP023", "Main Lobby", 200],
    ["14:15", "EMP088", "Server Room", 200],
    ["02:10", "EMP511", "Loading Dock", 403], # Anomaly (Late night)
]

def analyze_unauthorized_attempts(logs):
    """
    Parses logs to isolate and count total security breaches (Status 403).
    """
    failed_attempts = []
    for log in logs:
        if log[3] == 403:
            failed_attempts.append(log)
    return failed_attempts

def calculate_anomaly_rate(total_logs, total_failed):
    """
    Applies basic statistical ratio modeling to determine 
    the overall system vulnerability baseline.
    """
    if total_logs == 0:
        return 0.0
    
    # Calculate percentage breakdown
    rate = (total_failed / total_logs) * 100
    return round(rate, 2)

def main():
    print("==================================================")
    print("     STARTING DIGITAL SECURITY LOG ANALYZER       ")
    print("==================================================\n")
    
    total_records = len(security_logs)
    failed_records = analyze_unauthorized_attempts(security_logs)
    total_failures = len(failed_records)
    
    # Compute the statistical failure rate across the dataset
    failure_rate = calculate_anomaly_rate(total_records, total_failures)
    
    print(f"[INFO] Total Access Logs Processed: {total_records}")
    print(f"[INFO] Total Anomalies/Breaches Isolated: {total_failures}")
    print(f"[STATISTICS] Current System Anomaly Rate: {failure_rate}%\n")
    
    print("--------------------------------------------------")
    print("CRITICAL ALERT LOGS (STATUS 403 - ACTIONS REQUIRED):")
    print("--------------------------------------------------")
    
    for alert in failed_records:
        print(f"⏰ TIME: {alert[0]} | 👤 ID: {alert[1]} | 🚪 LOCATION: {alert[2]} -> [ACCESS DENIED]")
        
    print("\n==================================================")
    print("             LOG ANALYSIS COMPLETE                ")
    print("==================================================")

if __name__ == "__main__":
    main()
      
