import json
from datetime import datetime

# Mock SOAR playbook for VPN alerts: Simulates automation pipeline.
# Input: Alert JSON (user, geo, time from SIEM rule).
# Process: Enrich with FP check (whitelist CA during business hours).
# Output: Branch to EDR isolate (threat) or email notify (FP), with MTTR <1 min.
# Automates response to reduce manual triage—high-risk geo = isolate, low-risk = notify.

def handle_vpn_alert(alert_json):
    # Enrich alert with FP logic: Extract user/geo/time, compute hour.
    user = alert_json.get('UserPrincipalName', 'unknown')
    geo = alert_json.get('ip_geo', 'US')
    time_str = alert_json.get('TimeGenerated', '2025-11-24T10:00:00')
    hour = datetime.fromisoformat(time_str).hour  # Parse hour for business time check

    # FP check: Whitelist CA logins during 9-17 hours (common legit remote work).
    is_fp = geo == 'CA' and 9 <= hour <= 17

    print(f"Alert enriched: User {user}, Geo {geo}, Hour {hour}, isFP {is_fp}")

    if not is_fp:
        # Threat path: High-risk geo (RU/CN) = isolate endpoint to contain breach.
        edr_response = isolate_endpoint(user, geo)
        print(f"EDR Response: {edr_response}")
        status = "Isolated - Threat Contained"
    else:
        # FP path: Low-risk (CA business hours) = notify team for review, no disruption.
        email_response = send_fp_email(user, geo, hour)
        print(f"Email Response: {email_response}")
        status = "Notified - FP Whitelisted"

    return {"status": status, "MTTR": "<1 min"}

def isolate_endpoint(user, geo):
    # Mock EDR action: Quarantine user endpoint from high-risk geo.
    return f"Quarantined {user} from {geo} (endpoint isolated, threat contained)"

def send_fp_email(user, geo, hour):
    # Mock email action: Notify SOC for FP review (no auto-remediation).
    return f"FP alert emailed for {user} (geo: {geo}, hour: {hour}) – Whitelisted as business travel"

# Demo tests: verify threat/FP paths.
if __name__ == "__main__":
    # Threat test (RU geo – expect EDR isolate)
    alert_threat = {"UserPrincipalName": "nuggie_victim@costco.com", "ip_geo": "RU", "TimeGenerated": "2025-11-24T10:00:00"}
    print("=== Threat Test (RU Geo) ===")
    result_threat = handle_vpn_alert(alert_threat)
    print(result_threat)

    # FP test (CA geo, hour 10 – expect email notify)
    alert_fp = {"UserPrincipalName": "testuser@costco.com", "ip_geo": "CA", "TimeGenerated": "2025-11-24T10:00:00"}
    print("\n=== FP Test (CA Geo, Hour 10) ===")
    result_fp = handle_vpn_alert(alert_fp)
    print(result_fp)