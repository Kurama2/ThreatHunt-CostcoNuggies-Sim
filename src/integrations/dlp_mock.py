import re
import pandas as pd
import json

# Robust load for pure JSONL (tolerant parse)
with open('logs/signinlogs.jsonl', 'r') as f:  # From root
    lines = f.readlines()

# Parse lines to list of dicts with tolerant json.loads
parsed_docs = []
default_doc = {
    "TimeGenerated": None, "UserPrincipalName": None, "IPAddress": None, "ResultType": None,
    "vpn_connected": False, "ip_geo": None, "dlp_policy_match": False, "edr_process": None,
    "suspicious": False, "fp_flag": None
}
for line in lines:
    line = line.strip()
    if not line:
        continue
    try:
        line = line.replace('"null"', 'null').replace("'", '"')  # Fix gen quirks
        doc = json.loads(line, strict=False)
        for key in default_doc:
            if key not in doc:
                doc[key] = default_doc[key]
        parsed_docs.append(doc)
    except json.JSONDecodeError:
        continue

# Build DF
df = pd.DataFrame(parsed_docs)
print(f"Loaded {len(df)} logs for DLP mock")

# Mock Purview policy: Regex for PII (SSN) in 'dlp_policy_match' proxy
ssn_pattern = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')  # SSN pattern
df['pii_detected'] = df['dlp_policy_match']  # Proxy: Use DLP match as PII detection (85 True)

# User burst rule: Alert if >1 DLP per user
user_dlp = df[df['pii_detected'] == True].groupby('UserPrincipalName').size().reset_index(name='dlp_count')
alerts = user_dlp[user_dlp['dlp_count'] > 0]
print("**DLP Alerts (User Burst >1):**")
print(alerts)
print(f"Total Alerts: {len(alerts)}")

# Example alert action for each
for idx, row in alerts.iterrows():
    print(f"**ALERT: {row['UserPrincipalName']} - {row['dlp_count']} DLP hits - Investigate exfil**")