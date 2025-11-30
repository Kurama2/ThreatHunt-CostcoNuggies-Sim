from faker import Faker
import json
import random
import pandas as pd
from datetime import datetime, timedelta

fake = Faker()
logs = []
num_logs = 5000  # Start with 1000 for quick testing

# Geo weights: 80% US (normal), 15% CA (FP noise), 5% RU/CN (threats)
geos = ["US", "CA", "RU", "CN"]
weights_geo = [80, 15, 3, 2]

for i in range(num_logs):
    ts = fake.date_time_between(start_date='-7d', end_date='now')
    log = {
        "TimeGenerated": ts.isoformat(),  # Sentinel timestamp
        "UserPrincipalName": f"{fake.user_name()}@costco.com",  # Azure AD-style
        "IPAddress": fake.ipv4(),
        "ResultType": random.choice([0, 50126]),  # 0=success, 50126=fail
        "vpn_connected": random.choices([True, False], weights=[90, 10])[0],  # 10% bypass
        "ip_geo": random.choices(geos, weights=weights_geo)[0],
        "dlp_policy_match": random.random() < 0.02,  # Purview: 2% PII "exfil"
        "edr_process": None  # Placeholder for EDR IOCs
    }
    # FP Example: Benign CA login during "business hours" (9-5)
    if log["ip_geo"] == "CA" and not log["vpn_connected"] and 9 <= ts.hour <= 17:
        log["fp_flag"] = "legit_business_trip"  # Label for tuning
    logs.append(log)

# To DataFrame for quick stats
df = pd.DataFrame(logs)
output_file = "logs/signinlogs.jsonl"
df.to_json(output_file, orient='records', lines=True)
print(f"✅ Generated {len(logs)} logs to {output_file}")
print(f"   - Threats (RU/CN + no VPN): {df[(df['ip_geo'].isin(['RU', 'CN'])) & (~df['vpn_connected'])].shape[0]}")
print(f"   - FPs (CA trips): {df['fp_flag'].notna().sum()}")
print(f"   - DLP Matches (Purview sim): {df['dlp_policy_match'].sum()}")