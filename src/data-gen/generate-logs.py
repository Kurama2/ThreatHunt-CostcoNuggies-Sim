from faker import Faker
import random
import pandas as pd
from datetime import datetime, timedelta

fake = Faker()
logs = []
num_logs = 5000

# Geo weights: 80% US (normal), 15% CA (FP noise), 5% RU/CN (threats)
geos = ["US", "CA", "RU", "CN"]
weights_geo = [80, 15, 3, 2]

for i in range(num_logs):
    ts = fake.date_time_between(start_date='-7d', end_date='now')
    user_name = fake.user_name()
    log = {
        "TimeGenerated": ts.isoformat(),  # Sentinel timestamp
        "UserPrincipalName": f"{user_name}@costco.com",  # Azure AD-style
        "IPAddress": fake.ipv4(),
        "ResultType": random.choice([0, 50126]),  # 0=success, 50126=fail
        "vpn_connected": random.choices([True, False], weights=[90, 10])[0],  # 10% bypass
        "ip_geo": random.choices(geos, weights=weights_geo)[0],  # Always set
        "dlp_policy_match": random.random() < 0.02,  # Purview: 2% PII "exfil"
        "edr_process": None,  # Placeholder for EDR IOCs
        "suspicious": False,  # Default for chain
        "fp_flag": None  # Default for FPs
    }
    # Force Victim Name (~1% logs = ~50 events)
    if random.random() < 0.01:
        log["UserPrincipalName"] = "nuggie_victim@costco.com"
        # Force chain condition for 20% of victims (RU/CN + no VPN for escalation)
        if random.random() < 0.2:
            log["ip_geo"] = random.choice(["RU", "CN"])
            log["vpn_connected"] = False
    # FP Example: Benign CA login during "business hours" (9-5)
    if log["ip_geo"] == "CA" and not log["vpn_connected"] and 9 <= ts.hour <= 17:
        log["fp_flag"] = "legit_business_trip"
    # Nuggies APT Chain: Escalate for victim
    victims = ["nuggie_victim@costco.com"]
    if log["UserPrincipalName"] in victims and log["ip_geo"] in ["RU", "CN"] and not log["vpn_connected"]:
        log["suspicious"] = True  # Force flag on trigger
        if random.random() < 0.3:
            log["dlp_policy_match"] = True
        if random.random() < 0.2:
            log["edr_process"] = "nuggie_beacon.exe"
    logs.append(log)  # Append every iteration

# To DataFrame for quick stats
df = pd.DataFrame(logs)
print("DF Columns:", df.columns.tolist())  # Debug: Confirm 'ip_geo' present
output_file = "logs/signinlogs.jsonl"
df.to_json(output_file, orient='records', lines=True)  # Pure JSONL for notebook (no bulk)
print(f"✅ Generated {len(logs)} logs to {output_file} (pure JSONL format)")
print(f"   - Threats (RU/CN + no VPN): {df[(df['ip_geo'].isin(['RU', 'CN'])) & (~df['vpn_connected'])].shape[0]}")
print(f"   - FPs (CA trips): {df['fp_flag'].notna().sum()}")
print(f"   - DLP Matches (Purview sim): {df['dlp_policy_match'].sum()}")
# Victim Chain Stats
victim_df = df[df['UserPrincipalName'] == 'nuggie_victim@costco.com']
print(f"   - Victim Events Total: {len(victim_df)}")
print(f"   - Victim Suspicious: {len(victim_df[victim_df['suspicious'] == True])}")
print(f"   - Victim DLP: {len(victim_df[victim_df['dlp_policy_match'] == True])}")
print(f"   - Victim EDR: {len(victim_df[victim_df['edr_process'] == 'nuggie_beacon.exe'])}")