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
print(f"Loaded {len(df)} logs for EDR mock")

# EDR rule: Isolate if edr_process = nuggie_beacon.exe and suspicious = True
edr_df = df[(df['edr_process'] == 'nuggie_beacon.exe') & (df['suspicious'] == True)]
print(f"EDR Isolations: {len(edr_df)}")
print(edr_df[['UserPrincipalName', 'TimeGenerated', 'ip_geo']].head())  # Isolated users

# Mock response: "Quarantine endpoint for user"
for idx, row in edr_df.iterrows():
    print(f"Action: Isolate {row['UserPrincipalName']} at {row['TimeGenerated']} from {row['ip_geo']}")