import pandas as pd
import json
from sklearn.metrics import precision_score, recall_score

# Robust load for pure JSONL (tolerant parse)
with open('logs/signinlogs.jsonl', 'r') as f:
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
print(f"Loaded {len(df)} logs for tuning")

# Ensure no NaN in key columns
df['vpn_connected'] = df['vpn_connected'].fillna(False)
df['suspicious'] = df['suspicious'].fillna(False)
df['ip_geo'] = df['ip_geo'].fillna('US')

# y_true: suspicious as proxy for threats (1 = true positive)
y_true = df['suspicious'].astype(int)

# V1: Basic bypass alert
y_pred_v1 = (df['vpn_connected'] == False).astype(int)
print(f"V1 (Basic Bypass): Precision {precision_score(y_true, y_pred_v1, zero_division=0):.2f}, Recall {recall_score(y_true, y_pred_v1):.2f}")

# V2: Geo-tuned (RU/CN only)
y_pred_v2 = ((df['vpn_connected'] == False) & df['ip_geo'].isin(['RU', 'CN'])).astype(int)
print(f"V2 (Geo-Tuned): Precision {precision_score(y_true, y_pred_v2, zero_division=0):.2f}, Recall {recall_score(y_true, y_pred_v2):.2f}")