#  KQL Rules: Sentinel & Purview
These KQL rules adapt the sim's VPN breach detection for real tools. Sentinel for logins (H1 geo split: 37 RU threats vs. 22 CA FPs), Purview for DLP (H2 burst: 85 matches, H3 chain: 1 RU DLP hit). Thresholds tuned for 0.98 precision (Step 5 V3).

## 1. Purview DLP Rule: User Burst Exfil
## Run every 1h, lookback 1h; Sensitivity: High; MITRE T1048
DLPAll
| where TimeGenerated > ago(1h)  // 1-hour window
| where PolicyMatch == true  // DLP policy violation (PII leak)
| summarize EventCount = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by UserPrincipalName
| where EventCount > 1  // Burst >1 (tunes FPs, flags nuggie_victim)
| join kind=inner (SigninLogs | where suspicious == true) on UserPrincipalName  // Cross with suspicious for chain
| project UserPrincipalName, EventCount, FirstSeen, LastSeen
| order by EventCount desc

#### 2. Sentinel Rule: VPN Bypass Detection (SigninLogs Table)
**Why?** Detects no-VPN logins from RU/CN (37 threats), thresholds >3/hour to cut FPs (ignores single CA). Alerts bursts, integrates with SOAR for EDR isolate (MITRE T1078).

KQL
// Sentinel Analytic Rule: VPN Bypass High-Risk Geo
// Run every 1h, lookback 1h; Severity: High; MITRE T1078
SigninLogs
| where TimeGenerated > ago(1h)  // 1-hour window
| where ResultType == 0  // Successful logins
| where vpn_connected == false  // No VPN (core anomaly)
| where ip_geo in ("RU", "CN")  // High-risk geo (tune FPs—ignore CA)
| summarize EventCount = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by UserPrincipalName, IPAddress
| where EventCount > 3  // Threshold >3 (0.98 precision, drops single FPs)
| extend RiskScore = case(ip_geo == "RU", 0.8, ip_geo == "CN", 0.7, 0.5)  // Prioritize RU
| project UserPrincipalName, IPAddress, EventCount, FirstSeen, LastSeen, RiskScore
| order by EventCount desc