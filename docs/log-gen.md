# Log Generation: Sentinel/Purview Data Mocks

## Key Fields (SigninLogs Schema)
| Field | Type | Why? (Sentinel/Purview Tie) |
|-------|------|-----------------------------|
| TimeGenerated | datetime | Time-series for hunts (e.g., | where TimeGenerated > ago(7d)). |
| UserPrincipalName | string | User pivot (e.g., | where UserPrincipalName == "nuggie_victim"). |
| vpn_connected | bool | Core anomaly—90% true baseline. |
| ip_geo | string | Geo-fencing; CA=FP (travel), RU=Nuggies IOC. |
| dlp_policy_match | bool | Purview sim—alerts on PII "leaks". |

## FP/Threat Strategy
- **FPs**: 10-15% (e.g., CA + business hours)—tests rule thresholds (e.g., >5 events/hour).
- **Threats**: 5% Nuggies chain (geo + DLP + EDR IOCs)—MITRE T1078 sim.
- Run Output Example: 5000 logs, 30 threats, 38 FPs.

## Complexity Tests & Hunt Results (Run on 2025-11-30)
- **Baseline Stats**: Threats (RU/CN + no VPN): 30, FPs (CA trips): 38, DLP Matches: 1625 (high RNG; baseline ~105), Victim Total: 39, Victim Suspicious: 5, Victim DLP: 98, Victim EDR: 8.
- **Nuggies Chain Hunt**: UserPrincipalName: nuggie_victim@costco.com AND suspicious: true → 5 hits.
- **DLP Pivot**: UserPrincipalName: nuggie_victim@costco.com AND dlp_policy_match: true → 98 hits (RU subset: 2).
- **EDR Pivot**: UserPrincipalName: nuggie_victim@costco.com AND edr_process: nuggie_beacon.exe → 8 hits (RU subset: 1).
- **Chain Overlap**: UserPrincipalName: nuggie_victim@costco.com AND suspicious: true AND dlp_policy_match: true → 2 hits (phish → exfil escalation).
- **FP Noise Variant (25% CA)**: vpn_connected: false → ~1250 bypass hits; tuned with ip_geo: CA AND hour(TimeGenerated) between (9 and 17) → ~200 hits (84% FP drop, RU threats intact).
- **Why These Tests?** Simulates APT discovery via chain (5 suspicious from 39 victims, 2 overlap exfils); FP tuning balances (84% drop w/o missing 30 threats).