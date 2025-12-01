# Tools, Glossary, & Thought Process References
This file explains the tools I chose, a simple glossary for key terms for clarity and my own understanding, and the reasoning behind decisions like MITRE tactics.

## Tools Used & Why
I stuck to open-source tools that are free and easy to set up with Docker. They're common in real SOCs, so I thought it would bring some "realism" to the sim.

- **ELK Stack (Elasticsearch, Logstash, Kibana)**: Handles log storage, searching, and charts. Mimics Microsoft Sentinel for hunts like grouping bypasses by location (22 CA FPs vs. 37 RU threats in H1). One command to start, no cloud costs.

- **Wazuh**: Open-source SIEM for rules and alerts. Like a free Splunk—lets me add custom YAML for the VPN threshold rule (>3 logins/hour to cut FPs). [see vpn_breach.yaml].

- **Python (Pandas, scikit-learn, json)**: For generating logs, running hunts, and testing rules. Handles everything from fake data (Faker for 5000 events) to metrics (sklearn for 0.98 precision).

- **soar_mock.py**: Custom Python script for the automation pipeline. Simulates alert handling (EDR for RU threats, email for CA FPs) without complex UI.

## Glossary
Basic definitions for terms in the sim.

- **DLP (Data Loss Prevention)**: System to spot and stop sensitive info leaks (like credit card numbers). In sim: Regex checks flag 85 matches, with alerts for user bursts (nuggie_victim 1 hit).
- **EDR (Endpoint Detection and Response)**: Watches computers for bad behavior and locks them down. In sim: Mocks quarantining on suspicious processes (1 "nuggie_beacon.exe" action).
- **FP (False Positive)**: Alert that's not a real threat (like a normal login flagged). In sim: Tuned from 450 to <5 with location/time filters (84% drop).
- **MTTR (Mean Time to Respond)**: Average time from alert to fix (aim for minutes, not hours). In sim: <1 min via the mock script (timing from input to EDR/email).
- **Precision**: Share of alerts that are actual threats (0.98 = 98% right, few wrong flags). In sim: From sklearn on 5000 logs—iterated rules until FPs <5.
- **Recall**: Share of real threats caught (1.00 = all found). In sim: V2 geo filter catches 100% of 5 suspicious but with 0.30 precision—balance with thresholds.
- **SIEM (Security Information and Event Management)**: Collects and scans logs for patterns/alerts. In sim: Wazuh with VPN rule (>3/hour for 37 RU threats).

## Thought Process References
Why I picked certain elements.

- **MITRE T1078 (Valid Accounts)**: For VPN bypass sim—attackers use stolen logins to sneak in without VPN (like the 37 RU threats). Why? Fits remote work risks; rule thresholds detect it without too many FPs. https://attack.mitre.org/techniques/T1078/.
- **Hypothesis-Driven Hunting (H1-H3)**: Began with "bypass + location = threat?" (H1) to build rules—thinking: Group by location first to separate noise (22 CA FPs) from signals (37 RU).
- **FP Tuning (Geo + Time Whitelist)**: Went from alerting all 450 bypasses to 0.98 precision—thinking: "CA during work hours is normal, skip it." Cuts alert fatigue (84% drop) while keeping 85% threats.
- **SOAR Mock (Python Branch)**: Used Python for quick testing: "Script it to see MTTR <1 min, debug fast" Prototypes easy; swaps to full tools later (EDR for RU, email for CA).