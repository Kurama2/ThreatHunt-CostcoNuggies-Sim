# ThreatHunt-CostcoNuggies-Sim 🥡🔍

## Introduction
My name is Samuel Gauthier, an aspiring cybersecurity professional. This is meant as a learning exercise for myself, nothing more, nothing less! I was recently introduced to the role of a "Threat Detection Engineer" and wanted to gain a deeper understanding, visualize the role, to simulate a threat, and to learn about the different tools and polyvalence required for the job. I was inspired by [kc7cyber.com](https://kc7cyber.com) labs to create my own little scenario and try to enhance my current knowledge and understanding with all the tools used (refer to [tools-glossary-references.md](tools-glossary-references.md)). Special shoutout and thanks to "PoissonAvion" and "Marc, AKA le king des A+" for reviewing/mentoring.

That's how I came up with "CostcoNuggies Hunt," which is just a reference to an inside joke between friends. The project was humbling in many ways; I had to pivot away from tools like n8n and Grafana implementations for visuals, etc. Also, I thought I could verify the KQL in kc7 but they don't have all the data tables there. I wanted to make something cool and engaging at the same time but had to stick to the simpler side due to limitations in knowledge, skill, and time. Most importantly, the goal was to learn about the process of building rules, tweaking and adjusting scope to reduce FPs, and becoming more comfortable with KQL and that goal was achieved!

I also created a "self-evaluation" rubric for my own criticism and personal growth. I was presented with a question recently that tickled my brain: "How do you know if the work you've done is good?" For some reason, such a simple question puzzled me, because how do you really know? This made me think of evaluation rubrics I crafted for AIs, and I thought, why not do one for my own evaluation? See ("src/analytics/self-evaluation-rubric.py")

### The CostcoNuggies Hunt: Full Attack Story
This sim tells the story of the "CostcoNuggies" APT—a fictional phishing group tricking remote workers with "free nugget" lures to bypass VPNs and exfil data. It starts with a simple hypothesis ("bypass + location = threat?") and escalates through the pipeline, showing how hunts, rules, and automation contain it. All based on 5000 generated logs (85 DLP matches, 5 suspicious chain events).

#### The Hunt Begins: Hypothesis and Discovery
It kicked off with a hunch during remote work monitoring: "What if VPN bypasses are the entry point?" In the 5000 logs, 450 bypass events surfaced. Grouping by location (H1 in hunt_notebook.ipynb) revealed the split: 22 from CA (legit FPs, like business travel during 9-5 hours), but 37 from RU/CN (high-risk IOCs). This was the first clue—normal US/CA noise vs. anomalous RU/CN, linking to MITRE T1078 (Valid Accounts, where attackers use stolen creds to slip in without VPN).

Pivoting to DLP exfil chains (H2), the 85 matches showed a burst: nuggie_victim@costco.com with 1 hit. Cross-checking the APT chain (H3), that user had 5 suspicious events + 1 RU DLP overlap—sequence: RU login without VPN (suspicious True), followed by DLP True (PII leak), and nuggie_beacon.exe (EDR IOC).

##### The Attack Escalation
CostcoNuggies kicked off with phishing lures to bypass VPN (T1078 initial access). nuggie_victim fell for it: 3 RU logins in 1 hour (threshold >3 from VPN rule) triggered the SIEM alert. Escalation was quick:
- DLP flagged 1 PII exfil (regex for SSN-like patterns in 85 total matches).
- EDR spotted nuggie_beacon.exe (beaconing C2, MITRE T1048 exfiltration).
- Chain: Login → Exfil → Beacon (1 hit in H3 table, timestamp RU geo with True DLP/suspicious).

Without tuning, it'd flood the SOC with 450 alerts (V1 0.02 precision). Geo + time whitelist (CA 9-17 ignored) dropped FPs 84%, focusing on the 37 RU threats.

###### Response & Containment
The SOAR mock fired <1 min (MTTR): Alert → FP check (isFP false for RU) → EDR isolate ("Quarantined nuggie_victim from RU"). For CA FP (testuser at 10:00), it emailed "Whitelisted as business travel" (no disruption). Tuning (V3 0.98 precision) ensured 85% threats caught with <5 FPs.

In real terms, this contained the breach before spread—nuggie_victim's endpoint locked, PII safe, C2 blocked. The sim proves the loop: Hunt hypothesis → Rule alert → Automated response.

For the full hunt notebook (H1-H3 queries), see [hunt_notebook.ipynb](src/hunt/hunt_notebook.ipynb).

###### Why This Project?
- **Problem**: Remote work exposes VPN gaps—simulates real insider threats with "nugget" phish chains.
- **My Approach**: Polyvalent engineering: Hunt → Detect (tune for precision/recall) → Respond. Docs explain "why" (e.g., thresholds to balance FPs).
- **Tech Stack**: Wazuh (SIEM/EDR), ELK (logs/viz), Python (DLP mocks/ML).

###### Metrics Dashboard (Kibana Viz)
Interactive hunts and metrics from the notebook (localhost:5601 > Discover > signinlogs*).

![H1 VPN Bypass by Geo](docs/h1-geo-bar.png)  
*H1 Hunt: Bypass events grouped by ip_geo (CA FPs 22, RU threats 37)—shows sweet spot for geo-tuned rules (V2 precision 0.95 from Step 5).*

![H2 DLP by User (Top 5)](docs/h2-dlp-user-bar.png)  
*H2 Hunt: DLP matches by user (nuggie_victim burst 1)—highlights insider exfil signals for threshold alerts (>1/user, tuned to 85 alerts in Step 5.3).*

![H3 Chain RU DLP Hits](docs/h3-chain-table.png)  
*H3 Hunt: Victim chain table (nuggie_victim + suspicious + DLP + RU = 1 hit)—escalation sequence (timestamp RU geo, True DLP/suspicious), triggers EDR isolate in SOAR mock (MTTR <1 min from Step 6).*