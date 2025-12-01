# Teardown Report: ThreatHunt-CostcoNuggies-Sim

## Overview
This is my attempt at learning the basics of a Threat Detection Engineer workflow: Starting with hypothesis-driven hunts to spot VPN bypass threats (like 37 high-risk RU/CN logins amid 22 CA FPs), iterating on rules to hit 0.98 precision, and automating responses via a simple SOAR mock (MTTR under 1 min). I built it with open-source staples (ELK for logs, Wazuh for SIEM, Python for mocks) to showcase polyvalent skills and creativity—fork and run to see detections in action.

## Challenges & Learnings
Building this sim felt like piecing together a puzzle—each part (hunts, rules, automation) clicked with some trial and error. Here's what stood out, broken down simply.

### Challenges
- **RNG Variability**: Chain hits often rolled low (just 1 escalation event)—I tuned the victim probability to 20% to make demos reliable without forcing every run to feel like a major breach (balances realism with playability).
- **FP Noise Overload**: Early rules flagged all 450 bypasses, drowning in 22 CA FPs—I iterated geo + time whitelisting (CA 9-17) to slash 84% FPs while nabbing 85% threats, proving data-driven tweaks beat guesswork.
- **JSON Parsing Headaches**: pd.read_json choked on gen quirks like null strings—switched to json.loads with strict=False and defaults for bulletproof 5000-log loads (learned to always validate input formats early).

### Learnings
- **Hypothesis-Driven Hunts**: Starting with H1's geo split directly shaped the VPN rule (V2 filtered RU/CN for 0.95 precision)—thought process: "What if I group by ip_geo first? Boom, FPs vs. threats clear as day."
- **Tuning Balance**: V3's threshold >3/hour + whitelist hit 0.98 precision by balancing recall (catch 85% threats) and noise (drop 84% FPs)—key takeaway: Start broad (V1 0.02 precision), narrow with data (H1 insights), measure (sklearn metrics). Precision is the % of alerts that are true threats (0.98 = 98% accurate, low FPs); I got it from Step 5's sklearn scoring on 5000 logs, iterating until FPs <5 while keeping recall >80%.
- **Integration Simplicity**: Python SOAR mock let me test MTTR <1 min fast—EDR for RU threats, email for CA FPs—realized mocks are perfect for prototypes, easy to swap for n8n in prod. MTTR (Mean Time to Respond) is the average seconds from alert to action (mine <60s via mock branch)—measured by timing the script run.
- **Public Repo Mindset**: Self-contained comments/docs (no internal steps) make it fork-ready—fork and run for instant value, learned to write for the stranger who's about to star it.

## Key Metrics
- Logs: 5000 events (85 DLP matches, 5 suspicious chain events).
- Hunts: H1 geo split (CA FPs 22, RU threats 37), H2 DLP burst (nuggie_victim 1), H3 chain RU DLP 1 hit.
- Rules: VPN YAML (threshold >3/hour), DLP regex (85 alerts tuned >0), EDR isolate (1 action).
- Tuning: V3 precision 0.98, FP drop 84% (22 to <5).
- SOAR: Mock pipeline (EDR for threat, email for FP).

## Architecture
```mermaid
graph TD
    A[Logs Gen: 5000 Events] --> B[Hunt Notebook: H1-H3 Queries]
    B --> C[SIEM Rule: Wazuh VPN Threshold]
    C --> D[SOAR Mock: FP Branch → EDR/Email]
    D --> E[Metrics: 0.98 Precision, MTTR <1 min]