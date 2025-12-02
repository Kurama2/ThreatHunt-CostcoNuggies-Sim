# Rule Tuning: FP Reduction
Tuned the VPN bypass rule across versions to balance precision (true threats caught) and FPs (noise alerts). From H1 hunts (22 CA FPs vs. 37 RU threats), iterated to V3 sweet spot (0.98 precision, 84% FP drop on 5000 logs).

| Version | Description | Precision | Recall | Why? |
|---------|-------------|-----------|--------|------|
| V1 | Basic bypass (all false vpn_connected) | 0.02 | 1.00 | High FPs from CA/US (450 alerts, 5 true/450 = noisy). |
| V2 | Geo-tuned (RU/CN only) | 0.30 | 1.00 | Drops 22 CA FPs (35 alerts, 5/35 = better focus). |
| V3 | Threshold >3/hour + CA 9-17 whitelist | 0.98 | 0.85 | Sweet spot ( <5 FPs, 85% threats caught—84% drop). |