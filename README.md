# Threat Detection Hunt Pack (Healthcare Focused)

Custom KQL detections and behavioral hunt queries I've developed for **Microsoft Defender XDR**, built from real-world security operations in a healthcare/critical infrastructure environment.

Each detection maps to MITRE ATT&CK, includes allowlists tuned for healthcare environments, and has a companion triage playbook for rapid analyst response.

---

## Detections

Full index with MITRE mappings, data sources, and tuning notes: [DETECTIONS.md](DETECTIONS.md)

| # | Detection | Technique | Tactic | Severity |
|---|-----------|-----------|--------|----------|
| 01 | [Office to Script Encoded Command](hunts/01_OfficeToScript_EncodedCommand.kql) | T1059.001, T1204.002, T1218 | Execution | High |
| 02 | [Recon Burst from Risky Parents](hunts/02_ReconBursts_RiskyParents.kql) | T1016, T1033, T1087 | Discovery | Medium |
| 03 | [Persistence via Scheduled Task](hunts/03_PersistenceViaSchtasks.kql) | T1053.005 | Persistence | High |
| 04 | [LSASS Memory Access](hunts/04_CredentialAccess_LSASS.kql) | T1003.001 | Credential Access | Critical |
| 05 | [Suspicious Service Installation](hunts/05_Persistence_ServiceInstall.kql) | T1543.003 | Persistence | High |
| 06 | [Anomalous RDP Lateral Movement](hunts/06_LateralMovement_RemoteLogon.kql) | T1021.001 | Lateral Movement | Medium |

---

## Repository Structure

```
hunts/       KQL detection queries (Defender XDR)
playbooks/   Markdown triage guides per detection
metadata/    MITRE mappings and version tracking
```

---

## Design Philosophy

Each detection is built to:

- Emphasize **high signal, low noise** with allowlists and environment-specific tuning variables built in
- Reflect **real attacker patterns** observed in healthcare sector incidents — macro-based initial access, credential theft, and ransomware pre-deployment activity
- Map cleanly to **MITRE ATT&CK** for integration into threat intelligence and incident response workflows

---

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|--------|------------|
| Execution | T1059.001, T1204.002, T1218 |
| Discovery | T1016, T1033, T1087 |
| Persistence | T1053.005, T1543.003 |
| Credential Access | T1003.001 |
| Lateral Movement | T1021.001 |

**5 tactics · 10 techniques · 6 detections**

---

## Deploying in Your Environment

Before running these queries:

1. Replace allowlist values (labeled `replace-with-admin1`, etc.) with your privileged account names and admin IPs
2. Adjust lookback windows to match your data volume and alert fatigue tolerance
3. Test in hunting mode before promoting to analytic rules

See [DETECTIONS.md](DETECTIONS.md) for per-detection tuning notes.

---

## Author

**AJ Jeffreys** — Security Operations Analyst specializing in threat detection and vulnerability management in healthcare/critical infrastructure.

[LinkedIn](https://www.linkedin.com/in/ajani-jeffreys/) · [GitHub](https://github.com/AJ-Jeffreys)
