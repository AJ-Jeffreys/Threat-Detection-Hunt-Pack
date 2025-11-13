# 🛡️ Threat Detection Hunt Pack (Healthcare Focused)

This repository showcases custom detection logic and behavioral hunt queries I’ve developed for **Microsoft Defender (KQL)** and **CrowdStrike LogScale**, tailored for the healthcare sector.

Each detection aligns with **MITRE ATT&CK**, emphasizes **noise reduction and baseline tuning**, and includes a **triage playbook** for rapid analyst response.

---

## ⚙️ Contents

| Hunt Name | ATT&CK Techniques | Category | Description |
|------------|------------------|-----------|--------------|
| <a href="https://github.com/AJ-Jeffreys/Threat-Detection-Hunt-Pack/blob/main/hunts/01_OfficeToScript_EncodedCommand.kql" target="_blank">Office to Script Encoded Command/</a>  | T1059.001, T1204.002 | Execution | Detects Office apps spawning scripting engines with encoded payloads |
| <a href="https://github.com/AJ-Jeffreys/Threat-Detection-Hunt-Pack/blob/main/hunts/02_ReconBursts_RiskyParents.kql" target="_blank">Recon Burst from Risky Parents/</a> | T1016, T1033, T1087 | Discovery | Identifies multiple recon commands within short time windows |
 | | | |

---

## 🧩 Structure

<a href="https://github.com/AJ-Jeffreys/Threat-Detection-Hunt-Pack/blob/main/hunts" target="_blank">hunts/</a>       -->    Raw KQL detection queries

<a href="https://github.com/AJ-Jeffreys/Threat-Detection-Hunt-Pack/blob/main/playbooks" target="_blank">playbooks/</a>    -->  Markdown triage guides

<a href="https://github.com/AJ-Jeffreys/Threat-Detection-Hunt-Pack/blob/main/metadata" target="_blank">metadata/</a>     -->    MITRE mappings and version info


---

## 🧠 Design Philosophy
 
Each detection is designed to:
- Emphasize **high signal, low noise**.  
- Include **allowlists** and **NoiseTerms** for environment tuning.  
- Provide **clear triage steps** that map to attacker behaviors.  

---

## 🧭 MITRE ATT&CK Mapping

Each detection includes:
- `technique_id`
- `tactic`
- `data_source`
- `severity`
- `status: hunting | analytic | alert`

Example YAML snippet:
```yaml
id: 01
name: OfficeToScript_EncodedCommand
tactics: [Execution]
techniques: [T1059.001, T1204.002]
data_source: DeviceProcessEvents
status: analytic
severity: High
author: AJ Jeffreys
