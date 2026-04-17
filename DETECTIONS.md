# Detection Index

Master reference for all detections in this hunt pack. Each entry includes MITRE mapping, data source, severity, and a description of what it catches and why it matters in a healthcare environment.

---

| # | Detection | Technique ID | Tactic | Data Source | Severity | Status |
|---|-----------|-------------|--------|-------------|----------|--------|
| 01 | [Office to Script Encoded Command](hunts/01_OfficeToScript_EncodedCommand.kql) | T1059.001, T1204.002, T1218 | Execution | DeviceProcessEvents | High | Analytic |
| 02 | [Recon Burst from Risky Parents](hunts/02_ReconBursts_RiskyParents.kql) | T1016, T1033, T1087 | Discovery | DeviceProcessEvents | Medium | Hunting |
| 03 | [Persistence via Scheduled Task](hunts/03_PersistenceViaSchtasks.kql) | T1053.005 | Persistence | DeviceProcessEvents | High | Analytic |
| 04 | [LSASS Memory Access](hunts/04_CredentialAccess_LSASS.kql) | T1003.001 | Credential Access | DeviceEvents | Critical | Analytic |
| 05 | [Suspicious Service Installation](hunts/05_Persistence_ServiceInstall.kql) | T1543.003 | Persistence | DeviceProcessEvents | High | Analytic |
| 06 | [Anomalous RDP Lateral Movement](hunts/06_LateralMovement_RemoteLogon.kql) | T1021.001 | Lateral Movement | DeviceLogonEvents | Medium | Hunting |

---

## Detection Details

### 01 — Office to Script Encoded Command

Detects Office applications (Word, Excel, PowerPoint, Outlook, Teams) spawning scripting engines or LOLBINs with encoded or obfuscated command arguments. Primary indicator of macro-based malware execution.

**Why it matters in healthcare:** Medical billing attachments and insurance forms are high-trust phishing lures. This pattern catches the shell execution that follows a successful macro payload — the most common initial access vector in healthcare ransomware incidents.

**Tune:** Add admin account names to `AllowNames`. Expand `SusCmd` with additional obfuscation strings observed in your environment.

---

### 02 — Recon Burst from Risky Parents

Identifies three or more reconnaissance commands (whoami, ipconfig, net, quser) executed within a 1-hour window from a suspicious parent process. Burst pattern separates attacker recon from incidental admin activity.

**Why it matters in healthcare:** Attackers who land via phishing immediately run recon to understand network topology and user permissions before moving laterally to clinical systems and EHR platforms.

**Tune:** Adjust the `cnt >= 3` threshold and `lookback` window based on your environment's baseline noise. Add admin accounts to `AllowList`.

---

### 03 — Persistence via Scheduled Task

Catches schtasks.exe being invoked with `/create` or `/change` flags by script engines, Office applications, or LOLBINs. Scheduled task persistence survives reboots and blends with legitimate IT automation.

**Why it matters in healthcare:** ALPHV, LockBit, and Rhysida — all active threat actors targeting healthcare — use scheduled task persistence as a standard step in their deployment chain before detonating ransomware.

**Tune:** Add admin account names to `AllowList`. Consider adding known IT automation tool processes to a separate allowlist if your environment uses scripted scheduled task management.

---

### 04 — LSASS Memory Access

Flags processes opening LSASS with read access from unexpected callers. Covers credential dumping tools including Mimikatz, ProcDump abuse, and Cobalt Strike's built-in credential extraction.

**Why it matters in healthcare:** Stolen credentials are the primary mechanism for lateral movement to EHR systems, clinical workstations, and domain controllers. LSASS access is a critical chokepoint — detecting it early is often the difference between an incident and a breach.

**Tune:** Validate `AllowedCallers` against your environment's legitimate LSASS-accessing processes. Security tools (AV, EDR agents) may need to be added. Add admin accounts to `AllowList`.

---

### 05 — Suspicious Service Installation

Detects sc.exe being used to create or configure services from risky parent processes including script engines and Office applications. Malware uses service installation to achieve persistence and automatic restart on reboot.

**Why it matters in healthcare:** Ransomware operators install services to maintain access during a multi-day dwell period before detonating encryption. Catching this early is the difference between containing an incident and managing a full breach.

**Tune:** Add known legitimate deployment tools (SCCM, Intune agents) to a parent process allowlist if they trigger false positives. Add admin accounts to `AllowList`.

---

### 06 — Anomalous RDP Lateral Movement

Identifies remote interactive logons (RDP, LogonType 10) from IP addresses not on the known admin/jump host allowlist, particularly accounts authenticating to multiple systems within a short window.

**Why it matters in healthcare:** RDP lateral movement is the most common technique used to pivot from an initial endpoint compromise toward domain controllers and clinical data repositories. Most healthcare ransomware incidents include an RDP lateral movement phase before data exfiltration or encryption.

**Tune:** Populate `RemoteIPAllowList` with known admin workstation IPs and jump host addresses. Adjust `LogonCount >= 2` threshold based on your environment's RDP baseline. Add admin accounts to `AllowList`.

---

## Tuning Notes

All detections include allowlists that must be populated with environment-specific values before deployment. Look for variables named `AllowList`, `RemoteIPAllowList`, and `AllowedCallers` in each query file.

Replace placeholder values with:
- Privileged and admin account names used in your environment
- Known admin workstation IPs and jump host addresses
- Approved security tool process names

Promote from `Hunting` to `Analytic` status after validating false positive rates in your environment over a minimum 7-day observation period.
