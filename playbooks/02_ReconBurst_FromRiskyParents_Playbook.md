# Recon Burst from Risky Parents — Triage Playbook

**Detection Name:** ReconBurst_FromRiskyParents  
**Goal:** Identify clusters of discovery commands (whoami, ipconfig, net, etc.) executed within a short time window from risky parent processes (script engines, Office, browsers), indicating hands-on-keyboard post-compromise recon.

—

## 🔎 What this detection looks for

- Time window: last `2h`, aggregated into `1h` buckets.
- Child processes: `whoami.exe`, `ipconfig.exe`, `quser.exe`, `net.exe`, `net1.exe`.
- Parent processes (“riskyParents”):
  - `powershell.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`
  - `WINWORD.EXE`, `EXCEL.EXE`, `POWERPNT.EXE`, `outlook.exe`
  - `chrome.exe`, `msedge.exe`
- Filters:
  - For `net.exe`, keep only if command line contains `” user”`, `” group”`, or `” view”`.
  - Excludes known admin/service accounts via `AllowList`.
- Aggregation:
  - Groups by `DeviceId`, `DeviceName`, `AccountName`, `bin(Timestamp, 1h)`.
  - Requires `cnt >= 3` recon commands in the same 1-hour bucket.

—

## ⏱ First 60 seconds (fast triage)

1. **Confirm who & where**
   - Look at `AccountName` and `DeviceName`.
   - Ask: *“Should this user ever be running recon on this device?”*
   - Red flag: normal business user on a workstation, not IT/admin.

2. **Review recon commands**
   - Check `cmds` (set of child binaries) and `parents` (set of parent procs).
   - High suspicion if:
     - Multiple recon tools in same hour (e.g., `whoami`, `ipconfig`, `net`).
     - Parents are script engines (`powershell`, `wscript`, `mshta`) or Office.

3. **Look at the sample command line**
   - Use the `ProcessCommandLine` from `sample` (arg_max).
   - Look for:
     - Enumeration of users/groups (`net user`, `net group`, `quser`).
     - Domain info, shares, or IP configuration dumps.
     - Odd paths (recon tools spawned from temp paths or user profile subdirs).

—

## 🧬 Deeper investigation steps

### 1. Timeline pivot (±30 minutes)

- Pivot to **all processes** on that device around the same time:
  - Upstream: what started the risky parent (`powershell.exe`, `WINWORD.EXE`, `chrome.exe`, etc.)?
  - Downstream: did they launch more tools (e.g., `nltest`, `whoami /groups`, `netstat`, `ping` to internal servers)?

- Look for:
  - Suspicious documents or macros opened in Office.
  - Browsers downloading executables, scripts, or HTA files.
  - PowerShell with encoded commands, LOLBIN usage, or remote URLs.

### 2. Network pivot

- Pivot to `DeviceNetworkEvents` (or equivalent) for:
  - The parent process (`InitiatingProcessId`) and recon children (`ProcessId`), ±5 minutes.
- Red flags:
  - Outbound connections to unknown IPs or non-standard ports.
  - Connections to newly-seen external domains around the recon time.

### 3. Account & authentication context

- Check recent logons for `AccountName`:
  - Any unusual source IPs or locations?
  - Any recent VPN sign-ins that look off?
- Determine if the account:
  - Is part of admin groups (Domain Admins, local admins).
  - Was recently used from multiple machines unexpectedly.

—

## ✅ True positive vs. false positive guidance

### Likely true positive patterns

- Non-admin user on a normal workstation running:
  - `whoami /all`, `ipconfig /all`, `net user /domain`, `quser`
- Parent is `powershell.exe`, `wscript.exe`, `mshta.exe`, or Office.
- Recon appears shortly **after** suspicious events (phishing doc, script download, new tool execution).
- Recon followed by:
  - Credential dumping attempts (lsass access),
  - Lateral movement (RDP, SMB, PsExec),
  - Or new service creation.

### Common false positives

- IT admins/scripts doing inventory or troubleshooting.
- Scheduled health checks or management tools using `net`/`ipconfig` under known service accounts.
- Imaging/build/packaging hosts that run recon as part of automation.

For these, consider:
- Adding the accounts to `AllowList`.
- Adding devices (jump boxes, imaging servers) to a host allowlist in the query.
- Lowering severity for activity originating from known admin infra.

—

## 🚨 Containment & response recommendations

If the activity appears malicious:

1. **Contain**
   - Isolate the device from the network.
   - Invalidate or rotate credentials used on the host (especially if admin).

2. **Preserve evidence**
   - Collect relevant logs for the host (process, network, authentication).
   - Capture memory and critical artifacts if your IR playbook supports it.

3. **Scope the intrusion**
   - Search for similar recon bursts across:
     - Same `AccountName` on other devices.
     - Same `DeviceName` with other accounts.
     - Same `InitiatingProcessFileName` + command patterns environment-wide.

4. **Follow-on hunts**
   - Look for:
     - Credential dumping attempts (lsass access).
     - Lateral movement (RDP, SMB, PsExec, WMI).
     - Staging of data or archive creation on shares.

—

## 🛠 Tuning tips

- **AllowList**  
  Replace hardcoded names with:
  - AD groups (`Domain Admins`, `Helpdesk`, etc.), or
  - A broader list of verified service accounts.

- **Host allowlist**  
  Consider excluding:
  - Imaging/packaging servers
  - SCCM/Intune management hosts
  - Dedicated admin/jump boxes

- **Threshold**
  - Default `cnt >= 3` per device/account per 1h.
  - You may:
    - Use `cnt >= 2` for non-admin users.
    - Keep `cnt >= 3` for admin accounts.

—

## 🧬 MITRE ATT&CK

Primary techniques:
- **T1033** – Account Discovery (e.g., `whoami`, `quser`)  
- **T1016** – System Network Configuration Discovery (e.g., `ipconfig`)  
- **T1087** – Account Discovery (using `net user`, `net group`)  
- **T1082** – System Information Discovery (general recon)

—