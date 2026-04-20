# Recon Burst from Script Host or Productivity App — Triage Playbook

**Detection Name:** ReconBurst_FromRiskyParents
**Goal:** Identify clusters of discovery commands (whoami, ipconfig, net, nltest, systeminfo, tasklist, etc.) executed within a short time window from risky parent processes (script engines, LOLBINs, Office, browsers), indicating hands-on-keyboard post-compromise recon. The distinct-count requirement separates attacker-style multi-dimensional enumeration from scripted loops of a single command.

—

## 🔎 What this detection looks for

### Parameters (tune at top of query)
- `lookback = 2h` — detection window
- `bucket = 1h` — aggregation bucket
- `burstThreshold = 3` — minimum total recon executions per bucket
- `distinctMin = 2` — minimum number of **different** recon tools per bucket

### Child processes (`reconBins`)
Discovery tools commonly run during post-exploitation recon:
- `whoami.exe`, `ipconfig.exe`, `quser.exe`, `hostname.exe`
- `systeminfo.exe`, `tasklist.exe`, `nltest.exe`
- `net.exe`, `net1.exe`

### Parent processes (`riskyParents`)
Processes that should not be parenting recon bursts under normal use:
- **Script/LOLBIN hosts:** `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `hh.exe`, `msbuild.exe`
- **Office:** `winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe`, `onenote.exe`
- **Browsers / reader:** `chrome.exe`, `msedge.exe`, `firefox.exe`, `acrord32.exe`

### Filters
- For `net.exe` / `net1.exe`, only keep invocations where the command line contains recon-relevant args: ` user`, ` group`, ` view`, ` localgroup`, ` session`, ` accounts`, ` config`.
- Excludes known admin/service accounts via `AllowList`.

### Aggregation
- Groups by `DeviceId`, `DeviceName`, `AccountDomain`, `AccountName`, `bin(Timestamp, 1h)`.
- Requires `ReconCount >= 3` **AND** `DistinctRecon >= 2` in the same bucket.

—

## ⏱ First 60 seconds (fast triage)

1. **Confirm who & where**
   - Check `AccountName`, `AccountDomain`, and `DeviceName`.
   - Ask: *"Should this user ever be running recon on this device?"*
   - Red flag: normal business user on a workstation, not IT/admin.

2. **Review the recon mix**
   - Look at `ReconCommands` (distinct child binaries) and `ParentProcesses`.
   - High suspicion if:
     - The mix spans categories — e.g. `whoami` + `ipconfig` + `nltest` + `net user`.
     - Parents are script engines (`powershell`, `pwsh`, `wscript`, `mshta`) or Office.
     - `DistinctRecon` is at the high end (4+) — methodical enumeration, not scripted noise.

3. **Check the sample command lines**
   - Use `SampleCmdLines` and `ProcessCommandLine` from `arg_max`.
   - Look for:
     - User/group enumeration (`net user /domain`, `net group`, `quser`).
     - Domain trust enumeration (`nltest /domain_trusts`, `nltest /dclist`).
     - System info dumps (`systeminfo`, `hostname`, `tasklist /svc`).
     - Odd paths — recon tools spawned from temp directories or user profile subdirs (check `FolderPath`).

—

## 🧬 Deeper investigation steps

### 1. Timeline pivot (±30 minutes)
- Pivot to **all processes** on that device around the same time:
  - Upstream: what started the risky parent? Look at `InitiatingProcessFolderPath` and `InitiatingProcessCommandLine`.
  - Downstream: did they launch more tools (credential dumpers, archive tools, remote admin utilities)?
- Look for:
  - Suspicious documents or macros opened in Office.
  - Browsers downloading executables, scripts, or HTA files.
  - PowerShell with encoded commands, LOLBIN usage, or remote URLs.

### 2. Network pivot
- Pivot to `DeviceNetworkEvents` for:
  - The parent process (`InitiatingProcessId`) and recon children (`ProcessId`), ±5 minutes.
- Red flags:
  - Outbound connections to unknown IPs or non-standard ports.
  - Connections to newly-seen external domains around the recon time.
  - SMB (445) or RDP (3389) connections to internal hosts immediately after the recon burst.

### 3. Account & authentication context
- Check recent logons for `AccountName` + `AccountDomain`:
  - Unusual source IPs or locations?
  - Recent VPN sign-ins that look off?
- Determine if the account:
  - Is part of admin groups (Domain Admins, local admins).
  - Was recently used from multiple machines unexpectedly.

—

## ✅ True positive vs. false positive guidance

### Likely true positive patterns
- Non-admin user on a normal workstation running a diverse recon mix (e.g. `whoami` + `nltest` + `net group`).
- Parent is `powershell.exe`, `pwsh.exe`, `wscript.exe`, `mshta.exe`, `msbuild.exe`, or Office.
- Recon appears shortly **after** suspicious events (phishing doc, script download, new tool execution).
- Recon followed by:
  - Credential dumping attempts (LSASS access).
  - Lateral movement (RDP, SMB, PsExec, WMI).
  - New service creation or scheduled task persistence.

### Common false positives
- IT admins/scripts doing inventory or troubleshooting.
- Scheduled health checks using `net`/`ipconfig`/`systeminfo` under known service accounts.
- Imaging/build/packaging hosts that run recon as part of automation.
- Asset discovery tooling (e.g. Tenable agent deployment, SCCM inventory scripts).

For these, consider:
- Adding the accounts to `AllowList`.
- Adding devices (jump boxes, imaging servers, vulnerability scanners) to a host allowlist in the query.
- Raising `distinctMin` to 3 for environments where 2-tool bursts are routine admin behavior.

—

## 🚨 Containment & response recommendations

If the activity appears malicious:

1. **Contain**
   - Isolate the device from the network.
   - Rotate credentials used on the host (especially if admin or service).

2. **Preserve evidence**
   - Collect host logs (process, network, authentication) covering at least ±4 hours of the burst.
   - Capture memory and critical artifacts if your IR playbook supports it.

3. **Scope the intrusion**
   - Search for similar recon bursts across:
     - Same `AccountName` on other devices.
     - Same `DeviceName` with other accounts.
     - Same `InitiatingProcessFileName` + command patterns environment-wide.

4. **Follow-on hunts**
   - Credential dumping (LSASS access, SAM/SECURITY hive exports).
   - Lateral movement (RDP, SMB, PsExec, WMI, WinRM).
   - Staging of data or archive creation on shares.

—

## 🛠 Tuning tips

- **AllowList**
  Replace hardcoded names with:
  - AD groups (`Domain Admins`, `Helpdesk`, etc.), or
  - A broader list of verified service accounts and automation identities.

- **Host allowlist**
  Consider excluding:
  - Imaging/packaging servers
  - SCCM/Intune/BigFix management hosts
  - Vulnerability scanner collectors (Tenable, Qualys)
  - Dedicated admin/jump boxes

- **Thresholds**
  - Default: `burstThreshold = 3`, `distinctMin = 2`.
  - For noisy admin populations, raise to `burstThreshold = 4`, `distinctMin = 3`.
  - For high-sensitivity environments, lower to `burstThreshold = 2`, `distinctMin = 2`.

- **Promotion from Hunting → Analytic**
  Observe true-positive / false-positive rates for at least 7 days before converting to an analytic rule. Adjust thresholds and allowlists based on the first week of data.

—

## 🧬 MITRE ATT&CK

Primary techniques:
- **T1033** — System Owner/User Discovery (e.g., `whoami`, `quser`)
- **T1016** — System Network Configuration Discovery (e.g., `ipconfig`, `nltest`)
- **T1087** — Account Discovery (e.g., `net user`, `net group`)
- **T1082** — System Information Discovery (e.g., `systeminfo`, `hostname`, `tasklist`)

Tactic: **TA0007 — Discovery**

—
