# Office → Script Encoded Command — Triage Playbook

**Detection Name:** `OfficeToScript_EncodedCommand`  
**Goal:** Detect Office applications spawning scripting engines or LOLBINs (PowerShell, wscript, mshta, rundll32, regsvr32, cmd) with encoded, obfuscated, or download-oriented command lines — a classic initial access → execution pattern in phishing, maldocs, and hands-on-keyboard intrusions.

—

## 🔎 What this detection looks for

### Parent processes (“SusParent”)  
Office or Teams processes spawning child processes:
- winword.exe  
- excel.exe  
- powerpnt.exe  
- outlook.exe  
- teams.exe  

Office apps **should not** be creating scripting/LOLBIN children under normal business operations.

### Child processes (“SusChild”)  
Known LOLBIN or script interpreters commonly abused after phishing:
- powershell.exe  
- wscript.exe  
- cscript.exe  
- mshta.exe  
- cmd.exe  
- rundll32.exe  
- regsvr32.exe  

### Command-line indicators (“SusCmd”)  
Obfuscation, encoded payloads, staging or download activity:
- `-EncodedCommand`, `-Enc`, `-e`  
- `IEX`, `FromBase64String`  
- `DownloadString`  
- `Invoke-WebRequest`, `Start-BitsTransfer`, `DownloadFile`  

### Account filtering (AllowList)
- Known admin or IT automation accounts excluded.

### High-level logic  
Detection triggers when:
1. **Office → LOLBIN/script engine** process chain  
2. Child process contains **encoded or download-oriented** indicators  
3. Initiating user is **not** an admin/service account  
4. Timestamp within last 30 days (modifiable)  

—

## ⏱ First 60 Seconds — Fast Triage

1. **Confirm who & where**
   - Check `AccountName` and `DeviceName`
   - Ask: *“Should this user ever be spawning PowerShell via Word?”*
   - Red flag → standard business user on workstation

2. **Inspect the process chain**
   - Parent: Office app  
   - Child: PowerShell/wscript/LOLBIN  
   - This is inherently suspicious unless automation is involved.

3. **Check the command line**
   Look for:
   - Base64 strings  
   - Long obfuscated blobs  
   - `”IEX (New-Object Net.WebClient).DownloadString”` style patterns  
   - “bitsadmin”/BITS-style staging  

4. **Initial verdict**
   - If encoded **and** downloaded content appears