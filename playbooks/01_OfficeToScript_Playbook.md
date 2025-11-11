# Office → Script Encoded Command — Triage Playbook

**Goal:** Detect Office apps spawning scripting engines/PowerShell with obfuscation.

## First 60s
- Verify user & device (InitiatingProcessAccountName, DeviceName)
- Review full ProcessCommandLine and hashes (SHA1/SHA256)
- Pivot to DeviceNetworkEvents by PID ±2m

## Decision
- High: long encoded payload + unsigned child + egress → isolate
- Benign/service: add to Allowlist/NoiseTerms after review

**Note:** Replace AllowNames with an AD group once baselined.
