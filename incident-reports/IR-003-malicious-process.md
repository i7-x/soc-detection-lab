## IR-003 — Malicious PowerShell Execution (Process Discovery)

| Field | Details |
|-------|---------|
| **Incident ID** | IR-003 |
| **Date & Time** | 2026-02-25 (during lab session) |
| **Attack Type** | Malicious PowerShell Execution (Process Discovery) |
| **Severity** | 🟡 Medium |
| **Source IP** | 192.168.62.5 — local execution (DESKTOP-BSSP81K) |
| **Target IP** | 192.168.62.5 (DESKTOP-BSSP81K) — self-targeted |
| **Wazuh Rule ID** | 91815 — PowerShell Executing Process Discovery |
| **What Happened** | A series of suspicious PowerShell commands were executed on the Windows victim machine. These included creating a malicious script (update_helper.ps1) in C:\Windows\Temp, running encoded Base64 PowerShell commands, and executing reconnaissance commands targeting security processes (Defender, antivirus, McAfee). PowerShell Script Block Logging (Event ID 4104) captured the commands. Wazuh rule 91815 fired on the process discovery activity. |
| **How Detected** | PowerShell Operational log (Microsoft-Windows-PowerShell/Operational) was monitored by the Wazuh agent via eventchannel with a filter for Event ID 4104 (Script Block Logging). Rule 91815 triggered on PowerShell process discovery commands. The encoded command was also captured and flagged. |
| **Evidence** | agent.name: DESKTOP-BSSP81K \| agent.id: 002 \| eventID: 4104 \| ruleID: 91815 \| technique: T1082 (System Information Discovery) \| tactic: Discovery \| scriptBlock: Get-Process \| Where-Object { $_.Name -match 'defender\|antivirus\|mcafee' } \| location: C:\Windows\Temp\update_helper.ps1 |
| **Impact** | If this were a real attack, the attacker would have mapped running security processes to identify blind spots, then disabled or evaded them before proceeding with further compromise. Encoded PowerShell is a common defense evasion technique used in real-world APT campaigns. |
| **Response Actions** | 1. Isolate the endpoint immediately. 2. Pull the script from C:\Windows\Temp for forensic analysis. 3. Check PowerShell history and Event ID 4688 (Process Creation) for full command chain. 4. Scan for persistence mechanisms (scheduled tasks, registry run keys). 5. Escalate to Tier 2 / Incident Response team. |
| **Lessons Learned** | PowerShell Script Block Logging should be enabled by default via GPO across all endpoints. Constrained Language Mode should be enforced to limit PowerShell capabilities for non-admin users. AMSI integration with EDR solutions would catch encoded commands at runtime.