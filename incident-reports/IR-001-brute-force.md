## IR-001 — Brute Force Authentication Attack (RDP)

| Field | Details |
|-------|---------|
| **Incident ID** | IR-001 |
| **Date & Time** | 2026-02-23 13:54:27 UTC |
| **Attack Type** | Brute Force Authentication Attack (RDP) |
| **Severity** | 🔴 High |
| **Source IP** | 192.168.62.4 (SOC-Kali-Attacker) |
| **Target IP** | 192.168.62.5 (DESKTOP-BSSP81K) |
| **Wazuh Rule ID** | 60204 — Multiple Windows Logon Failures |
| **What Happened** | Automated brute force attack launched from Kali (192.168.62.4) using Hydra against RDP on the Windows victim machine (192.168.62.5). A wordlist of 6 passwords was submitted for the victim-user account over approximately 30 seconds. All attempts failed. Wazuh correlated the repeated Event ID 4625 (Failed Logon) entries and triggered rule 60204 after detecting 10 failures from the same source IP. |
| **How Detected** | Wazuh rule 60204 triggered after correlating multiple Windows Security Event ID 4625 (Failed Logon) entries from the same source IP (192.168.62.4) within a 60-second window. Authentication package: NTLM. Logon type: 3 (Network). |
| **Evidence** | agent.name: DESKTOP-BSSP81K \| agent.id: 002 \| eventID: 4625 \| ipAddress: 192.168.62.4 \| targetUserName: victim-user \| authPackage: NTLM \| logonType: 3 \| ruleID: 60204 \| level: 10 \| count: 10 alerts in ~30s |
| **Impact** | If a correct password had been found, the attacker would have gained remote desktop access to the Windows VM with user-level privileges, enabling lateral movement, privilege escalation, and data exfiltration across the network. |
| **Response Actions** | 1. Block 192.168.62.4 at the host firewall immediately. 2. Escalate to Tier 2. 3. Search all agents for Event ID 4624 (Successful Logon) from the same source IP to confirm no successful access. 4. Notify the account owner. 5. Review all other accounts targeted from the same IP. |
| **Lessons Learned** | RDP should never be directly exposed — enforce VPN-first access policy. Implement account lockout after 5 failed attempts via GPO. Consider deploying a honeypot account to detect credential stuffing. Alert threshold could be lowered to 5 failures for faster detection.