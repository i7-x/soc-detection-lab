## IR-002 — Network Port Scan (Reconnaissance)

| Field | Details |
|-------|---------|
| **Incident ID** | IR-002 |
| **Date & Time** | 2026-02-24 21:49:46 UTC |
| **Attack Type** | Network Port Scan (Reconnaissance) |
| **Severity** | 🟡 Medium |
| **Source IP** | 192.168.62.4 (SOC-Kali-Attacker) |
| **Target IP** | 192.168.62.5 (DESKTOP-BSSP81K) |
| **Wazuh Rule ID** | 4151 — Multiple Firewall Drop Events From Same Source |
| **What Happened** | An Nmap SYN scan was launched from Kali (192.168.62.4) targeting ports 1-1000 on the Windows victim machine (192.168.62.5). The Windows firewall logged numerous DROP events for TCP and ICMP packets from the attacker IP. Wazuh rule 4151 fired after correlating multiple firewall drop events from the same source, indicating active reconnaissance activity. |
| **How Detected** | Windows Firewall logging was enabled and configured to write to pfirewall.log. The Wazuh agent monitored the Microsoft-Windows Firewall event channel (Event IDs 5152/5157). Rule 4151 triggered on multiple DROP events from the same source IP. Additionally, pfirewall.log confirmed DROP TCP entries from 192.168.62.4 across multiple ports. |
| **Evidence** | agent.name: DESKTOP-BSSP81K \| agent.id: 002 \| ruleID: 4151 \| level: 10 \| description: Multiple Firewall drop events from same source \| sourceIP: 192.168.62.4 \| protocol: TCP/ICMP \| ports scanned: 1-1000 \| firewall log: pfirewall.log confirmed DROP entries |
| **Impact** | Port scanning reveals open services and their versions, enabling targeted exploitation. Open ports identified could be used to plan follow-on attacks such as service exploitation, brute force, or privilege escalation. |
| **Response Actions** | 1. Block 192.168.62.4 at perimeter firewall. 2. Review open ports identified in the scan — close unnecessary services. 3. Check for follow-on attack activity from same IP across all agents. 4. Escalate if scan is followed by exploitation attempts. |
| **Lessons Learned** | Network-level port scan detection (IDS/IPS) should supplement host-based firewall logging. Consider deploying Snort or Suricata for real-time scan detection. Firewall log permissions should be verified during agent setup — the Wazuh agent (WazuhSvc) initially lacked read access to pfirewall.log, causing a detection gap.