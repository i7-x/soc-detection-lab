# SOC Detection Lab
### Security Monitoring & Incident Response — Home Lab Project
**by Muhammad Omar** | [GitHub](https://github.com/i7-x) / [LinkedIn](https://www.linkedin.com/in/omar0x)  
**Published:** 9 March 2026 

---

## What This Is

A fully functional Security Operations Center (SOC) home lab built from scratch. I deployed a real SIEM (Wazuh), connected Windows and Linux endpoints, executed 5 real attacks, detected them live, investigated the alerts, and wrote professional incident reports — exactly what a day-1 SOC analyst does on the job.

---

## Lab Architecture

```
┌──────────────────────────────────────────────────────┐
│                  VirtualBox Host                     │
│                                                      │
│ ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│ │  SOC-Wazuh   │  │   DESKTOP-   │  │   SOC-Kali   │ │
│ │    Server    │  │   BSSP81K    │  │   Attacker   │ │
│ │ Ubuntu 22.04 │  │  Windows 10  │  │  Kali Linux  │ │
│ │ 192.168.62.3 │  │ 192.168.62.5 │  │ 192.168.62.4 │ │
│ │              │  │              │  │              │ │
│ │  Wazuh SIEM  │◄─│  Wazuh Agent │  │    Hydra     │ │
│ │   Manager    │  │    (logs)    │  │    Nmap      │ │
│ │  Dashboard   │  │              │  │    Netcat    │ │
│ └──────────────┘  └──────────────┘  └──────────────┘ │
│                                                      │
│         Host-Only Network: 192.168.62.0/24           │
└──────────────────────────────────────────────────────┘
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Wazuh 4.7 | SIEM — log collection, correlation, alerting |
| VirtualBox | Hypervisor — running all 3 VMs |
| Ubuntu Server 22.04 | Wazuh server OS |
| Windows 10 | Victim endpoint (monitored) |
| Kali Linux | Attacker machine |
| Hydra | Brute force tool |
| Nmap | Port scanner / reconnaissance |
| Netcat | Data exfiltration listener |
| PowerShell | Attack simulation on Windows |

---

## Attacks Executed & Detected

| # | Attack | Tool | Wazuh Rule | Severity |
|---|--------|------|------------|----------|
| 1 | [Brute Force RDP](incident-reports/IR-001-brute-force.md) | Hydra | 60204 — Multiple Windows Logon Failures | 🔴 High |
| 2 | [Port Scan](incident-reports/IR-002-port-scan.md) | Nmap | 4151 — Multiple Firewall Drop Events | 🟡 Medium |
| 3 | [Malicious PowerShell](incident-reports/IR-003-malicious-process.md) | PowerShell | 91815 — PowerShell Process Discovery | 🟡 Medium |
| 4 | [Privilege Escalation](incident-reports/IR-004-privilege-escalation.md) | net.exe / runas | 60170 — Users Group Changed | 🔴 High |
| 5 | [Data Exfiltration](incident-reports/IR-005-data-exfiltration.md) | PowerShell + Netcat | 100002 — TcpClient Exfiltration (custom) | 🔴 High |

---

## Incident Reports

Each attack has a full professional incident report documenting what happened, how it was detected, evidence collected, impact, response actions, and lessons learned.

- [IR-001 — Brute Force Attack](incident-reports/IR-001-brute-force.md)
- [IR-002 — Port Scan](incident-reports/IR-002-port-scan.md)
- [IR-003 — Malicious PowerShell](incident-reports/IR-003-malicious-process.md)
- [IR-004 — Privilege Escalation](incident-reports/IR-004-privilege-escalation.md)
- [IR-005 — Data Exfiltration](incident-reports/IR-005-data-exfiltration.md)

---

## Custom Detection Rules

Two custom Wazuh rules were written and deployed in `/var/ossec/etc/rules/local_rules.xml` to detect attacks that Wazuh doesn't cover out of the box. Rule 100001 detects port scan activity via firewall DROP events. Rule 100002 detects PowerShell-based data exfiltration by matching the TcpClient keyword in script block logs (Event ID 4104).

```xml
<group name="firewall,drop,">
  <rule id="100001" level="8">
    <if_sid>0</if_sid>
    <match>DROP</match>
    <description>Port scan detected</description>
  </rule>
</group>

<group name="powershell,">
  <rule id="100002" level="12">
    <if_sid>0</if_sid>
    <match>TcpClient</match>
    <description>PowerShell exfiltration detected</description>
  </rule>
</group>
```

---

## Screenshots

All evidence screenshots are in the [`screenshots/`](screenshots/) folder.

| # | File | What It Shows |
|---|------|--------------|
| 01 | [`01_virtualbox_installed.png`](screenshots/01_virtualbox_installed.png) | VirtualBox main window |
| 02 | [`02_isos_downloaded.png`](screenshots/02_isos_downloaded.png) | ISOs ready for installation |
| 03 | [`03_ubuntu_server_running.png`](screenshots/03_ubuntu_server_running.png) | Ubuntu server login prompt |
| 04 | [`04_windows10_desktop.png`](screenshots/04_windows10_desktop.png) | Windows 10 VM running |
| 05 | [`05_kali_desktop.png`](screenshots/05_kali_desktop.png) | Kali Linux desktop |
| 06 | [`06_network_connectivity.png`](screenshots/06_network_connectivity.png) | Ping between VMs confirmed |
| 07 | [`07_wazuh_install_complete.png`](screenshots/07_wazuh_install_complete.png) | Wazuh install summary |
| 08 | [`08_wazuh_dashboard_login.png`](screenshots/08_wazuh_dashboard_login.png) | Wazuh dashboard |
| 09 | [`09_agent_installed_windows.png`](screenshots/09_agent_installed_windows.png) | WazuhSvc running on Windows |
| 10 | [`10_agent_active_dashboard.png`](screenshots/10_agent_active_dashboard.png) | Agent showing Active in Wazuh |
| 11 | [`11_bruteforce_attack_running.png`](screenshots/11_bruteforce_attack_running.png) | Hydra brute force running |
| 12 | [`12_bruteforce_alerts_wazuh.png`](screenshots/12_bruteforce_alerts_wazuh.png) | Multiple logon failure alerts |
| 13 | [`13_bruteforce_alert_detail.png`](screenshots/13_bruteforce_alert_detail.png) | Alert detail — rule 60204 |
| 14 | [`14_nmap_scan_running.png`](screenshots/14_nmap_scan_running.png) | Nmap scan from Kali |
| 15 | [`15_portscan_firewall_drops.png`](screenshots/15_portscan_firewall_drops.png) | Firewall DROP entries confirmed |
| 16 | [`16_suspicious_commands_windows.png`](screenshots/16_suspicious_commands_windows.png) | Malicious PowerShell running |
| 17 | [`17_suspicious_process_alert.png`](screenshots/17_suspicious_process_alert.png) | Wazuh alert — rule 91815 |
| 18 | [`18_privesc_commands.png`](screenshots/18_privesc_commands.png) | Privilege escalation attempt |
| 19 | [`19_privesc_alert_wazuh.png`](screenshots/19_privesc_alert_wazuh.png) | Wazuh alert — rules 60108/60170 |
| 20 | [`20_exfiltration_kali_received.png`](screenshots/20_exfiltration_kali_received.png) | Kali received the file |
| 22 | [`22_sample_incident_report.png`](screenshots/22_sample_incident_report.png) | Incident report IR-001 rendered |

---

## Key Takeaways

- Deployed and configured a production-grade open source SIEM from scratch
- Hands-on experience with Windows Security event IDs (4625, 4720, 4732, 4104)
- Wrote custom Wazuh detection rules to close real detection gaps
- Documented a real detection gap (Wazuh agent lacking read permissions on pfirewall.log) and resolved it — exactly the kind of finding you'd escalate in a real SOC
- Produced 5 professional incident reports following SOC industry format

---

## Repo Structure

```
soc-detection-lab/
├── README.md
├── screenshots/
│   ├── 01_virtualbox_installed.png
│   ├── 02_isos_downloaded.png
│   └── ... (21 screenshots total)
└── incident-reports/
    ├── IR-001-brute-force.md
    ├── IR-002-port-scan.md
    ├── IR-003-malicious-process.md
    ├── IR-004-privilege-escalation.md
    └── IR-005-data-exfiltration.md
```

---

*Built as a portfolio project to demonstrate practical SOC analyst skills — log analysis, SIEM configuration, threat detection, and incident response.*
