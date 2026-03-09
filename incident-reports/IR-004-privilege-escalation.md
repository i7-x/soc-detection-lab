## IR-004 — Privilege Escalation Attempt

| Field | Details |
|-------|---------|
| **Incident ID** | IR-004 |
| **Date & Time** | 2026-02-25 (during lab session) |
| **Attack Type** | Privilege Escalation Attempt |
| **Severity** | 🔴 High |
| **Source IP** | 192.168.62.5 — local execution (DESKTOP-BSSP81K) |
| **Target IP** | 192.168.62.5 (DESKTOP-BSSP81K) — local accounts |
| **Wazuh Rule ID** | 60170 — Users Group Changed \| 60108 — User Account Created |
| **What Happened** | A new low-privilege user account ('attacker') was created on the Windows victim machine. The attacker then attempted to escalate privileges by adding the account to the local Administrators group using 'net localgroup administrators attacker /add', which failed with Access Denied. Attempts to query the SAM registry hive (reg query HKLM\SAM\SAM) also failed. Wazuh detected the account creation and group modification attempts via Windows Security event logs. |
| **How Detected** | Wazuh monitored the Windows Security event channel. Rule 60108 triggered on Event ID 4720 (User Account Created) when the 'attacker' account was created. Rule 60170 triggered on Event ID 4732 (Member Added to Security-Enabled Local Group) when the group modification was attempted. Rule 60110 also fired on account changes. |
| **Evidence** | agent.name: DESKTOP-BSSP81K \| agent.id: 002 \| eventIDs: 4720, 4732, 4725 \| rules: 60108, 60110, 60170 \| newAccount: attacker \| targetGroup: Administrators \| result: Access Denied \| technique: T1136 (Create Account), T1548 (Abuse Elevation Control) |
| **Impact** | If the privilege escalation had succeeded, the attacker would have gained full administrative control of the Windows VM, enabling them to disable security controls, create backdoors, dump credentials from LSASS, and move laterally across the network. |
| **Response Actions** | 1. Immediately disable and delete the 'attacker' account. 2. Review all accounts created in the last 24 hours across all endpoints. 3. Check for successful privilege escalation (Event ID 4672 — Special Privileges Assigned). 4. Audit local administrator group membership on all endpoints. 5. Escalate to Tier 2. |
| **Lessons Learned** | Principle of least privilege must be enforced — standard users should not have rights to create local accounts. Account creation events should trigger automatic alerts at level 10 or above. Deploy a PAM solution to control and audit admin-level actions.