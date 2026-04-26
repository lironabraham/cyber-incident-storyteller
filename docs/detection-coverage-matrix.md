## MITRE ATT&CK Coverage Matrix

**83 of ~242 parent techniques** detected across **13 of 13 tactics** (MITRE ATT&CK Enterprise v18).

!!! tip "Full interactive matrix"
    Drag [`mitre-coverage-layer.json`](mitre-coverage-layer.json) onto
    [navigator.attack.mitre.org](https://mitre-attack.github.io/attack-navigator/)
    to see every ATT&CK technique colour-coded by whether this tool detects it.

### Tactic Summary

| Tactic | Detected | Total (v18) | Coverage |
|---|---|---|---|
| Reconnaissance | **2** | 11 | 18% |
| Initial Access | **1** | 11 | 9% |
| Execution | **7** | 17 | 41% |
| Persistence | **8** | 23 | 35% |
| Privilege Escalation | **2** | 14 | 14% |
| Defense Evasion | **22** | 47 | 47% |
| Credential Access | **12** | 17 | 71% |
| Discovery | **13** | 34 | 38% |
| Lateral Movement | **4** | 9 | 44% |
| Collection | **3** | 17 | 18% |
| Command and Control | **3** | 18 | 17% |
| Exfiltration | **1** | 9 | 11% |
| Impact | **5** | 15 | 33% |

---

### Reconnaissance

| Technique | Name | Detection Source |
|---|---|---|
| `T1595` | Active Scanning | `Web Scan` |
| `T1595.002` | Vulnerability Scanning | `Tool Fingerprint` |

### Initial Access

| Technique | Name | Detection Source |
|---|---|---|
| `T1190` | Exploit Public-Facing Application | `Web Attack` |

### Execution

| Technique | Name | Detection Source |
|---|---|---|
| `T1047` | Windows Management Instrumentation | `cmd:wmic` |
| `T1059` | Command and Script Interpreter | `cmd:nc`, `cmd:ncat`, `cmd:netcat`, `cmd:perl`, +2 more |
| `T1059.001` | Command and Script Interpreter: PowerShell | `cmd:powershell`, `cmd:pwsh` |
| `T1059.003` | Command and Script Interpreter: Windows Command Shell | `cmd:cmd` |
| `T1059.004` | Unix Shell | `Shell Execution`, `cmd:bash`, `cmd:sh` |
| `T1059.005` | Command and Script Interpreter: Visual Basic | `cmd:wscript`, `cmd:cscript` |
| `T1059.006` | Python | `cmd:python`, `cmd:python3` |

### Persistence

| Technique | Name | Detection Source |
|---|---|---|
| `T1053.002` | Scheduled Task/Job: At | `cmd:at` |
| `T1053.003` | Scheduled Task/Job: Cron | `Cron Execution`, `cmd:crontab` |
| `T1053.005` | Scheduled Task/Job: Scheduled Task | `Windows Scheduled Task`, `cmd:schtasks` |
| `T1098` | Account Manipulation | `Windows Group Member Added`, `Windows Account Changed`, `cmd:usermod` |
| `T1136.001` | Create Account: Local Account | `Windows Account Created`, `cmd:useradd`, `cmd:adduser` |
| `T1505.003` | Server Software Component: Web Shell | `Web Shell` |
| `T1543.002` | Create or Modify System Process: Systemd Service | `Service Started` |
| `T1543.003` | Create or Modify System Process: Windows Service | `Windows Service Installed`, `cmd:sc` |

### Privilege Escalation

| Technique | Name | Detection Source |
|---|---|---|
| `T1134` | Access Token Manipulation | `Windows Token Rights Adjusted` |
| `T1548.003` | Abuse Elevation Control: Sudo | `Sudo Command` |

### Defense Evasion

| Technique | Name | Detection Source |
|---|---|---|
| `T1070` | Indicator Removal | `cmd:fsutil` |
| `T1070.001` | Indicator Removal: Clear Windows Event Logs | `Windows Log Cleared` |
| `T1070.002` | Indicator Removal: Clear Linux Logs | `cmd:shred`, `cmd:truncate` |
| `T1070.003` | Indicator Removal: Clear Command History | `cmd:history`, `cmd:unset` |
| `T1070.004` | Indicator Removal: File Deletion | `File Deleted` |
| `T1078` | Valid Accounts | `Accepted Password`, `Accepted Publickey`, `Audit Login`, `Admin Access`, +1 more |
| `T1078.002` | Valid Accounts: Domain Accounts | `Windows Privilege Assigned` |
| `T1112` | Modify Registry | `Windows Registry Modified`, `cmd:reg`, `cmd:regedit` |
| `T1140` | Deobfuscate/Decode Files or Information | `cmd:certutil` |
| `T1197` | BITS Jobs | `cmd:bitsadmin` |
| `T1218.001` | System Binary Proxy Execution: Compiled HTML File | `cmd:hh` |
| `T1218.003` | System Binary Proxy Execution: CMSTP | `cmd:cmstp` |
| `T1218.004` | System Binary Proxy Execution: InstallUtil | `cmd:installutil` |
| `T1218.005` | System Binary Proxy Execution: Mshta | `cmd:mshta` |
| `T1218.007` | System Binary Proxy Execution: Msiexec | `cmd:msiexec` |
| `T1218.008` | System Binary Proxy Execution: Odbcconf | `cmd:odbcconf` |
| `T1218.009` | System Binary Proxy Execution: Regasm and Regsvcs | `cmd:regasm`, `cmd:regsvcs` |
| `T1218.010` | System Binary Proxy Execution: Regsvr32 | `cmd:regsvr32` |
| `T1218.011` | System Binary Proxy Execution: Rundll32 | `cmd:rundll32` |
| `T1222` | File and Directory Permissions Modification | `cmd:chmod` |
| `T1562.002` | Impair Defenses: Disable Windows Event Logging | `cmd:auditpol`, `cmd:wevtutil` |
| `T1564.001` | Hide Artifacts: Hidden Files and Directories | `cmd:attrib` |

### Credential Access

| Technique | Name | Detection Source |
|---|---|---|
| `T1003` | OS Credential Dumping | `cmd:mimikatz` |
| `T1003.001` | OS Credential Dumping: LSASS Memory | `Windows Object Access`, `cmd:procdump` |
| `T1003.003` | OS Credential Dumping: NTDS | `cmd:ntdsutil` |
| `T1003.006` | OS Credential Dumping: DCSync | `Windows DS Object Access` |
| `T1003.008` | OS Credential Dumping: /etc/passwd and /etc/shadow | `File Access` |
| `T1110` | Brute Force | `Failed Login`, `Auth Failure`, `Audit Auth Failure`, `Windows Kerberos PreAuth Failure`, +1 more |
| `T1110.001` | Password Guessing | `Invalid User`, `Windows Logon Failure`, `cmd:hydra` |
| `T1110.002` | Brute Force: Password Cracking | `cmd:john`, `cmd:hashcat` |
| `T1552` | Unsecured Credentials | `cmd:cmdkey` |
| `T1555` | Credentials from Password Stores | `cmd:vaultcmd` |
| `T1558` | Steal or Forge Kerberos Tickets | `Windows Kerberos TGT Request` |
| `T1558.003` | Kerberoasting | `Windows Kerberos Service Ticket` |

### Discovery

| Technique | Name | Detection Source |
|---|---|---|
| `T1016` | System Network Configuration Discovery | `cmd:ifconfig`, `cmd:ip`, `cmd:ipconfig` |
| `T1018` | Remote System Discovery | `cmd:arp`, `cmd:ping`, `cmd:nbtstat` |
| `T1033` | System Owner/User Discovery | `cmd:whoami`, `cmd:id` |
| `T1046` | Network Service Scanning | `cmd:nmap`, `cmd:masscan` |
| `T1049` | System Network Connections Discovery | `cmd:netstat`, `cmd:ss` |
| `T1057` | Process Discovery | `cmd:ps`, `cmd:tasklist` |
| `T1069` | Permission Groups Discovery | `cmd:net`, `cmd:net1` |
| `T1082` | System Information Discovery | `cmd:uname`, `cmd:hostname` |
| `T1083` | File and Directory Discovery | `cmd:find`, `cmd:dir` |
| `T1087.002` | Account Discovery: Domain Account | `cmd:dsquery`, `cmd:dsget`, `cmd:adfind`, `cmd:ldifde`, +1 more |
| `T1124` | System Time Discovery | `cmd:w32tm` |
| `T1201` | Password Policy Discovery | `cmd:chage` |
| `T1482` | Domain Trust Discovery | `cmd:nltest` |

### Lateral Movement

| Technique | Name | Detection Source |
|---|---|---|
| `T1021` | Remote Services | `Windows Remote Logon`, `Windows Network Connection` |
| `T1021.002` | Remote Services: SMB/Windows Admin Shares | `Windows Share Access` |
| `T1021.004` | Remote Services: SSH | `Session Opened`, `cmd:ssh` |
| `T1550.002` | Use Alternate Authentication Material: Pass the Hash | `Windows Explicit Credential Use`, `Windows NTLM Auth` |

### Collection

| Technique | Name | Detection Source |
|---|---|---|
| `T1025` | Data from Removable Media | `USB Connected` |
| `T1115` | Clipboard Data | `cmd:clip` |
| `T1560.001` | Archive Collected Data: Archive via Utility | `cmd:tar`, `cmd:zip`, `cmd:gzip` |

### Command and Control

| Technique | Name | Detection Source |
|---|---|---|
| `T1071` | Application Layer Protocol | `Network Connection`, `cmd:socat` |
| `T1105` | Ingress Tool Transfer | `cmd:wget`, `cmd:curl` |
| `T1132.001` | Data Encoding: Standard Encoding | `cmd:base64` |

### Exfiltration

| Technique | Name | Detection Source |
|---|---|---|
| `T1048` | Exfiltration Over Alternative Protocol | `cmd:scp`, `cmd:rsync`, `cmd:ftp`, `cmd:sftp` |

### Impact

| Technique | Name | Detection Source |
|---|---|---|
| `T1485` | Data Destruction | `cmd:cipher`, `cmd:sdelete` |
| `T1489` | Service Stop | `Service Stopped` |
| `T1490` | Inhibit System Recovery | `cmd:vssadmin`, `cmd:bcdedit` |
| `T1529` | System Shutdown/Reboot | `cmd:shutdown` |
| `T1531` | Account Access Removal | `Windows Account Deleted`, `cmd:passwd` |

