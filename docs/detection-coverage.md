# Detection Coverage

Every event type, Windows EventID, MITRE technique, and detection pathway the tool currently supports.

---

## Windows EventIDs (EVTX parser)

| EventID | Channel | Event Type | MITRE Technique |
|---|---|---|---|
| 4624 | Security | Windows Logon Success (type 3/10 → Remote Logon) | T1078 / T1021 |
| 4625 | Security | Windows Logon Failure | T1110.001 |
| 4648 | Security | Windows Explicit Credential Use | T1550.002 |
| 4672 | Security | Windows Privilege Assigned | T1078.002 |
| 4688 | Security | Windows Process Creation | mapped per command |
| 4697 | Security | Windows Service Installed | T1543.003 |
| 4698 | Security | Windows Scheduled Task (created) | T1053.005 |
| 4699 | Security | Windows Scheduled Task (deleted) | T1053.005 |
| 4702 | Security | Windows Scheduled Task (modified) | T1053.005 |
| 4720 | Security | Windows Account Created | T1136.001 |
| 4728 | Security | Windows Group Member Added (global) | T1098 |
| 4732 | Security | Windows Group Member Added (local) | T1098 |
| 4768 | Security | Windows Kerberos TGT Request | T1558 |
| 4769 | Security | Windows Kerberos Service Ticket | T1558.003 |
| 4771 | Security | Windows Kerberos PreAuth Failure | T1110 |
| 5145 | Security | Windows Share Access | T1021.002 |
| 7045 | System | Windows Service Installed | T1543.003 |
| 4689 | Security | Process Terminated | *(skipped — noise)* |

---

## Linux Event Types

### auth.log

| Event Type | Source pattern | MITRE Technique |
|---|---|---|
| Failed Login | `Failed password for ...` | T1110 Brute Force |
| Invalid User | `Invalid user ... from` | T1110.001 Password Guessing |
| Auth Failure | `pam_unix(...): authentication failure` | T1110 Brute Force |
| Accepted Password | `Accepted password for ...` | T1078 Valid Accounts |
| Accepted Publickey | `Accepted publickey for ...` | T1078 Valid Accounts |
| Session Opened | `session opened for user ...` | T1021.004 SSH |
| Sudo Command | `sudo: ... COMMAND=...` | T1548.003 Sudo |

### syslog

| Event Type | Source pattern | MITRE Technique |
|---|---|---|
| Service Started | `systemd: Started ...` | T1543.002 Systemd Service |
| Service Stopped | `systemd: Stopped ...` | T1489 Service Stop |
| Service Failed | `systemd: Failed ...` | — |
| Cron Execution | `CRON: ... CMD (...)` | T1053.003 Cron |
| OOM Kill | `kernel: Out of memory: Kill process` | — |
| USB Connected | `kernel: usb ...: new USB device found` | T1025 Removable Media |

### audit.log

| Event Type | Source pattern | MITRE Technique |
|---|---|---|
| Process Execution | `type=EXECVE a0="..."` | mapped per command |
| Shell Execution | `type=SYSCALL comm="bash/sh"` | T1059.004 Unix Shell |
| File Access | `type=OPEN name="/etc/shadow"` | T1003.008 /etc/shadow |
| Audit Login | `type=USER_LOGIN res=success` | T1078 Valid Accounts |
| Audit Auth Failure | `type=USER_AUTH res=failed` | T1110 Brute Force |

### web_access (nginx / Apache)

| Event Type | Detection logic | MITRE Technique |
|---|---|---|
| Web Shell | POST to `.php`/`.asp`/`.jsp` returning 200 | T1505.003 Web Shell |
| Web Attack | SQLi/XSS/traversal patterns in URI | T1190 Exploit Public-Facing |
| Web Scan | Rapid sequential 404s from one IP | T1595 Active Scanning |
| Tool Fingerprint | `sqlmap`/`nikto`/`masscan` in User-Agent | T1595.002 Vulnerability Scan |
| Admin Access | Requests to `/admin`, `/wp-admin`, `/.env` | T1078 Valid Accounts |

### sysmon_linux (Microsoft Sysmon for Linux)

| Sysmon EventID | Event Type | MITRE Technique |
|---|---|---|
| 1 | Process Created | mapped per command |
| 3 | Network Connection | T1071 Application Layer Protocol |
| 11 | File Created | — |
| 23 | File Deleted | T1070.004 File Deletion |
| 5 | Process Terminated | *(skipped — noise)* |

---

## Command-Level MITRE Mapping (53 commands)

`map_command()` strips path prefixes and `.exe`/`.com` extensions before lookup — works on both
Unix (`/usr/bin/wget`) and Windows (`C:\Windows\System32\cmd.exe`) process paths.

### Ingress / C2

| Command | Technique | Name |
|---|---|---|
| `wget`, `curl` | T1105 | Ingress Tool Transfer |
| `socat` | T1071 | Application Layer Protocol |

### Execution

| Command | Technique | Name |
|---|---|---|
| `nc`, `ncat`, `netcat` | T1059 | Command and Script Interpreter |
| `python`, `python3` | T1059.006 | Python |
| `perl`, `ruby`, `php` | T1059 | Command and Script Interpreter |
| `bash`, `sh` | T1059.004 | Unix Shell |
| `powershell`, `pwsh` | T1059.001 | PowerShell |
| `cmd` | T1059.003 | Windows Command Shell |
| `wscript`, `cscript` | T1059.005 | Visual Basic |
| `mshta` | T1218.005 | Mshta |
| `rundll32` | T1218.011 | Rundll32 |
| `regsvr32` | T1218.010 | Regsvr32 |
| `wmic` | T1047 | Windows Management Instrumentation |

### Defense Evasion

| Command | Technique | Name |
|---|---|---|
| `shred`, `truncate` | T1070.002 | Clear Linux Logs |
| `history`, `unset` | T1070.003 | Clear Command History |
| `chmod` | T1222 | File and Directory Permissions Modification |
| `certutil` | T1140 | Deobfuscate/Decode Files or Information |
| `vssadmin`, `bcdedit` | T1490 | Inhibit System Recovery |
| `fsutil` | T1070 | Indicator Removal |

### Discovery

| Command | Technique | Name |
|---|---|---|
| `whoami`, `id` | T1033 | System Owner/User Discovery |
| `uname`, `hostname` | T1082 | System Information Discovery |
| `ps` | T1057 | Process Discovery |
| `netstat`, `ss` | T1049 | System Network Connections Discovery |
| `ifconfig`, `ip` | T1016 | System Network Configuration Discovery |
| `find` | T1083 | File and Directory Discovery |
| `nmap`, `masscan` | T1046 | Network Service Scanning |
| `net`, `net1` | T1069 | Permission Groups Discovery |

### Lateral Movement / Exfiltration

| Command | Technique | Name |
|---|---|---|
| `ssh` | T1021.004 | Remote Services: SSH |
| `scp`, `rsync`, `ftp`, `sftp` | T1048 | Exfiltration Over Alternative Protocol |

### Archive / Staging

| Command | Technique | Name |
|---|---|---|
| `tar`, `zip`, `gzip` | T1560.001 | Archive Collected Data via Utility |
| `base64` | T1132.001 | Data Encoding: Standard Encoding |

### Persistence

| Command | Technique | Name |
|---|---|---|
| `crontab` | T1053.003 | Scheduled Task/Job: Cron |
| `at` | T1053.001 | Scheduled Task/Job: At |
| `useradd`, `adduser` | T1136.001 | Create Account: Local Account |
| `usermod` | T1098 | Account Manipulation |
| `passwd` | T1531 | Account Access Removal |
| `schtasks` | T1053.005 | Scheduled Task |
| `sc` | T1543.003 | Windows Service |
| `reg`, `regedit` | T1112 | Modify Registry |
| `bitsadmin` | T1197 | BITS Jobs |

### Credential Access

| Command | Technique | Name |
|---|---|---|
| `john`, `hashcat` | T1110.002 | Brute Force: Password Cracking |
| `hydra` | T1110.001 | Brute Force: Password Guessing |
| `mimikatz` | T1003 | OS Credential Dumping |
| `procdump` | T1003.001 | LSASS Memory |
| `ntdsutil` | T1003.003 | NTDS |

---

## Attack Chain Types

The hunter classifies each detected actor into one of five chain types:

| Chain Type | Meaning | `compromised` |
|---|---|---|
| `brute_force` | Many failures, no successful logon | `False` |
| `credential_stuffing` | Failures followed by a successful logon | `True` |
| `post_exploitation` | Success + post-exploit actions (process creation, shell, service) | `True` |
| `unauthorized_access` | Successful logon with no prior failures (silent compromise) | `True` |
| `lateral_movement` | High-value persistence/LM events with no logon evidence | `True` |

---

## Detection Pathways

`build_attack_chains()` runs four passes over the full event list:

| Pass | Trigger | Catches |
|---|---|---|
| 1 — Brute-Force | ≥5 failures from same IP | SSH brute force, password spray |
| 2 — Silent Access | Successful logon, zero prior failures from same IP | NTLM relay, pass-the-hash, golden/silver ticket |
| 3 — Probe | ≥3 Kerberos TGT/service-ticket requests from same IP | Kerberoasting, AS-REP roasting, Kerberos password spray |
| 4 — High-Value Sweep | Service installs, scheduled tasks, group changes, share access | Persistence and lateral movement with no network attribution |

Events not claimed by Passes 1–3 fall to Pass 4, which groups them by user account
(or anonymous bucket) and produces lateral-movement chains.
