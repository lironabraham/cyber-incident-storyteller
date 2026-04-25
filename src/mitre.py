"""
Local MITRE ATT&CK mapping for known event types and suspicious commands.

No external API calls — purely dictionary-based for offline/air-gapped use.
"""

MITRE_MAP: dict[str, tuple[str | None, str | None]] = {
    # ── auth.log ───────────────────────────────────────────────────────────────
    'Failed Login':       ('T1110',     'Brute Force'),
    'Invalid User':       ('T1110.001', 'Password Guessing'),
    'Auth Failure':       ('T1110',     'Brute Force'),
    'Accepted Password':  ('T1078',     'Valid Accounts'),
    'Accepted Publickey': ('T1078',     'Valid Accounts'),
    'Session Opened':     ('T1021.004', 'Remote Services: SSH'),
    'Sudo Command':       ('T1548.003', 'Abuse Elevation Control: Sudo'),
    'Connection Closed':  (None, None),
    'Session Closed':     (None, None),
    'Disconnected':       (None, None),
    # ── syslog ────────────────────────────────────────────────────────────────
    'Service Started':    ('T1543.002', 'Create or Modify System Process: Systemd Service'),
    'Service Stopped':    ('T1489',     'Service Stop'),
    'Service Failed':     (None, None),
    'Cron Execution':     ('T1053.003', 'Scheduled Task/Job: Cron'),
    'OOM Kill':           (None, None),
    'USB Connected':      ('T1025',     'Data from Removable Media'),
    # ── auditd ────────────────────────────────────────────────────────────────
    'Process Execution':  (None, None),   # resolved per-command via map_command()
    'Audit Login':        ('T1078',     'Valid Accounts'),
    'Audit Auth Failure': ('T1110',     'Brute Force'),
    'Shell Execution':    ('T1059.004', 'Unix Shell'),
    'File Access':        ('T1003.008', 'OS Credential Dumping: /etc/passwd and /etc/shadow'),
    # ── web access ────────────────────────────────────────────────────────────
    'Web Request':        (None, None),
    'Web Scan':           ('T1595',     'Active Scanning'),
    'Web Attack':         ('T1190',     'Exploit Public-Facing Application'),
    'Admin Access':       ('T1078',     'Valid Accounts'),
    'Web Shell':          ('T1505.003', 'Server Software Component: Web Shell'),
    'Tool Fingerprint':   ('T1595.002', 'Vulnerability Scanning'),
    # ── sysmon_linux ──────────────────────────────────────────────────────────
    'Network Connection': ('T1071',     'Application Layer Protocol'),
    'File Deleted':       ('T1070.004', 'Indicator Removal: File Deletion'),
    # ── Windows EVTX ──────────────────────────────────────────────────────────
    'Windows Logon Success':           ('T1078',     'Valid Accounts'),
    'Windows Remote Logon':            ('T1021',     'Remote Services'),
    'Windows Logon Failure':           ('T1110.001', 'Brute Force: Password Guessing'),
    'Windows Explicit Credential Use': ('T1550.002', 'Use Alternate Authentication Material: Pass the Hash'),
    'Windows Privilege Assigned':      ('T1078.002', 'Valid Accounts: Domain Accounts'),
    'Windows Process Creation':        (None, None),   # resolved per-command via map_command()
    'Windows Service Installed':       ('T1543.003', 'Create or Modify System Process: Windows Service'),
    'Windows Scheduled Task':          ('T1053.005', 'Scheduled Task/Job: Scheduled Task'),
    'Windows Account Created':         ('T1136.001', 'Create Account: Local Account'),
    'Windows Group Member Added':      ('T1098',     'Account Manipulation'),
    'Windows Kerberos TGT Request':    ('T1558',     'Steal or Forge Kerberos Tickets'),
    'Windows Kerberos Service Ticket': ('T1558.003', 'Kerberoasting'),
    'Windows Kerberos PreAuth Failure':('T1110',     'Brute Force'),
    'Windows Share Access':            ('T1021.002', 'Remote Services: SMB/Windows Admin Shares'),
    # ── catch-all ─────────────────────────────────────────────────────────────
    'Other':              (None, None),
}

SUSPICIOUS_COMMANDS: dict[str, tuple[str, str]] = {
    # ── Ingress / C2 ──────────────────────────────────────────────────────────
    'wget':      ('T1105',     'Ingress Tool Transfer'),
    'curl':      ('T1105',     'Ingress Tool Transfer'),
    # ── Execution ─────────────────────────────────────────────────────────────
    'nc':        ('T1059',     'Command and Script Interpreter'),
    'ncat':      ('T1059',     'Command and Script Interpreter'),
    'netcat':    ('T1059',     'Command and Script Interpreter'),
    'socat':     ('T1071',     'Application Layer Protocol'),
    'python':    ('T1059.006', 'Python'),
    'python3':   ('T1059.006', 'Python'),
    'perl':      ('T1059',     'Command and Script Interpreter'),
    'ruby':      ('T1059',     'Command and Script Interpreter'),
    'php':       ('T1059',     'Command and Script Interpreter'),
    'bash':      ('T1059.004', 'Unix Shell'),
    'sh':        ('T1059.004', 'Unix Shell'),
    # ── Defense Evasion ───────────────────────────────────────────────────────
    'shred':     ('T1070.002', 'Indicator Removal: Clear Linux Logs'),
    'truncate':  ('T1070.002', 'Indicator Removal: Clear Linux Logs'),
    'history':   ('T1070.003', 'Indicator Removal: Clear Command History'),
    'unset':     ('T1070.003', 'Indicator Removal: Clear Command History'),
    'chmod':     ('T1222',     'File and Directory Permissions Modification'),
    # ── Discovery ─────────────────────────────────────────────────────────────
    'whoami':    ('T1033',     'System Owner/User Discovery'),
    'id':        ('T1033',     'System Owner/User Discovery'),
    'uname':     ('T1082',     'System Information Discovery'),
    'hostname':  ('T1082',     'System Information Discovery'),
    'ps':        ('T1057',     'Process Discovery'),
    'netstat':   ('T1049',     'System Network Connections Discovery'),
    'ss':        ('T1049',     'System Network Connections Discovery'),
    'ifconfig':  ('T1016',     'System Network Configuration Discovery'),
    'ip':        ('T1016',     'System Network Configuration Discovery'),
    'find':      ('T1083',     'File and Directory Discovery'),
    'nmap':      ('T1046',     'Network Service Scanning'),
    'masscan':   ('T1046',     'Network Service Scanning'),
    # ── Lateral Movement / Exfiltration ───────────────────────────────────────
    'ssh':       ('T1021.004', 'Remote Services: SSH'),
    'scp':       ('T1048',     'Exfiltration Over Alternative Protocol'),
    'rsync':     ('T1048',     'Exfiltration Over Alternative Protocol'),
    'ftp':       ('T1048',     'Exfiltration Over Alternative Protocol'),
    'sftp':      ('T1048',     'Exfiltration Over Alternative Protocol'),
    # ── Archive / Staging ─────────────────────────────────────────────────────
    'tar':       ('T1560.001', 'Archive Collected Data: Archive via Utility'),
    'zip':       ('T1560.001', 'Archive Collected Data: Archive via Utility'),
    'gzip':      ('T1560.001', 'Archive Collected Data: Archive via Utility'),
    'base64':    ('T1132.001', 'Data Encoding: Standard Encoding'),
    # ── Persistence ───────────────────────────────────────────────────────────
    'crontab':   ('T1053.003', 'Scheduled Task/Job: Cron'),
    'at':        ('T1053.001', 'Scheduled Task/Job: At'),
    'useradd':   ('T1136.001', 'Create Account: Local Account'),
    'adduser':   ('T1136.001', 'Create Account: Local Account'),
    'usermod':   ('T1098',     'Account Manipulation'),
    'passwd':    ('T1531',     'Account Access Removal'),
    # ── Credential Access ─────────────────────────────────────────────────────
    'john':      ('T1110.002', 'Brute Force: Password Cracking'),
    'hashcat':   ('T1110.002', 'Brute Force: Password Cracking'),
    'hydra':     ('T1110.001', 'Brute Force: Password Guessing'),
    # ── Windows execution ─────────────────────────────────────────────────────
    'powershell':('T1059.001', 'Command and Script Interpreter: PowerShell'),
    'pwsh':      ('T1059.001', 'Command and Script Interpreter: PowerShell'),
    'cmd':       ('T1059.003', 'Command and Script Interpreter: Windows Command Shell'),
    'wscript':   ('T1059.005', 'Command and Script Interpreter: Visual Basic'),
    'cscript':   ('T1059.005', 'Command and Script Interpreter: Visual Basic'),
    'mshta':     ('T1218.005', 'System Binary Proxy Execution: Mshta'),
    'rundll32':  ('T1218.011', 'System Binary Proxy Execution: Rundll32'),
    'regsvr32':  ('T1218.010', 'System Binary Proxy Execution: Regsvr32'),
    'certutil':  ('T1140',     'Deobfuscate/Decode Files or Information'),
    'bitsadmin': ('T1197',     'BITS Jobs'),
    'wmic':      ('T1047',     'Windows Management Instrumentation'),
    # ── Windows persistence ───────────────────────────────────────────────────
    'schtasks':  ('T1053.005', 'Scheduled Task/Job: Scheduled Task'),
    'sc':        ('T1543.003', 'Create or Modify System Process: Windows Service'),
    'reg':       ('T1112',     'Modify Registry'),
    'regedit':   ('T1112',     'Modify Registry'),
    'net':       ('T1069',     'Permission Groups Discovery'),
    'net1':      ('T1069',     'Permission Groups Discovery'),
    # ── Windows credential access ─────────────────────────────────────────────
    'mimikatz':  ('T1003',     'OS Credential Dumping'),
    'procdump':  ('T1003.001', 'OS Credential Dumping: LSASS Memory'),
    'ntdsutil':  ('T1003.003', 'OS Credential Dumping: NTDS'),
    # ── Windows defense evasion / impact ──────────────────────────────────────
    'vssadmin':  ('T1490',     'Inhibit System Recovery'),
    'bcdedit':   ('T1490',     'Inhibit System Recovery'),
    'fsutil':    ('T1070',     'Indicator Removal'),
}


def map_event(event_type: str) -> tuple[str | None, str | None]:
    """Return (mitre_id, technique_name) for a known event_type, else (None, None)."""
    return MITRE_MAP.get(event_type, (None, None))


def map_command(command: str) -> tuple[str | None, str | None]:
    """Return (mitre_id, technique_name) for a command string, else (None, None).

    Matches on the base command name, ignoring path prefixes and arguments.
    Handles both Unix (/usr/bin/wget) and Windows (C:\\Windows\\System32\\cmd.exe) paths.
    """
    if not command or not command.strip():
        return (None, None)
    base = command.strip().split()[0]
    base = base.replace('\\', '/').split('/')[-1].lower()
    for ext in ('.exe', '.com', '.bat', '.cmd', '.scr'):
        if base.endswith(ext):
            base = base[: -len(ext)]
            break
    return SUSPICIOUS_COMMANDS.get(base, (None, None))
