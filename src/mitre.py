"""
Local MITRE ATT&CK mapping for known event types and suspicious commands.

No external API calls — purely dictionary-based for offline/air-gapped use.

This module serves as a re-export shim for backward compatibility:
- MITRE_MAP and map_event() remain here (event type → technique)
- SUSPICIOUS_COMMANDS and map_command() are re-exported from lolbins module
- SUSPICIOUS_DLLS is re-exported from signature_filters module
"""

# Re-export command mapping and DLL filters for backward compatibility
from lolbins import SUSPICIOUS_COMMANDS, map_command
from signature_filters import SUSPICIOUS_DLLS

__all__ = ['MITRE_MAP', 'map_event', 'SUSPICIOUS_COMMANDS', 'map_command', 'SUSPICIOUS_DLLS']

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
    'Windows NewCredentials Logon':    ('T1078',     'Valid Accounts'),
    'Windows Local Relay Logon':       ('T1021',     'Remote Services'),
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
    # ── Windows EVTX — Wave 2 ─────────────────────────────────────────────────
    'Windows Object Access':          ('T1003.001', 'OS Credential Dumping: LSASS Memory'),
    'Windows NTLM Auth':              ('T1550.002', 'Use Alternate Authentication Material: Pass the Hash'),
    'Windows Account Lockout':        ('T1110',     'Brute Force'),
    'Windows DS Object Access':       ('T1003.006', 'OS Credential Dumping: DCSync'),
    'Windows Log Cleared':            ('T1070.001', 'Indicator Removal: Clear Windows Event Logs'),
    'Windows Registry Modified':      ('T1112',     'Modify Registry'),
    'Windows Token Rights Adjusted':  ('T1134',     'Access Token Manipulation'),
    'Windows Account Deleted':        ('T1531',     'Account Access Removal'),
    'Windows Account Changed':        ('T1098',     'Account Manipulation'),
    'Windows Network Connection':     ('T1021',     'Remote Services'),
    # ── Windows Sysmon EVTX ───────────────────────────────────────────────────
    'Sysmon Process Created':        (None, None),     # resolved per-command via map_command()
    'Sysmon Network Connection':     ('T1071',     'Application Layer Protocol'),
    'Sysmon Image Loaded':           ('T1055.001', 'Process Injection: DLL Injection'),
    'Sysmon Remote Thread':          ('T1055',     'Process Injection'),
    'Sysmon Process Access':         ('T1003.001', 'OS Credential Dumping: LSASS Memory'),
    'Sysmon File Created':           (None, None),     # context-dependent
    'Sysmon Registry Key Modified':  ('T1547.001', 'Boot or Logon Autostart: Registry Run Keys'),
    'Sysmon Registry Value Modified':('T1547.001', 'Boot or Logon Autostart: Registry Run Keys'),
    'Sysmon Named Pipe Created':     ('T1559.001', 'Inter-Process Communication: COM'),
    'Sysmon Named Pipe Connected':   ('T1559.001', 'Inter-Process Communication: COM'),
    'Sysmon WMI Subscription':       ('T1546.003', 'Event Triggered Execution: WMI Event Subscription'),
    # ── PowerShell script-block / module logging ──────────────────────────────
    'Windows PowerShell Execution':   ('T1059.001', 'Command and Script Interpreter: PowerShell'),
    'Windows PowerShell Script Block':('T1059.001', 'Command and Script Interpreter: PowerShell'),
    # ── BITS persistence ──────────────────────────────────────────────────────
    'Windows BITS Job':               ('T1197',     'BITS Jobs'),
    # ── WinRM remote shell ────────────────────────────────────────────────────
    'Windows WinRM Activity':         ('T1021.006', 'Remote Services: WinRM'),
    # ── DCOM lateral movement ─────────────────────────────────────────────────
    'Windows DCOM Access Denied':     ('T1021.003', 'Remote Services: Distributed Component Object Model'),
    # ── SID History injection (T1178 / T1134.005) ─────────────────────────────
    'Windows SID History Modified':   ('T1134.005', 'Access Token Manipulation: SID-History Injection'),
    # ── catch-all ─────────────────────────────────────────────────────────────
    'Other':              (None, None),
}


def map_event(event_type: str) -> tuple[str | None, str | None]:
    """Return (mitre_id, technique_name) for a known event_type, else (None, None)."""
    return MITRE_MAP.get(event_type, (None, None))
