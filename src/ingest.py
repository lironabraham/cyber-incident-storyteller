"""
Multi-parser ingestion engine.

Wraps the low-level parsers, normalizes output into StandardEvent objects,
computes context-aware severity, stores a SHA-256 integrity hash, and
serializes processed events to data/processed/.

Public API
----------
ingest(log_path, fmt, processed_dir)  -> list[StandardEvent]
verify_integrity(log_path, processed_dir) -> bool
"""

import hashlib
import json
import re
import sys
from datetime import timezone
from pathlib import Path

import pandas as pd

# Ensure src/ is importable when running as a script
sys.path.insert(0, str(Path(__file__).parent))

from mitre import map_event, map_command
from schema import StandardEvent, make_event_id, to_json
from parser import parse_log

# ── Constants ──────────────────────────────────────────────────────────────────

_SUCCESS_TYPES = {
    'Accepted Password', 'Accepted Publickey', 'Audit Login',
    'Windows Logon Success', 'Windows Remote Logon',
}
_SEVERITY_ORDER = ('info', 'low', 'medium', 'high', 'critical')

_DEFAULT_PROCESSED_DIR = Path(__file__).parent.parent / 'data' / 'processed'

_PID_RE = re.compile(r'\w+\[(\d+)\]')
_COMMAND_RE = re.compile(r'COMMAND=(.+)$')


# ── Severity computation ───────────────────────────────────────────────────────

def _compute_severity(
    event_type: str,
    source_ip: str | None,
    ip_failure_counts: dict[str, int],
) -> str:
    """Context-aware severity — a single failed login ≠ threat; 20 from one IP = high."""
    failures = ip_failure_counts.get(source_ip, 0) if source_ip else 0

    if event_type in _SUCCESS_TYPES:
        # Successful login: critical if attacker had prior failures (credential stuffing)
        return 'critical' if failures >= 5 else 'info'

    if event_type == 'Failed Login':
        if failures >= 20:
            return 'high'    # active brute-force campaign
        if failures >= 5:
            return 'medium'  # threshold crossed
        return 'low'         # background noise

    if event_type == 'Sudo Command':
        return 'high'

    if event_type in ('Auth Failure', 'Invalid User'):
        return 'medium'

    if event_type in ('Session Opened', 'Session Closed', 'Connection Closed', 'Disconnected'):
        return 'info'

    # ── syslog ────────────────────────────────────────────────────────────────
    if event_type == 'Cron Execution':
        return 'low'
    if event_type == 'Service Stopped':
        return 'medium'
    if event_type in ('Service Started', 'Service Failed', 'OOM Kill'):
        return 'low'
    if event_type == 'USB Connected':
        return 'medium'

    # ── auditd ────────────────────────────────────────────────────────────────
    if event_type == 'Process Execution':
        # Severity depends on what command was run (stored in user field by audit parser)
        return 'info'   # ingest() upgrades this via _upgrade_process_severity()
    if event_type == 'Audit Auth Failure':
        return 'medium'
    if event_type == 'Audit Login':
        return 'info'
    if event_type == 'Shell Execution':
        return 'high'
    if event_type == 'File Access':
        return 'high'

    # ── web access ────────────────────────────────────────────────────────────
    if event_type == 'Web Shell':
        return 'critical'
    if event_type == 'Web Attack':
        return 'high'
    if event_type in ('Web Scan', 'Tool Fingerprint', 'Admin Access'):
        return 'medium'
    if event_type == 'Web Request':
        return 'info'

    # ── sysmon_linux ──────────────────────────────────────────────────────────
    if event_type == 'Network Connection':
        return 'low'
    if event_type == 'File Deleted':
        return 'medium'

    # ── Windows EVTX ──────────────────────────────────────────────────────────
    if event_type in ('Windows NewCredentials Logon', 'Windows Local Relay Logon'):
        return 'high'   # token impersonation / self-relay — always suspicious
    if event_type == 'Windows Logon Failure':
        if failures >= 20:
            return 'high'
        if failures >= 5:
            return 'medium'
        return 'low'
    if event_type == 'Windows Explicit Credential Use':
        return 'high'
    if event_type == 'Windows Privilege Assigned':
        return 'medium'
    if event_type == 'Windows Process Creation':
        return 'info'   # upgraded via map_command() in ingest()
    if event_type in ('Windows Service Installed', 'Windows Account Created'):
        return 'high'
    if event_type in ('Windows Scheduled Task', 'Windows Group Member Added'):
        return 'medium'
    if event_type == 'Windows Kerberos PreAuth Failure':
        return 'medium'
    if event_type in ('Windows Kerberos TGT Request', 'Windows Kerberos Service Ticket'):
        return 'low'
    if event_type == 'Windows Share Access':
        return 'low'

    # ── Windows new channel types ─────────────────────────────────────────────
    if event_type in ('Windows PowerShell Script Block', 'Windows PowerShell Execution'):
        return 'high'   # Script-block logging fires on obfuscated / suspicious scripts
    if event_type == 'Windows BITS Job':
        return 'high'   # BITS used for staging / C2 transfer
    if event_type == 'Windows WinRM Activity':
        return 'medium'
    if event_type == 'Windows DCOM Access Denied':
        return 'low'    # common DCOM noise; elevated when lateral movement is suspected
    if event_type == 'Windows SID History Modified':
        return 'high'   # T1134.005 — privilege escalation via SID injection

    # ── Windows Sysmon EVTX ───────────────────────────────────────────────────
    if event_type == 'Sysmon Process Access':
        return 'critical'   # LSASS memory read — noise filtered in sysmon_evtx.py
    if event_type in ('Sysmon Remote Thread', 'Sysmon WMI Subscription'):
        return 'high'
    if event_type in ('Sysmon Image Loaded', 'Sysmon Registry Key Modified',
                      'Sysmon Registry Value Modified', 'Sysmon Named Pipe Created',
                      'Sysmon Named Pipe Connected'):
        return 'medium'
    if event_type == 'Sysmon Network Connection':
        return 'low'
    if event_type in ('Sysmon Process Created', 'Sysmon File Created'):
        return 'info'   # Sysmon Process Created upgraded via map_command() in ingest()

    return 'low'


# ── Human-readable action summary ─────────────────────────────────────────────

def _action_taken(event_type: str, user: str | None, ip: str | None, raw: str) -> str:
    u = user or 'unknown'
    s = ip or 'unknown'

    if event_type == 'Failed Login':
        return f"Failed login attempt for user '{u}' from {s}"
    if event_type == 'Accepted Password':
        return f"Successful password authentication for '{u}' from {s}"
    if event_type == 'Accepted Publickey':
        return f"Successful publickey authentication for '{u}' from {s}"
    if event_type == 'Invalid User':
        return f"Login attempt for non-existent user '{u}' from {s}"
    if event_type == 'Session Opened':
        return f"Interactive session opened for user '{u}'"
    if event_type == 'Session Closed':
        return f"Session closed for user '{u}'"
    if event_type == 'Auth Failure':
        return f"PAM authentication failure for user '{u}'"
    if event_type == 'Sudo Command':
        cmd_m = _COMMAND_RE.search(raw)
        cmd = cmd_m.group(1).strip() if cmd_m else 'unknown'
        return f"Sudo command by '{u}': {cmd}"
    if event_type in ('Connection Closed', 'Disconnected'):
        return f"{event_type} from {s}"
    # ── syslog ────────────────────────────────────────────────────────────────
    if event_type == 'Cron Execution':
        return f"Cron job executed by '{u}'"
    if event_type in ('Service Started', 'Service Stopped', 'Service Failed'):
        return f"{event_type}: see raw log"
    if event_type == 'USB Connected':
        return "USB device connected to host"
    if event_type == 'OOM Kill':
        return "Kernel OOM killer triggered — process terminated"
    # ── auditd ────────────────────────────────────────────────────────────────
    if event_type == 'Process Execution':
        # auditd EXECVE stores the command (a0) in the user field
        return f"Process executed: {u}"
    if event_type == 'Audit Login':
        return f"Login recorded by auditd for '{u}' from {s}"
    if event_type == 'Audit Auth Failure':
        return f"Authentication failure recorded by auditd for '{u}'"
    if event_type == 'Shell Execution':
        return f"Interactive shell spawned by '{u}'"
    if event_type == 'File Access':
        return f"Sensitive file accessed by '{u}'"
    # ── web access ────────────────────────────────────────────────────────────
    if event_type == 'Web Shell':
        return f"Possible web shell access from {s}"
    if event_type == 'Web Attack':
        return f"Attack pattern detected in request from {s}"
    if event_type == 'Web Scan':
        return f"Directory/path scanning from {s}"
    if event_type == 'Tool Fingerprint':
        return f"Attack tool fingerprint detected from {s}"
    if event_type == 'Admin Access':
        return f"Admin panel access from {s}"
    if event_type == 'Web Request':
        return f"Web request from {s}"
    # ── Windows new channel types ─────────────────────────────────────────────
    if event_type == 'Windows PowerShell Script Block':
        return f"PowerShell script block logged for '{u}'"
    if event_type == 'Windows PowerShell Execution':
        return f"PowerShell execution recorded for '{u}'"
    if event_type == 'Windows BITS Job':
        return f"BITS transfer job created: {u}"
    if event_type == 'Windows WinRM Activity':
        return f"WinRM remote shell activity for '{u}'"
    if event_type == 'Windows DCOM Access Denied':
        return f"DCOM access denied for '{u}'"
    if event_type == 'Windows SID History Modified':
        return f"SID History modified on account '{u}' — possible privilege escalation"
    # ── sysmon_linux ──────────────────────────────────────────────────────────
    if event_type == 'Network Connection':
        return f"Outbound network connection to {s}"
    if event_type == 'File Deleted':
        return f"File deleted by process (possible indicator removal)"
    # ── Windows EVTX ──────────────────────────────────────────────────────────
    if event_type == 'Windows Logon Success':
        return f"Windows interactive logon for '{u}'"
    if event_type == 'Windows Remote Logon':
        return f"Windows remote/network logon for '{u}' from {s}"
    if event_type == 'Windows NewCredentials Logon':
        return f"NewCredentials logon (LogonType 9) — token impersonation for '{u}'"
    if event_type == 'Windows Local Relay Logon':
        return f"Local relay logon for '{u}' — possible Kerberos/NTLM self-relay attack"
    if event_type == 'Windows Logon Failure':
        return f"Windows logon failure for '{u}' from {s}"
    if event_type == 'Windows Explicit Credential Use':
        return f"Explicit credential use (pass-the-hash indicator) for '{u}' targeting {s}"
    if event_type == 'Windows Privilege Assigned':
        return f"Special privileges assigned to '{u}' (admin token)"
    if event_type == 'Windows Process Creation':
        return f"Process created: {u}"   # u holds command line (stored in user field)
    if event_type == 'Windows Service Installed':
        return f"New Windows service installed by '{u}'"
    if event_type == 'Windows Scheduled Task':
        return f"Scheduled task created or modified by '{u}'"
    if event_type == 'Windows Account Created':
        return f"Windows account created: '{u}'"
    if event_type == 'Windows Group Member Added':
        return f"User '{u}' added to privileged group"
    if event_type in ('Windows Kerberos TGT Request', 'Windows Kerberos Service Ticket'):
        return f"Kerberos ticket request for '{u}' from {s}"
    if event_type == 'Windows Kerberos PreAuth Failure':
        return f"Kerberos pre-authentication failure for '{u}' from {s}"
    if event_type == 'Windows Share Access':
        return f"Windows network share access from {s}"
    return event_type


# ── SHA-256 integrity ──────────────────────────────────────────────────────────

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


# ── Public API ─────────────────────────────────────────────────────────────────

def ingest(
    log_path: str | Path,
    fmt: str = 'auth_log',
    processed_dir: Path | None = None,
) -> list[StandardEvent]:
    """
    Parse a log file and return a list of StandardEvent objects.

    Side effects (written to processed_dir):
      - <stem>.sha256  — SHA-256 hash of the original log
      - <stem>.json    — serialized StandardEvent list

    The original log file is never modified.
    """
    log_path = Path(log_path)
    if processed_dir is None:
        processed_dir = _DEFAULT_PROCESSED_DIR
    processed_dir = Path(processed_dir)
    processed_dir.mkdir(parents=True, exist_ok=True)

    # Store integrity hash before any processing.
    # Use a collision-safe key: stem + 8-char hash of the resolved absolute path,
    # so two files named 'auth.log' from different directories get distinct records.
    path_tag = hashlib.sha256(str(log_path.resolve()).encode()).hexdigest()[:8]
    safe_stem = f'{log_path.stem}_{path_tag}'
    hash_val = _sha256(log_path)
    (processed_dir / f'{safe_stem}.sha256').write_text(hash_val, encoding='utf-8')

    df = parse_log(log_path, fmt=fmt)

    # First pass: tally failures per IP for context-aware severity
    ip_failure_counts: dict[str, int] = {}
    for _, row in df.iterrows():
        if row['event_type'] in (
            'Failed Login', 'Invalid User', 'Audit Auth Failure',
            'Windows Logon Failure', 'Windows Kerberos PreAuth Failure',
        ):
            ip = row.get('source_ip')
            if ip and pd.notna(ip):
                ip_failure_counts[ip] = ip_failure_counts.get(ip, 0) + 1

    # Second pass: build StandardEvent objects
    events: list[StandardEvent] = []
    for _, row in df.iterrows():
        ts = row['timestamp']
        if pd.isna(ts):
            continue

        if hasattr(ts, 'to_pydatetime'):
            ts = ts.to_pydatetime()
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        source_ip = row['source_ip'] if pd.notna(row.get('source_ip')) else None
        user = row['user'] if pd.notna(row.get('user')) else None
        raw = str(row.get('raw', ''))
        event_type = row['event_type']

        # Extract PID from the raw line (parser strips it from the process field)
        pid_m = _PID_RE.search(raw)
        pid = pid_m.group(1) if pid_m else None

        mitre_id, mitre_name = map_event(event_type)
        is_lolbin = False
        # Process Execution / Windows Process Creation / Sysmon Process Created:
        # resolve MITRE technique from command name stored in the user field.
        if event_type in ('Process Execution', 'Windows Process Creation', 'Sysmon Process Created') and user:
            cmd_mitre_id, cmd_mitre_name = map_command(user)
            if not cmd_mitre_id and event_type == 'Sysmon Process Created':
                # Fallback: some EVTX CommandLine values start with flags (e.g. "/u /s /i:...")
                # rather than the executable name. Try matching via the process basename.
                proc_name = str(row.get('process', '') or '')
                cmd_mitre_id, cmd_mitre_name = map_command(proc_name)
            if cmd_mitre_id:
                mitre_id, mitre_name = cmd_mitre_id, cmd_mitre_name
                severity = 'high'
                # Flag as LOLBin / standalone-chain-worthy attack tool.
                is_lolbin = (
                    cmd_mitre_id.startswith('T1218')    # System Binary Proxy Execution
                    or cmd_mitre_id.startswith('T1021')  # Lateral movement tools (SharpRDP, etc.)
                    or cmd_mitre_id in ('T1140', 'T1197', 'T1220', 'T1047')
                )
            else:
                severity = 'low'
        else:
            severity = _compute_severity(event_type, source_ip, ip_failure_counts)
        action = _action_taken(event_type, user, source_ip, raw)

        # Extended fields — populated from sysmon_evtx extras when available.
        cmd_line    = row.get('command_line')
        parent_proc = row.get('parent_process')
        obj_path    = row.get('object_path')
        acc_flags   = row.get('access_flags')

        events.append(StandardEvent(
            event_id=make_event_id(),
            timestamp=ts,
            event_type=event_type,
            source_actor={'ip': source_ip, 'user': user},
            target_system={
                'hostname': str(row.get('hostname', '')),
                'process': str(row.get('process', '')),
            },
            action_taken=action,
            severity=severity,
            mitre_technique={'id': mitre_id, 'name': mitre_name},
            raw=raw,
            source_log=log_path.name,
            log_format=fmt,
            pid=pid,
            is_lolbin=is_lolbin,
            command_line=str(cmd_line) if cmd_line else None,
            parent_process=str(parent_proc) if parent_proc else None,
            object_path=str(obj_path) if obj_path else None,
            access_flags=str(acc_flags) if acc_flags else None,
        ))

    # Persist processed events
    (processed_dir / f'{safe_stem}.json').write_text(
        json.dumps([to_json(e) for e in events], indent=2, default=str),
        encoding='utf-8',
    )

    return events


def verify_integrity(
    log_path: str | Path,
    processed_dir: Path | None = None,
) -> bool:
    """
    Return True if the log file's current SHA-256 matches the hash stored at ingest time.
    Returns False if no hash file exists (log was never ingested).
    """
    log_path = Path(log_path)
    if processed_dir is None:
        processed_dir = _DEFAULT_PROCESSED_DIR
    path_tag = hashlib.sha256(str(log_path.resolve()).encode()).hexdigest()[:8]
    safe_stem = f'{log_path.stem}_{path_tag}'
    hash_file = Path(processed_dir) / f'{safe_stem}.sha256'
    if not hash_file.exists():
        return False
    stored = hash_file.read_text(encoding='utf-8').strip()
    return _sha256(log_path) == stored
