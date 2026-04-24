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

_SUCCESS_TYPES = {'Accepted Password', 'Accepted Publickey'}
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
    if event_type in ('Service Started', 'Service Stopped', 'Service Failed', 'OOM Kill'):
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
        return f"Interactive shell spawned"
    if event_type == 'File Access':
        return f"Sensitive file accessed by process"
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

    # Store integrity hash before any processing
    hash_val = _sha256(log_path)
    (processed_dir / f'{log_path.stem}.sha256').write_text(hash_val, encoding='utf-8')

    df = parse_log(log_path, fmt=fmt)

    # First pass: tally failures per IP for context-aware severity
    ip_failure_counts: dict[str, int] = {}
    for _, row in df.iterrows():
        if row['event_type'] == 'Failed Login':
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
        # Process Execution: resolve MITRE + severity from the command (stored in user)
        if event_type == 'Process Execution' and user:
            cmd_mitre_id, cmd_mitre_name = map_command(user)
            if cmd_mitre_id:
                mitre_id, mitre_name = cmd_mitre_id, cmd_mitre_name
                severity = 'high'
            else:
                severity = 'low'
        else:
            severity = _compute_severity(event_type, source_ip, ip_failure_counts)
        action = _action_taken(event_type, user, source_ip, raw)

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
        ))

    # Persist processed events
    (processed_dir / f'{log_path.stem}.json').write_text(
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
    hash_file = Path(processed_dir) / f'{log_path.stem}.sha256'
    if not hash_file.exists():
        return False
    stored = hash_file.read_text(encoding='utf-8').strip()
    return _sha256(log_path) == stored
