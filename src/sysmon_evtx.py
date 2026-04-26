"""
Windows Sysmon EVTX parser.

Handles records from the Microsoft-Windows-Sysmon/Operational channel.
Called from parser._parse_evtx_record() when the Provider Name contains "Sysmon".

Noise filters applied at extraction time:
  EventID 7  — only DLLs in mitre.SUSPICIOUS_DLLS
  EventID 10 — only lsass.exe target + memory-read access bit (0x0010)
  EventID 12/13 — only autorun / persistence registry key paths

Public API
----------
extract_record(event_id, data, hostname, timestamp, raw_xml)  -> dict | None
"""

import re

from mitre import SUSPICIOUS_DLLS

# Sysmon EventID → event_type string
SYSMON_EVENT_TYPES: dict[int, str] = {
    1:  'Sysmon Process Created',
    3:  'Sysmon Network Connection',
    7:  'Sysmon Image Loaded',
    8:  'Sysmon Remote Thread',
    10: 'Sysmon Process Access',
    11: 'Sysmon File Created',
    12: 'Sysmon Registry Key Modified',
    13: 'Sysmon Registry Value Modified',
    17: 'Sysmon Named Pipe Created',
    18: 'Sysmon Named Pipe Connected',
    20: 'Sysmon WMI Subscription',
    21: 'Sysmon WMI Subscription',
    # EventID 5 (Process Terminated) intentionally absent — noise, per CLAUDE.md
}

# EventID 10: must have PROCESS_VM_READ bit set to indicate memory-read capability.
_VM_READ_BIT = 0x0010

# EventID 12/13: only persistence / autorun registry key paths.
_PERSISTENCE_KEY_RE = re.compile(
    r'\\(?:Run|RunOnce|Services|Image File Execution Options|'
    r'Winlogon|AppInit_DLLs|UserInit|Shell|CurrentVersion\\Explorer\\Shell Folders|'
    r'Security\\LSA|WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon)',
    re.IGNORECASE,
)


def _basename(path: str) -> str:
    """Return lowercase basename of a Windows or Unix path."""
    return path.replace('\\', '/').split('/')[-1].lower() if path else ''


def _has_memory_read(granted_access: str) -> bool:
    """Return True when the access mask includes PROCESS_VM_READ (0x0010)."""
    try:
        return bool(int(granted_access, 16) & _VM_READ_BIT)
    except (ValueError, TypeError):
        return False


def _row(
    event_type: str,
    timestamp,
    hostname: str,
    process: str,
    source_ip: str | None,
    user: str | None,
    raw: str,
) -> dict:
    return {
        'timestamp':  timestamp,
        'hostname':   hostname,
        'process':    process,
        'event_type': event_type,
        'source_ip':  source_ip,
        'user':       user,
        'raw':        raw,
    }


def extract_record(
    event_id: int,
    data: dict[str, str],
    hostname: str,
    timestamp,
    raw_xml: str,
) -> dict | None:
    """Extract a Sysmon EventData dict into a unified row dict.

    Returns None for unsupported EventIDs and noise-filtered records.
    The 'user' field stores contextual information (command line, target process,
    registry key, etc.) following the same convention as the auditd EXECVE pattern
    in parser.py — ready for map_command() routing in ingest.py.
    """
    if event_id not in SYSMON_EVENT_TYPES:
        return None

    event_type = SYSMON_EVENT_TYPES[event_id]
    image = data.get('Image', '') or ''
    proc  = _basename(image)
    user  = (data.get('User') or data.get('SourceUser') or
             data.get('SubjectUserName') or None)

    # ── EventID 1: Process Created ────────────────────────────────────────────
    if event_id == 1:
        cmd = data.get('CommandLine', '') or image
        return _row(event_type, timestamp, hostname, proc, None, cmd or None, raw_xml)

    # ── EventID 3: Network Connection ─────────────────────────────────────────
    if event_id == 3:
        dst_ip = data.get('DestinationIp') or None
        if dst_ip in ('127.0.0.1', '::1'):
            dst_ip = None
        return _row(event_type, timestamp, hostname, proc, dst_ip, user, raw_xml)

    # ── EventID 7: Image Loaded — only suspicious DLLs ────────────────────────
    if event_id == 7:
        dll = _basename(data.get('ImageLoaded', '') or '')
        if dll not in SUSPICIOUS_DLLS:
            return None
        return _row(event_type, timestamp, hostname, proc, None, dll or user, raw_xml)

    # ── EventID 8: CreateRemoteThread ─────────────────────────────────────────
    if event_id == 8:
        target_proc = _basename(data.get('TargetImage', '') or '')
        return _row(event_type, timestamp, hostname, proc, None,
                    target_proc or user, raw_xml)

    # ── EventID 10: ProcessAccess — LSASS + memory-read only ──────────────────
    if event_id == 10:
        target = _basename(data.get('TargetImage', '') or '')
        if target != 'lsass.exe':
            return None
        access = data.get('GrantedAccess', '') or ''
        if not _has_memory_read(access):
            return None
        return _row(event_type, timestamp, hostname, proc, None, user, raw_xml)

    # ── EventID 11: FileCreate ────────────────────────────────────────────────
    if event_id == 11:
        target_file = data.get('TargetFilename', '') or ''
        return _row(event_type, timestamp, hostname, proc, None,
                    target_file or user, raw_xml)

    # ── EventID 12/13: Registry — persistence keys only ──────────────────────
    if event_id in (12, 13):
        target_obj = data.get('TargetObject', '') or ''
        if not _PERSISTENCE_KEY_RE.search(target_obj):
            return None
        return _row(event_type, timestamp, hostname, proc, None,
                    target_obj or user, raw_xml)

    # ── EventID 17/18: Named Pipe ─────────────────────────────────────────────
    if event_id in (17, 18):
        pipe_name = data.get('PipeName', '') or ''
        return _row(event_type, timestamp, hostname, proc, None,
                    pipe_name or user, raw_xml)

    # ── EventID 20/21: WMI Subscription ──────────────────────────────────────
    if event_id in (20, 21):
        name = (data.get('Name') or data.get('Consumer') or
                data.get('Destination') or user or '')
        return _row(event_type, timestamp, hostname, proc, None, name or None, raw_xml)

    return None
