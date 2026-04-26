"""
StandardEvent — the unified event schema for all parsed log sources.

All parsers normalize their output into this dataclass before downstream
analysis. The raw original log line is always preserved unmodified.
"""

import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import TypedDict


class SourceActor(TypedDict):
    ip: str | None
    user: str | None


class TargetSystem(TypedDict):
    hostname: str
    process: str


class MitreTechnique(TypedDict):
    id: str | None
    name: str | None


@dataclass
class StandardEvent:
    event_id: str                    # UUID4 — unique per parsed event
    timestamp: datetime              # UTC-aware datetime
    event_type: str                  # 'Failed Login', 'Accepted Password', etc.
    source_actor: SourceActor        # {'ip': str|None, 'user': str|None}
    target_system: TargetSystem      # {'hostname': str, 'process': str}
    action_taken: str                # human-readable description of the event
    severity: str                    # 'info' | 'low' | 'medium' | 'high' | 'critical'
    mitre_technique: MitreTechnique  # {'id': str|None, 'name': str|None}
    raw: str                         # original log line — NEVER modified
    source_log: str                  # filename of the origin log file
    log_format: str                  # 'auth_log' | 'syslog' | 'audit_log' | 'web_access' | 'sysmon_linux'
    pid: str | None = None           # syslog PID for session-affinity linking
    is_lolbin: bool = False          # True when process command matches a known LOLBin

    def __post_init__(self):
        # Enforce UTC-aware timestamp
        if self.timestamp and self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)


def make_event_id() -> str:
    return str(uuid.uuid4())


def to_json(event: StandardEvent) -> dict:
    """Serialize a StandardEvent to a JSON-safe dict."""
    d = asdict(event)
    if event.timestamp:
        d['timestamp'] = event.timestamp.isoformat()
    else:
        d['timestamp'] = None
    return d


def from_json(d: dict) -> StandardEvent:
    """Deserialize a StandardEvent from a dict (e.g., loaded from JSON)."""
    d = d.copy()
    raw_ts = d.get('timestamp')
    if raw_ts:
        ts = datetime.fromisoformat(raw_ts)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        d['timestamp'] = ts
    else:
        d['timestamp'] = None
    try:
        return StandardEvent(**d)
    except TypeError as exc:
        raise ValueError(f'Cannot deserialize StandardEvent: {exc}') from exc
