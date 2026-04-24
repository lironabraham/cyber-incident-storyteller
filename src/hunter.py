"""
Trigger-Pivot investigation engine.

Algorithm
---------
1. find_triggers()       — IPs with >= threshold failed logins
2. pivot_on_actor()      — all events for a flagged IP, then bidirectionally
                           expand on any account they compromised (pulls that
                           user's events across ALL source IPs within a time window)
3. build_attack_chains() — ties it together: trigger → pivot → classify → score → sort

Public API
----------
find_triggers(events, threshold)            -> list[str]
pivot_on_actor(ip, events, window_hours)    -> list[StandardEvent]
build_attack_chains(events, threshold)      -> list[AttackChain]
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import TypedDict

from schema import StandardEvent


class MitreTechniqueRef(TypedDict):
    """Per-chain technique entry — extends MitreTechnique with the source event_type."""
    id: str | None
    name: str | None
    event_type: str

_SUCCESS_TYPES  = {'Accepted Password', 'Accepted Publickey', 'Audit Login'}
_FAILURE_TYPES  = {'Failed Login', 'Invalid User', 'Auth Failure', 'Audit Auth Failure'}
_SEVERITY_ORDER = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


# ── Result type ────────────────────────────────────────────────────────────────

@dataclass
class AttackChain:
    actor_ip: str
    actor_user: str | None                # most-targeted or compromised account
    severity: str                         # max severity across all events in the chain
    mitre_techniques: list[MitreTechniqueRef]  # unique techniques, ordered by first appearance
    events: list[StandardEvent]           # causally-linked events, sorted by timestamp
    chain_type: str                       # 'brute_force' | 'credential_stuffing' | 'post_exploitation'
    compromised: bool                     # True if attacker achieved a successful login


# ── Internal helpers ───────────────────────────────────────────────────────────

def _max_severity(events: list[StandardEvent]) -> str:
    if not events:
        return 'info'
    return max((e.severity for e in events), key=lambda s: _SEVERITY_ORDER.get(s, 0))


def _classify_chain(events: list[StandardEvent]) -> tuple[str, bool]:
    """Classify the attack chain type and whether a compromise occurred."""
    types = {e.event_type for e in events}
    has_success = bool(types & _SUCCESS_TYPES)
    has_failures = bool(types & _FAILURE_TYPES)
    has_post_exploit = bool({'Sudo Command', 'Session Opened', 'Shell Execution', 'Process Execution'} & types)

    if has_success and has_failures and has_post_exploit:
        return 'post_exploitation', True
    if has_success and has_failures:
        return 'credential_stuffing', True
    if has_success:
        return 'unauthorized_access', True
    return 'brute_force', False


def _primary_user(events: list[StandardEvent]) -> str | None:
    """Return the most-frequently-targeted user in the event set."""
    counts: dict[str, int] = defaultdict(int)
    for e in events:
        u = e.source_actor.get('user')
        if u:
            counts[u] += 1
    return max(counts, key=counts.get) if counts else None


def _unique_techniques(events: list[StandardEvent]) -> list[MitreTechniqueRef]:
    """Collect unique MITRE techniques in order of first appearance."""
    seen: set[str] = set()
    techniques = []
    for e in events:
        mid = e.mitre_technique.get('id')
        if mid and mid not in seen:
            seen.add(mid)
            techniques.append({
                'id': mid,
                'name': e.mitre_technique.get('name'),
                'event_type': e.event_type,
            })
    return techniques


# ── Public API ─────────────────────────────────────────────────────────────────

def find_triggers(events: list[StandardEvent], threshold: int = 5) -> list[str]:
    """
    Return IPs with >= threshold failed login events.

    These are the "trigger" points that initiate the pivot phase.
    """
    counts: dict[str, int] = defaultdict(int)
    for event in events:
        if event.event_type in _FAILURE_TYPES:
            ip = event.source_actor.get('ip')
            if ip:
                counts[ip] += 1
    return [ip for ip, n in counts.items() if n >= threshold]


def pivot_on_actor(
    ip: str,
    events: list[StandardEvent],
    window_hours: int = 4,
) -> list[StandardEvent]:
    """
    Return all events causally linked to a flagged IP.

    Step 1 — Direct: all events where source_actor.ip == ip.
    Step 2 — Bidirectional: if the IP achieved a successful login, pull every
             event involving the compromised user across all source IPs,
             within window_hours of the first successful login.
    """
    ip_events = [e for e in events if e.source_actor.get('ip') == ip]

    # Find the earliest successful login to define the pivot window
    compromised_users: set[str] = set()
    earliest_compromise = None
    for e in ip_events:
        if e.event_type in _SUCCESS_TYPES:
            u = e.source_actor.get('user')
            if u:
                compromised_users.add(u)
            if earliest_compromise is None or e.timestamp < earliest_compromise:
                earliest_compromise = e.timestamp

    # Bidirectional pivot: pull all events for compromised users within the window
    extra_events: list[StandardEvent] = []
    if compromised_users and earliest_compromise:
        cutoff = earliest_compromise + timedelta(hours=window_hours)
        for e in events:
            if e in ip_events:
                continue
            u = e.source_actor.get('user')
            if u in compromised_users and earliest_compromise <= e.timestamp <= cutoff:
                extra_events.append(e)

    # Deduplicate by event_id and sort by timestamp
    seen: set[str] = set()
    all_events: list[StandardEvent] = []
    for e in ip_events + extra_events:
        if e.event_id not in seen:
            seen.add(e.event_id)
            all_events.append(e)

    return sorted(all_events, key=lambda e: e.timestamp)


def build_attack_chains(
    events: list[StandardEvent],
    threshold: int = 5,
) -> list[AttackChain]:
    """
    Build a list of AttackChains from a set of StandardEvents.

    Pipeline:
      find_triggers → pivot_on_actor → classify → score → sort by severity
    """
    flagged_ips = find_triggers(events, threshold)
    chains: list[AttackChain] = []

    for ip in flagged_ips:
        linked = pivot_on_actor(ip, events)
        if not linked:
            continue

        chain_type, compromised = _classify_chain(linked)
        severity = _max_severity(linked)
        techniques = _unique_techniques(linked)
        actor_user = _primary_user(linked)

        chains.append(AttackChain(
            actor_ip=ip,
            actor_user=actor_user,
            severity=severity,
            mitre_techniques=techniques,
            events=linked,
            chain_type=chain_type,
            compromised=compromised,
        ))

    # Sort: critical first, then by event count (most active attacker first)
    chains.sort(key=lambda c: (-_SEVERITY_ORDER.get(c.severity, 0), -len(c.events)))
    return chains
