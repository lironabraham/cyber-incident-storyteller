"""
Trigger-Pivot investigation engine.

Algorithm
---------
Three trigger pathways feed a shared pivot-classify-score pipeline:

1. find_triggers()           — IPs with >= threshold failed logins (brute force)
2. find_silent_access_ips()  — IPs with successful logons but NO failures
                               (NTLM relay, pass-the-hash, stolen credentials)
3. find_probe_triggers()     — IPs with many Kerberos/scan probes at a lower
                               threshold (Kerberoasting, password spray)

After IP-based pivots, a fourth sweep collects any uncovered high-value events
(service installs, scheduled tasks, group changes) and builds user-attributed or
anonymous chains for them.

Public API
----------
find_triggers(events, threshold)              -> list[str]
find_silent_access_ips(events, failure_ips)   -> list[str]
find_probe_triggers(events, threshold)        -> list[str]
pivot_on_actor(ip, events, window_hours)      -> list[StandardEvent]
build_attack_chains(events, threshold)        -> list[AttackChain]
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

_SUCCESS_TYPES = {
    'Accepted Password', 'Accepted Publickey', 'Audit Login',
    'Windows Logon Success', 'Windows Remote Logon',
}
_FAILURE_TYPES = {
    'Failed Login', 'Invalid User', 'Auth Failure', 'Audit Auth Failure',
    'Windows Logon Failure', 'Windows Kerberos PreAuth Failure',
}
# Authentication probes: not failures per se, but high-volume patterns are suspicious.
_PROBE_TYPES = {
    'Windows Kerberos TGT Request',    # mass TGT requests → Kerberoasting / spray
    'Windows Kerberos Service Ticket', # mass service tickets → Kerberoasting
    'Tool Fingerprint',                # attack tool fingerprint
    'Web Scan',                        # directory/path scanning
}
# High-value event types that indicate attacker activity regardless of prior failures.
# These are inherently suspicious when they appear — especially from unexpected actors.
_HIGH_VALUE_TYPES = {
    'Windows Service Installed',   # T1543.003 — persistence
    'Windows Scheduled Task',      # T1053.005 — persistence
    'Windows Account Created',     # T1136.001 — persistence
    'Windows Group Member Added',  # T1098     — privilege escalation
    'Windows Share Access',        # T1021.002 — lateral movement
    'Web Shell',                   # T1505.003 — persistence
    'Shell Execution',             # T1059.004 — execution
    'File Access',                 # T1003.008 — credential access
}
# Subset of _HIGH_VALUE_TYPES that represent confirmed persistence actions.
_PERSISTENCE_TYPES = {
    'Windows Service Installed',
    'Windows Scheduled Task',
    'Windows Account Created',
    'Windows Group Member Added',
}
_SEVERITY_ORDER = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


# ── Result type ────────────────────────────────────────────────────────────────

@dataclass
class AttackChain:
    actor_ip: str | None
    actor_user: str | None                # most-targeted or compromised account
    severity: str                         # max severity across all events in the chain
    mitre_techniques: list[MitreTechniqueRef]  # unique techniques, ordered by first appearance
    events: list[StandardEvent]           # causally-linked events, sorted by timestamp
    chain_type: str                       # see _classify_chain for valid values
    compromised: bool                     # True if attacker achieved or implied a compromise


# ── Internal helpers ───────────────────────────────────────────────────────────

def _max_severity(events: list[StandardEvent]) -> str:
    if not events:
        return 'info'
    return max((e.severity for e in events), key=lambda s: _SEVERITY_ORDER.get(s, 0))


def _classify_chain(events: list[StandardEvent]) -> tuple[str, bool]:
    """Classify the attack chain type and whether a compromise occurred.

    Chain types:
      brute_force        — failures only, no successful logon
      credential_stuffing — failures followed by success
      post_exploitation   — (failures or silent) + success + post-exploit actions
      unauthorized_access — successful logon with no prior failures
      lateral_movement    — high-value persistence/LM actions, no logon evidence
    """
    types = {e.event_type for e in events}
    has_success = bool(types & _SUCCESS_TYPES)
    has_failures = bool(types & _FAILURE_TYPES)
    has_post_exploit = bool({
        'Sudo Command', 'Session Opened', 'Shell Execution', 'Process Execution',
        'Windows Process Creation', 'Windows Service Installed', 'Windows Scheduled Task',
    } & types)
    has_high_value = bool(_HIGH_VALUE_TYPES & types)

    if has_success and has_failures and has_post_exploit:
        return 'post_exploitation', True
    if has_success and has_failures:
        return 'credential_stuffing', True
    if has_success and has_post_exploit:
        return 'post_exploitation', True   # silent compromise + post-exploitation
    if has_success:
        return 'unauthorized_access', True
    if has_high_value:
        return 'lateral_movement', True    # standalone high-value event = assumed compromise
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


def _make_chain(events: list[StandardEvent], actor_ip: str | None) -> AttackChain:
    """Build an AttackChain from a list of causally-linked events."""
    chain_type, compromised = _classify_chain(events)
    return AttackChain(
        actor_ip=actor_ip,
        actor_user=_primary_user(events),
        severity=_max_severity(events),
        mitre_techniques=_unique_techniques(events),
        events=events,
        chain_type=chain_type,
        compromised=compromised,
    )


# ── Public API ─────────────────────────────────────────────────────────────────

def find_triggers(events: list[StandardEvent], threshold: int = 5) -> list[str]:
    """Return IPs with >= threshold failed login events (brute-force trigger)."""
    counts: dict[str, int] = defaultdict(int)
    for event in events:
        if event.event_type in _FAILURE_TYPES:
            ip = event.source_actor.get('ip')
            if ip:
                counts[ip] += 1
    return [ip for ip, n in counts.items() if n >= threshold]


def find_silent_access_ips(
    events: list[StandardEvent],
    failure_ips: set[str],
) -> list[str]:
    """Return IPs with successful logons but NO prior failures.

    These are indicators of credential reuse, NTLM relay, pass-the-hash, or
    golden/silver ticket attacks — attacks that skip the brute-force phase
    entirely and would be invisible to find_triggers().
    """
    success_ips: set[str] = set()
    for e in events:
        if e.event_type in _SUCCESS_TYPES:
            ip = e.source_actor.get('ip')
            if ip and ip not in failure_ips:
                success_ips.add(ip)
    return list(success_ips)


def find_probe_triggers(
    events: list[StandardEvent],
    threshold: int = 3,
) -> list[str]:
    """Return IPs with many authentication probes at a lower threshold.

    Kerberos password sprays and Kerberoasting attacks generate TGT/service-ticket
    requests rather than traditional login failures. The lower threshold (default 3)
    reflects that even a small number of Kerberos probes from one IP is unusual.
    """
    counts: dict[str, int] = defaultdict(int)
    for e in events:
        if e.event_type in _PROBE_TYPES:
            ip = e.source_actor.get('ip')
            if ip:
                counts[ip] += 1
    return [ip for ip, n in counts.items() if n >= threshold]


def pivot_on_actor(
    ip: str,
    events: list[StandardEvent],
    window_hours: int = 4,
) -> list[StandardEvent]:
    """Return all events causally linked to a flagged IP.

    Step 1 — Direct: all events where source_actor.ip == ip.
    Step 2 — Bidirectional: if the IP achieved a successful login, pull every
             event involving the compromised user across all source IPs,
             within window_hours of the first successful login.
    """
    ip_events = [e for e in events if e.source_actor.get('ip') == ip]

    compromised_users: set[str] = set()
    earliest_compromise = None
    for e in ip_events:
        if e.event_type in _SUCCESS_TYPES:
            u = e.source_actor.get('user')
            if u:
                compromised_users.add(u)
            if earliest_compromise is None or e.timestamp < earliest_compromise:
                earliest_compromise = e.timestamp

    extra_events: list[StandardEvent] = []
    if compromised_users and earliest_compromise:
        cutoff = earliest_compromise + timedelta(hours=window_hours)
        for e in events:
            if e in ip_events:
                continue
            u = e.source_actor.get('user')
            if u in compromised_users and earliest_compromise <= e.timestamp <= cutoff:
                extra_events.append(e)

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
    """Build a list of AttackChains from a set of StandardEvents.

    Detection pipeline (four passes):

    Pass 1 — Brute-force IPs: IPs with >= threshold failures.
    Pass 2 — Silent-access IPs: IPs with successful logons but no failures.
             Catches NTLM relay, pass-the-hash, golden ticket.
    Pass 3 — Probe IPs: IPs with >= 3 Kerberos/scan probes.
             Catches Kerberoasting and password sprays.
    Pass 4 — High-value user/anonymous chains: Persistence and lateral-movement
             events (service installs, scheduled tasks, group changes) that were
             not attributed to any IP-based actor in passes 1-3.
    """
    # ── Pass 1-3: IP-based chains ──────────────────────────────────────────────
    failure_ips = set(find_triggers(events, threshold))
    silent_ips = set(find_silent_access_ips(events, failure_ips))
    probe_ips = set(find_probe_triggers(events)) - failure_ips - silent_ips

    all_ips = list(failure_ips | silent_ips | probe_ips)

    covered_event_ids: set[str] = set()
    chains: list[AttackChain] = []

    for ip in all_ips:
        linked = pivot_on_actor(ip, events)
        if not linked:
            continue
        for e in linked:
            covered_event_ids.add(e.event_id)
        chains.append(_make_chain(linked, actor_ip=ip))

    # ── Pass 4: high-value events not covered by IP chains ────────────────────
    # Group uncovered high-value events by user (None = unattributed).
    user_buckets: dict[str | None, list[StandardEvent]] = defaultdict(list)
    for e in events:
        if e.event_type in _HIGH_VALUE_TYPES and e.event_id not in covered_event_ids:
            user_buckets[e.source_actor.get('user')].append(e)

    for user, bucket in user_buckets.items():
        if not bucket:
            continue
        # Expand: pull all events for this user that aren't already covered.
        if user:
            user_events = [
                e for e in events
                if e.source_actor.get('user') == user
                and e.event_id not in covered_event_ids
            ]
        else:
            user_events = bucket  # no user — only the high-value events themselves
        user_events = sorted(user_events, key=lambda e: e.timestamp)
        for e in user_events:
            covered_event_ids.add(e.event_id)
        chains.append(_make_chain(user_events, actor_ip=None))

    # Sort: highest severity first, then by event count
    chains.sort(key=lambda c: (-_SEVERITY_ORDER.get(c.severity, 0), -len(c.events)))
    return chains
