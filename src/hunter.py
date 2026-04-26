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
    'Windows NewCredentials Logon',   # LogonType 9 — token impersonation
    'Windows Local Relay Logon',      # LogonType 3/10 from localhost — self-relay
}
_FAILURE_TYPES = {
    'Failed Login', 'Invalid User', 'Auth Failure', 'Audit Auth Failure',
    'Windows Logon Failure', 'Windows Kerberos PreAuth Failure',
    'Windows Account Lockout', 'Windows NTLM Auth',
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
    'Windows Service Installed',       # T1543.003 — persistence
    'Windows Scheduled Task',          # T1053.005 — persistence
    'Windows Account Created',         # T1136.001 — persistence
    'Windows Group Member Added',      # T1098     — privilege escalation
    'Windows Share Access',            # T1021.002 — lateral movement
    'Web Shell',                       # T1505.003 — persistence
    'Shell Execution',                 # T1059.004 — execution
    'File Access',                     # T1003.008 — credential access
    'Windows Object Access',           # T1003.001 — LSASS / credential dumping
    'Windows DS Object Access',        # T1003.006 — DCSync
    'Windows Log Cleared',             # T1070.001 — defense evasion
    'Windows Registry Modified',       # T1112     — defense evasion / persistence
    'Windows Token Rights Adjusted',   # T1134     — privilege escalation
    'Windows Account Deleted',         # T1531     — impact
    'Windows Account Changed',         # T1098     — account manipulation
    'Windows Network Connection',      # T1021     — lateral movement (filtered to key ports)
    'Windows NewCredentials Logon',    # T1078     — token impersonation (LogonType 9)
    'Windows Local Relay Logon',       # T1021     — Kerberos/NTLM self-relay (localhost)
    # ── Sysmon ────────────────────────────────────────────────────────────────
    'Sysmon Remote Thread',            # T1055     — process injection
    'Sysmon WMI Subscription',         # T1546.003 — persistence
    'Sysmon Image Loaded',             # T1055.001 — DLL injection (pre-filtered)
    'Sysmon Registry Key Modified',    # T1547.001 — autorun persistence
    'Sysmon Registry Value Modified',  # T1547.001 — autorun persistence
    'Sysmon Named Pipe Created',       # T1559.001 — IPC / lateral movement
    'Sysmon Named Pipe Connected',     # T1559.001 — IPC / lateral movement
    'Sysmon File Created',             # context-dependent — included for sweep
    'Sysmon Network Connection',       # T1071     — C2 network activity
}
# Sysmon credential access events — handled by dedicated Pass 5.
_CREDENTIAL_ACCESS_TYPES = {
    'Sysmon Process Access',           # T1003.001 — LSASS memory read (pre-filtered)
    'Windows Object Access',           # T1003.001 — LSASS / credential dumping
}
_DEFENSE_EVASION_TYPES = {
    'Windows Log Cleared',
    'Windows Registry Modified',
}
# IPs that indicate a local / host-initiated logon (no network attribution).
_LOCAL_NULL_IPS: frozenset[str] = frozenset({
    '', '-', '127.0.0.1', '::1', 'localhost', '0.0.0.0',
})
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
      defense_evasion     — log-clearing or registry tampering, no logon evidence
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
    has_defense_evasion = bool(_DEFENSE_EVASION_TYPES & types)
    has_credential_access = bool(_CREDENTIAL_ACCESS_TYPES & types)

    if has_success and has_failures and has_post_exploit:
        return 'post_exploitation', True
    if has_success and has_failures:
        return 'credential_stuffing', True
    if has_success and has_post_exploit:
        return 'post_exploitation', True   # silent compromise + post-exploitation
    if has_success:
        return 'unauthorized_access', True
    if has_credential_access:
        return 'credential_access', True   # LSASS dump or object access — no logon required
    if has_defense_evasion and not has_success:
        return 'defense_evasion', True     # log-clearing / registry tampering = assumed compromise
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
    return max(counts, key=lambda u: counts[u]) if counts else None


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


def _is_local_or_null_ip(ip: str | None) -> bool:
    """Return True for IPs that indicate a local / host-to-host logon."""
    if not ip:
        return True
    return ip.lower() in _LOCAL_NULL_IPS


def _find_elevation_chains(
    events: list[StandardEvent],
    covered_ids: set[str],
) -> list[AttackChain]:
    """Pass 2.5: Hybrid elevation detection (4624 + 4672 correlation).

    Primary Seed: a Windows Logon Success / Remote Logon with a local or null IP
    correlated with a Windows Privilege Assigned event within 60 seconds for the
    same user.  This catches UAC-bypass and KrbRelayUp logons that are invisible
    to the IP-based passes because they originate from localhost.

    Secondary Context: once a primary seed is found, all events for the same user
    within the preceding 10 minutes are included as passive context nodes — giving
    the analyst the full pre-elevation activity picture.

    A plain local 4624 without a co-occurring 4672 does NOT create a chain, which
    prevents false positives from normal interactive desktop logons.
    """
    _ELEV_WINDOW_S = 60
    _PASSIVE_WINDOW = timedelta(minutes=10)

    uncovered = [e for e in events if e.event_id not in covered_ids]

    privilege_events = [
        e for e in uncovered if e.event_type == 'Windows Privilege Assigned'
    ]
    local_logons = [
        e for e in uncovered
        if e.event_type in ('Windows Logon Success', 'Windows Remote Logon')
        and _is_local_or_null_ip(e.source_actor.get('ip'))
    ]

    if not privilege_events or not local_logons:
        return []

    new_covered: set[str] = set()
    chains: list[AttackChain] = []
    used_logon_ids: set[str] = set()

    for priv_ev in privilege_events:
        if priv_ev.event_id in new_covered:
            continue
        priv_user = priv_ev.source_actor.get('user')
        if not priv_user:
            continue

        correlated = [
            e for e in local_logons
            if e.source_actor.get('user') == priv_user
            and abs((e.timestamp - priv_ev.timestamp).total_seconds()) <= _ELEV_WINDOW_S
            and e.event_id not in used_logon_ids
            and e.event_id not in new_covered
        ]
        if not correlated:
            continue

        seed = correlated[0]
        used_logon_ids.add(seed.event_id)

        # Passive context: all same-user events in the 10 min before the seed logon.
        context_start = seed.timestamp - _PASSIVE_WINDOW
        context_end = priv_ev.timestamp + timedelta(seconds=_ELEV_WINDOW_S)

        chain_events: list[StandardEvent] = []
        seen_ids: set[str] = set()
        for e in sorted(
            (e for e in events
             if e.source_actor.get('user') == priv_user
             and context_start <= e.timestamp <= context_end
             and e.event_id not in covered_ids
             and e.event_id not in new_covered),
            key=lambda x: x.timestamp,
        ):
            if e.event_id not in seen_ids:
                seen_ids.add(e.event_id)
                chain_events.append(e)

        # Ensure the privilege event itself is included even if user differs.
        if priv_ev.event_id not in seen_ids:
            chain_events.append(priv_ev)
            chain_events.sort(key=lambda x: x.timestamp)

        for e in chain_events:
            new_covered.add(e.event_id)

        chains.append(_make_chain(chain_events, actor_ip=None))

    covered_ids.update(new_covered)
    return chains


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
        ip_event_ids = {e.event_id for e in ip_events}
        for e in events:
            if e.event_id in ip_event_ids:
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

    Detection pipeline (five passes):

    Pass 1 — Brute-force IPs: IPs with >= threshold failures.
    Pass 2 — Silent-access IPs: IPs with successful logons but no failures.
             Catches NTLM relay, pass-the-hash, golden ticket.
    Pass 2.5 — Local elevation: Windows Logon Success/Remote Logon with null/local
               IP correlated with Windows Privilege Assigned within 60 s (same user).
               Primary seed only fires when both events are present; plain local
               4624s without a 4672 are passive nodes and never start a chain.
               Catches UAC-bypass and KrbRelayUp logons invisible to Pass 2.
    Pass 3 — Probe IPs: IPs with >= 3 Kerberos/scan probes.
             Catches Kerberoasting and password sprays.
    Pass 4 — High-value user/anonymous chains: Persistence, lateral-movement,
             and Sysmon behavioural events not attributed to any IP-based actor.
    Pass 5 — Credential access: Sysmon LSASS memory-read events (EventID 10)
             and Windows Object Access that are not yet covered.  Single-event
             chains with chain_type='credential_access'.
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

    # ── Pass 2.5: Local elevation correlation (4624 + 4672) ───────────────────
    elevation_chains = _find_elevation_chains(events, covered_event_ids)
    chains.extend(elevation_chains)

    # ── Pass 4: high-value events not covered by IP/elevation chains ──────────
    # Group uncovered high-value events by user (None = unattributed).
    # For SYSTEM-owned events, compound key (user, process) prevents all Sysmon
    # SYSTEM events collapsing into one undifferentiated chain.
    user_buckets: dict[str | tuple, list[StandardEvent]] = defaultdict(list)
    for e in events:
        if e.event_type in _HIGH_VALUE_TYPES and e.event_id not in covered_event_ids:
            user = e.source_actor.get('user')
            proc = e.target_system.get('process', '')
            key: str | tuple = (user, proc) if user and 'SYSTEM' in (user or '') else (user or '')
            user_buckets[key].append(e)

    for key, bucket in user_buckets.items():
        if not bucket:
            continue
        user = bucket[0].source_actor.get('user')
        if user:
            user_events = [
                e for e in events
                if e.source_actor.get('user') == user
                and e.event_id not in covered_event_ids
            ]
        else:
            user_events = bucket
        user_events = sorted(user_events, key=lambda e: e.timestamp)
        for e in user_events:
            covered_event_ids.add(e.event_id)
        chains.append(_make_chain(user_events, actor_ip=None))

    # ── Pass 5: Credential access (LSASS / Sysmon Process Access) ─────────────
    for e in events:
        if e.event_type in _CREDENTIAL_ACCESS_TYPES and e.event_id not in covered_event_ids:
            covered_event_ids.add(e.event_id)
            chains.append(_make_chain([e], actor_ip=None))

    # Sort: highest severity first, then by event count
    chains.sort(key=lambda c: (-_SEVERITY_ORDER.get(c.severity, 0), -len(c.events)))
    return chains
