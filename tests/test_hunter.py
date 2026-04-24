"""Tests for src/hunter.py"""

from datetime import datetime, timezone, timedelta

import pytest

from hunter import AttackChain, find_triggers, pivot_on_actor, build_attack_chains
from schema import StandardEvent, make_event_id


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_event(
    event_type: str = 'Failed Login',
    ip: str = '1.2.3.4',
    user: str | None = 'root',
    ts: datetime | None = None,
    severity: str = 'low',
    pid: str | None = None,
) -> StandardEvent:
    if ts is None:
        ts = datetime(2024, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
    return StandardEvent(
        event_id=make_event_id(),
        timestamp=ts,
        event_type=event_type,
        source_actor={'ip': ip, 'user': user},
        target_system={'hostname': 'server1', 'process': 'sshd'},
        action_taken=event_type,
        severity=severity,
        mitre_technique={'id': None, 'name': None},
        raw='',
        source_log='auth.log',
        log_format='auth_log',
        pid=pid,
    )


def _n_failures(ip: str = '1.2.3.4', n: int = 5, base_ts: datetime | None = None) -> list[StandardEvent]:
    if base_ts is None:
        base_ts = datetime(2024, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
    return [
        _make_event('Failed Login', ip=ip, ts=base_ts + timedelta(minutes=i))
        for i in range(n)
    ]


# ── find_triggers ──────────────────────────────────────────────────────────────

class TestFindTriggers:
    def test_empty_events(self):
        assert find_triggers([]) == []

    def test_ip_at_threshold_is_flagged(self):
        events = _n_failures(n=5)
        assert '1.2.3.4' in find_triggers(events, threshold=5)

    def test_ip_below_threshold_not_flagged(self):
        events = _n_failures(n=4)
        assert find_triggers(events, threshold=5) == []

    def test_ip_above_threshold_is_flagged(self):
        events = _n_failures(n=20)
        assert '1.2.3.4' in find_triggers(events, threshold=5)

    def test_multiple_ips_both_flagged(self):
        e1 = _n_failures(ip='1.1.1.1', n=6)
        e2 = _n_failures(ip='2.2.2.2', n=8)
        flagged = find_triggers(e1 + e2, threshold=5)
        assert '1.1.1.1' in flagged
        assert '2.2.2.2' in flagged

    def test_ip_with_no_failures_not_flagged(self):
        events = [_make_event('Accepted Password', ip='3.3.3.3')]
        assert find_triggers(events, threshold=5) == []

    def test_events_without_ip_ignored(self):
        events = [_make_event('Failed Login', ip=None) for _ in range(10)]
        # No IP, should produce no triggers
        assert find_triggers(events, threshold=5) == []

    def test_custom_threshold(self):
        events = _n_failures(n=3)
        assert '1.2.3.4' in find_triggers(events, threshold=3)
        assert find_triggers(events, threshold=4) == []


# ── pivot_on_actor ─────────────────────────────────────────────────────────────

class TestPivotOnActor:
    def test_returns_all_ip_events(self):
        events = _n_failures(ip='1.2.3.4', n=7)
        events += [_make_event('Failed Login', ip='9.9.9.9')]  # other actor
        result = pivot_on_actor('1.2.3.4', events)
        assert all(e.source_actor['ip'] == '1.2.3.4' for e in result)
        assert len(result) == 7

    def test_sorted_by_timestamp(self):
        events = _n_failures(n=5)
        result = pivot_on_actor('1.2.3.4', events)
        ts_list = [e.timestamp for e in result]
        assert ts_list == sorted(ts_list)

    def test_bidirectional_pivot_on_compromised_user(self):
        base = datetime(2024, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
        # Attacker brute-forces and succeeds
        failures = _n_failures(n=6, base_ts=base)
        success = _make_event('Accepted Password', ip='1.2.3.4', user='alice',
                              ts=base + timedelta(minutes=10))
        # A sudo command from alice (different source context — linked via user)
        post_exploit = _make_event('Sudo Command', ip=None, user='alice',
                                   ts=base + timedelta(minutes=15))

        all_events = failures + [success, post_exploit]
        result = pivot_on_actor('1.2.3.4', all_events, window_hours=4)

        # post_exploit should be pulled in because alice was compromised
        result_ids = {e.event_id for e in result}
        assert post_exploit.event_id in result_ids

    def test_bidirectional_respects_time_window(self):
        base = datetime(2024, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
        failures = _n_failures(n=6, base_ts=base)
        success = _make_event('Accepted Password', ip='1.2.3.4', user='alice',
                              ts=base + timedelta(minutes=10))
        # Far outside the window — should NOT be included
        late_event = _make_event('Sudo Command', ip=None, user='alice',
                                  ts=base + timedelta(hours=10))

        result = pivot_on_actor('1.2.3.4', failures + [success, late_event], window_hours=4)
        result_ids = {e.event_id for e in result}
        assert late_event.event_id not in result_ids

    def test_no_duplicates_in_result(self):
        events = _n_failures(n=5)
        result = pivot_on_actor('1.2.3.4', events)
        ids = [e.event_id for e in result]
        assert len(ids) == len(set(ids))

    def test_empty_events(self):
        assert pivot_on_actor('1.2.3.4', []) == []


# ── build_attack_chains ────────────────────────────────────────────────────────

class TestBuildAttackChains:
    def test_empty_events_returns_empty(self):
        assert build_attack_chains([]) == []

    def test_chain_created_for_flagged_ip(self):
        events = _n_failures(n=6)
        chains = build_attack_chains(events, threshold=5)
        assert len(chains) == 1
        assert chains[0].actor_ip == '1.2.3.4'

    def test_no_chain_below_threshold(self):
        events = _n_failures(n=4)
        chains = build_attack_chains(events, threshold=5)
        assert chains == []

    def test_brute_force_chain_type(self):
        events = _n_failures(n=10)
        chains = build_attack_chains(events, threshold=5)
        assert chains[0].chain_type == 'brute_force'
        assert chains[0].compromised is False

    def test_credential_stuffing_chain_type(self):
        base = datetime(2024, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
        events = _n_failures(n=6, base_ts=base)
        events.append(_make_event('Accepted Password', ip='1.2.3.4', user='root',
                                  ts=base + timedelta(minutes=10), severity='critical'))
        chains = build_attack_chains(events, threshold=5)
        assert chains[0].chain_type in ('credential_stuffing', 'post_exploitation')
        assert chains[0].compromised is True

    def test_post_exploitation_chain_type(self):
        base = datetime(2024, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
        events = _n_failures(n=6, base_ts=base)
        events.append(_make_event('Accepted Password', ip='1.2.3.4', user='root',
                                  ts=base + timedelta(minutes=10), severity='critical'))
        events.append(_make_event('Session Opened', ip='1.2.3.4', user='root',
                                  ts=base + timedelta(minutes=11)))
        events.append(_make_event('Sudo Command', ip=None, user='root',
                                  ts=base + timedelta(minutes=12), severity='high'))
        chains = build_attack_chains(events, threshold=5)
        assert chains[0].chain_type == 'post_exploitation'

    def test_sorted_by_severity_critical_first(self):
        base = datetime(2024, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
        # IP1: brute force only (medium)
        e1 = _n_failures(ip='1.1.1.1', n=6, base_ts=base)
        # IP2: brute force + successful login (critical)
        e2 = _n_failures(ip='2.2.2.2', n=6, base_ts=base)
        e2.append(_make_event('Accepted Password', ip='2.2.2.2', user='root',
                              ts=base + timedelta(minutes=10), severity='critical'))
        chains = build_attack_chains(e1 + e2, threshold=5)
        assert chains[0].actor_ip == '2.2.2.2'

    def test_mitre_techniques_collected(self):
        base = datetime(2024, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
        events = _n_failures(n=6, base_ts=base)
        events.append(_make_event('Accepted Password', ip='1.2.3.4', user='root',
                                  ts=base + timedelta(minutes=10), severity='critical'))
        # Manually set MITRE on the events since _make_event doesn't set it
        for e in events:
            if e.event_type == 'Failed Login':
                e.mitre_technique = {'id': 'T1110', 'name': 'Brute Force'}
            elif e.event_type == 'Accepted Password':
                e.mitre_technique = {'id': 'T1078', 'name': 'Valid Accounts'}
        chains = build_attack_chains(events, threshold=5)
        technique_ids = {t['id'] for t in chains[0].mitre_techniques if t['id']}
        assert 'T1110' in technique_ids
        assert 'T1078' in technique_ids

    def test_actor_user_identified(self):
        base = datetime(2024, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
        events = _n_failures(n=6, base_ts=base)
        events.append(_make_event('Accepted Password', ip='1.2.3.4', user='alice',
                                  ts=base + timedelta(minutes=10), severity='critical'))
        chains = build_attack_chains(events, threshold=5)
        assert chains[0].actor_user is not None


# ── AttackChain dataclass ──────────────────────────────────────────────────────

class TestAttackChain:
    def _make_chain(self, **kwargs) -> AttackChain:
        defaults = dict(
            actor_ip='1.2.3.4',
            actor_user='root',
            severity='medium',
            mitre_techniques=[],
            events=[],
            chain_type='brute_force',
            compromised=False,
        )
        defaults.update(kwargs)
        return AttackChain(**defaults)

    def test_compromised_false_for_brute_force(self):
        chain = self._make_chain(compromised=False)
        assert not chain.compromised

    def test_compromised_true_for_success(self):
        chain = self._make_chain(compromised=True)
        assert chain.compromised
