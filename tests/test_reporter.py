"""Tests for src/reporter.py"""

from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from hunter import AttackChain
from reporter import generate_report
from schema import StandardEvent, make_event_id


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_event(
    event_type: str = 'Failed Login',
    ip: str = '1.2.3.4',
    user: str | None = 'root',
    ts: datetime | None = None,
    severity: str = 'medium',
    mitre_id: str | None = 'T1110',
    mitre_name: str | None = 'Brute Force',
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
        mitre_technique={'id': mitre_id, 'name': mitre_name},
        raw='Apr 23 10:00:00 server1 sshd[1234]: ...',
        source_log='auth.log',
        log_format='auth_log',
        pid='1234',
    )


def _make_chain(
    ip: str = '1.2.3.4',
    user: str = 'root',
    severity: str = 'critical',
    compromised: bool = True,
    chain_type: str = 'credential_stuffing',
) -> tuple[AttackChain, list[StandardEvent]]:
    base = datetime(2024, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        _make_event('Failed Login', ip=ip, user=user, ts=base, severity='medium'),
        _make_event('Failed Login', ip=ip, user=user, ts=base + timedelta(minutes=1), severity='medium'),
        _make_event('Accepted Password', ip=ip, user=user,
                    ts=base + timedelta(minutes=5), severity='critical',
                    mitre_id='T1078', mitre_name='Valid Accounts'),
        _make_event('Session Opened', ip=ip, user=user,
                    ts=base + timedelta(minutes=6), severity='info',
                    mitre_id='T1021.004', mitre_name='Remote Services: SSH'),
    ]
    chain = AttackChain(
        actor_ip=ip,
        actor_user=user,
        severity=severity,
        mitre_techniques=[
            {'id': 'T1110', 'name': 'Brute Force', 'event_type': 'Failed Login'},
            {'id': 'T1078', 'name': 'Valid Accounts', 'event_type': 'Accepted Password'},
        ],
        events=events,
        chain_type=chain_type,
        compromised=compromised,
    )
    return chain, events


# ── generate_report ────────────────────────────────────────────────────────────

class TestGenerateReport:
    def test_creates_output_file(self, tmp_path):
        chain, events = _make_chain()
        out = tmp_path / 'report.md'
        result = generate_report([chain], events, out)
        assert result == out
        assert out.exists()

    def test_creates_parent_directories(self, tmp_path):
        chain, events = _make_chain()
        out = tmp_path / 'sub' / 'dir' / 'report.md'
        generate_report([chain], events, out)
        assert out.exists()

    def test_returns_path_object(self, tmp_path):
        chain, events = _make_chain()
        result = generate_report([chain], events, tmp_path / 'r.md')
        assert isinstance(result, Path)

    def test_empty_chains_produces_valid_file(self, tmp_path):
        _, events = _make_chain()
        out = tmp_path / 'empty.md'
        generate_report([], events, out)
        content = out.read_text()
        assert '# Cyber Incident Report' in content

    def test_contains_report_header(self, tmp_path):
        chain, events = _make_chain()
        out = tmp_path / 'r.md'
        generate_report([chain], events, out)
        content = out.read_text()
        assert '# Cyber Incident Report' in content

    def test_contains_executive_summary(self, tmp_path):
        chain, events = _make_chain()
        out = tmp_path / 'r.md'
        generate_report([chain], events, out)
        content = out.read_text()
        assert 'Executive Summary' in content or 'BLUF' in content

    def test_contains_attack_timeline(self, tmp_path):
        chain, events = _make_chain()
        out = tmp_path / 'r.md'
        generate_report([chain], events, out)
        content = out.read_text()
        assert 'Attack Timeline' in content

    def test_timeline_contains_event_types(self, tmp_path):
        chain, events = _make_chain()
        out = tmp_path / 'r.md'
        generate_report([chain], events, out)
        content = out.read_text()
        assert 'Failed Login' in content
        assert 'Accepted Password' in content

    def test_contains_mermaid_block(self, tmp_path):
        chain, events = _make_chain()
        out = tmp_path / 'r.md'
        generate_report([chain], events, out)
        content = out.read_text()
        assert '```mermaid' in content
        assert 'sequenceDiagram' in content

    def test_mermaid_contains_attacker_ip(self, tmp_path):
        chain, events = _make_chain(ip='5.6.7.8')
        out = tmp_path / 'r.md'
        generate_report([chain], events, out)
        content = out.read_text()
        assert '5.6.7.8' in content

    def test_contains_mitre_technique_ids(self, tmp_path):
        chain, events = _make_chain()
        out = tmp_path / 'r.md'
        generate_report([chain], events, out)
        content = out.read_text()
        assert 'T1110' in content
        assert 'T1078' in content

    def test_contains_recommendations(self, tmp_path):
        chain, events = _make_chain()
        out = tmp_path / 'r.md'
        generate_report([chain], events, out)
        content = out.read_text()
        assert 'Recommendations' in content

    def test_contains_forensic_integrity_section(self, tmp_path):
        chain, events = _make_chain()
        out = tmp_path / 'r.md'
        generate_report([chain], events, out)
        content = out.read_text()
        assert 'Forensic Integrity' in content

    def test_alert_present_for_compromised_chain(self, tmp_path):
        chain, events = _make_chain(compromised=True)
        out = tmp_path / 'r.md'
        generate_report([chain], events, out)
        content = out.read_text()
        # Should mention the successful login somewhere prominent
        assert 'successful authentication' in content.lower() or 'compromised' in content.lower()

    def test_severity_appears_in_output(self, tmp_path):
        chain, events = _make_chain(severity='critical')
        out = tmp_path / 'r.md'
        generate_report([chain], events, out)
        content = out.read_text()
        assert 'CRITICAL' in content or 'critical' in content

    def test_actor_ip_in_threat_actor_detail(self, tmp_path):
        chain, events = _make_chain(ip='10.20.30.40')
        out = tmp_path / 'r.md'
        generate_report([chain], events, out)
        content = out.read_text()
        assert '10.20.30.40' in content

    def test_no_crash_with_no_mitre_techniques(self, tmp_path):
        chain, events = _make_chain()
        chain.mitre_techniques = []
        out = tmp_path / 'r.md'
        generate_report([chain], events, out)  # must not raise
        assert out.exists()
