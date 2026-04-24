"""
RED-phase tests for 6 confirmed bugs.

These tests are written BEFORE any fix is applied and are expected to FAIL.
Do NOT modify src/ files — only this test file was created.

Bug inventory:
  Bug 1 — SHA-256 stem collision: two log files with the same filename in
           different directories overwrite each other's .sha256 record.
  Bug 2 — _SUCCESS_TYPES divergence: 'Audit Login' is missing from
           ingest.py's _SUCCESS_TYPES, so it never reaches severity 'critical'.
  Bug 3 — ip_failure_counts only counts 'Failed Login', not 'Invalid User',
           so brute-force via non-existent accounts is never escalated.
  Bug 4 — from_json() raises bare TypeError (not ValueError) for unknown keys.
  Bug 5 — Mermaid aliases are not sanitised for dots; '192.168.1.1' becomes
           '192.168.1.' which is invalid Mermaid syntax.
  Bug 6 — _classify_chain returns 'credential_stuffing' for success with no
           prior failures, which is incorrect.
"""

import re
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

# Make src/ importable — mirrors conftest.py
_src = str(Path(__file__).parent.parent / 'src')
if _src not in sys.path:
    sys.path.insert(0, _src)

from hunter import AttackChain, _classify_chain, build_attack_chains
from ingest import ingest
from reporter import generate_report
from schema import StandardEvent, from_json, make_event_id


# ── Shared helper ──────────────────────────────────────────────────────────────

def _make_event(
    event_type: str = 'Failed Login',
    ip: str = '1.2.3.4',
    user: str | None = 'root',
    ts: datetime | None = None,
    severity: str = 'low',
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
        pid=None,
    )


# ── Bug 1: SHA-256 stem collision ──────────────────────────────────────────────

class TestBug1Sha256StemCollision:
    """
    Two log files named 'auth.log' from different source directories must
    each produce a distinct .sha256 file when ingested into the same
    processed_dir.  Currently both map to 'auth.sha256' and the second
    silently overwrites the first chain-of-custody record.
    """

    def test_two_auth_logs_produce_two_distinct_sha256_files(self, tmp_path):
        # Arrange: two directories each holding a file called auth.log
        # with different content so their hashes differ.
        dir_a = tmp_path / 'logs'
        dir_b = tmp_path / 'backup'
        dir_a.mkdir()
        dir_b.mkdir()

        log_a = dir_a / 'auth.log'
        log_b = dir_b / 'auth.log'
        processed = tmp_path / 'processed'

        log_a.write_text(
            "Apr 23 10:00:00 server1 sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2\n",
            encoding='utf-8',
        )
        log_b.write_text(
            "Apr 23 10:00:00 server2 sshd[2]: Failed password for admin from 2.2.2.2 port 22 ssh2\n",
            encoding='utf-8',
        )

        # Act
        ingest(log_a, processed_dir=processed)
        ingest(log_b, processed_dir=processed)

        # Assert: two distinct .sha256 files must exist (not one)
        sha256_files = list(processed.glob('*.sha256'))
        assert len(sha256_files) == 2, (
            f'Expected 2 distinct .sha256 files but found {len(sha256_files)}: '
            f'{[f.name for f in sha256_files]}. '
            f'ingest.py uses log_path.stem as the key, so two files named '
            f'"auth.log" from different directories collide on "auth.sha256".'
        )

        # The two hash files must contain different hashes (different content)
        hashes = [f.read_text(encoding='utf-8').strip() for f in sha256_files]
        assert hashes[0] != hashes[1], (
            'Both .sha256 files contain the same hash — the second ingest '
            'overwrote the first chain-of-custody record.'
        )


# ── Bug 2: Audit Login severity never reaches 'critical' ──────────────────────

class TestBug2AuditLoginSeverity:
    """
    hunter.py _SUCCESS_TYPES includes 'Audit Login', but ingest.py
    _SUCCESS_TYPES does not.  An 'Audit Login' event occurring after 5+
    failures from the same IP should be severity 'critical'.  Currently
    _compute_severity() returns 'info' because the event_type falls through
    to the static auditd branch instead of the success-type escalation path.
    """

    def test_audit_login_after_brute_force_is_critical(self, tmp_path):
        # Arrange: build a raw audit.log with 6 USER_AUTH failures from
        # 10.0.0.1, then a LOGIN record (which the audit parser maps to
        # 'Audit Login').  The hostname/addr field carries the IP.
        audit_lines: list[str] = []
        base_ts = 1714000000.0

        for i in range(6):
            t = base_ts + i
            audit_lines.append(
                f'type=USER_AUTH msg=audit({t:.3f}:{i + 1}): '
                f'pid=100{i} uid=0 auid=4294967295 ses=4294967295 '
                f'msg=\'op=PAM:authentication acct="root" exe="/usr/sbin/sshd" '
                f'hostname=10.0.0.1 addr=10.0.0.1 terminal=ssh res=failed\''
            )

        # type=USER_LOGIN maps to 'Audit Login' in the audit parser
        login_ts = base_ts + 10
        audit_lines.append(
            f'type=USER_LOGIN msg=audit({login_ts:.3f}:100): '
            f'pid=9000 uid=0 auid=1000 ses=42 '
            f'msg=\'op=login acct="root" exe="/usr/sbin/sshd" '
            f'hostname=10.0.0.1 addr=10.0.0.1 terminal=ssh res=success\''
        )

        log = tmp_path / 'test_audit.log'
        log.write_text('\n'.join(audit_lines) + '\n', encoding='utf-8')

        # Act
        events = ingest(log, fmt='audit_log', processed_dir=tmp_path / 'proc')

        audit_login_events = [e for e in events if e.event_type == 'Audit Login']
        assert audit_login_events, (
            'No Audit Login events were parsed — verify the audit.log fixture '
            'format produces an event_type of "Audit Login".'
        )

        # Assert: after 5+ failures from same IP, Audit Login must be 'critical'
        login_event = audit_login_events[0]
        assert login_event.severity == 'critical', (
            f'Expected severity "critical" for Audit Login after 6 brute-force '
            f'failures, got "{login_event.severity}". '
            f'ingest.py _SUCCESS_TYPES must include "Audit Login".'
        )


# ── Bug 3: ip_failure_counts ignores 'Invalid User' ───────────────────────────

class TestBug3InvalidUserNotCounted:
    """
    ingest.py's first-pass loop only increments ip_failure_counts when
    event_type == 'Failed Login'.  An attacker sending 20 'Invalid User'
    events followed by an 'Accepted Password' will not have the success
    event escalated to 'critical'.  Honeypots log non-existent accounts as
    'Invalid User', not 'Failed Login'.
    """

    def test_accepted_password_after_invalid_user_flood_is_critical(self, tmp_path):
        # Arrange: 20 "Invalid user" lines from 10.0.0.2, then 1 accepted login.
        lines = [
            f'Apr 23 10:{i:02d}:00 server1 sshd[{2000 + i}]: '
            f'Invalid user hacker from 10.0.0.2 port 22'
            for i in range(20)
        ]
        lines.append(
            'Apr 23 10:20:00 server1 sshd[2099]: '
            'Accepted password for admin from 10.0.0.2 port 22 ssh2'
        )

        log = tmp_path / 'invalid_user_flood.log'
        log.write_text('\n'.join(lines) + '\n', encoding='utf-8')

        # Act
        events = ingest(log, fmt='auth_log', processed_dir=tmp_path / 'proc')

        accepted = [e for e in events if e.event_type == 'Accepted Password']
        assert accepted, 'No Accepted Password event was parsed — check log fixture.'

        # Assert: 20 Invalid User failures from same IP → success must be critical
        assert accepted[0].severity == 'critical', (
            f'Expected severity "critical" for Accepted Password after 20 Invalid '
            f'User failures from same IP, got "{accepted[0].severity}". '
            f'ingest.py ip_failure_counts must also count "Invalid User" events.'
        )


# ── Bug 4: from_json raises TypeError instead of ValueError ───────────────────

class TestBug4FromJsonBadKeysRaisesValueError:
    """
    from_json({'unknown_field': 'foo'}) passes **d straight to
    StandardEvent(**d), which raises a bare TypeError with a message like
    '__init__() got an unexpected keyword argument "unknown_field"'.
    The public API should catch that and raise ValueError with a descriptive
    message containing 'Cannot deserialize'.
    """

    def test_from_json_bad_keys_raises_value_error(self):
        bad = {'unknown_field': 'foo'}
        with pytest.raises(ValueError, match='Cannot deserialize'):
            from_json(bad)

    def test_from_json_bad_keys_does_not_raise_bare_type_error(self):
        """The raw TypeError must be wrapped — not propagated to the caller."""
        bad = {'unknown_field': 'foo'}
        try:
            from_json(bad)
        except TypeError as exc:
            pytest.fail(
                f'from_json raised bare TypeError instead of ValueError: {exc}. '
                f'Wrap the StandardEvent(**d) call in a try/except TypeError '
                f'and re-raise as ValueError("Cannot deserialize ...").'
            )
        except ValueError:
            pass  # expected after the fix


# ── Bug 5: Mermaid aliases contain dots for IP-address hostnames ───────────────

class TestBug5MermaidAliasDotsInvalid:
    """
    reporter._mermaid_diagram() produces participant aliases via
    host.replace('-', '_')[:12].  An IP hostname like '192.168.1.1'
    becomes '192.168.1.' after the 12-char slice — dots are NOT replaced,
    yielding an alias that is syntactically invalid in Mermaid.
    """

    def _make_ip_chain(
        self, hostname: str = '192.168.1.1'
    ) -> tuple[AttackChain, list[StandardEvent]]:
        base = datetime(2024, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            StandardEvent(
                event_id=make_event_id(),
                timestamp=base + timedelta(minutes=i),
                event_type='Failed Login',
                source_actor={'ip': '10.0.0.9', 'user': 'root'},
                target_system={'hostname': hostname, 'process': 'sshd'},
                action_taken='Failed Login',
                severity='medium',
                mitre_technique={'id': 'T1110', 'name': 'Brute Force'},
                raw='',
                source_log='auth.log',
                log_format='auth_log',
                pid=None,
            )
            for i in range(3)
        ]
        chain = AttackChain(
            actor_ip='10.0.0.9',
            actor_user='root',
            severity='medium',
            mitre_techniques=[
                {'id': 'T1110', 'name': 'Brute Force', 'event_type': 'Failed Login'}
            ],
            events=events,
            chain_type='brute_force',
            compromised=False,
        )
        return chain, events

    def _extract_mermaid_block(self, report_content: str) -> str:
        assert '```mermaid' in report_content, 'No Mermaid block found in report.'
        return report_content.split('```mermaid')[1].split('```')[0]

    def test_mermaid_participant_alias_contains_no_dots(self, tmp_path):
        chain, events = self._make_ip_chain(hostname='192.168.1.1')
        out = tmp_path / 'report.md'
        generate_report([chain], events, out)

        mermaid = self._extract_mermaid_block(out.read_text(encoding='utf-8'))
        aliases = re.findall(r'participant\s+(\S+)\s+as', mermaid)

        for alias in aliases:
            assert '.' not in alias, (
                f'Mermaid participant alias "{alias}" contains a dot — invalid '
                f'Mermaid syntax. reporter.py must replace dots as well as hyphens '
                f'when building participant alias strings.'
            )

    def test_mermaid_arrow_target_alias_contains_no_dots(self, tmp_path):
        """Arrow lines (A->>alias: ...) must also use dot-free aliases."""
        chain, events = self._make_ip_chain(hostname='192.168.1.1')
        out = tmp_path / 'report.md'
        generate_report([chain], events, out)

        mermaid = self._extract_mermaid_block(out.read_text(encoding='utf-8'))
        # Arrow syntax: SomeAlias->>OtherAlias: label
        arrow_targets = re.findall(r'->>\s*(\S+)\s*:', mermaid)

        for alias in arrow_targets:
            if alias == 'A':
                continue  # the Attacker participant — always valid
            assert '.' not in alias, (
                f'Mermaid arrow target alias "{alias}" contains a dot. '
                f'The same sanitisation applied to participant declarations must '
                f'also be applied to per-event arrow targets in reporter.py.'
            )


# ── Bug 6: _classify_chain returns 'credential_stuffing' for lone success ──────

class TestBug6ClassifyChainLoneSuccess:
    """
    _classify_chain's fallback branch `if has_success` (line 71 in hunter.py)
    returns ('credential_stuffing', True) regardless of whether there were
    any prior failures.  A clean successful login with NO failures is not
    credential stuffing.
    """

    def test_single_accepted_password_is_not_credential_stuffing(self):
        events = [_make_event('Accepted Password', ip='5.5.5.5', user='alice')]
        chain_type, compromised = _classify_chain(events)
        assert chain_type != 'credential_stuffing', (
            f'_classify_chain returned "credential_stuffing" for a lone successful '
            f'login with no prior failures (chain_type="{chain_type}"). '
            f'A successful login without preceding failures is not credential '
            f'stuffing — hunter.py must add a has_failures guard to the bare '
            f'"if has_success" branch.'
        )

    def test_lone_success_classify_returns_sensible_type(self):
        """A lone success should be classified as something other than brute_force too."""
        events = [_make_event('Accepted Password', ip='5.5.5.5', user='alice')]
        chain_type, compromised = _classify_chain(events)
        # It should indicate a compromise occurred but not be labelled
        # credential_stuffing when there are no failures.
        assert compromised is True, (
            'A successful login must set compromised=True regardless of classification.'
        )
        assert chain_type != 'credential_stuffing', (
            f'Got chain_type="{chain_type}" — must not be "credential_stuffing" '
            f'without prior failures.'
        )

    def test_success_with_failures_remains_credential_stuffing(self):
        """Positive control: failures + success IS credential stuffing."""
        base = datetime(2024, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event('Failed Login', ip='6.6.6.6', ts=base + timedelta(minutes=i))
            for i in range(5)
        ]
        events.append(
            _make_event('Accepted Password', ip='6.6.6.6', ts=base + timedelta(minutes=10))
        )
        chain_type, compromised = _classify_chain(events)
        assert chain_type == 'credential_stuffing'
        assert compromised is True
