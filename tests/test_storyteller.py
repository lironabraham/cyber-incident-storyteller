"""Tests for src/storyteller.py"""

import pytest
import pandas as pd

from parser import parse_log
from storyteller import (
    ThreatActor,
    IncidentReport,
    analyze,
    generate_narrative,
    report,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_df(rows: list[dict]) -> pd.DataFrame:
    """Build a minimal events DataFrame from a list of dicts."""
    cols = ['timestamp', 'hostname', 'process', 'event_type', 'source_ip', 'user', 'raw']
    base = {c: None for c in cols}
    records = [{**base, **r} for r in rows]
    df = pd.DataFrame(records, columns=cols)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df


# ── ThreatActor ────────────────────────────────────────────────────────────────

class TestThreatActor:
    def _actor(self, failed=0, successful=0):
        return ThreatActor(
            ip='1.2.3.4',
            failed_attempts=failed,
            successful_logins=successful,
            targeted_users=[],
            first_seen=pd.Timestamp('2024-01-01 10:00:00'),
            last_seen=pd.Timestamp('2024-01-01 10:05:00'),
        )

    def test_is_successful_true(self):
        assert self._actor(failed=3, successful=1).is_successful

    def test_is_successful_false(self):
        assert not self._actor(failed=3, successful=0).is_successful

    def test_is_brute_force_at_threshold(self):
        assert self._actor(failed=5).is_brute_force

    def test_is_brute_force_below_threshold(self):
        assert not self._actor(failed=4).is_brute_force

    def test_is_brute_force_above_threshold(self):
        assert self._actor(failed=100).is_brute_force


# ── analyze ────────────────────────────────────────────────────────────────────

class TestAnalyze:
    def test_empty_df_returns_report(self):
        df = pd.DataFrame(columns=['timestamp', 'hostname', 'process',
                                   'event_type', 'source_ip', 'user', 'raw'])
        inc = analyze(df)
        assert isinstance(inc, IncidentReport)
        assert inc.total_events == 0
        assert inc.threat_actors == []

    def test_total_events(self, sample_log):
        df = parse_log(sample_log)
        inc = analyze(df, log_path='test.log')
        assert inc.total_events == len(df)

    def test_log_path_stored(self, sample_log):
        df = parse_log(sample_log)
        inc = analyze(df, log_path='custom/path.log')
        assert inc.log_path == 'custom/path.log'

    def test_start_end_time(self, sample_log):
        df = parse_log(sample_log)
        inc = analyze(df)
        assert inc.start_time == df['timestamp'].min()
        assert inc.end_time == df['timestamp'].max()

    def test_event_counts_present(self, sample_log):
        df = parse_log(sample_log)
        inc = analyze(df)
        assert 'Failed Login' in inc.event_counts
        assert inc.event_counts['Failed Login'] > 0

    def test_affected_users_list(self, sample_log):
        df = parse_log(sample_log)
        inc = analyze(df)
        assert 'alice' in inc.affected_users

    def test_threat_actors_detected(self, brute_force_log):
        df = parse_log(brute_force_log)
        inc = analyze(df)
        assert len(inc.threat_actors) == 1
        actor = inc.threat_actors[0]
        assert actor.ip == '9.9.9.9'
        assert actor.failed_attempts == 10
        assert actor.successful_logins == 1
        assert actor.is_successful
        assert actor.is_brute_force

    def test_recommendations_not_empty(self, sample_log):
        df = parse_log(sample_log)
        inc = analyze(df)
        assert len(inc.recommendations) > 0

    def test_brute_force_recommendation(self, brute_force_log):
        df = parse_log(brute_force_log)
        inc = analyze(df)
        recs_text = ' '.join(inc.recommendations).lower()
        assert 'block' in recs_text or 'brute' in recs_text

    def test_root_login_recommendation(self, brute_force_log):
        df = parse_log(brute_force_log)
        inc = analyze(df)
        recs_text = ' '.join(inc.recommendations).lower()
        assert 'root' in recs_text

    def test_no_threats_gives_monitoring_recommendation(self):
        df = _make_df([{
            'timestamp': '2024-01-01 10:00:00',
            'event_type': 'Session Opened',
            'user': 'alice',
        }])
        inc = analyze(df)
        assert any('monitoring' in r.lower() for r in inc.recommendations)

    def test_threat_actors_sorted_by_severity(self):
        df = _make_df([
            {'timestamp': '2024-01-01 10:00:00', 'event_type': 'Failed Login',
             'source_ip': '1.1.1.1', 'user': 'root'},
            {'timestamp': '2024-01-01 10:01:00', 'event_type': 'Failed Login',
             'source_ip': '2.2.2.2', 'user': 'root'},
            {'timestamp': '2024-01-01 10:02:00', 'event_type': 'Accepted Password',
             'source_ip': '2.2.2.2', 'user': 'root'},
        ])
        inc = analyze(df)
        # 2.2.2.2 has a successful login → should appear first
        assert inc.threat_actors[0].ip == '2.2.2.2'

    def test_ip_with_no_login_events_excluded(self):
        df = _make_df([
            {'timestamp': '2024-01-01 10:00:00', 'event_type': 'Connection Closed',
             'source_ip': '3.3.3.3'},
        ])
        inc = analyze(df)
        # Connection Closed from 3.3.3.3 has no failed/successful count → not a threat actor
        assert all(a.ip != '3.3.3.3' for a in inc.threat_actors)


# ── generate_narrative ─────────────────────────────────────────────────────────

class TestGenerateNarrative:
    def test_returns_string(self, sample_log):
        df = parse_log(sample_log)
        text = generate_narrative(analyze(df))
        assert isinstance(text, str)
        assert len(text) > 0

    def test_contains_header(self, sample_log):
        df = parse_log(sample_log)
        text = generate_narrative(analyze(df))
        assert 'CYBER INCIDENT REPORT' in text

    def test_contains_event_breakdown(self, sample_log):
        df = parse_log(sample_log)
        text = generate_narrative(analyze(df))
        assert 'EVENT BREAKDOWN' in text

    def test_contains_threat_actors(self, brute_force_log):
        df = parse_log(brute_force_log)
        text = generate_narrative(analyze(df))
        assert 'THREAT ACTORS' in text
        assert '9.9.9.9' in text

    def test_contains_recommendations(self, sample_log):
        df = parse_log(sample_log)
        text = generate_narrative(analyze(df))
        assert 'RECOMMENDATIONS' in text

    def test_alert_shown_for_successful_breach(self, brute_force_log):
        df = parse_log(brute_force_log)
        text = generate_narrative(analyze(df))
        assert 'ALERT' in text or 'COMPROMISED' in text

    def test_empty_log_graceful_message(self, empty_log):
        df = parse_log(empty_log)
        text = generate_narrative(analyze(df))
        assert 'No events' in text

    def test_contains_log_path(self, sample_log):
        df = parse_log(sample_log)
        text = generate_narrative(analyze(df, log_path='my/test.log'))
        assert 'my/test.log' in text


# ── report convenience function ────────────────────────────────────────────────

class TestReportConvenience:
    def test_report_equals_analyze_then_narrative(self, sample_log):
        df = parse_log(sample_log)
        expected = generate_narrative(analyze(df, log_path='auth.log'))
        actual = report(df, log_path='auth.log')
        assert actual == expected

    def test_report_returns_string(self, sample_log):
        df = parse_log(sample_log)
        assert isinstance(report(df), str)
