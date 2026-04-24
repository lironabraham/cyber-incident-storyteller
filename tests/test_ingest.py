"""Tests for src/ingest.py"""

import json
from datetime import timezone
from pathlib import Path

import pytest

from ingest import ingest, verify_integrity
from schema import StandardEvent


class TestIngest:
    def test_returns_list_of_standard_events(self, sample_log, tmp_path):
        events = ingest(sample_log, processed_dir=tmp_path)
        assert isinstance(events, list)
        assert all(isinstance(e, StandardEvent) for e in events)

    def test_no_events_from_empty_log(self, empty_log, tmp_path):
        events = ingest(empty_log, processed_dir=tmp_path)
        assert events == []

    def test_events_have_utc_timestamps(self, sample_log, tmp_path):
        events = ingest(sample_log, processed_dir=tmp_path)
        for e in events:
            assert e.timestamp.tzinfo is not None
            assert e.timestamp.tzinfo == timezone.utc

    def test_source_log_name_stored(self, sample_log, tmp_path):
        events = ingest(sample_log, processed_dir=tmp_path)
        assert all(e.source_log == sample_log.name for e in events)

    def test_log_format_stored(self, sample_log, tmp_path):
        events = ingest(sample_log, processed_dir=tmp_path)
        assert all(e.log_format == 'auth_log' for e in events)

    def test_source_actor_populated(self, sample_log, tmp_path):
        events = ingest(sample_log, processed_dir=tmp_path)
        failed = [e for e in events if e.event_type == 'Failed Login']
        assert failed  # fixture must have at least one
        for e in failed:
            assert e.source_actor.get('ip') is not None
            assert e.source_actor.get('user') is not None

    def test_mitre_technique_populated_for_failed_login(self, sample_log, tmp_path):
        events = ingest(sample_log, processed_dir=tmp_path)
        failed = next(e for e in events if e.event_type == 'Failed Login')
        assert failed.mitre_technique['id'] == 'T1110'

    def test_pid_extracted_from_raw(self, sample_log, tmp_path):
        events = ingest(sample_log, processed_dir=tmp_path)
        # Sample log lines include PIDs like sshd[1234]
        pids = [e.pid for e in events if e.pid is not None]
        assert len(pids) > 0

    def test_raw_line_preserved(self, sample_log, tmp_path):
        events = ingest(sample_log, processed_dir=tmp_path)
        for e in events:
            assert len(e.raw) > 0

    def test_log_file_not_modified(self, sample_log, tmp_path):
        original_content = sample_log.read_text()
        ingest(sample_log, processed_dir=tmp_path)
        assert sample_log.read_text() == original_content

    def test_sha256_file_created(self, sample_log, tmp_path):
        ingest(sample_log, processed_dir=tmp_path)
        sha256_files = list(tmp_path.glob(f'{sample_log.stem}_*.sha256'))
        assert len(sha256_files) == 1
        assert len(sha256_files[0].read_text().strip()) == 64  # SHA-256 hex length

    def test_json_file_created(self, sample_log, tmp_path):
        ingest(sample_log, processed_dir=tmp_path)
        json_files = list(tmp_path.glob(f'{sample_log.stem}_*.json'))
        assert len(json_files) == 1

    def test_json_file_is_valid(self, sample_log, tmp_path):
        ingest(sample_log, processed_dir=tmp_path)
        json_file = next(tmp_path.glob(f'{sample_log.stem}_*.json'))
        data = json.loads(json_file.read_text())
        assert isinstance(data, list)

    def test_json_round_trip_preserves_event_type(self, sample_log, tmp_path):
        events = ingest(sample_log, processed_dir=tmp_path)
        json_file = next(tmp_path.glob(f'{sample_log.stem}_*.json'))
        data = json.loads(json_file.read_text())
        original_types = [e.event_type for e in events]
        json_types = [d['event_type'] for d in data]
        assert original_types == json_types


class TestContextualSeverity:
    """Severity must be computed from context, not just event type."""

    def test_single_failed_login_is_low(self, tmp_path):
        # Only 1 failure from this IP → low
        lines = [
            "Apr 23 10:00:00 server1 sshd[100]: Failed password for root from 9.9.9.9 port 22 ssh2"
        ]
        log = tmp_path / "single.log"
        log.write_text('\n'.join(lines), encoding='utf-8')
        events = ingest(log, processed_dir=tmp_path / 'proc')
        failed = [e for e in events if e.event_type == 'Failed Login']
        assert failed[0].severity == 'low'

    def test_five_failures_escalates_to_medium(self, tmp_path):
        lines = [
            f"Apr 23 10:0{i}:00 server1 sshd[10{i}]: Failed password for root from 9.9.9.9 port 22 ssh2"
            for i in range(5)
        ]
        log = tmp_path / "five.log"
        log.write_text('\n'.join(lines), encoding='utf-8')
        events = ingest(log, processed_dir=tmp_path / 'proc')
        # The 5th failed login (cumulative count == 5) must be medium
        failed = [e for e in events if e.event_type == 'Failed Login']
        sevs = [e.severity for e in failed]
        assert 'medium' in sevs

    def test_successful_login_after_brute_force_is_critical(self, brute_force_log, tmp_path):
        events = ingest(brute_force_log, processed_dir=tmp_path)
        success = [e for e in events if e.event_type == 'Accepted Password']
        assert len(success) == 1
        assert success[0].severity == 'critical'

    def test_sudo_command_is_high(self, sample_log, tmp_path):
        events = ingest(sample_log, processed_dir=tmp_path)
        sudo = [e for e in events if e.event_type == 'Sudo Command']
        assert sudo  # sample log has a sudo line
        assert all(e.severity == 'high' for e in sudo)

    def test_session_events_are_info(self, sample_log, tmp_path):
        events = ingest(sample_log, processed_dir=tmp_path)
        sessions = [e for e in events if e.event_type in ('Session Opened', 'Session Closed')]
        assert all(e.severity == 'info' for e in sessions)


class TestVerifyIntegrity:
    def test_returns_true_for_unmodified_log(self, sample_log, tmp_path):
        ingest(sample_log, processed_dir=tmp_path)
        assert verify_integrity(sample_log, processed_dir=tmp_path) is True

    def test_returns_false_when_no_hash_file(self, sample_log, tmp_path):
        assert verify_integrity(sample_log, processed_dir=tmp_path) is False

    def test_returns_false_after_modification(self, sample_log, tmp_path):
        ingest(sample_log, processed_dir=tmp_path)
        # Tamper with the log
        sample_log.write_text(
            sample_log.read_text() + '\nAPR 23 99:99:99 TAMPERED\n',
            encoding='utf-8',
        )
        assert verify_integrity(sample_log, processed_dir=tmp_path) is False

    def test_accepts_string_path(self, sample_log, tmp_path):
        ingest(sample_log, processed_dir=tmp_path)
        assert verify_integrity(str(sample_log), processed_dir=tmp_path) is True
