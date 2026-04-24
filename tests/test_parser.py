"""Tests for src/parser.py"""

import pytest
import pandas as pd
from pathlib import Path

from parser import _classify_message, parse_log, SUPPORTED_FORMATS


# ── _classify_message ──────────────────────────────────────────────────────────

class TestClassifyMessage:
    def test_failed_password_for_valid_user(self):
        et, user, ip = _classify_message("Failed password for root from 1.2.3.4 port 22 ssh2")
        assert et == 'Failed Login'
        assert user == 'root'
        assert ip == '1.2.3.4'

    def test_failed_password_for_invalid_user(self):
        et, user, ip = _classify_message("Failed password for invalid user admin from 5.6.7.8 port 22 ssh2")
        assert et == 'Failed Login'
        assert user == 'admin'
        assert ip == '5.6.7.8'

    def test_accepted_password(self):
        et, user, ip = _classify_message("Accepted password for alice from 10.0.0.1 port 22 ssh2")
        assert et == 'Accepted Password'
        assert user == 'alice'
        assert ip == '10.0.0.1'

    def test_accepted_publickey(self):
        et, user, ip = _classify_message("Accepted publickey for bob from 10.0.0.2 port 22 ssh2")
        assert et == 'Accepted Publickey'
        assert user == 'bob'
        assert ip == '10.0.0.2'

    def test_invalid_user(self):
        et, user, ip = _classify_message("Invalid user nobody from 9.8.7.6 port 22")
        assert et == 'Invalid User'
        assert user == 'nobody'
        assert ip == '9.8.7.6'

    def test_connection_closed_invalid_user(self):
        et, user, ip = _classify_message(
            "Connection closed by invalid user nobody 9.8.7.6 port 22"
        )
        assert et == 'Connection Closed'
        assert ip == '9.8.7.6'

    def test_connection_closed_known_user(self):
        et, user, ip = _classify_message("Connection closed by 10.0.0.5 port 22")
        assert et == 'Connection Closed'
        assert ip == '10.0.0.5'

    def test_disconnected_invalid_user(self):
        et, user, ip = _classify_message(
            "Disconnected from invalid user testuser 1.1.1.1 port 22"
        )
        assert et == 'Disconnected'
        assert ip == '1.1.1.1'

    def test_session_opened(self):
        et, user, ip = _classify_message(
            "pam_unix(sshd:session): session opened for user alice by (uid=0)"
        )
        assert et == 'Session Opened'
        assert user == 'alice'
        assert ip is None

    def test_session_closed(self):
        et, user, ip = _classify_message(
            "pam_unix(sshd:session): session closed for user alice"
        )
        assert et == 'Session Closed'
        assert user == 'alice'
        assert ip is None

    def test_sudo_command(self):
        et, user, ip = _classify_message(
            "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls"
        )
        assert et == 'Sudo Command'
        assert user == 'alice'
        assert ip is None

    def test_auth_failure(self):
        et, user, ip = _classify_message(
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 tty=ssh "
            "ruser= rhost=2.3.4.5  user=mallory"
        )
        assert et == 'Auth Failure'
        assert user == 'mallory'

    def test_unclassified_returns_other(self):
        et, user, ip = _classify_message("Some random kernel message")
        assert et == 'Other'
        assert user is None
        assert ip is None

    def test_ipv6_address(self):
        et, user, ip = _classify_message(
            "Failed password for root from ::1 port 22 ssh2"
        )
        assert et == 'Failed Login'
        assert ip == '::1'


# ── parse_log ─────────────────────────────────────────────────────────────────

class TestParseLog:
    def test_raises_for_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            parse_log(tmp_path / 'nonexistent.log')

    def test_raises_for_unsupported_format(self, sample_log):
        with pytest.raises(ValueError, match="Unsupported format"):
            parse_log(sample_log, fmt='cloudtrail')

    def test_returns_dataframe(self, sample_log):
        df = parse_log(sample_log)
        assert isinstance(df, pd.DataFrame)

    def test_expected_columns(self, sample_log):
        df = parse_log(sample_log)
        expected = {'timestamp', 'hostname', 'process', 'event_type', 'source_ip', 'user', 'raw'}
        assert expected == set(df.columns)

    def test_malformed_lines_skipped(self, sample_log):
        # The fixture has one malformed line; it must not appear in results
        df = parse_log(sample_log)
        assert not df['raw'].str.contains("this is not a valid").any()

    def test_event_types_present(self, sample_log):
        df = parse_log(sample_log)
        types = set(df['event_type'])
        assert 'Failed Login' in types
        assert 'Accepted Password' in types
        assert 'Accepted Publickey' in types
        assert 'Session Opened' in types
        assert 'Sudo Command' in types

    def test_timestamps_are_datetime(self, sample_log):
        df = parse_log(sample_log)
        assert pd.api.types.is_datetime64_any_dtype(df['timestamp'])

    def test_sorted_by_timestamp(self, sample_log):
        df = parse_log(sample_log)
        ts = df['timestamp'].dropna()
        assert ts.is_monotonic_increasing

    def test_empty_log_returns_empty_dataframe(self, empty_log):
        df = parse_log(empty_log)
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 0

    def test_hostname_parsed(self, sample_log):
        df = parse_log(sample_log)
        assert (df['hostname'] == 'server1').all()

    def test_source_ip_parsed(self, sample_log):
        df = parse_log(sample_log)
        failed = df[df['event_type'] == 'Failed Login']
        assert not failed['source_ip'].isna().any()

    def test_user_parsed_for_failed_login(self, sample_log):
        df = parse_log(sample_log)
        failed = df[df['event_type'] == 'Failed Login']
        assert not failed['user'].isna().any()

    def test_path_accepts_string(self, sample_log):
        df = parse_log(str(sample_log))
        assert len(df) > 0

    def test_supported_formats_dict(self):
        assert 'auth_log' in SUPPORTED_FORMATS

    def test_brute_force_log_counts(self, brute_force_log):
        df = parse_log(brute_force_log)
        assert (df['event_type'] == 'Failed Login').sum() == 10
        assert (df['event_type'] == 'Accepted Password').sum() == 1
