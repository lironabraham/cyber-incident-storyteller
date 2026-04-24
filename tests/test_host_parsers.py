"""Tests for the three new host log parsers: syslog, audit_log, web_access."""

import pytest
import pandas as pd
from pathlib import Path

from parser import parse_log, SUPPORTED_FORMATS


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _write(tmp_path, name, lines):
    p = tmp_path / name
    p.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return p


def _types(df):
    return set(df['event_type'])


# ══════════════════════════════════════════════════════════════════════════════
# SYSLOG
# ══════════════════════════════════════════════════════════════════════════════

class TestSyslogFormat:
    def test_format_registered(self):
        assert 'syslog' in SUPPORTED_FORMATS

    def test_returns_dataframe(self, syslog_log):
        df = parse_log(syslog_log, fmt='syslog')
        assert isinstance(df, pd.DataFrame)

    def test_expected_columns(self, syslog_log):
        df = parse_log(syslog_log, fmt='syslog')
        expected = {'timestamp', 'hostname', 'process', 'event_type', 'source_ip', 'user', 'raw'}
        assert expected == set(df.columns)

    def test_service_started_detected(self, syslog_log):
        df = parse_log(syslog_log, fmt='syslog')
        assert 'Service Started' in _types(df)

    def test_service_stopped_detected(self, syslog_log):
        df = parse_log(syslog_log, fmt='syslog')
        assert 'Service Stopped' in _types(df)

    def test_service_failed_detected(self, syslog_log):
        df = parse_log(syslog_log, fmt='syslog')
        assert 'Service Failed' in _types(df)

    def test_cron_execution_detected(self, syslog_log):
        df = parse_log(syslog_log, fmt='syslog')
        assert 'Cron Execution' in _types(df)

    def test_cron_user_extracted(self, syslog_log):
        df = parse_log(syslog_log, fmt='syslog')
        cron = df[df['event_type'] == 'Cron Execution']
        assert not cron.empty
        assert not cron['user'].isna().all()

    def test_oom_kill_detected(self, syslog_log):
        df = parse_log(syslog_log, fmt='syslog')
        assert 'OOM Kill' in _types(df)

    def test_usb_connected_detected(self, syslog_log):
        df = parse_log(syslog_log, fmt='syslog')
        assert 'USB Connected' in _types(df)

    def test_malformed_lines_skipped(self, tmp_path):
        log = _write(tmp_path, 'bad_syslog.log', [
            'this is not a valid syslog line',
            '',
            'Apr 24 09:00:00 server1 systemd[1]: Started nginx.service.',
        ])
        df = parse_log(log, fmt='syslog')
        assert len(df) == 1

    def test_sorted_by_timestamp(self, syslog_log):
        df = parse_log(syslog_log, fmt='syslog')
        ts = df['timestamp'].dropna()
        assert ts.is_monotonic_increasing

    def test_empty_log_returns_empty_df(self, empty_log):
        df = parse_log(empty_log, fmt='syslog')
        assert len(df) == 0

    def test_unrecognised_message_is_other(self, tmp_path):
        log = _write(tmp_path, 's.log', [
            'Apr 24 10:00:00 host1 daemon[1]: some completely unknown message here'
        ])
        df = parse_log(log, fmt='syslog')
        assert df.iloc[0]['event_type'] == 'Other'

    def test_service_started_inline(self, tmp_path):
        log = _write(tmp_path, 's.log', [
            'Apr 24 10:00:00 server1 systemd[1]: Started ssh.service.'
        ])
        df = parse_log(log, fmt='syslog')
        assert df.iloc[0]['event_type'] == 'Service Started'


# ══════════════════════════════════════════════════════════════════════════════
# AUDITD
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditLogFormat:
    def test_format_registered(self):
        assert 'audit_log' in SUPPORTED_FORMATS

    def test_returns_dataframe(self, audit_log):
        df = parse_log(audit_log, fmt='audit_log')
        assert isinstance(df, pd.DataFrame)

    def test_expected_columns(self, audit_log):
        df = parse_log(audit_log, fmt='audit_log')
        expected = {'timestamp', 'hostname', 'process', 'event_type', 'source_ip', 'user', 'raw'}
        assert expected == set(df.columns)

    def test_audit_login_success_detected(self, audit_log):
        df = parse_log(audit_log, fmt='audit_log')
        assert 'Audit Login' in _types(df)

    def test_audit_auth_failure_detected(self, audit_log):
        df = parse_log(audit_log, fmt='audit_log')
        assert 'Audit Auth Failure' in _types(df)

    def test_process_execution_detected(self, audit_log):
        df = parse_log(audit_log, fmt='audit_log')
        assert 'Process Execution' in _types(df)

    def test_shell_execution_detected(self, audit_log):
        df = parse_log(audit_log, fmt='audit_log')
        assert 'Shell Execution' in _types(df)

    def test_file_access_detected(self, audit_log):
        df = parse_log(audit_log, fmt='audit_log')
        assert 'File Access' in _types(df)

    def test_execve_command_in_user_field(self, audit_log):
        df = parse_log(audit_log, fmt='audit_log')
        execs = df[df['event_type'] == 'Process Execution']
        assert not execs.empty
        # Command (a0) is stored in user field for routing
        assert not execs['user'].isna().all()

    def test_ip_extracted_for_login(self, audit_log):
        df = parse_log(audit_log, fmt='audit_log')
        logins = df[df['event_type'] == 'Audit Login']
        assert not logins.empty
        assert not logins['source_ip'].isna().all()

    def test_timestamp_is_datetime(self, audit_log):
        df = parse_log(audit_log, fmt='audit_log')
        assert pd.api.types.is_datetime64_any_dtype(df['timestamp'])

    def test_epoch_timestamp_parsed(self, tmp_path):
        log = _write(tmp_path, 'a.log', [
            'type=USER_LOGIN msg=audit(1714000000.000:100): pid=1 uid=0 msg=\'acct="user1" hostname=1.2.3.4 addr=1.2.3.4 res=success\''
        ])
        df = parse_log(log, fmt='audit_log')
        assert len(df) == 1
        ts = df.iloc[0]['timestamp']
        assert not pd.isna(ts)

    def test_malformed_lines_skipped(self, tmp_path):
        log = _write(tmp_path, 'a.log', [
            'this is not auditd format',
            'type=USER_LOGIN msg=audit(1714000000.000:1): pid=1 uid=0 msg=\'acct="u" hostname=1.1.1.1 addr=1.1.1.1 res=success\'',
        ])
        df = parse_log(log, fmt='audit_log')
        assert len(df) == 1

    def test_question_mark_hostname_excluded(self, tmp_path):
        log = _write(tmp_path, 'a.log', [
            'type=USER_AUTH msg=audit(1714000000.000:1): pid=1 uid=0 msg=\'acct="root" hostname=? addr=? res=failed\'',
        ])
        df = parse_log(log, fmt='audit_log')
        assert df.iloc[0]['source_ip'] is None

    def test_sorted_by_timestamp(self, audit_log):
        df = parse_log(audit_log, fmt='audit_log')
        ts = df['timestamp'].dropna()
        assert ts.is_monotonic_increasing


# ══════════════════════════════════════════════════════════════════════════════
# WEB ACCESS
# ══════════════════════════════════════════════════════════════════════════════

class TestWebAccessFormat:
    def test_format_registered(self):
        assert 'web_access' in SUPPORTED_FORMATS

    def test_returns_dataframe(self, web_log):
        df = parse_log(web_log, fmt='web_access')
        assert isinstance(df, pd.DataFrame)

    def test_expected_columns(self, web_log):
        df = parse_log(web_log, fmt='web_access')
        expected = {'timestamp', 'hostname', 'process', 'event_type', 'source_ip', 'user', 'raw'}
        assert expected == set(df.columns)

    def test_tool_fingerprint_detected(self, web_log):
        df = parse_log(web_log, fmt='web_access')
        assert 'Tool Fingerprint' in _types(df)

    def test_web_attack_path_traversal(self, web_log):
        df = parse_log(web_log, fmt='web_access')
        assert 'Web Attack' in _types(df)

    def test_admin_access_detected(self, web_log):
        df = parse_log(web_log, fmt='web_access')
        assert 'Admin Access' in _types(df)

    def test_web_shell_detected(self, web_log):
        df = parse_log(web_log, fmt='web_access')
        assert 'Web Shell' in _types(df)

    def test_web_scan_from_404s(self, web_log):
        df = parse_log(web_log, fmt='web_access')
        # Attacker IP hits 5+ 404s → should produce Web Scan events
        assert 'Web Scan' in _types(df)

    def test_ip_extracted(self, web_log):
        df = parse_log(web_log, fmt='web_access')
        assert not df['source_ip'].isna().all()

    def test_timestamp_is_datetime(self, web_log):
        df = parse_log(web_log, fmt='web_access')
        assert pd.api.types.is_datetime64_any_dtype(df['timestamp'])

    def test_timestamp_utc_aware(self, web_log):
        df = parse_log(web_log, fmt='web_access')
        ts = df['timestamp'].dropna().iloc[0]
        assert ts.tzinfo is not None

    def test_malformed_lines_skipped(self, tmp_path):
        log = _write(tmp_path, 'w.log', [
            'not a web log line',
            '1.2.3.4 - - [24/Apr/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
        ])
        df = parse_log(log, fmt='web_access')
        assert len(df) == 1

    def test_normal_request_is_web_request(self, tmp_path):
        log = _write(tmp_path, 'w.log', [
            '10.0.0.1 - - [24/Apr/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        ])
        df = parse_log(log, fmt='web_access')
        assert df.iloc[0]['event_type'] == 'Web Request'

    def test_sqlmap_ua_is_tool_fingerprint(self, tmp_path):
        log = _write(tmp_path, 'w.log', [
            '1.2.3.4 - - [24/Apr/2024:10:00:00 +0000] "GET /login HTTP/1.1" 200 512 "-" "sqlmap/1.4.7"',
        ])
        df = parse_log(log, fmt='web_access')
        assert df.iloc[0]['event_type'] == 'Tool Fingerprint'

    def test_path_traversal_is_web_attack(self, tmp_path):
        log = _write(tmp_path, 'w.log', [
            '1.2.3.4 - - [24/Apr/2024:10:00:00 +0000] "GET /../../etc/passwd HTTP/1.1" 404 0 "-" "curl/7.68"',
        ])
        df = parse_log(log, fmt='web_access')
        assert df.iloc[0]['event_type'] == 'Web Attack'

    def test_post_php_200_is_web_shell(self, tmp_path):
        log = _write(tmp_path, 'w.log', [
            '1.2.3.4 - - [24/Apr/2024:10:00:00 +0000] "POST /uploads/shell.php HTTP/1.1" 200 128 "-" "python-requests/2.25"',
        ])
        df = parse_log(log, fmt='web_access')
        assert df.iloc[0]['event_type'] == 'Web Shell'

    def test_five_404s_upgrades_to_web_scan(self, tmp_path):
        base = '1.2.3.4 - - [24/Apr/2024:10:00:0{} +0000] "GET /path{} HTTP/1.1" 404 0 "-" "curl/7.68"'
        lines = [base.format(i, i) for i in range(5)]
        log = _write(tmp_path, 'w.log', lines)
        df = parse_log(log, fmt='web_access')
        assert (df['event_type'] == 'Web Scan').any()

    def test_four_404s_stays_web_request(self, tmp_path):
        base = '1.2.3.4 - - [24/Apr/2024:10:00:0{} +0000] "GET /path{} HTTP/1.1" 404 0 "-" "curl/7.68"'
        lines = [base.format(i, i) for i in range(4)]
        log = _write(tmp_path, 'w.log', lines)
        df = parse_log(log, fmt='web_access')
        assert 'Web Scan' not in _types(df)

    def test_sorted_by_timestamp(self, web_log):
        df = parse_log(web_log, fmt='web_access')
        ts = df['timestamp'].dropna()
        assert ts.is_monotonic_increasing

    def test_admin_path_dotenv(self, tmp_path):
        log = _write(tmp_path, 'w.log', [
            '1.2.3.4 - - [24/Apr/2024:10:00:00 +0000] "GET /.env HTTP/1.1" 200 0 "-" "curl/7.68"',
        ])
        df = parse_log(log, fmt='web_access')
        assert df.iloc[0]['event_type'] == 'Admin Access'
