"""
Tests for the Windows EVTX / XML event-log parser (Phase 3.5).

Covers:
  - DataFrame schema (columns, UTC timestamps, sort order)
  - All 6 attack-stage event types from the lab fixture
  - LogonType routing (network/remote vs interactive)
  - Null-value normalisation (dash, loopback, localhost → None)
  - 4689 skip and 'Other' skip
  - Empty / all-skipped input → empty DataFrame
  - _evtx_extract_event_data helper
  - _parse_evtx_record helper (round-trip, invalid XML, skip IDs)
  - parse_log() public API with fmt='evtx'
"""

import sys
import textwrap
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import pytest

_src = str(Path(__file__).parent.parent / 'src')
if _src not in sys.path:
    sys.path.insert(0, _src)

from parser import (
    _evtx_classify,
    _evtx_extract_event_data,
    _parse_evtx_record,
    parse_log,
)

# ── Helpers ────────────────────────────────────────────────────────────────────

_HOST = 'WINSERVER01'
_ATTACKER = '192.168.99.1'
_USER = 'Administrator'


def _make_xml(eid: str, data_fields: dict[str, str], logon_type: str | None = None,
              ts: str = '2024-04-23T10:00:00.000000000Z',
              hostname: str = _HOST) -> str:
    """Build a minimal Windows Event XML string without real namespaces."""
    fields = dict(data_fields)
    if logon_type is not None:
        fields['LogonType'] = logon_type
    data_xml = ''.join(f'<Data Name="{k}">{v}</Data>' for k, v in fields.items())
    return (
        f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        f'<System>'
        f'<Provider Name="Microsoft-Windows-Security-Auditing"/>'
        f'<EventID>{eid}</EventID>'
        f'<TimeCreated SystemTime="{ts}"/>'
        f'<Computer>{hostname}</Computer>'
        f'</System>'
        f'<EventData>{data_xml}</EventData>'
        f'</Event>'
    )


def _events_xml(*xml_strings: str) -> str:
    """Wrap Event strings in an <Events> envelope."""
    return '<Events>' + ''.join(xml_strings) + '</Events>'


# ── DataFrame schema ───────────────────────────────────────────────────────────

class TestEvtxParserDataFrameSchema:
    """parse_log(..., fmt='evtx') must return a correctly-typed DataFrame."""

    EXPECTED_COLUMNS = {'timestamp', 'hostname', 'process', 'event_type',
                        'source_ip', 'user', 'raw'}

    def test_columns_present(self, evtx_log):
        df = parse_log(evtx_log, fmt='evtx')
        assert self.EXPECTED_COLUMNS.issubset(df.columns), (
            f'Missing columns: {self.EXPECTED_COLUMNS - set(df.columns)}'
        )

    def test_timestamps_are_utc(self, evtx_log):
        df = parse_log(evtx_log, fmt='evtx')
        assert df['timestamp'].dt.tz is not None, 'timestamps must be tz-aware'
        # pandas UTC is represented as UTC or pytz.UTC — both have utcoffset == 0
        sample = df['timestamp'].iloc[0]
        assert sample.utcoffset().total_seconds() == 0, 'timestamps must be UTC'

    def test_rows_sorted_ascending_by_timestamp(self, evtx_log):
        df = parse_log(evtx_log, fmt='evtx')
        assert df['timestamp'].is_monotonic_increasing, (
            'DataFrame must be sorted ascending by timestamp'
        )

    def test_non_empty_for_lab_fixture(self, evtx_log):
        df = parse_log(evtx_log, fmt='evtx')
        assert len(df) > 0, 'lab fixture must produce at least one row'

    def test_process_column_contains_event_id_prefix(self, evtx_log):
        df = parse_log(evtx_log, fmt='evtx')
        # Every process value should be like 'EventID-4625'
        assert df['process'].str.startswith('EventID-').all(), (
            'process column must be formatted as "EventID-<N>"'
        )


# ── Event classification from lab fixture ─────────────────────────────────────

class TestEvtxParserEventClassification:
    """The lab fixture generates 6 attack stages; each must be classified."""

    def test_logon_failure_events_present(self, evtx_log):
        df = parse_log(evtx_log, fmt='evtx')
        count = (df['event_type'] == 'Windows Logon Failure').sum()
        assert count == 10, f'Expected 10 Windows Logon Failure events, got {count}'

    def test_remote_logon_event_present(self, evtx_log):
        df = parse_log(evtx_log, fmt='evtx')
        count = (df['event_type'] == 'Windows Remote Logon').sum()
        assert count >= 1, 'Expected at least 1 Windows Remote Logon event'

    def test_privilege_assigned_event_present(self, evtx_log):
        df = parse_log(evtx_log, fmt='evtx')
        count = (df['event_type'] == 'Windows Privilege Assigned').sum()
        assert count >= 1, 'Expected at least 1 Windows Privilege Assigned event'

    def test_process_creation_event_present(self, evtx_log):
        df = parse_log(evtx_log, fmt='evtx')
        count = (df['event_type'] == 'Windows Process Creation').sum()
        assert count >= 1, 'Expected at least 1 Windows Process Creation event'

    def test_service_installed_event_present(self, evtx_log):
        df = parse_log(evtx_log, fmt='evtx')
        count = (df['event_type'] == 'Windows Service Installed').sum()
        assert count >= 1, 'Expected at least 1 Windows Service Installed event'

    def test_scheduled_task_event_present(self, evtx_log):
        df = parse_log(evtx_log, fmt='evtx')
        count = (df['event_type'] == 'Windows Scheduled Task').sum()
        assert count >= 1, 'Expected at least 1 Windows Scheduled Task event'

    def test_attacker_ip_extracted_for_logon_failure(self, evtx_log):
        df = parse_log(evtx_log, fmt='evtx')
        failures = df[df['event_type'] == 'Windows Logon Failure']
        assert (failures['source_ip'] == _ATTACKER).all(), (
            f'Expected all logon failures to have source_ip={_ATTACKER!r}'
        )

    def test_powershell_command_stored_in_user_field(self, evtx_log):
        df = parse_log(evtx_log, fmt='evtx')
        proc = df[df['event_type'] == 'Windows Process Creation']
        assert len(proc) >= 1
        user_val = proc.iloc[0]['user']
        assert user_val and 'powershell' in str(user_val).lower(), (
            f'Expected PowerShell command in user field, got: {user_val!r}'
        )

    def test_hostname_populated(self, evtx_log):
        df = parse_log(evtx_log, fmt='evtx')
        assert (df['hostname'] == _HOST).all(), (
            f'Expected hostname={_HOST!r} for all events'
        )


# ── LogonType routing ──────────────────────────────────────────────────────────

class TestEvtxParserLogonTypeRouting:
    """EventID 4624 must be classified by LogonType."""

    @pytest.mark.parametrize('logon_type,expected', [
        ('3',  'Windows Remote Logon'),
        ('10', 'Windows Remote Logon'),
        ('2',  'Windows Logon Success'),
        ('0',  'Windows Logon Success'),
        ('7',  'Windows Logon Success'),
    ])
    def test_4624_logon_type_routing(self, logon_type, expected):
        event_type, user, ip, cmd = _evtx_classify('4624', {
            'TargetUserName': 'alice',
            'IpAddress': '10.0.0.1',
            'LogonType': logon_type,
        })
        assert event_type == expected, (
            f'LogonType={logon_type!r} → expected {expected!r}, got {event_type!r}'
        )

    def test_4624_network_logon_has_ip(self):
        event_type, user, ip, cmd = _evtx_classify('4624', {
            'TargetUserName': 'alice',
            'IpAddress': '10.0.0.5',
            'LogonType': '3',
        })
        assert ip == '10.0.0.5'

    def test_4624_interactive_logon_via_parse_log(self, tmp_path):
        xml_content = _events_xml(_make_xml('4624', {
            'TargetUserName': 'bob',
            'IpAddress': '-',
        }, logon_type='2'))
        log = tmp_path / 'interactive.xml'
        log.write_text(xml_content, encoding='utf-8')
        df = parse_log(log, fmt='evtx')
        row = df[df['event_type'] == 'Windows Logon Success']
        assert len(row) == 1


# ── Null-value normalisation ───────────────────────────────────────────────────

class TestEvtxParserNullHandling:
    """Dash, empty string, loopback IPs, and localhost must be normalised to None."""

    @pytest.mark.parametrize('ip_value', ['-', '', '127.0.0.1', '::1', 'localhost'])
    def test_null_ip_values_become_none(self, ip_value):
        event_type, user, ip, cmd = _evtx_classify('4625', {
            'TargetUserName': 'root',
            'IpAddress': ip_value,
        })
        assert ip is None, f'IP value {ip_value!r} should normalise to None, got {ip!r}'

    @pytest.mark.parametrize('user_value', ['-', ''])
    def test_null_user_values_become_none(self, user_value):
        event_type, user, ip, cmd = _evtx_classify('4624', {
            'TargetUserName': user_value,
            'IpAddress': '10.0.0.1',
            'LogonType': '3',
        })
        assert user is None, f'User value {user_value!r} should normalise to None, got {user!r}'

    def test_invalid_xml_returns_none(self):
        assert _parse_evtx_record('<Event>BROKEN XML') is None

    def test_non_event_xml_returns_none(self):
        assert _parse_evtx_record('<NotAnEvent><foo/></NotAnEvent>') is None

    def test_4689_is_skipped(self):
        xml = _make_xml('4689', {'SubjectUserName': 'SYSTEM'})
        assert _parse_evtx_record(xml) is None, '4689 (Process Terminated) must be skipped'

    def test_unknown_event_id_returns_none(self):
        xml = _make_xml('9999', {'Foo': 'bar'})
        assert _parse_evtx_record(xml) is None, 'Unknown EventIDs → Other → must be filtered out'


# ── Empty / all-skipped input ──────────────────────────────────────────────────

class TestEvtxParserEmptyInput:
    def test_empty_file_returns_empty_dataframe(self, tmp_path):
        log = tmp_path / 'empty.xml'
        log.write_text('', encoding='utf-8')
        df = parse_log(log, fmt='evtx')
        assert len(df) == 0

    def test_all_skipped_events_returns_empty_dataframe(self, tmp_path):
        # Only 4689 (skipped) events
        xml_content = _events_xml(
            _make_xml('4689', {'SubjectUserName': 'SYSTEM'}),
            _make_xml('4689', {'SubjectUserName': 'SYSTEM'}),
        )
        log = tmp_path / 'all_skipped.xml'
        log.write_text(xml_content, encoding='utf-8')
        df = parse_log(log, fmt='evtx')
        assert len(df) == 0

    def test_only_unknown_event_ids_returns_empty_dataframe(self, tmp_path):
        xml_content = _events_xml(
            _make_xml('1234', {'Foo': 'bar'}),
            _make_xml('5678', {'Baz': 'qux'}),
        )
        log = tmp_path / 'unknown_ids.xml'
        log.write_text(xml_content, encoding='utf-8')
        df = parse_log(log, fmt='evtx')
        assert len(df) == 0

    def test_empty_dataframe_has_correct_columns(self, tmp_path):
        log = tmp_path / 'empty2.xml'
        log.write_text('', encoding='utf-8')
        df = parse_log(log, fmt='evtx')
        expected = {'timestamp', 'hostname', 'process', 'event_type', 'source_ip', 'user', 'raw'}
        assert expected.issubset(df.columns)


# ── _evtx_extract_event_data helper ───────────────────────────────────────────

class TestEvtxExtractEventData:
    def _make_event_data_root(self, fields: dict[str, str]):
        data_xml = ''.join(f'<Data Name="{k}">{v}</Data>' for k, v in fields.items())
        return ET.fromstring(f'<Event><EventData>{data_xml}</EventData></Event>')

    def test_extracts_name_value_pairs(self):
        root = self._make_event_data_root({'IpAddress': '10.0.0.1', 'LogonType': '3'})
        result = _evtx_extract_event_data(root)
        assert result == {'IpAddress': '10.0.0.1', 'LogonType': '3'}

    def test_empty_event_data_returns_empty_dict(self):
        root = ET.fromstring('<Event><EventData></EventData></Event>')
        assert _evtx_extract_event_data(root) == {}

    def test_data_without_name_attr_is_skipped(self):
        root = ET.fromstring('<Event><EventData><Data>no name</Data></EventData></Event>')
        assert _evtx_extract_event_data(root) == {}

    def test_none_text_becomes_empty_string(self):
        root = ET.fromstring('<Event><EventData><Data Name="Key"/></EventData></Event>')
        result = _evtx_extract_event_data(root)
        assert result == {'Key': ''}


# ── _parse_evtx_record round-trip ──────────────────────────────────────────────

class TestEvtxParseRecord:
    def test_4625_round_trip(self):
        xml = _make_xml('4625', {'TargetUserName': 'admin', 'IpAddress': '1.2.3.4'})
        row = _parse_evtx_record(xml)
        assert row is not None
        assert row['event_type'] == 'Windows Logon Failure'
        assert row['source_ip'] == '1.2.3.4'
        assert row['user'] == 'admin'
        assert row['hostname'] == _HOST
        assert row['process'] == 'EventID-4625'

    def test_4688_command_stored_in_user_field(self):
        xml = _make_xml('4688', {
            'SubjectUserName': 'SYSTEM',
            'NewProcessName': r'C:\Windows\System32\cmd.exe',
            'CommandLine': 'cmd.exe /c whoami',
        })
        row = _parse_evtx_record(xml)
        assert row is not None
        assert row['event_type'] == 'Windows Process Creation'
        assert row['user'] == 'cmd.exe /c whoami'

    def test_timestamp_parsed_as_utc_datetime(self):
        xml = _make_xml('4625', {'TargetUserName': 'u'}, ts='2024-01-15T08:30:00.000000000Z')
        row = _parse_evtx_record(xml)
        assert row is not None
        ts = row['timestamp']
        assert ts.tzinfo is not None
        assert ts.year == 2024
        assert ts.month == 1
        assert ts.day == 15

    def test_namespace_stripped_before_parsing(self):
        # The xmlns attribute must not prevent parsing
        xml = (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            '<System><EventID>4625</EventID>'
            '<TimeCreated SystemTime="2024-04-23T10:00:00.000000000Z"/>'
            '<Computer>HOST</Computer></System>'
            '<EventData><Data Name="TargetUserName">root</Data>'
            '<Data Name="IpAddress">5.5.5.5</Data></EventData></Event>'
        )
        row = _parse_evtx_record(xml)
        assert row is not None
        assert row['event_type'] == 'Windows Logon Failure'

    def test_raw_field_preserved(self):
        xml = _make_xml('4625', {'TargetUserName': 'u', 'IpAddress': '9.9.9.9'})
        row = _parse_evtx_record(xml)
        assert row is not None
        assert row['raw'] == xml


# ── parse_log public API ───────────────────────────────────────────────────────

class TestParseLogEvtxFormat:
    def test_fmt_evtx_dispatches_correctly(self, evtx_log):
        df = parse_log(evtx_log, fmt='evtx')
        assert isinstance(df, pd.DataFrame)
        assert len(df) > 0

    def test_single_event_xml_file(self, tmp_path):
        xml = _make_xml('4625', {'TargetUserName': 'hacker', 'IpAddress': '8.8.8.8'})
        log = tmp_path / 'single.xml'
        log.write_text(xml, encoding='utf-8')
        df = parse_log(log, fmt='evtx')
        assert len(df) == 1
        assert df.iloc[0]['event_type'] == 'Windows Logon Failure'
        assert df.iloc[0]['source_ip'] == '8.8.8.8'

    def test_events_wrapper_xml(self, tmp_path):
        xml_content = _events_xml(
            _make_xml('4625', {'TargetUserName': 'u1', 'IpAddress': '1.1.1.1'}),
            _make_xml('4624', {'TargetUserName': 'u2', 'IpAddress': '1.1.1.1'}, logon_type='3'),
        )
        log = tmp_path / 'wrapped.xml'
        log.write_text(xml_content, encoding='utf-8')
        df = parse_log(log, fmt='evtx')
        assert len(df) == 2
        assert set(df['event_type']) == {'Windows Logon Failure', 'Windows Remote Logon'}

    def test_multiline_events_format(self, tmp_path):
        # One <Event> per line (no outer wrapper)
        lines = '\n'.join([
            _make_xml('4625', {'TargetUserName': 'a', 'IpAddress': '2.2.2.2'}),
            _make_xml('4625', {'TargetUserName': 'b', 'IpAddress': '3.3.3.3'}),
        ])
        log = tmp_path / 'lines.xml'
        log.write_text(lines, encoding='utf-8')
        df = parse_log(log, fmt='evtx')
        assert len(df) == 2
