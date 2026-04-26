"""Tests for src/schema.py"""

import json
from datetime import datetime, timezone

import pytest

from schema import StandardEvent, make_event_id, to_json, from_json, SourceActor, TargetSystem, MitreTechnique


def _make_event(**kwargs) -> StandardEvent:
    defaults = dict(
        event_id=make_event_id(),
        timestamp=datetime(2024, 4, 23, 10, 0, 0, tzinfo=timezone.utc),
        event_type='Failed Login',
        source_actor={'ip': '1.2.3.4', 'user': 'root'},
        target_system={'hostname': 'server1', 'process': 'sshd'},
        action_taken="Failed login attempt for user 'root' from 1.2.3.4",
        severity='low',
        mitre_technique={'id': 'T1110', 'name': 'Brute Force'},
        raw='Apr 23 10:00:00 server1 sshd[1234]: Failed password for root from 1.2.3.4',
        source_log='auth.log',
        log_format='auth_log',
        pid='1234',
    )
    defaults.update(kwargs)
    return StandardEvent(**defaults)


class TestMakeEventId:
    def test_returns_string(self):
        assert isinstance(make_event_id(), str)

    def test_unique(self):
        ids = {make_event_id() for _ in range(100)}
        assert len(ids) == 100

    def test_uuid_format(self):
        import re
        pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
        assert pattern.match(make_event_id())


class TestStandardEvent:
    def test_fields_stored(self):
        e = _make_event()
        assert e.event_type == 'Failed Login'
        assert e.source_actor['ip'] == '1.2.3.4'
        assert e.severity == 'low'

    def test_naive_timestamp_becomes_utc(self):
        naive = datetime(2024, 4, 23, 10, 0, 0)
        e = _make_event(timestamp=naive)
        assert e.timestamp.tzinfo is not None
        assert e.timestamp.tzinfo == timezone.utc

    def test_utc_timestamp_preserved(self):
        utc_ts = datetime(2024, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
        e = _make_event(timestamp=utc_ts)
        assert e.timestamp == utc_ts

    def test_pid_defaults_to_none(self):
        e = StandardEvent(
            event_id=make_event_id(),
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            event_type='Other',
            source_actor={'ip': None, 'user': None},
            target_system={'hostname': 'host', 'process': 'proc'},
            action_taken='',
            severity='info',
            mitre_technique={'id': None, 'name': None},
            raw='',
            source_log='auth.log',
            log_format='auth_log',
        )
        assert e.pid is None


class TestToJson:
    def test_returns_dict(self):
        e = _make_event()
        d = to_json(e)
        assert isinstance(d, dict)

    def test_timestamp_is_string(self):
        e = _make_event()
        d = to_json(e)
        assert isinstance(d['timestamp'], str)

    def test_timestamp_is_iso_format(self):
        e = _make_event()
        d = to_json(e)
        # Must be parseable
        datetime.fromisoformat(d['timestamp'])

    def test_all_fields_present(self):
        e = _make_event()
        d = to_json(e)
        required = {
            'event_id', 'timestamp', 'event_type', 'source_actor',
            'target_system', 'action_taken', 'severity', 'mitre_technique',
            'raw', 'source_log', 'log_format', 'pid', 'is_lolbin',
            'command_line', 'parent_process', 'object_path', 'access_flags',
        }
        assert required == set(d.keys())

    def test_json_serializable(self):
        e = _make_event()
        # Must not raise
        json.dumps(to_json(e))


class TestFromJson:
    def test_round_trip(self):
        e = _make_event()
        d = to_json(e)
        e2 = from_json(d)
        assert e2.event_id == e.event_id
        assert e2.event_type == e.event_type
        assert e2.severity == e.severity
        assert e2.source_actor == e.source_actor

    def test_timestamp_is_datetime(self):
        e = _make_event()
        d = to_json(e)
        e2 = from_json(d)
        assert isinstance(e2.timestamp, datetime)

    def test_timestamp_is_utc_aware(self):
        e = _make_event()
        d = to_json(e)
        e2 = from_json(d)
        assert e2.timestamp.tzinfo is not None

    def test_none_timestamp_handled(self):
        e = _make_event()
        d = to_json(e)
        d['timestamp'] = None
        e2 = from_json(d)
        assert e2.timestamp is None

    def test_full_json_string_round_trip(self):
        e = _make_event()
        serialized = json.dumps(to_json(e))
        e2 = from_json(json.loads(serialized))
        assert e2.source_actor == {'ip': '1.2.3.4', 'user': 'root'}
        assert e2.target_system == {'hostname': 'server1', 'process': 'sshd'}
        assert e2.mitre_technique == {'id': 'T1110', 'name': 'Brute Force'}


class TestTypedDicts:
    def test_source_actor_importable(self):
        actor: SourceActor = {'ip': '1.2.3.4', 'user': 'root'}
        assert actor['ip'] == '1.2.3.4'

    def test_target_system_importable(self):
        system: TargetSystem = {'hostname': 'server1', 'process': 'sshd'}
        assert system['hostname'] == 'server1'

    def test_mitre_technique_importable(self):
        technique: MitreTechnique = {'id': 'T1110', 'name': 'Brute Force'}
        assert technique['id'] == 'T1110'

    def test_standard_event_accepts_typed_dicts(self):
        e = StandardEvent(
            event_id=make_event_id(),
            timestamp=datetime(2024, 4, 23, 10, 0, 0, tzinfo=timezone.utc),
            event_type='Failed Login',
            source_actor=SourceActor(ip='1.2.3.4', user='root'),
            target_system=TargetSystem(hostname='server1', process='sshd'),
            action_taken='Failed login',
            severity='low',
            mitre_technique=MitreTechnique(id='T1110', name='Brute Force'),
            raw='raw line',
            source_log='auth.log',
            log_format='auth_log',
        )
        assert e.source_actor['ip'] == '1.2.3.4'
        assert e.target_system['hostname'] == 'server1'
        assert e.mitre_technique['id'] == 'T1110'
