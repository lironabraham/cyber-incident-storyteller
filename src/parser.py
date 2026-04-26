import logging
import re
import pandas as pd
from pathlib import Path
from dateutil import parser as dateparser

_log = logging.getLogger(__name__)

# ── Auth.log line structure ────────────────────────────────────────────────────
# Example: Apr 23 10:15:32 server1 sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2

_AUTH_LINE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+(?P<process>\S+?)(?:\[\d+\])?\s*:\s+(?P<message>.+)$'
)

# ── Event classifiers: (compiled regex, event_type, user_group, ip_group) ─────
# Groups are None when the field is absent for that event type.
_EVENT_RULES = [
    (
        re.compile(r'Failed password for(?: invalid user)? (\S+) from ([\d.a-fA-F:]+)'),
        'Failed Login', 1, 2,
    ),
    (
        re.compile(r'Accepted password for (\S+) from ([\d.a-fA-F:]+)'),
        'Accepted Password', 1, 2,
    ),
    (
        re.compile(r'Accepted publickey for (\S+) from ([\d.a-fA-F:]+)'),
        'Accepted Publickey', 1, 2,
    ),
    (
        re.compile(r'Invalid user (\S+) from ([\d.a-fA-F:]+)'),
        'Invalid User', 1, 2,
    ),
    (
        re.compile(r'Connection closed by(?: invalid user (\S+))? ([\d.a-fA-F:]+)'),
        'Connection Closed', 1, 2,
    ),
    (
        re.compile(r'Disconnected from(?: invalid user (\S+))? ([\d.a-fA-F:]+)'),
        'Disconnected', 1, 2,
    ),
    (
        re.compile(r'session opened for user (\S+)'),
        'Session Opened', 1, None,
    ),
    (
        re.compile(r'session closed for user (\S+)'),
        'Session Closed', 1, None,
    ),
    (
        re.compile(r'(\S+)\s+:.*COMMAND='),
        'Sudo Command', 1, None,
    ),
    (
        re.compile(r'authentication failure.*user=(\S+)'),
        'Auth Failure', 1, None,
    ),
]


def _classify(message: str, rules: list) -> tuple[str, str | None, str | None]:
    """Apply a rule list to a message; return (event_type, user, source_ip)."""
    for pattern, event_type, user_grp, ip_grp in rules:
        m = pattern.search(message)
        if m:
            user = m.group(user_grp) if user_grp and m.lastindex >= user_grp else None
            ip   = m.group(ip_grp)   if ip_grp   and m.lastindex >= ip_grp   else None
            return event_type, user or None, ip or None
    return 'Other', None, None


def _classify_message(message: str) -> tuple[str, str | None, str | None]:
    """Return (event_type, user, source_ip) for an auth.log message."""
    return _classify(message, _EVENT_RULES)


def _parse_auth_log(path: Path) -> pd.DataFrame:
    """Parse a Linux auth.log file into a unified DataFrame."""
    rows = []
    with open(path, encoding='utf-8', errors='replace') as fh:
        for raw in fh:
            line = raw.rstrip('\n')
            m = _AUTH_LINE.match(line)
            if not m:
                continue

            # Build a parseable timestamp string; year defaults to current year
            ts_str = f"{m.group('month')} {m.group('day')} {m.group('time')}"
            try:
                timestamp = dateparser.parse(ts_str)
            except ValueError:
                timestamp = pd.NaT

            event_type, user, source_ip = _classify_message(m.group('message'))

            rows.append({
                'timestamp':  timestamp,
                'hostname':   m.group('hostname'),
                'process':    m.group('process'),
                'event_type': event_type,
                'source_ip':  source_ip,
                'user':       user,
                'raw':        line,
            })

    df = pd.DataFrame(rows, columns=['timestamp', 'hostname', 'process',
                                     'event_type', 'source_ip', 'user', 'raw'])
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df.sort_values('timestamp').reset_index(drop=True)


# ── Syslog parser ──────────────────────────────────────────────────────────────
# Same line format as auth.log; different event classifiers.

_SYSLOG_RULES = [
    (re.compile(r'Started (.+?)(?:\.service)?\.?$'),  'Service Started', None, None),
    (re.compile(r'Stopped (.+?)(?:\.service)?\.?$'),  'Service Stopped', None, None),
    (re.compile(r'\S+\.service.*[Ff]ailed'),           'Service Failed',  None, None),
    (re.compile(r'\((\S+)\) CMD'),                     'Cron Execution',  1,    None),
    (re.compile(r'Out of memory.*[Kk]ill process'),    'OOM Kill',        None, None),
    (re.compile(r'usb \d+-[\d.]+.*USB device'),        'USB Connected',   None, None),
]


def _parse_syslog(path: Path) -> pd.DataFrame:
    """Parse a Linux syslog file into a unified DataFrame."""
    rows = []
    with open(path, encoding='utf-8', errors='replace') as fh:
        for raw in fh:
            line = raw.rstrip('\n')
            m = _AUTH_LINE.match(line)
            if not m:
                continue
            ts_str = f"{m.group('month')} {m.group('day')} {m.group('time')}"
            try:
                timestamp = dateparser.parse(ts_str)
            except ValueError:
                timestamp = pd.NaT
            event_type, user, source_ip = _classify(m.group('message'), _SYSLOG_RULES)
            rows.append({
                'timestamp':  timestamp,
                'hostname':   m.group('hostname'),
                'process':    m.group('process'),
                'event_type': event_type,
                'source_ip':  source_ip,
                'user':       user,
                'raw':        line,
            })
    df = pd.DataFrame(rows, columns=['timestamp', 'hostname', 'process',
                                     'event_type', 'source_ip', 'user', 'raw'])
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df.sort_values('timestamp').reset_index(drop=True)


# ── Auditd parser ──────────────────────────────────────────────────────────────

_AUDIT_TS_RE   = re.compile(r'msg=audit\((\d+\.\d+):\d+\)')
_AUDIT_TYPE_RE = re.compile(r'^type=(\w+)')
_AUDIT_KV_RE   = re.compile(r'(\w+)=(?:"([^"]*)"|([\S]*))')


def _audit_fields(line: str) -> dict[str, str]:
    """Extract key=value pairs from an auditd log line."""
    result = {}
    for m in _AUDIT_KV_RE.finditer(line):
        val = m.group(2) if m.group(2) is not None else m.group(3).strip("'\"")
        result[m.group(1)] = val
    return result


def _parse_audit_log(path: Path) -> pd.DataFrame:
    """Parse a Linux auditd log file into a unified DataFrame."""
    import datetime as _dt

    rows = []
    with open(path, encoding='utf-8', errors='replace') as fh:
        for raw in fh:
            line = raw.rstrip('\n')

            type_m = _AUDIT_TYPE_RE.match(line)
            ts_m   = _AUDIT_TS_RE.search(line)
            if not type_m or not ts_m:
                continue

            record_type = type_m.group(1)
            try:
                timestamp = _dt.datetime.fromtimestamp(
                    float(ts_m.group(1)), tz=_dt.timezone.utc
                )
            except (ValueError, OSError):
                timestamp = pd.NaT

            fields = _audit_fields(line)
            user      = fields.get('acct') or None
            source_ip = fields.get('addr') or fields.get('hostname') or None
            # '?' and 'localhost' are not useful IPs
            if source_ip in ('?', 'localhost', '::1', '127.0.0.1'):
                source_ip = None

            # Classify by record type and result
            res = fields.get('res', '')
            if record_type == 'PROCTITLE':
                # Hex-encoded null-separated argv: decode and extract base command
                raw_proctitle = fields.get('proctitle', '')
                try:
                    argv = bytes.fromhex(raw_proctitle).split(b'\x00')
                    command = argv[0].decode('utf-8', errors='replace')
                except (ValueError, UnicodeDecodeError):
                    command = raw_proctitle
                event_type = 'Process Execution'
                user = command or user
                source_ip = None
            elif record_type == 'EXECVE':
                event_type = 'Process Execution'
                user = fields.get('a0') or user   # store command as user for routing
                source_ip = None
            elif record_type == 'USER_LOGIN':
                event_type = 'Audit Login' if res == 'success' else 'Audit Auth Failure'
            elif record_type in ('USER_AUTH', 'USER_ACCT'):
                event_type = 'Audit Auth Failure' if res == 'failed' else 'Other'
            elif record_type == 'SYSCALL':
                comm = fields.get('comm', '')
                if comm in ('bash', 'sh', 'zsh', 'fish', 'dash'):
                    event_type = 'Shell Execution'
                else:
                    event_type = 'Other'
            elif record_type in ('OPEN', 'OPENAT'):
                name = fields.get('name', '')
                if any(s in name for s in ('/etc/passwd', '/etc/shadow', '/etc/sudoers')):
                    event_type = 'File Access'
                else:
                    event_type = 'Other'
            else:
                event_type = 'Other'

            rows.append({
                'timestamp':  timestamp,
                'hostname':   fields.get('hostname', ''),
                'process':    record_type,
                'event_type': event_type,
                'source_ip':  source_ip,
                'user':       user,
                'raw':        line,
            })

    df = pd.DataFrame(rows, columns=['timestamp', 'hostname', 'process',
                                     'event_type', 'source_ip', 'user', 'raw'])
    df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True)
    return df.sort_values('timestamp').reset_index(drop=True)


# ── Web access log parser ──────────────────────────────────────────────────────

_WEB_LINE_RE = re.compile(
    r'^(?P<ip>[\d.a-fA-F:]+)\s+'
    r'\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<dt>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+[^"]+"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
    r'(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
)

_WEB_ATTACK_PATTERNS = re.compile(
    r'(?:\.\./|%2e%2e|%252e|'           # path traversal
    r"'|%27|1=1|UNION\s+SELECT|OR\s+1|"  # SQLi
    r'<script|%3cscript|'               # XSS
    r'\$\{|%24%7b)',                    # template injection
    re.IGNORECASE,
)
_WEB_ADMIN_PATHS = re.compile(
    r'^/(?:admin|administrator|wp-admin|wp-login\.php|phpmyadmin|'
    r'\.env|\.git|config|setup|install|panel)',
    re.IGNORECASE,
)
_WEB_SHELL_EXT = re.compile(r'\.(php|asp|aspx|jsp|cgi|sh|py|rb|pl)\b', re.IGNORECASE)
_WEB_TOOL_UAS  = re.compile(
    r'sqlmap|nikto|nmap|masscan|dirb|gobuster|wfuzz|hydra',
    re.IGNORECASE,
)


def _classify_web_request(method: str, path: str, status: int, ua: str) -> str:
    if _WEB_ATTACK_PATTERNS.search(path):
        return 'Web Attack'
    if method == 'POST' and _WEB_SHELL_EXT.search(path) and status == 200:
        return 'Web Shell'
    if _WEB_ADMIN_PATHS.match(path):
        return 'Admin Access'
    if _WEB_TOOL_UAS.search(ua):
        return 'Tool Fingerprint'
    return 'Web Request'


def _parse_web_access(path: Path) -> pd.DataFrame:
    """Parse an Nginx/Apache combined access log into a unified DataFrame."""
    import datetime as _dt

    rows = []
    ip_404_counts: dict[str, int] = {}

    with open(path, encoding='utf-8', errors='replace') as fh:
        for raw in fh:
            line = raw.rstrip('\n')
            m = _WEB_LINE_RE.match(line)
            if not m:
                continue
            try:
                timestamp = _dt.datetime.strptime(
                    m.group('dt'), '%d/%b/%Y:%H:%M:%S %z'
                )
            except ValueError:
                timestamp = pd.NaT

            ip     = m.group('ip')
            user   = m.group('user') if m.group('user') != '-' else None
            method = m.group('method')
            path_  = m.group('path')
            status = int(m.group('status'))
            ua     = m.group('ua') or ''

            if status == 404:
                ip_404_counts[ip] = ip_404_counts.get(ip, 0) + 1

            event_type = _classify_web_request(method, path_, status, ua)
            rows.append({
                'timestamp':  timestamp,
                'hostname':   '',
                'process':    'web',
                'event_type': event_type,
                'source_ip':  ip,
                'user':       user,
                'raw':        line,
                '_status':    status,
            })

    # Second pass: upgrade high-404-count IPs to Web Scan (only 404s, not already-classified attacks)
    _scan_upgradeable = {'Web Request', 'Tool Fingerprint', 'Admin Access'}
    scan_ips = {ip for ip, n in ip_404_counts.items() if n >= 5}
    for row in rows:
        if row['source_ip'] in scan_ips and row['_status'] == 404 and row['event_type'] in _scan_upgradeable:
            row['event_type'] = 'Web Scan'
        row.pop('_status')

    df = pd.DataFrame(rows, columns=['timestamp', 'hostname', 'process',
                                     'event_type', 'source_ip', 'user', 'raw'])
    df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True)
    return df.sort_values('timestamp').reset_index(drop=True)


# ── Linux Sysmon XML parser ────────────────────────────────────────────────────

_SYSMON_SHELLS    = {'bash', 'sh', 'zsh', 'fish', 'dash', 'ksh'}
_SYSMON_SENSITIVE = ('/etc/passwd', '/etc/shadow', '/etc/sudoers', '/root/')


def _parse_sysmon_linux(path: Path) -> pd.DataFrame:
    """Parse a Linux Sysmon XML log (one <Event> per line) into a unified DataFrame."""
    import datetime as _dt
    import xml.etree.ElementTree as ET

    rows = []
    with open(path, encoding='utf-8', errors='replace') as fh:
        for raw in fh:
            line = raw.strip()
            if not line.startswith('<Event'):
                continue
            try:
                root = ET.fromstring(line)
            except ET.ParseError:
                continue

            event_id = root.findtext('System/EventID') or ''
            if event_id == '5':
                continue  # Process Terminated — noise

            tc = root.find('System/TimeCreated')
            ts_str = tc.get('SystemTime', '') if tc is not None else ''
            try:
                # Truncate sub-microsecond precision before parsing
                ts_str = ts_str[:26] + 'Z' if len(ts_str) > 26 else ts_str
                timestamp = _dt.datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            except ValueError:
                timestamp = pd.NaT

            hostname = root.findtext('System/Computer') or ''
            data = {d.get('Name'): d.text for d in root.findall('EventData/Data')}

            image    = data.get('Image', '') or ''
            cmd_line = data.get('CommandLine', '') or ''
            user     = data.get('User') or None
            proc     = image.split('/')[-1] if image else 'sysmon'

            if event_id == '1':
                base = proc.lower()
                if base in _SYSMON_SHELLS:
                    event_type = 'Shell Execution'
                    user_field = cmd_line or proc
                else:
                    event_type = 'Process Execution'
                    user_field = cmd_line or proc   # stored in user for map_command routing
                source_ip  = None
            elif event_id == '3':
                event_type = 'Network Connection'
                source_ip  = data.get('DestinationIp') or None
                user_field = user
            elif event_id == '11':
                target = data.get('TargetFilename', '') or ''
                if any(s in target for s in _SYSMON_SENSITIVE):
                    event_type = 'File Access'
                else:
                    event_type = 'Other'
                source_ip  = None
                user_field = user
            elif event_id == '23':
                event_type = 'File Deleted'
                source_ip  = None
                user_field = user
            else:
                event_type = 'Other'
                source_ip  = None
                user_field = user

            rows.append({
                'timestamp':  timestamp,
                'hostname':   hostname,
                'process':    proc,
                'event_type': event_type,
                'source_ip':  source_ip,
                'user':       user_field,
                'raw':        line,
            })

    df = pd.DataFrame(rows, columns=['timestamp', 'hostname', 'process',
                                     'event_type', 'source_ip', 'user', 'raw'])
    df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True)
    return df.sort_values('timestamp').reset_index(drop=True)


# ── Windows EVTX / XML parser ─────────────────────────────────────────────────
# Accepts binary EVTX (magic: ElfFile\x00) or wevtutil XML export format.
# Both paths share the same per-record XML parsing logic.

_EVTX_NS_RE = re.compile(r'\s+xmlns(?::\w+)?=["\'][^"\']*["\']')
_EVTX_SKIP_IDS = {'4689'}  # Process Terminated — noise (mirrors Sysmon EID 5)
_EVTX_ATTACKER_IP_FIELDS = ('IpAddress', 'WorkstationName')
_EVTX_NULL_VALUES = frozenset({'-', '', '::1', '127.0.0.1', 'localhost'})


def _strip_evtx_ns(xml_str: str) -> str:
    """Remove XML namespace declarations so plain XPath queries work."""
    return _EVTX_NS_RE.sub('', xml_str)


def _evtx_extract_event_data(root) -> dict[str, str]:
    """Flatten <EventData><Data Name="..."> entries into a plain dict."""
    return {
        d.get('Name', ''): (d.text or '')
        for d in root.findall('EventData/Data')
        if d.get('Name')
    }


def _evtx_classify(
    event_id: str,
    data: dict[str, str],
) -> tuple[str, str | None, str | None, str | None]:
    """Return (event_type, user, source_ip, command) for a Windows event record.

    command is populated only for EventID 4688; stored in user field by the
    caller for map_command() routing — consistent with the auditd EXECVE pattern.
    """
    ip: str | None = None
    for field in _EVTX_ATTACKER_IP_FIELDS:
        candidate = data.get(field, '')
        if candidate and candidate not in _EVTX_NULL_VALUES:
            ip = candidate
            break

    user = data.get('TargetUserName') or data.get('SubjectUserName') or None
    if user in _EVTX_NULL_VALUES:
        user = None

    if event_id == '4624':
        lt = data.get('LogonType', '0')
        if lt in ('3', '10'):
            return 'Windows Remote Logon', user, ip, None
        return 'Windows Logon Success', user, ip, None

    if event_id == '4625':
        return 'Windows Logon Failure', user, ip, None

    if event_id == '4648':
        target_server = data.get('TargetServerName')
        return 'Windows Explicit Credential Use', user, ip, target_server

    if event_id == '4672':
        u = data.get('SubjectUserName') or user
        if u in _EVTX_NULL_VALUES:
            u = None
        return 'Windows Privilege Assigned', u, None, None

    if event_id == '4688':
        proc = data.get('NewProcessName', '') or ''
        cmd = data.get('CommandLine', '') or proc
        u = data.get('SubjectUserName') or user
        if u in _EVTX_NULL_VALUES:
            u = None
        return 'Windows Process Creation', u, None, cmd or None

    if event_id in ('4697', '7045'):
        u = data.get('SubjectUserName') or user
        return 'Windows Service Installed', u, None, None

    if event_id in ('4698', '4702'):
        u = data.get('SubjectUserName') or user
        return 'Windows Scheduled Task', u, None, None

    if event_id == '4720':
        u = data.get('SubjectUserName') or user
        return 'Windows Account Created', u, None, None

    if event_id in ('4728', '4732'):
        u = data.get('SubjectUserName') or user
        return 'Windows Group Member Added', u, None, None

    if event_id == '4768':
        u = data.get('CNameString') or user
        return 'Windows Kerberos TGT Request', u, ip, None

    if event_id == '4769':
        u = data.get('AccountName') or user
        return 'Windows Kerberos Service Ticket', u, ip, None

    if event_id == '4771':
        u = data.get('CNameString') or user
        return 'Windows Kerberos PreAuth Failure', u, ip, None

    if event_id == '5145':
        return 'Windows Share Access', user, ip, None

    if event_id == '4663':
        obj = data.get('ObjectName', '').lower()
        if any(kw in obj for kw in ('lsass', 'ntds', 'sam', 'security', 'system')):
            u = data.get('SubjectUserName') or user
            return 'Windows Object Access', u, None, None

    if event_id == '4776':
        u = data.get('TargetUserName') or user
        return 'Windows NTLM Auth', u, ip, None

    if event_id == '4740':
        u = data.get('TargetUserName') or user
        return 'Windows Account Lockout', u, ip, None

    if event_id == '4662':
        u = data.get('SubjectUserName') or user
        return 'Windows DS Object Access', u, None, None

    if event_id == '1102':
        u = data.get('SubjectUserName') or user
        return 'Windows Log Cleared', u, None, None

    if event_id == '4657':
        u = data.get('SubjectUserName') or user
        return 'Windows Registry Modified', u, None, None

    if event_id == '4703':
        u = data.get('SubjectUserName') or user
        return 'Windows Token Rights Adjusted', u, None, None

    if event_id == '4726':
        u = data.get('SubjectUserName') or user
        return 'Windows Account Deleted', u, None, None

    if event_id == '4738':
        u = data.get('SubjectUserName') or user
        return 'Windows Account Changed', u, None, None

    if event_id == '5156':
        dest_port = data.get('DestPort', '')
        if dest_port in ('445', '3389', '135', '5985', '5986'):
            u = data.get('Application') or user
            return 'Windows Network Connection', u, ip, None

    return 'Other', user, ip, None


def _parse_evtx_record(xml_str: str) -> dict | None:
    """Parse one Windows Event XML string into a row dict, or None to skip."""
    import datetime as _dt
    import xml.etree.ElementTree as ET

    clean = _strip_evtx_ns(xml_str)
    try:
        root = ET.fromstring(clean)
    except ET.ParseError:
        return None

    event_id = root.findtext('System/EventID') or ''
    if event_id in _EVTX_SKIP_IDS:
        return None

    tc = root.find('System/TimeCreated')
    ts_str = tc.get('SystemTime', '') if tc is not None else ''
    try:
        ts_str = ts_str[:26] + 'Z' if len(ts_str) > 26 else ts_str
        timestamp = _dt.datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except ValueError:
        timestamp = pd.NaT

    hostname = root.findtext('System/Computer') or ''
    data = _evtx_extract_event_data(root)
    event_type, user, source_ip, command = _evtx_classify(event_id, data)

    if event_type == 'Other':
        return None

    # Store command in user field for map_command() routing (auditd EXECVE pattern)
    user_field = command if command else user

    return {
        'timestamp':  timestamp,
        'hostname':   hostname,
        'process':    f'EventID-{event_id}',
        'event_type': event_type,
        'source_ip':  source_ip,
        'user':       user_field,
        'raw':        xml_str,
    }


def _build_evtx_dataframe(rows: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(rows, columns=['timestamp', 'hostname', 'process',
                                     'event_type', 'source_ip', 'user', 'raw'])
    df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True)
    return df.sort_values('timestamp').reset_index(drop=True)


def _parse_evtx_binary(path: Path) -> pd.DataFrame:
    """Parse a binary .evtx file using python-evtx."""
    try:
        from Evtx.Evtx import Evtx
    except ImportError as exc:
        raise ImportError(
            "Binary EVTX support requires python-evtx: pip install python-evtx"
        ) from exc

    rows = []
    with Evtx(str(path)) as log:
        for record in log.records():
            try:
                row = _parse_evtx_record(record.xml())
                if row:
                    rows.append(row)
            except Exception as exc:
                _log.warning("Skipped malformed EVTX record: %s", exc)
                continue
    return _build_evtx_dataframe(rows)


def _parse_evtx_xml(path: Path) -> pd.DataFrame:
    """Parse a wevtutil XML export or one-<Event>-per-line text file."""
    import xml.etree.ElementTree as ET

    content = path.read_text(encoding='utf-8', errors='replace')
    rows: list[dict] = []

    # Try as a full XML document first (<Events>...</Events> or bare <Event>)
    try:
        root = ET.fromstring(_strip_evtx_ns(content))
        tag = root.tag.split('}')[-1] if '}' in root.tag else root.tag
        if tag == 'Events':
            event_elements = root.findall('Event')
        elif tag == 'Event':
            event_elements = [root]
        else:
            event_elements = []

        if event_elements:
            for elem in event_elements:
                xml_str = ET.tostring(elem, encoding='unicode')
                row = _parse_evtx_record(xml_str)
                if row:
                    rows.append(row)
            return _build_evtx_dataframe(rows)
    except ET.ParseError:
        pass

    # Fall back: one <Event ...> per line (matches generate_lab output format)
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped.startswith('<Event'):
            continue
        row = _parse_evtx_record(stripped)
        if row:
            rows.append(row)

    return _build_evtx_dataframe(rows)


def _parse_evtx(path: Path) -> pd.DataFrame:
    """Parse Windows event logs — binary EVTX or wevtutil XML export.

    Format auto-detected from file magic bytes (ElfFile\\x00 = binary EVTX).
    Also accepts one-<Event>-per-line text and full <Events>...</Events> XML.
    """
    with open(path, 'rb') as fh:
        magic = fh.read(8)
    if magic == b'ElfFile\x00':
        return _parse_evtx_binary(path)
    return _parse_evtx_xml(path)


# ── Public API ─────────────────────────────────────────────────────────────────

SUPPORTED_FORMATS = {
    'auth_log':     _parse_auth_log,
    'syslog':       _parse_syslog,
    'audit_log':    _parse_audit_log,
    'web_access':   _parse_web_access,
    'sysmon_linux': _parse_sysmon_linux,
    'evtx':         _parse_evtx,
}


def parse_log(path: str | Path, fmt: str = 'auth_log') -> pd.DataFrame:
    """
    Parse a log file into a unified DataFrame.

    Parameters
    ----------
    path : str or Path
        Path to the log file.
    fmt  : str
        Log format key. See SUPPORTED_FORMATS for valid values.

    Returns
    -------
    pd.DataFrame with columns: timestamp, hostname, process,
                                event_type, source_ip, user, raw
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported format '{fmt}'. Choose from: {list(SUPPORTED_FORMATS)}")
    return SUPPORTED_FORMATS[fmt](path)


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import sys
    from storyteller import report

    log_path = sys.argv[1] if len(sys.argv) > 1 else 'logs/auth.log'
    df = parse_log(log_path, fmt='auth_log')
    print(report(df, log_path=log_path))
