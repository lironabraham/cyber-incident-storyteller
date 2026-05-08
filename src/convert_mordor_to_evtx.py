"""
Convert a MORDOR / OTRF ndjson file to one-<Event>-per-line EVTX XML.

The output is accepted by the existing `parse_log(..., fmt='evtx')` pipeline
with no parser changes required.

Usage
-----
    py src/convert_mordor_to_evtx.py <input.json> [output.xml]

If output path is omitted, the file is written alongside the input with a
'.evtx.xml' extension.
"""

from __future__ import annotations

import html
import json
import sys
from pathlib import Path

# Fields from Logstash/NXLog enrichment, not from Windows EventData.
# Excluded from <EventData> so they don't pollute the classifier.
_META_KEYS: frozenset[str] = frozenset({
    # Used for the <System> block already
    'EventID', 'EventTime', 'Hostname', 'Channel',
    # Logstash metadata
    '@timestamp', '@version', 'port', 'tags',
    # NXLog transport fields
    'EventReceivedTime', 'SourceModuleName', 'SourceModuleType', 'SourceName',
    'host',
    # Windows event system fields (not EventData)
    'SeverityValue', 'Severity', 'OpcodeValue', 'Opcode', 'Keywords',
    'RecordNumber', 'ProcessId', 'ExecutionProcessID', 'ProviderGuid',
    'Task', 'Version', 'EventType', 'AccountType',
    # Full-text message — redundant, captured via individual fields
    'Message',
})

# Lowercase channel name → Provider/@Name expected by the existing classifier.
_CHANNEL_TO_PROVIDER: dict[str, str] = {
    'microsoft-windows-sysmon/operational':      'Microsoft-Windows-Sysmon',
    'sysmon':                                    'Microsoft-Windows-Sysmon',
    'security':                                  'Microsoft-Windows-Security-Auditing',
    'microsoft-windows-powershell/operational':  'Microsoft-Windows-PowerShell',
    'windows powershell':                        'Windows PowerShell',
    'system':                                    'System',
    'microsoft-windows-wmi-activity/operational':'Microsoft-Windows-WMI-Activity',
}


def _system_time(rec: dict) -> str:
    """Return a UTC ISO timestamp for <TimeCreated SystemTime="...">.

    Preference order:
    1. @timestamp  (Logstash UTC, e.g. "2020-05-02T02:55:26.493Z")
    2. UtcTime     (Sysmon field, e.g. "2020-05-02 02:55:23.551")
    3. EventTime   (NXLog local time, e.g. "2020-05-01 22:55:23") — least accurate
    """
    ts = rec.get('@timestamp') or ''
    if ts:
        return ts if ts.endswith('Z') else ts.replace('+00:00', 'Z') + 'Z'

    utc = rec.get('UtcTime') or ''
    if utc:
        return utc.replace(' ', 'T') + 'Z'

    evt = rec.get('EventTime') or ''
    return (evt.replace(' ', 'T') + 'Z') if evt else '1970-01-01T00:00:00Z'


def _record_to_xml(rec: dict) -> str | None:
    """Convert one MORDOR JSON record to a single-line <Event> XML string."""
    raw_eid = str(rec.get('EventID', ''))
    if not raw_eid:
        return None

    channel = (rec.get('Channel') or '').lower()
    provider = _CHANNEL_TO_PROVIDER.get(channel, rec.get('Channel') or 'Unknown')
    hostname = html.escape(rec.get('Hostname') or rec.get('host') or '')
    sys_time = html.escape(_system_time(rec))

    system_block = (
        f'<System>'
        f'<Provider Name="{html.escape(provider)}"/>'
        f'<EventID>{html.escape(raw_eid)}</EventID>'
        f'<TimeCreated SystemTime="{sys_time}"/>'
        f'<Computer>{hostname}</Computer>'
        f'</System>'
    )

    data_parts: list[str] = []
    for k, v in rec.items():
        if k in _META_KEYS or not isinstance(v, (str, int, float)):
            continue
        data_parts.append(
            f'<Data Name="{html.escape(k)}">{html.escape(str(v))}</Data>'
        )

    event_data = f'<EventData>{"".join(data_parts)}</EventData>'
    return f'<Event>{system_block}{event_data}</Event>'


def convert(src: Path, dst: Path) -> int:
    """Convert ndjson → one-Event-per-line XML. Returns count of written records."""
    written = 0
    skipped = 0

    with open(src, encoding='utf-8', errors='replace') as fin, \
         open(dst, 'w', encoding='utf-8') as fout:

        for lineno, line in enumerate(fin, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            xml = _record_to_xml(rec)
            if xml is None:
                skipped += 1
                continue

            fout.write(xml + '\n')
            written += 1

            if written % 10_000 == 0:
                print(f'  {written:,} records written…', flush=True)

    print(f'  skipped {skipped:,} unparseable lines')
    return written


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    src = Path(sys.argv[1])
    if not src.exists():
        print(f'Error: {src} not found', file=sys.stderr)
        sys.exit(1)

    dst = Path(sys.argv[2]) if len(sys.argv) > 2 else src.with_suffix('').with_suffix('.evtx.xml')

    print(f'Converting {src} -> {dst}')
    n = convert(src, dst)
    print(f'Done: {n:,} events written to {dst}')


if __name__ == '__main__':
    main()
