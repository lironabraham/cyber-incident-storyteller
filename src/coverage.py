"""
MITRE ATT&CK coverage reporting.

Derives coverage directly from MITRE_MAP and SUSPICIOUS_COMMANDS in mitre.py
so the output never drifts from the live detection logic.

Public API
----------
build_coverage_layer()     -> dict   ATT&CK Navigator layer (v4.4, enterprise-attack)
build_coverage_markdown()  -> str    Markdown tactic matrix
coverage_summary()         -> str    one-line CLI summary
"""

import json

from mitre import MITRE_MAP, SUSPICIOUS_COMMANDS

# Primary display tactic for each technique ID.
# Source: MITRE ATT&CK Enterprise v18.
# Techniques that span multiple tactics are listed under their most common usage.
_TECHNIQUE_TACTIC: dict[str, str] = {
    'T1003':     'Credential Access',
    'T1003.001': 'Credential Access',
    'T1003.003': 'Credential Access',
    'T1003.006': 'Credential Access',
    'T1003.008': 'Credential Access',
    'T1021':     'Lateral Movement',
    'T1021.002': 'Lateral Movement',
    'T1021.004': 'Lateral Movement',
    'T1025':     'Collection',
    'T1033':     'Discovery',
    'T1046':     'Discovery',
    'T1047':     'Execution',
    'T1048':     'Exfiltration',
    'T1049':     'Discovery',
    'T1053':     'Persistence',
    'T1053.002': 'Persistence',
    'T1053.003': 'Persistence',
    'T1053.005': 'Persistence',
    'T1057':     'Discovery',
    'T1059':     'Execution',
    'T1059.001': 'Execution',
    'T1059.003': 'Execution',
    'T1059.004': 'Execution',
    'T1059.005': 'Execution',
    'T1059.006': 'Execution',
    'T1016':     'Discovery',
    'T1069':     'Discovery',
    'T1070':     'Defense Evasion',
    'T1070.001': 'Defense Evasion',
    'T1070.002': 'Defense Evasion',
    'T1070.003': 'Defense Evasion',
    'T1070.004': 'Defense Evasion',
    'T1071':     'Command and Control',
    'T1078':     'Defense Evasion',
    'T1078.002': 'Defense Evasion',
    'T1082':     'Discovery',
    'T1083':     'Discovery',
    'T1098':     'Persistence',
    'T1105':     'Command and Control',
    'T1110':     'Credential Access',
    'T1110.001': 'Credential Access',
    'T1110.002': 'Credential Access',
    'T1110.003': 'Credential Access',
    'T1112':     'Defense Evasion',
    'T1132.001': 'Command and Control',
    'T1134':     'Privilege Escalation',
    'T1136.001': 'Persistence',
    'T1140':     'Defense Evasion',
    'T1190':     'Initial Access',
    'T1197':     'Defense Evasion',
    'T1218.005': 'Defense Evasion',
    'T1218.010': 'Defense Evasion',
    'T1218.011': 'Defense Evasion',
    'T1222':     'Defense Evasion',
    'T1482':     'Discovery',
    'T1489':     'Impact',
    'T1490':     'Impact',
    'T1505.003': 'Persistence',
    'T1531':     'Impact',
    'T1543.002': 'Persistence',
    'T1543.003': 'Persistence',
    'T1548.003': 'Privilege Escalation',
    'T1550.002': 'Lateral Movement',
    'T1558':     'Credential Access',
    'T1558.003': 'Credential Access',
    'T1560.001': 'Collection',
    'T1595':     'Reconnaissance',
    'T1595.002': 'Reconnaissance',
}

_TACTIC_ORDER = [
    'Reconnaissance',
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'Command and Control',
    'Exfiltration',
    'Impact',
]

# Total parent technique count per tactic — MITRE ATT&CK Enterprise v18.
# Used to show "X / Y" coverage ratios. Sub-techniques excluded to keep the
# count readable; Navigator shows the full sub-technique breakdown interactively.
_TACTIC_TOTALS: dict[str, int] = {
    'Reconnaissance':       11,
    'Initial Access':       11,
    'Execution':            17,
    'Persistence':          23,
    'Privilege Escalation': 14,
    'Defense Evasion':      47,
    'Credential Access':    17,
    'Discovery':            34,
    'Lateral Movement':      9,
    'Collection':           17,
    'Command and Control':  18,
    'Exfiltration':          9,
    'Impact':               15,
}


def _collect_techniques() -> dict[str, dict]:
    """Return {technique_id: {name, sources}} from MITRE_MAP + SUSPICIOUS_COMMANDS."""
    techniques: dict[str, dict] = {}

    for event_type, (tid, tname) in MITRE_MAP.items():
        if not tid:
            continue
        if tid not in techniques:
            techniques[tid] = {'name': tname or '', 'sources': []}
        techniques[tid]['sources'].append(event_type)

    for cmd, (tid, tname) in SUSPICIOUS_COMMANDS.items():
        if not tid:
            continue
        if tid not in techniques:
            techniques[tid] = {'name': tname or '', 'sources': []}
        techniques[tid]['sources'].append(f'cmd:{cmd}')

    return techniques


def build_coverage_layer() -> dict:
    """Return an ATT&CK Navigator layer dict (v4.4 schema, enterprise-attack domain)."""
    techniques = _collect_techniques()
    layer_techniques = []
    for tid, info in sorted(techniques.items()):
        sources = info['sources']
        comment = ', '.join(sources[:4])
        if len(sources) > 4:
            comment += f' (+{len(sources) - 4} more)'
        layer_techniques.append({
            'techniqueID': tid,
            'score': 1,
            'comment': comment,
            'enabled': True,
        })

    return {
        'name': 'Cyber Incident Storyteller',
        'versions': {'layer': '4.4', 'navigator': '4.9.5', 'attack': '18'},
        'domain': 'enterprise-attack',
        'description': (
            'Techniques detectable from host logs — no cloud, no LLM, no SIEM required. '
            'Generated by: ais coverage --fmt navigator'
        ),
        'techniques': layer_techniques,
        'gradient': {
            'colors': ['#ffffff', '#00b4d8'],
            'minValue': 0,
            'maxValue': 1,
        },
        'legendItems': [
            {'label': 'Detected', 'color': '#00b4d8'},
        ],
        'hideDisabled': False,
        'showTacticRowBackground': True,
        'tacticRowBackground': '#1a1a2e',
    }


def build_coverage_markdown() -> str:
    """Return a Markdown MITRE ATT&CK tactic matrix derived from live mitre.py data."""
    techniques = _collect_techniques()

    tactic_groups: dict[str, list[tuple[str, str, list[str]]]] = {
        t: [] for t in _TACTIC_ORDER
    }
    uncategorized: list[tuple[str, str, list[str]]] = []

    for tid, info in sorted(techniques.items()):
        tactic = _TECHNIQUE_TACTIC.get(tid)
        entry = (tid, info['name'], info['sources'])
        if tactic in tactic_groups:
            tactic_groups[tactic].append(entry)
        else:
            uncategorized.append(entry)

    covered_tactics = sum(1 for entries in tactic_groups.values() if entries)
    total_framework = sum(_TACTIC_TOTALS.values())
    total_detected = len(techniques)

    lines = [
        '## MITRE ATT&CK Coverage Matrix',
        '',
        (
            f'**{total_detected} of ~{total_framework} parent techniques** detected '
            f'across **{covered_tactics} of {len(_TACTIC_ORDER)} tactics** '
            f'(MITRE ATT&CK Enterprise v18).'
        ),
        '',
        '!!! tip "Full interactive matrix"',
        '    Drag [`mitre-coverage-layer.json`](mitre-coverage-layer.json) onto',
        '    [navigator.attack.mitre.org](https://mitre-attack.github.io/attack-navigator/)',
        '    to see every ATT&CK technique colour-coded by whether this tool detects it.',
        '',
        '### Tactic Summary',
        '',
        '| Tactic | Detected | Total (v18) | Coverage |',
        '|---|---|---|---|',
    ]

    for tactic in _TACTIC_ORDER:
        count = len(tactic_groups.get(tactic, []))
        total = _TACTIC_TOTALS.get(tactic, '?')
        if count:
            pct = f'{count / total * 100:.0f}%' if isinstance(total, int) else '?'
            lines.append(f'| {tactic} | **{count}** | {total} | {pct} |')
        else:
            lines.append(f'| {tactic} | — | {total} | 0% |')

    lines += ['', '---', '']

    for tactic in _TACTIC_ORDER:
        entries = tactic_groups.get(tactic, [])
        if not entries:
            continue
        lines.append(f'### {tactic}')
        lines.append('')
        lines.append('| Technique | Name | Detection Source |')
        lines.append('|---|---|---|')
        for tid, tname, sources in sorted(entries):
            src_parts = [f'`{s}`' for s in sources[:4]]
            if len(sources) > 4:
                src_parts.append(f'+{len(sources) - 4} more')
            lines.append(f'| `{tid}` | {tname} | {", ".join(src_parts)} |')
        lines.append('')

    if uncategorized:
        lines += ['### Other', '', '| Technique | Name | Detection Source |', '|---|---|---|']
        for tid, tname, sources in sorted(uncategorized):
            src_str = ', '.join(f'`{s}`' for s in sources[:3])
            lines.append(f'| `{tid}` | {tname} | {src_str} |')
        lines.append('')

    return '\n'.join(lines)


def coverage_summary() -> str:
    """Return a one-line coverage summary suitable for CLI stdout."""
    techniques = _collect_techniques()
    covered_tactics = sum(
        1 for t in _TACTIC_ORDER
        if any(_TECHNIQUE_TACTIC.get(tid) == t for tid in techniques)
    )
    return (
        f'{len(techniques)} techniques | {covered_tactics}/{len(_TACTIC_ORDER)} tactics | '
        'sources: auth_log, syslog, audit_log, web_access, sysmon_linux, evtx'
    )


if __name__ == '__main__':
    import sys
    fmt = sys.argv[1] if len(sys.argv) > 1 else 'markdown'
    if fmt == 'navigator':
        print(json.dumps(build_coverage_layer(), indent=2))
    else:
        print(build_coverage_markdown())
