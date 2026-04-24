"""
Markdown report generator with Mermaid.js sequence diagrams.

Output sections
---------------
1. Executive Summary (BLUF)   — plain-English leadership paragraph
2. Attack Timeline            — Markdown table, all chain events sorted by time
3. Visual Sequence Map        — Mermaid sequenceDiagram of the top chain
4. Threat Actor Detail        — per-IP breakdown
5. Recommendations            — numbered action list
6. Forensic Integrity         — source log hashes and event counts

Public API
----------
generate_report(chains, events, output_path) -> Path
"""

import textwrap
from datetime import datetime, timezone
from pathlib import Path

from hunter import AttackChain
from schema import StandardEvent

_SEVERITY_ORDER = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
_SUCCESS_TYPES = {'Accepted Password', 'Accepted Publickey'}


# ── Public API ─────────────────────────────────────────────────────────────────

def generate_report(
    chains: list[AttackChain],
    events: list[StandardEvent],
    output_path: Path,
) -> Path:
    """Render chains + events to a Markdown file and return its path."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_build_markdown(chains, events), encoding='utf-8')
    return output_path


# ── Section builders ───────────────────────────────────────────────────────────

def _build_markdown(chains: list[AttackChain], events: list[StandardEvent]) -> str:
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    parts = [
        f'# Cyber Incident Report\n',
        f'*Generated: {now}*\n',
        _executive_summary(chains, events),
        _attack_timeline(chains),
        _mermaid_diagram(chains),
        _threat_actor_detail(chains),
        _recommendations(chains),
        _integrity_section(events),
    ]
    return '\n'.join(parts)


def _executive_summary(chains: list[AttackChain], events: list[StandardEvent]) -> str:
    lines = ['## Executive Summary (BLUF)\n']

    if not chains:
        lines.append('No attack chains detected in the analyzed log period.\n')
        return '\n'.join(lines)

    total = len(events)
    compromised = [c for c in chains if c.compromised]
    max_sev = max(
        (c.severity for c in chains),
        key=lambda s: _SEVERITY_ORDER.get(s, 0),
    )

    lines.append(
        f'Analysis of **{total}** log events identified **{len(chains)} attacking IP(s)**.'
    )

    if compromised:
        users = sorted({c.actor_user for c in compromised if c.actor_user})
        user_str = ', '.join(f'`{u}`' for u in users) or 'unknown'
        lines.append(
            f'**{len(compromised)} attacker(s) achieved successful authentication**, '
            f'potentially compromising account(s): {user_str}.'
        )
    else:
        lines.append('No attackers achieved successful authentication during this period.')

    lines.append(f'Maximum incident severity: **{max_sev.upper()}**.\n')
    return '\n'.join(lines)


def _attack_timeline(chains: list[AttackChain]) -> str:
    if not chains:
        return ''

    lines = ['## Attack Timeline\n']
    lines.append('| UTC Time | Attacker IP | User | Event | MITRE | Severity |')
    lines.append('|----------|-------------|------|-------|-------|----------|')

    # Flatten and sort all chain events chronologically
    all_events: list[tuple[StandardEvent, str]] = []
    for chain in chains:
        for e in chain.events:
            all_events.append((e, chain.actor_ip))
    all_events.sort(key=lambda x: x[0].timestamp)

    for event, actor_ip in all_events:
        ts = event.timestamp.strftime('%H:%M:%S')
        user = event.source_actor.get('user') or '—'
        mid = event.mitre_technique.get('id')
        mname = event.mitre_technique.get('name')
        mitre_cell = f'`{mid}` {mname}' if mid else '—'
        lines.append(
            f'| {ts} | {actor_ip} | `{user}` | {event.event_type} | {mitre_cell} | {event.severity} |'
        )

    lines.append('')
    return '\n'.join(lines)


def _mermaid_diagram(chains: list[AttackChain]) -> str:
    if not chains:
        return ''

    chain = chains[0]  # highest-severity chain
    lines = ['## Visual Sequence Map\n']
    lines.append('```mermaid')
    lines.append('sequenceDiagram')
    lines.append(f'    participant A as Attacker ({chain.actor_ip})')

    # Collect unique hosts (cap at 3 for readability)
    hosts = list(dict.fromkeys(
        e.target_system.get('hostname', 'server') for e in chain.events
    ))[:3]
    for host in hosts:
        safe = host.replace('-', '_')[:12]
        lines.append(f'    participant {safe} as {host}')

    for event in chain.events:
        host = event.target_system.get('hostname', 'server')
        safe_host = host.replace('-', '_')[:12]
        mid = event.mitre_technique.get('id')
        mitre_label = f' [{mid}]' if mid else ''
        ts = event.timestamp.strftime('%H:%M:%S')
        label = f'{event.event_type}{mitre_label} ({ts})'

        # Internal events (session lifecycle) use self-arrows
        if event.event_type in ('Session Opened', 'Session Closed'):
            lines.append(f'    {safe_host}->>{safe_host}: {label}')
        else:
            lines.append(f'    A->>{safe_host}: {label}')

    lines.append('```\n')
    return '\n'.join(lines)


def _threat_actor_detail(chains: list[AttackChain]) -> str:
    if not chains:
        return ''

    lines = ['## Threat Actor Detail\n']
    for chain in chains:
        sev = chain.severity.upper()
        start = chain.events[0].timestamp.strftime('%H:%M:%S') if chain.events else '—'
        end = chain.events[-1].timestamp.strftime('%H:%M:%S') if chain.events else '—'

        lines.append(f'### `{chain.actor_ip}` — {sev}')
        lines.append(f'- **Chain type**: {chain.chain_type.replace("_", " ").title()}')
        lines.append(f'- **Compromised**: {"Yes ⚠" if chain.compromised else "No"}')
        if chain.actor_user:
            lines.append(f'- **Primary target account**: `{chain.actor_user}`')
        if chain.mitre_techniques:
            tech_str = ' → '.join(
                f"`{t['id']}`" for t in chain.mitre_techniques if t['id']
            )
            lines.append(f'- **Attack progression**: {tech_str}')
        lines.append(f'- **Events in chain**: {len(chain.events)}')
        lines.append(f'- **Active window**: {start} → {end}')
        lines.append('')

    return '\n'.join(lines)


def _recommendations(chains: list[AttackChain]) -> str:
    recs: list[str] = []

    brute_ips = [c.actor_ip for c in chains if not c.compromised]
    compromised = [c for c in chains if c.compromised]

    if brute_ips:
        ip_list = ', '.join(brute_ips[:5])
        extra = f' and {len(brute_ips) - 5} more' if len(brute_ips) > 5 else ''
        recs.append(
            f'Block {len(brute_ips)} IP(s) exhibiting brute-force behavior: {ip_list}{extra}.'
        )

    if compromised:
        recs.append(
            'Immediately audit and rotate credentials for all compromised accounts.'
        )
        recs.append(
            'Review sudo logs and session commands for post-exploitation activity '
            '(file downloads, persistence mechanisms, privilege escalation).'
        )

    all_events_flat = [e for c in chains for e in c.events]
    has_sudo = any(e.event_type == 'Sudo Command' for e in all_events_flat)
    if has_sudo:
        recs.append(
            'Audit sudo policy — restrict to minimum required privileges '
            '(principle of least privilege).'
        )

    root_attacks = any(
        e.source_actor.get('user') == 'root' and e.event_type == 'Failed Login'
        for c in chains for e in c.events
    )
    if root_attacks:
        recs.append(
            'Disable direct root SSH login: set `PermitRootLogin no` in sshd_config.'
        )

    recs.append(
        'Enable fail2ban or equivalent rate-limiting to automatically throttle '
        'repeated authentication failures.'
    )

    if not [r for r in recs if 'Block' in r or 'Immediately' in r]:
        recs.insert(0, 'No immediate threats detected. Continue routine monitoring.')

    lines = ['## Recommendations\n']
    for i, rec in enumerate(recs, 1):
        wrapped = textwrap.fill(rec, width=90, subsequent_indent='   ')
        lines.append(f'{i}. {wrapped}')
    lines.append('')
    return '\n'.join(lines)


def _integrity_section(events: list[StandardEvent]) -> str:
    if not events:
        return ''

    sources = list(dict.fromkeys(e.source_log for e in events))
    lines = ['## Forensic Integrity\n']
    lines.append('| Source Log | Events Analyzed |')
    lines.append('|-----------|----------------|')
    for src in sources:
        count = sum(1 for e in events if e.source_log == src)
        lines.append(f'| `{src}` | {count} |')
    lines.append('')
    lines.append(
        '> Original log files are opened read-only and never modified. '
        'SHA-256 hashes are stored in `data/processed/` for chain-of-custody verification.'
    )
    lines.append('')
    return '\n'.join(lines)
