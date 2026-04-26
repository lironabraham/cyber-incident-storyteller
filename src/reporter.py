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

_CHAIN_TYPE_RECOMMENDATIONS: dict[str, list[str]] = {
    'brute_force': [
        'Enforce MFA on all externally-accessible services',
        'Implement account lockout after 5 failed attempts',
        'Block originating IP at the perimeter firewall',
        'Review VPN and RDP exposure — restrict to known IP ranges',
    ],
    'credential_stuffing': [
        'Rotate credentials for all accounts targeted in the attack',
        'Enforce MFA — credential stuffing succeeds when passwords are the only factor',
        'Deploy a credential-breach monitoring service (e.g. HaveIBeenPwned API)',
        'Review and revoke any active sessions for affected accounts',
    ],
    'post_exploitation': [
        'Isolate affected host immediately and capture a forensic image',
        'Rotate all credentials accessible from the compromised host',
        'Review parent-child process relationships and new persistence mechanisms',
        'Hunt for lateral movement from the compromised host across the network',
    ],
    'unauthorized_access': [
        'Investigate the successful login — verify it is not a legitimate user',
        'Revoke session tokens and force re-authentication for the affected account',
        'Review what resources were accessed after the login',
        'Check for new scheduled tasks, services, or startup entries added post-login',
    ],
    'lateral_movement': [
        'Implement network segmentation — restrict lateral movement paths',
        'Disable NTLM authentication where Kerberos is available',
        'Audit SMB shares and RDP access — apply least-privilege',
        'Deploy host-based firewall rules to block unexpected inbound connections',
    ],
    'credential_access': [
        'Assume all credentials on the affected host are compromised — rotate immediately',
        'Enable Credential Guard on Windows endpoints',
        'Restrict LSASS access — enable RunAsPPL (Protected Process Light)',
        'Audit and disable unnecessary accounts with LSASS access rights',
    ],
    'defense_evasion': [
        'Review and restore audit log settings — check for gaps in the event timeline',
        'Enable tamper protection on endpoint security software',
        'Centralize log forwarding to a SIEM — prevent local log tampering',
        'Hunt for additional LOLBin executions (certutil, regsvr32, mshta, rundll32)',
    ],
}


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
        safe = host.replace('-', '_').replace('.', '_')[:12]
        lines.append(f'    participant {safe} as {host}')

    for event in chain.events:
        host = event.target_system.get('hostname', 'server')
        safe_host = host.replace('-', '_').replace('.', '_')[:12]
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
        lines.append(f'- **Compromised**: {"Yes [!]" if chain.compromised else "No"}')
        if chain.actor_user:
            lines.append(f'- **Primary target account**: `{chain.actor_user}`')
        if chain.mitre_techniques:
            tech_str = ' -> '.join(
                f"`{t['id']}`" for t in chain.mitre_techniques if t['id']
            )
            lines.append(f'- **Attack progression**: {tech_str}')
        lines.append(f'- **Events in chain**: {len(chain.events)}')
        lines.append(f'- **Active window**: {start} -> {end}')
        lines.append('')

    return '\n'.join(lines)


def _chain_type_recommendations(chain_types: set[str]) -> list[str]:
    """Generate actionable recommendations based on detected chain types.

    Args:
        chain_types: Set of chain type strings from detected attacks

    Returns:
        Deduplicated list of recommendations for all detected chain types.
        Falls back to 3 generic recommendations if no specific types match.
    """
    recommendations: list[str] = []
    seen: set[str] = set()

    # Collect recommendations for all detected chain types (in order)
    for chain_type in sorted(chain_types):
        if chain_type in _CHAIN_TYPE_RECOMMENDATIONS:
            for rec in _CHAIN_TYPE_RECOMMENDATIONS[chain_type]:
                if rec not in seen:
                    recommendations.append(rec)
                    seen.add(rec)

    # Fall back to generic recommendations if no specific ones found
    if not recommendations:
        recommendations = [
            'No immediate threats detected. Continue routine monitoring.',
            'Review access logs for any unusual patterns.',
            'Maintain current security posture and alert thresholds.',
        ]

    return recommendations


def _recommendations(chains: list[AttackChain]) -> str:
    if not chains:
        lines = ['## Recommendations\n']
        lines.append('1. No attack chains detected. Continue routine monitoring.')
        lines.append('')
        return '\n'.join(lines)

    # Collect all chain types present in the incident
    chain_types = {c.chain_type for c in chains}

    # Get chain-type-specific recommendations
    recs = _chain_type_recommendations(chain_types)

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
