"""
API schema builder for the web UI.

Converts attack chains + events into the JSON contract consumed by
the Cytoscape.js frontend.  All graph structure lives here so
webapp.py stays thin.
"""
from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hunter import AttackChain
from reporter import generate_report
from schema import StandardEvent

_CHAIN_COLORS: dict[str, str] = {
    'post_exploitation':   '#dc2626',
    'brute_force':         '#ea580c',
    'credential_stuffing': '#d97706',
    'lateral_movement':    '#7c3aed',
    'credential_access':   '#991b1b',
    'defense_evasion':     '#0d9488',
    'unauthorized_access': '#2563eb',
}
_SEVERITY_COLORS: dict[str, str] = {
    'critical': '#ef4444',
    'high':     '#f97316',
    'medium':   '#eab308',
    'low':      '#22c55e',
    'info':     '#94a3b8',
}
_DEFAULT_CHAIN_COLOR = '#64748b'
_DEFAULT_EVENT_COLOR = '#94a3b8'


def _chain_node(chain: AttackChain, idx: int) -> dict[str, Any]:
    actor = chain.actor_ip or chain.actor_user or 'unknown'
    mitre_ids   = ', '.join(t['id']   for t in chain.mitre_techniques if t.get('id'))
    mitre_names = '; '.join(t['name'] for t in chain.mitre_techniques if t.get('name'))
    label = f"{chain.chain_type}\n{actor}"
    return {
        'data': {
            'id':          f'chain_{idx}',
            'label':       label,
            'type':        'chain',
            'chain_type':  chain.chain_type,
            'severity':    chain.severity,
            'actor_ip':    chain.actor_ip   or '',
            'actor_user':  chain.actor_user or '',
            'event_count': len(chain.events),
            'compromised': chain.compromised,
            'mitre_ids':   mitre_ids,
            'mitre_names': mitre_names,
            'color':       _CHAIN_COLORS.get(chain.chain_type, _DEFAULT_CHAIN_COLOR),
        },
        'classes': f'chain {chain.severity} {chain.chain_type}',
    }


def _event_node(event: StandardEvent, chain_idx: int) -> dict[str, Any]:
    """Event node with NO parent — added dynamically by the frontend on expand."""
    actor  = event.source_actor
    target = event.target_system
    mitre  = event.mitre_technique
    return {
        'data': {
            'id':           f'event_{event.event_id}',
            'label':        event.event_type,
            'chain_id':     f'chain_{chain_idx}',
            'type':         'event',
            'event_type':   event.event_type,
            'severity':     event.severity,
            'timestamp':    event.timestamp.isoformat() if event.timestamp else '',
            'action_taken': event.action_taken,
            'source_ip':    actor.get('ip')   or '',
            'user':         actor.get('user') or '',
            'hostname':     target.get('hostname') or '',
            'process':      target.get('process')  or '',
            'mitre_id':     mitre.get('id')   or '',
            'mitre_name':   mitre.get('name') or '',
            'command_line': event.command_line or '',
            'is_lolbin':    event.is_lolbin,
            'color':        _SEVERITY_COLORS.get(event.severity, _DEFAULT_EVENT_COLOR),
        },
        'classes': f'event {event.severity}',
    }


def _build_graph(chains: list[AttackChain]) -> dict[str, Any]:
    """Return chain-only Cytoscape nodes+edges, plus a per-chain event map.

    Event nodes are NOT included in the main graph — the frontend adds them
    dynamically when the user expands a chain node.  This avoids compound-node
    layout issues and keeps the initial render fast for large EVTX files.
    """
    nodes: list[dict] = []
    edges: list[dict] = []
    event_map: dict[str, dict] = {}   # chain_id -> {nodes, edges}
    actor_to_chains: dict[str, list[int]] = {}

    for idx, chain in enumerate(chains):
        chain_id = f'chain_{idx}'
        nodes.append(_chain_node(chain, idx))

        # Build per-chain event payload (sent to frontend but not in main graph)
        evt_nodes = [_event_node(e, idx) for e in chain.events]
        evt_edges = []
        for i in range(len(chain.events) - 1):
            a = chain.events[i]
            b = chain.events[i + 1]
            evt_edges.append({
                'data': {
                    'id':     f'eet_{a.event_id}_{b.event_id}',
                    'source': f'event_{a.event_id}',
                    'target': f'event_{b.event_id}',
                    'type':   'temporal',
                    'chain_id': chain_id,
                },
                'classes': 'event-edge',
            })
        event_map[chain_id] = {'nodes': evt_nodes, 'edges': evt_edges}

        # Track actors for inter-chain edges (use both ip and user)
        for actor_key in {chain.actor_ip, chain.actor_user} - {None, ''}:
            actor_to_chains.setdefault(actor_key, []).append(idx)

    # Same-actor edges between chain nodes (deduplicated)
    seen_edges: set[tuple[int, int]] = set()
    for actor, idxs in actor_to_chains.items():
        for i in range(len(idxs) - 1):
            a, b = idxs[i], idxs[i + 1]
            key = (min(a, b), max(a, b))
            if key in seen_edges:
                continue
            seen_edges.add(key)
            edges.append({
                'data': {
                    'id':     f'eca_{a}_{b}',
                    'source': f'chain_{a}',
                    'target': f'chain_{b}',
                    'type':   'same-actor',
                    'actor':  actor,
                },
                'classes': 'chain-edge',
            })

    return {'nodes': nodes, 'edges': edges, 'event_map': event_map}


def _generate_markdown(chains: list[AttackChain], events: list[StandardEvent]) -> str:
    with tempfile.NamedTemporaryFile(suffix='.md', delete=False,
                                     mode='w', encoding='utf-8') as f:
        tmp = Path(f.name)
    try:
        generate_report(chains, events, tmp)
        return tmp.read_text(encoding='utf-8')
    except Exception:
        return ''
    finally:
        tmp.unlink(missing_ok=True)


def build_analysis_response(
    chains: list[AttackChain],
    events: list[StandardEvent],
    file_name: str,
) -> dict[str, Any]:
    """Full API response for a completed analysis."""
    sev_dist: dict[str, int] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    chain_type_dist: dict[str, int] = {}

    for e in events:
        key = e.severity if e.severity in sev_dist else 'info'
        sev_dist[key] += 1
    for c in chains:
        chain_type_dist[c.chain_type] = chain_type_dist.get(c.chain_type, 0) + 1

    return {
        'status': 'success',
        'cy': _build_graph(chains),
        'metadata': {
            'file_name':              file_name,
            'analyzed_at':            datetime.now(timezone.utc).isoformat(),
            'event_count':            len(events),
            'chain_count':            len(chains),
            'severity_distribution':  sev_dist,
            'chain_type_distribution':chain_type_dist,
        },
        'report_markdown': _generate_markdown(chains, events),
    }
