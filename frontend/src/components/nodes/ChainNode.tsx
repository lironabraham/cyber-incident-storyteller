import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import type { ChainNodeData, Severity } from '../../types';

const CHAIN_COLORS: Record<string, string> = {
  post_exploitation:   '#dc2626',
  brute_force:         '#ea580c',
  credential_stuffing: '#d97706',
  lateral_movement:    '#7c3aed',
  credential_access:   '#991b1b',
  defense_evasion:     '#0d9488',
  unauthorized_access: '#2563eb',
};

const SEV_COLOR: Record<Severity, string> = {
  critical: '#EF4444',
  high:     '#F59E0B',
  medium:   '#EAB308',
  low:      '#10B981',
  info:     '#71717A',
};

const CHAIN_LABEL: Record<string, string> = {
  post_exploitation:   'POST EXPLOIT',
  brute_force:         'BRUTE FORCE',
  credential_stuffing: 'CRED STUFF',
  lateral_movement:    'LATERAL MOV',
  credential_access:   'CRED ACCESS',
  defense_evasion:     'DEF EVASION',
  unauthorized_access: 'UNAUTH ACC',
};

function fmtTime(iso: string): string {
  try { return iso.slice(11, 19); } catch { return iso; }
}

function ChainNode({ data, selected }: NodeProps) {
  const d           = data as unknown as ChainNodeData;
  const accentColor = CHAIN_COLORS[d.chain_type] ?? '#3B82F6';
  const sevColor    = SEV_COLOR[d.severity]       ?? '#71717A';
  const actor       = d.actor_user || d.actor_ip  || '—';

  return (
    <div style={{
      width: '100%', height: '100%',
      background:     'rgba(22,22,24,0.92)',
      backdropFilter: 'blur(8px)',
      border:         `1px solid ${selected ? sevColor : 'rgba(255,255,255,0.08)'}`,
      borderRadius:   '10px',
      borderLeft:     `3px solid ${accentColor}`,
      boxShadow:      selected
        ? `0 0 0 1px ${sevColor}40, 0 0 20px ${sevColor}30`
        : '0 2px 8px rgba(0,0,0,0.4)',
      display: 'flex', flexDirection: 'column',
      overflow: 'hidden', cursor: 'pointer',
      transition: 'border-color 0.15s, box-shadow 0.15s',
    }}>
      <div style={{ height: 2, background: sevColor, opacity: 0.7, flexShrink: 0 }} />

      <div style={{ padding: '7px 10px', flex: 1, display: 'flex', flexDirection: 'column', gap: 3 }}>
        {/* Row 1: chain type + severity */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{
            fontFamily: 'JetBrains Mono, monospace', fontSize: 10, fontWeight: 600,
            color: accentColor, letterSpacing: '0.06em', textTransform: 'uppercase',
          }}>
            {CHAIN_LABEL[d.chain_type] ?? d.chain_type}
          </span>
          <span style={{
            fontFamily: 'JetBrains Mono, monospace', fontSize: 9, fontWeight: 600,
            color: sevColor, background: `${sevColor}18`,
            border: `1px solid ${sevColor}40`, borderRadius: 4,
            padding: '1px 5px', letterSpacing: '0.04em', textTransform: 'uppercase',
          }}>
            {d.severity}
          </span>
        </div>

        {/* Row 2: actor */}
        <div style={{
          fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: '#E4E4E7',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>
          {actor}
        </div>

        {/* Row 3: bottom meta */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 'auto', flexWrap: 'nowrap', overflow: 'hidden' }}>
          <span style={{ fontSize: 9, color: '#71717A', flexShrink: 0 }}>
            {d.event_count}ev
          </span>
          {d.firstSeen && (
            <span style={{ fontSize: 9, color: '#52525B', fontFamily: 'JetBrains Mono, monospace', flexShrink: 0 }}>
              {fmtTime(d.firstSeen)}
            </span>
          )}
          {d.mitre_ids && (
            <span style={{ fontSize: 9, color: '#3B82F6', fontFamily: 'JetBrains Mono, monospace', flexShrink: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {d.mitre_ids.split(',')[0].trim()}
            </span>
          )}
          {d.compromised && (
            <span style={{
              fontSize: 8, fontWeight: 700, letterSpacing: '0.05em', textTransform: 'uppercase',
              color: '#EF4444', background: '#EF444418', border: '1px solid #EF444440',
              borderRadius: 3, padding: '1px 4px', flexShrink: 0, marginLeft: 'auto',
            }}>
              COMP
            </span>
          )}
        </div>
      </div>

      <Handle type="target" position={Position.Left}
        style={{ background: '#2A2A2E', border: '1px solid #3B82F6', width: 7, height: 7 }} />
      <Handle type="source" position={Position.Right}
        style={{ background: '#2A2A2E', border: '1px solid #3B82F6', width: 7, height: 7 }} />
      <Handle type="source" position={Position.Bottom} id="bottom"
        style={{ background: '#2A2A2E', border: '1px solid rgba(59,130,246,0.4)', width: 6, height: 6 }} />
    </div>
  );
}

export default memo(ChainNode);
