import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import { User, Server, AlertTriangle } from 'lucide-react';
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
  unauthorized_access: 'UNAUTH ACCESS',
};

function ChainNode({ data, selected }: NodeProps) {
  const d           = data as unknown as ChainNodeData;
  const accentColor = CHAIN_COLORS[d.chain_type] ?? '#3B82F6';
  const sevColor    = SEV_COLOR[d.severity]       ?? '#71717A';
  const isComp      = d.compromised === true;
  const hasUser     = Boolean(d.actor_user);
  const hasIp       = Boolean(d.actor_ip);
  const actor       = d.actor_user || d.actor_ip || '—';
  const iconColor   = isComp ? '#EF4444' : '#52525B';

  const borderColor = selected
    ? sevColor
    : isComp
      ? 'rgba(239,68,68,0.45)'
      : 'rgba(255,255,255,0.08)';

  const shadow = isComp
    ? '0 0 0 1px rgba(239,68,68,0.3), 0 0 16px rgba(239,68,68,0.15)'
    : selected
      ? `0 0 0 1px ${sevColor}40, 0 0 20px ${sevColor}30`
      : '0 2px 8px rgba(0,0,0,0.4)';

  return (
    <div style={{
      width: '100%', height: '100%', position: 'relative',
      background:     'rgba(22,22,24,0.94)',
      backdropFilter: 'blur(8px)',
      border:         `1px solid ${borderColor}`,
      borderRadius:   '10px',
      borderLeft:     `3px solid ${isComp ? '#EF4444' : accentColor}`,
      boxShadow:      shadow,
      display: 'flex', flexDirection: 'column',
      overflow: 'hidden', cursor: 'pointer',
      transition: 'border-color 0.15s, box-shadow 0.15s',
    }}>
      {/* Top severity bar */}
      <div style={{ height: 2, background: sevColor, opacity: 0.7, flexShrink: 0 }} />

      <div style={{ padding: '7px 10px', flex: 1, display: 'flex', flexDirection: 'column', gap: 4, minWidth: 0 }}>

        {/* Row 1: chain type + severity badge */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 4, minWidth: 0 }}>
          <span style={{
            fontFamily: 'JetBrains Mono, monospace', fontSize: 10, fontWeight: 700,
            color: isComp ? '#EF4444' : accentColor,
            letterSpacing: '0.06em', textTransform: 'uppercase',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1,
          }}>
            {CHAIN_LABEL[d.chain_type] ?? d.chain_type}
          </span>
          <span style={{
            fontFamily: 'JetBrains Mono, monospace', fontSize: 8, fontWeight: 700,
            color: sevColor, background: `${sevColor}18`,
            border: `1px solid ${sevColor}40`, borderRadius: 3,
            padding: '1px 4px', letterSpacing: '0.04em', textTransform: 'uppercase', flexShrink: 0,
          }}>
            {d.severity}
          </span>
        </div>

        {/* Row 2: primary actor — user or IP with icon */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 5, minWidth: 0 }}>
          {hasUser
            ? <User size={11} color={iconColor} style={{ flexShrink: 0 }} />
            : hasIp
              ? <Server size={11} color={iconColor} style={{ flexShrink: 0 }} />
              : null
          }
          {isComp && <AlertTriangle size={10} color="#EF4444" style={{ flexShrink: 0 }} />}
          <span style={{
            fontFamily: 'JetBrains Mono, monospace', fontSize: 11,
            color: isComp ? '#FCA5A5' : '#E4E4E7',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1,
          }}>
            {actor}
          </span>
        </div>

        {/* Row 3 (optional): secondary actor — show IP when both user+IP present */}
        {hasUser && hasIp && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 5, minWidth: 0 }}>
            <Server size={10} color={iconColor} style={{ flexShrink: 0 }} />
            <span style={{
              fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: '#71717A',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }}>
              {d.actor_ip}
            </span>
          </div>
        )}

        {/* Row 4: meta — event count · first seen · MITRE */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 'auto', overflow: 'hidden' }}>
          <span style={{ fontSize: 9, color: '#52525B', flexShrink: 0 }}>
            {d.event_count}ev
          </span>
          {d.firstSeen && (
            <span style={{ fontSize: 9, color: '#3F3F46', fontFamily: 'JetBrains Mono, monospace', flexShrink: 0 }}>
              {d.firstSeen.slice(11, 19)}
            </span>
          )}
          {d.mitre_ids && (
            <span style={{
              fontSize: 9, color: '#3B82F6', fontFamily: 'JetBrains Mono, monospace',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }}>
              {d.mitre_ids.split(',')[0].trim()}
            </span>
          )}
        </div>
      </div>

      {/* Compromised badge — absolute so it doesn't displace content */}
      {isComp && (
        <div style={{
          position: 'absolute', top: 6, right: 8,
          background: '#EF444420', border: '1px solid #EF444440',
          borderRadius: 3, padding: '1px 5px',
        }}>
          <span style={{ fontSize: 7, fontWeight: 800, letterSpacing: '0.07em', color: '#EF4444', textTransform: 'uppercase' }}>
            COMPROMISED
          </span>
        </div>
      )}

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
