import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import type { EventNodeData, Severity } from '../../types';

const SEV_COLOR: Record<Severity, string> = {
  critical: '#EF4444',
  high:     '#F59E0B',
  medium:   '#EAB308',
  low:      '#10B981',
  info:     '#71717A',
};

function fmtTime(ts: string): string {
  try { return new Date(ts).toISOString().slice(11, 19); }
  catch { return ts.slice(0, 8); }
}

function EventNode({ data, selected }: NodeProps) {
  const d        = data as unknown as EventNodeData;
  const sevColor = SEV_COLOR[d.severity] ?? '#71717A';

  return (
    <div style={{
      width: '100%', height: '100%',
      background:     'rgba(16,16,18,0.95)',
      backdropFilter: 'blur(6px)',
      border:         `1px solid ${selected ? sevColor : 'rgba(255,255,255,0.06)'}`,
      borderRadius:   '7px',
      borderLeft:     `2px solid ${sevColor}`,
      boxShadow:      selected ? `0 0 12px ${sevColor}28` : 'none',
      display:        'flex', alignItems: 'center', gap: 8,
      padding:        '0 10px',
      cursor:         'pointer', overflow: 'hidden',
      transition:     'border-color 0.12s, box-shadow 0.12s',
    }}>
      <div style={{ width: 6, height: 6, borderRadius: '50%', background: sevColor, flexShrink: 0 }} />

      <div style={{ flex: 1, overflow: 'hidden', minWidth: 0 }}>
        <div style={{
          fontFamily: 'JetBrains Mono, monospace', fontSize: 10, fontWeight: 600,
          color: '#E4E4E7', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>
          {d.label}
        </div>
        <div style={{ display: 'flex', gap: 6, marginTop: 2 }}>
          {d.timestamp && (
            <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#71717A' }}>
              {fmtTime(d.timestamp)}
            </span>
          )}
          {d.process && (
            <span style={{
              fontSize: 9, color: '#3B82F6', fontFamily: 'JetBrains Mono, monospace',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 90,
            }}>
              {d.process}
            </span>
          )}
          {d.is_lolbin && (
            <span style={{
              fontSize: 8, color: '#F59E0B', background: '#F59E0B18',
              border: '1px solid #F59E0B40', borderRadius: 3, padding: '0 3px', letterSpacing: '0.04em',
            }}>
              LOLBin
            </span>
          )}
        </div>
      </div>

      {d.mitre_id && (
        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 8, color: '#71717A', flexShrink: 0 }}>
          {d.mitre_id}
        </span>
      )}

      <Handle type="target" position={Position.Top}
        style={{ background: '#2A2A2E', border: '1px solid #2A2A2E', width: 5, height: 5 }} />
      <Handle type="source" position={Position.Bottom}
        style={{ background: '#2A2A2E', border: '1px solid #2A2A2E', width: 5, height: 5 }} />
    </div>
  );
}

export default memo(EventNode);
