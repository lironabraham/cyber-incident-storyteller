import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Hexagon } from 'lucide-react';
import type { SelectedNode, ChainNodeData, EventNodeData, Severity, EventBucket } from '../types';

const SEV_COLOR: Record<Severity, string> = {
  critical: '#EF4444', high: '#F59E0B', medium: '#EAB308', low: '#10B981', info: '#71717A',
};
const CHAIN_COLORS: Record<string, string> = {
  post_exploitation: '#dc2626', brute_force: '#ea580c', credential_stuffing: '#d97706',
  lateral_movement:  '#7c3aed', credential_access: '#991b1b',
  defense_evasion:   '#0d9488', unauthorized_access: '#2563eb',
};

interface Props {
  selected: SelectedNode | null;
  eventMap: Record<string, EventBucket>;
  onClose: () => void;
  onEventSelect: (data: EventNodeData) => void;
}

function Row({ label, value, mono, color }: { label: string; value: string; mono?: boolean; color?: string }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
      <span style={{ fontSize: 11, color: '#71717A', flexShrink: 0 }}>{label}</span>
      <span style={{ fontSize: 11, color: color ?? '#E4E4E7', fontFamily: mono ? 'JetBrains Mono, monospace' : undefined, textAlign: 'right', wordBreak: 'break-all' }}>
        {value}
      </span>
    </div>
  );
}

function SevGauge({ severity }: { severity: Severity }) {
  const scores: Record<Severity, number> = { critical: 95, high: 72, medium: 48, low: 22, info: 8 };
  const score = scores[severity] ?? 0;
  const color = SEV_COLOR[severity];
  const r = 28; const circ = 2 * Math.PI * r;
  const dash = (score / 100) * circ;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
      <svg width={72} height={72} viewBox="0 0 72 72">
        <circle cx={36} cy={36} r={r} fill="none" stroke="#2A2A2E" strokeWidth={5} />
        <circle cx={36} cy={36} r={r} fill="none" stroke={color} strokeWidth={5}
          strokeDasharray={`${dash} ${circ - dash}`} strokeLinecap="round"
          transform="rotate(-90 36 36)" />
        <text x={36} y={41} textAnchor="middle" fill={color}
          style={{ fontSize: 16, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>
          {score}
        </text>
      </svg>
      <span style={{ fontSize: 10, color: '#71717A', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Risk</span>
    </div>
  );
}

function ChainDetail({ data, eventMap, onEventSelect }: { data: ChainNodeData; eventMap: Record<string, EventBucket>; onEventSelect: (d: EventNodeData) => void }) {
  const [eventsOpen, setEventsOpen] = useState(false);
  const accentColor = CHAIN_COLORS[data.chain_type] ?? '#3B82F6';
  const bucket      = eventMap[data.id];
  const events      = bucket?.nodes ?? [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, padding: '16px 16px 24px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <div style={{ fontSize: 10, color: '#71717A', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 4 }}>Chain Type</div>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '4px 10px', borderRadius: 6, background: `${accentColor}18`, border: `1px solid ${accentColor}40` }}>
            <div style={{ width: 6, height: 6, borderRadius: 2, background: accentColor }} />
            <span style={{ fontSize: 12, color: accentColor, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              {data.chain_type.replace(/_/g, ' ')}
            </span>
          </div>
        </div>
        <SevGauge severity={data.severity} />
      </div>

      <div style={{ background: '#1C1C1F', borderRadius: 8, padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 6 }}>
        <Row label="Actor IP"    value={data.actor_ip   || '—'} mono />
        <Row label="Actor User"  value={data.actor_user || '—'} mono />
        <Row label="Events"      value={String(data.event_count)} mono />
        <Row label="Compromised" value={data.compromised ? 'Yes' : 'No'} color={data.compromised ? '#EF4444' : '#10B981'} />
      </div>

      {data.mitre_ids && (
        <div>
          <div style={{ fontSize: 10, color: '#71717A', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 6 }}>MITRE ATT&CK</div>
          {data.mitre_ids.split(',').map((id, i) => {
            const name = (data.mitre_names.split(';')[i] ?? '').trim();
            return (
              <div key={id} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: '#3B82F6', background: '#3B82F618', border: '1px solid #3B82F630', borderRadius: 4, padding: '1px 6px', flexShrink: 0 }}>
                  {id.trim()}
                </span>
                {name && <span style={{ fontSize: 11, color: '#71717A' }}>{name}</span>}
              </div>
            );
          })}
        </div>
      )}

      {events.length > 0 && (
        <div>
          <button onClick={() => setEventsOpen(v => !v)} style={{
            width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            background: '#1C1C1F', border: '1px solid #2A2A2E', borderRadius: 8,
            padding: '8px 12px', cursor: 'pointer', color: '#E4E4E7',
          }}>
            <span style={{ fontSize: 12, fontWeight: 500 }}>Events ({events.length})</span>
            <span style={{ fontSize: 12, color: '#71717A' }}>{eventsOpen ? '▲' : '▼'}</span>
          </button>
          {eventsOpen && (
            <div style={{ marginTop: 4, display: 'flex', flexDirection: 'column', gap: 3 }}>
              {events.map(n => {
                const e = n.data as EventNodeData;
                const sc = SEV_COLOR[e.severity] ?? '#71717A';
                return (
                  <button key={e.id} onClick={() => onEventSelect(e)} style={{
                    width: '100%', textAlign: 'left', padding: '6px 10px', borderRadius: 6,
                    background: '#1C1C1F', border: `1px solid ${sc}20`, borderLeft: `2px solid ${sc}`,
                    cursor: 'pointer', display: 'block',
                  }}>
                    <div style={{ fontSize: 11, color: '#E4E4E7', fontFamily: 'JetBrains Mono, monospace' }}>{e.label}</div>
                    {e.timestamp && <div style={{ fontSize: 10, color: '#71717A', marginTop: 2 }}>{e.timestamp.slice(0, 19).replace('T', ' ')}</div>}
                    {e.hostname && <div style={{ fontSize: 10, color: '#52525B', marginTop: 1 }}>{e.hostname}{e.user ? ` · ${e.user}` : ''}</div>}
                  </button>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function EventDetail({ data }: { data: EventNodeData }) {
  const [rawOpen, setRawOpen] = useState(false);
  const sevColor = SEV_COLOR[data.severity] ?? '#71717A';
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, padding: '16px 16px 24px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <div style={{ width: 8, height: 8, borderRadius: '50%', background: sevColor }} />
        <span style={{ fontSize: 11, color: sevColor, textTransform: 'capitalize', fontWeight: 600 }}>{data.severity}</span>
        {data.is_lolbin && <span style={{ fontSize: 9, color: '#F59E0B', background: '#F59E0B18', border: '1px solid #F59E0B40', borderRadius: 4, padding: '1px 6px' }}>LOLBin</span>}
      </div>
      <div style={{ background: '#1C1C1F', borderRadius: 8, padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 6 }}>
        {data.timestamp && <Row label="Time"    value={data.timestamp.slice(0, 19).replace('T', ' ')} mono />}
        {data.process   && <Row label="Process" value={data.process}   mono />}
        {data.hostname  && <Row label="Host"    value={data.hostname}  mono />}
        {data.user      && <Row label="User"    value={data.user}      mono />}
        {data.source_ip && <Row label="Src IP"  value={data.source_ip} mono />}
      </div>
      {data.mitre_id && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: '#3B82F6', background: '#3B82F618', border: '1px solid #3B82F630', borderRadius: 4, padding: '1px 6px' }}>
            {data.mitre_id}
          </span>
          {data.mitre_name && <span style={{ fontSize: 11, color: '#71717A' }}>{data.mitre_name}</span>}
        </div>
      )}
      {data.command_line && (
        <div>
          <div style={{ fontSize: 10, color: '#71717A', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 6 }}>Command Line</div>
          <pre style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: '#E4E4E7', background: '#0A0A0B', border: '1px solid #2A2A2E', borderRadius: 6, padding: '8px 10px', margin: 0, overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
            {data.command_line}
          </pre>
        </div>
      )}
      {data.action_taken && (
        <div>
          <div style={{ fontSize: 10, color: '#71717A', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 4 }}>Action</div>
          <div style={{ fontSize: 12, color: '#E4E4E7', lineHeight: 1.5 }}>{data.action_taken}</div>
        </div>
      )}
      <button onClick={() => setRawOpen(v => !v)} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: '#1C1C1F', border: '1px solid #2A2A2E', borderRadius: 8, padding: '8px 12px', cursor: 'pointer', color: '#E4E4E7', width: '100%' }}>
        <span style={{ fontSize: 12, fontWeight: 500 }}>Raw data</span>
        <span style={{ fontSize: 12, color: '#71717A' }}>{rawOpen ? '▲' : '▼'}</span>
      </button>
      {rawOpen && (
        <pre style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#71717A', background: '#0A0A0B', border: '1px solid #2A2A2E', borderRadius: 6, padding: '10px', margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 200, overflowY: 'auto' }}>
          {JSON.stringify(data, null, 2)}
        </pre>
      )}
    </div>
  );
}

export default function Inspector({ selected, eventMap, onClose, onEventSelect }: Props) {
  const sevColor = selected
    ? SEV_COLOR[(selected.data as ChainNodeData | EventNodeData).severity as Severity] ?? '#3B82F6'
    : '#3B82F6';
  const title = selected
    ? selected.kind === 'chain'
      ? (selected.data as ChainNodeData).chain_type.replace(/_/g, ' ').toUpperCase()
      : (selected.data as EventNodeData).label
    : 'Inspector';

  return (
    <AnimatePresence>
      <motion.div
        key="inspector"
        initial={{ x: 340, opacity: 0 }}
        animate={{ x: 0, opacity: 1 }}
        exit={{ x: 340, opacity: 0 }}
        transition={{ type: 'spring', stiffness: 380, damping: 38 }}
        style={{ width: 320, flexShrink: 0, background: '#161618', borderLeft: '1px solid #2A2A2E', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}
      >
        <div style={{ height: 3, background: selected ? sevColor : 'transparent', opacity: 0.7, flexShrink: 0, transition: 'background 0.3s' }} />
        <div style={{ padding: '12px 14px', borderBottom: '1px solid #2A2A2E', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
          <span style={{ fontSize: 12, fontWeight: 600, color: '#E4E4E7', letterSpacing: '-0.01em', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 240 }}>
            {title}
          </span>
          {selected && (
            <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#71717A', padding: 2, display: 'flex' }}>
              <X size={14} />
            </button>
          )}
        </div>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {!selected ? (
            <div style={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 14, padding: 24, textAlign: 'center' }}>
              <div style={{ width: 56, height: 56, display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid #2A2A2E', borderRadius: 12 }}>
                <Hexagon size={24} color="#2A2A2E" />
              </div>
              <div>
                <div style={{ fontSize: 13, color: '#E4E4E7', fontWeight: 500, marginBottom: 6 }}>Select a node</div>
                <div style={{ fontSize: 12, color: '#71717A', lineHeight: 1.5 }}>Click any chain node to begin forensic analysis</div>
              </div>
            </div>
          ) : selected.kind === 'chain' ? (
            <ChainDetail data={selected.data as ChainNodeData} eventMap={eventMap} onEventSelect={onEventSelect} />
          ) : (
            <EventDetail data={selected.data as EventNodeData} />
          )}
        </div>
      </motion.div>
    </AnimatePresence>
  );
}
