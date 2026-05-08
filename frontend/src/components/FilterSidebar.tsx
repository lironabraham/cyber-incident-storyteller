import type { AnalysisMetadata, Severity } from '../types';

const CHAIN_COLORS: Record<string, string> = {
  post_exploitation:   '#dc2626',
  brute_force:         '#ea580c',
  credential_stuffing: '#d97706',
  lateral_movement:    '#7c3aed',
  credential_access:   '#991b1b',
  defense_evasion:     '#0d9488',
  unauthorized_access: '#2563eb',
};

const CHAIN_LABELS: Record<string, string> = {
  post_exploitation:   'Post Exploit',
  brute_force:         'Brute Force',
  credential_stuffing: 'Cred Stuffing',
  lateral_movement:    'Lateral Mov.',
  credential_access:   'Cred Access',
  defense_evasion:     'Def. Evasion',
  unauthorized_access: 'Unauth Access',
};

const SEV_COLOR: Record<Severity, string> = {
  critical: '#EF4444', high: '#F59E0B', medium: '#EAB308', low: '#10B981', info: '#71717A',
};

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

interface Props {
  metadata: AnalysisMetadata;
  activeChainTypes: Set<string>;
  activeSeverities: Set<string>;
  onToggleChainType: (t: string) => void;
  onToggleSeverity:  (s: string) => void;
  onClearAll: () => void;
}

export default function FilterSidebar({
  metadata, activeChainTypes, activeSeverities, onToggleChainType, onToggleSeverity, onClearAll,
}: Props) {
  const hasFilters = activeChainTypes.size > 0 || activeSeverities.size > 0;
  const chainTypes = Object.entries(metadata.chain_type_distribution).sort((a, b) => b[1] - a[1]);

  return (
    <div style={{
      width: 200, flexShrink: 0,
      background: '#161618', borderRight: '1px solid #2A2A2E',
      display: 'flex', flexDirection: 'column', overflow: 'hidden',
    }}>
      <div style={{
        padding: '14px 14px 10px', borderBottom: '1px solid #2A2A2E',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      }}>
        <span style={{ fontSize: 11, fontWeight: 600, color: '#71717A', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
          Filters
        </span>
        {hasFilters && (
          <button onClick={onClearAll} style={{ fontSize: 10, color: '#3B82F6', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
            Clear all
          </button>
        )}
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: '12px 10px' }}>
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 10, color: '#71717A', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 8, paddingLeft: 4 }}>
            Tactic
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {chainTypes.map(([type, count]) => {
              const isActive = activeChainTypes.has(type);
              const dimmed   = activeChainTypes.size > 0 && !isActive;
              const color    = CHAIN_COLORS[type] ?? '#3B82F6';
              return (
                <button key={type} onClick={() => onToggleChainType(type)} style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '5px 8px', borderRadius: 6, textAlign: 'left',
                  border:      `1px solid ${isActive ? color + '60' : 'transparent'}`,
                  background:  isActive ? `${color}18` : dimmed ? 'transparent' : `${color}08`,
                  cursor:      'pointer', opacity: dimmed ? 0.4 : 1,
                  transition:  'all 0.12s',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <div style={{ width: 6, height: 6, borderRadius: 2, background: color, flexShrink: 0 }} />
                    <span style={{ fontSize: 11, color: '#E4E4E7' }}>{CHAIN_LABELS[type] ?? type}</span>
                  </div>
                  <span style={{ fontSize: 10, color, background: `${color}20`, borderRadius: 10, padding: '0 5px', fontFamily: 'JetBrains Mono, monospace' }}>
                    {count}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        <div>
          <div style={{ fontSize: 10, color: '#71717A', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 8, paddingLeft: 4 }}>
            Severity
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {SEVERITIES.map(sev => {
              const count   = metadata.severity_distribution[sev] ?? 0;
              const color   = SEV_COLOR[sev];
              const isActive = activeSeverities.has(sev);
              const dimmed  = activeSeverities.size > 0 && !isActive;
              return (
                <button key={sev} onClick={() => onToggleSeverity(sev)} style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '5px 8px', borderRadius: 6, textAlign: 'left',
                  border:     `1px solid ${isActive ? color + '60' : 'transparent'}`,
                  background: isActive ? `${color}18` : dimmed ? 'transparent' : `${color}08`,
                  cursor:     'pointer', opacity: dimmed ? 0.4 : 1,
                  transition: 'all 0.12s',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <div style={{ width: 6, height: 6, borderRadius: '50%', background: color, flexShrink: 0 }} />
                    <span style={{ fontSize: 11, color: '#E4E4E7', textTransform: 'capitalize' }}>{sev}</span>
                  </div>
                  <span style={{ fontSize: 10, color, background: `${color}20`, borderRadius: 10, padding: '0 5px', fontFamily: 'JetBrains Mono, monospace' }}>
                    {count}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
