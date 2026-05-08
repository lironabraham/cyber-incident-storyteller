import { Shield, Download, RefreshCw } from 'lucide-react';
import type { AnalysisMetadata, Severity } from '../types';

const SEV_COLOR: Record<Severity, string> = {
  critical: '#EF4444', high: '#F59E0B', medium: '#EAB308', low: '#10B981', info: '#71717A',
};
const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

interface Props {
  metadata: AnalysisMetadata | null;
  reportMarkdown: string;
  onReset: () => void;
}

export default function Header({ metadata, reportMarkdown, onReset }: Props) {
  function downloadReport() {
    const blob = new Blob([reportMarkdown], { type: 'text/markdown' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = 'incident-report.md';
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div style={{
      height: 48, flexShrink: 0,
      background: '#161618', borderBottom: '1px solid #2A2A2E',
      display: 'flex', alignItems: 'center', padding: '0 16px', gap: 12,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
        <div style={{ width: 26, height: 26, background: 'rgba(59,130,246,0.12)', border: '1px solid rgba(59,130,246,0.3)', borderRadius: 6, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Shield size={14} color="#3B82F6" />
        </div>
        <span style={{ fontSize: 13, fontWeight: 700, color: '#E4E4E7', letterSpacing: '-0.02em', whiteSpace: 'nowrap' }}>
          Incident Storyteller
        </span>
      </div>

      <div style={{ width: 1, height: 20, background: '#2A2A2E', flexShrink: 0 }} />

      {metadata && (
        <span style={{ fontSize: 12, color: '#71717A', fontFamily: 'JetBrains Mono, monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 200 }}>
          {metadata.file_name}
        </span>
      )}

      {metadata && (
        <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
          {SEV_ORDER.map(sev => {
            const count = metadata.severity_distribution[sev] ?? 0;
            if (count === 0) return null;
            const color = SEV_COLOR[sev];
            return (
              <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '2px 7px', borderRadius: 10, background: `${color}14`, border: `1px solid ${color}30` }}>
                <div style={{ width: 5, height: 5, borderRadius: '50%', background: color }} />
                <span style={{ fontSize: 10, color, fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>{count}</span>
              </div>
            );
          })}
        </div>
      )}

      {metadata && (
        <div style={{ display: 'flex', gap: 12, flexShrink: 0 }}>
          <span style={{ fontSize: 11, color: '#71717A' }}>
            <span style={{ color: '#E4E4E7', fontWeight: 600 }}>{metadata.chain_count}</span> chains
          </span>
          <span style={{ fontSize: 11, color: '#71717A' }}>
            <span style={{ color: '#E4E4E7', fontWeight: 600 }}>{metadata.event_count}</span> events
          </span>
        </div>
      )}

      <div style={{ flex: 1 }} />

      {metadata && (
        <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
          {reportMarkdown && (
            <button onClick={downloadReport} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 10px', borderRadius: 6, cursor: 'pointer', background: 'rgba(59,130,246,0.1)', border: '1px solid rgba(59,130,246,0.3)', color: '#3B82F6', fontSize: 11, fontWeight: 500 }}>
              <Download size={12} /> Report
            </button>
          )}
          <button onClick={onReset} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 10px', borderRadius: 6, cursor: 'pointer', background: 'transparent', border: '1px solid #2A2A2E', color: '#71717A', fontSize: 11 }}>
            <RefreshCw size={12} /> New file
          </button>
        </div>
      )}
    </div>
  );
}
