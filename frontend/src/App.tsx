import { useState, useMemo, useCallback } from 'react';
import { ReactFlowProvider } from '@xyflow/react';
import { useAnalysis }       from './hooks/useAnalysis';
import Header                from './components/Header';
import FilterSidebar         from './components/FilterSidebar';
import GraphCanvas           from './components/GraphCanvas';
import Inspector             from './components/Inspector';
import UploadOverlay         from './components/UploadOverlay';
import TimelineScrubber      from './components/TimelineScrubber';
import type { SelectedNode, EventNodeData } from './types';

export default function App() {
  const { status, data, error, upload, reset } = useAnalysis();

  const [selectedNode,     setSelectedNode]     = useState<SelectedNode | null>(null);
  const [activeChainTypes, setActiveChainTypes] = useState<Set<string>>(new Set());
  const [activeSeverities, setActiveSeverities] = useState<Set<string>>(new Set());
  const [currentTime,      setCurrentTime]      = useState<number | null>(null);

  const toggleChainType = useCallback((t: string) => {
    setActiveChainTypes(prev => { const n = new Set(prev); n.has(t) ? n.delete(t) : n.add(t); return n; });
  }, []);

  const toggleSeverity = useCallback((s: string) => {
    setActiveSeverities(prev => { const n = new Set(prev); n.has(s) ? n.delete(s) : n.add(s); return n; });
  }, []);

  const clearFilters = useCallback(() => {
    setActiveChainTypes(new Set());
    setActiveSeverities(new Set());
  }, []);

  const handleEventSelect = useCallback((evtData: EventNodeData) => {
    setSelectedNode({ kind: 'event', data: evtData });
  }, []);

  const handleReset = useCallback(() => {
    reset();
    setSelectedNode(null);
    setActiveChainTypes(new Set());
    setActiveSeverities(new Set());
    setCurrentTime(null);
  }, [reset]);

  const eventTimestamps = useMemo(() => {
    if (!data) return [];
    return Object.values(data.cy.event_map)
      .flatMap(b => b.nodes.map(n => (n.data as EventNodeData).timestamp).filter(Boolean));
  }, [data]);

  const showGraph = status === 'done' && data != null;

  return (
    <div style={{ height: '100vh', display: 'flex', flexDirection: 'column', background: '#0A0A0B', overflow: 'hidden' }}>
      <Header
        metadata={data?.metadata ?? null}
        reportMarkdown={data?.report_markdown ?? ''}
        onReset={handleReset}
      />

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden', position: 'relative' }}>
        {showGraph && (
          <FilterSidebar
            metadata={data.metadata}
            activeChainTypes={activeChainTypes}
            activeSeverities={activeSeverities}
            onToggleChainType={toggleChainType}
            onToggleSeverity={toggleSeverity}
            onClearAll={clearFilters}
          />
        )}

        <div style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
          {!showGraph && (
            <UploadOverlay
              loading={status === 'loading'}
              error={error}
              onUpload={upload}
            />
          )}
          {showGraph && (
            <ReactFlowProvider>
              <GraphCanvas
                data={data}
                activeChainTypes={activeChainTypes}
                activeSeverities={activeSeverities}
                currentTime={currentTime}
                onNodeSelect={setSelectedNode}
              />
            </ReactFlowProvider>
          )}
        </div>

        <Inspector
          selected={selectedNode}
          eventMap={data?.cy.event_map ?? {}}
          onClose={() => setSelectedNode(null)}
          onEventSelect={handleEventSelect}
        />
      </div>

      <div style={{
        height: 36, flexShrink: 0,
        background: '#161618', borderTop: '1px solid #2A2A2E',
        display: 'flex', alignItems: 'center', padding: '0 14px', gap: 14,
      }}>
        {showGraph ? (
          <>
            <span style={{ fontSize: 10, color: '#71717A', flexShrink: 0 }}>
              {data.metadata.chain_count} chains · {data.metadata.event_count} events
            </span>
            <div style={{ width: 1, height: 14, background: '#2A2A2E', flexShrink: 0 }} />
            <TimelineScrubber
              eventTimestamps={eventTimestamps}
              onTimeChange={setCurrentTime}
            />
          </>
        ) : (
          <span style={{ fontSize: 10, color: '#3a3a3e' }}>
            Cyber Incident Storyteller · Local analysis · No data leaves this machine
          </span>
        )}
      </div>
    </div>
  );
}
