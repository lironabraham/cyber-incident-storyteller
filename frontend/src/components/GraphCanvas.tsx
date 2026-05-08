import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ReactFlow, Controls, Background, BackgroundVariant,
  useNodesState, useEdgesState, useReactFlow,
  MarkerType,
  type NodeMouseHandler, type Edge,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import ChainNode from './nodes/ChainNode';
import EventNode from './nodes/EventNode';
import { computeLayout, EVENT_W, EVENT_H } from '../hooks/useGraphLayout';
import type { AnalysisResponse, SelectedNode, AnyNodeData, ChainNodeData } from '../types';

type RFData = Record<string, unknown>;
type RFNode = import('@xyflow/react').Node<RFData>;

const NODE_TYPES = { chainNode: ChainNode, eventNode: EventNode };
const CHAIN_H = 90;

interface Props {
  data: AnalysisResponse;
  activeChainTypes: Set<string>;
  activeSeverities: Set<string>;
  currentTime: number | null;
  onNodeSelect: (node: SelectedNode | null) => void;
}

function GraphCanvasInner({ data, activeChainTypes, activeSeverities, currentTime, onNodeSelect }: Props) {
  const [expandedChains, setExpandedChains] = useState<Set<string>>(new Set());
  const { fitView, getNode } = useReactFlow();

  const layout = useMemo(
    () => computeLayout(data.cy.nodes, data.cy.edges, data.cy.event_map),
    [data],
  );

  const visibleNodes = useMemo(() => layout.nodes.map(n => {
    const d = n.data as unknown as AnyNodeData;
    let hidden = false;
    if (d.type === 'chain') {
      const cd = d as ChainNodeData;
      if (activeChainTypes.size > 0 && !activeChainTypes.has(cd.chain_type)) hidden = true;
      if (activeSeverities.size > 0 && !activeSeverities.has(cd.severity))   hidden = true;
    }
    if (currentTime !== null && d.type === 'event') {
      const ts = (d as { timestamp?: string }).timestamp;
      if (ts && new Date(ts).getTime() > currentTime) hidden = true;
    }
    return { ...n, hidden } as typeof n & { hidden: boolean };
  }), [layout.nodes, activeChainTypes, activeSeverities, currentTime]);

  const [nodes, setNodes, onNodesChange] = useNodesState(visibleNodes as unknown as RFNode[]);
  const [edges, setEdges, onEdgesChange] = useEdgesState(layout.edges);

  // When filters or data change, collapse all and reset to chain-only view
  useEffect(() => {
    setExpandedChains(new Set());
    setNodes(visibleNodes as unknown as RFNode[]);
    setEdges(layout.edges);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visibleNodes, layout.edges]);

  useEffect(() => { setTimeout(() => fitView({ padding: 0.15, duration: 400 }), 100); }, [data, fitView]);

  const expand = useCallback((chainId: string) => {
    const rfNode = getNode(chainId);
    if (!rfNode) return;
    const bucket = data.cy.event_map[chainId];
    if (!bucket || bucket.nodes.length === 0) return;

    const { x, y } = rfNode.position;
    const baseY = y + CHAIN_H + 40;

    const evtNodes: RFNode[] = bucket.nodes.map((n, i) => ({
      id:       n.data.id,
      type:     'eventNode',
      position: { x, y: baseY + i * (EVENT_H + 16) },
      data:     n.data as unknown as RFData,
      style:    { width: EVENT_W, height: EVENT_H },
    }));

    const spokeEdge: Edge = {
      id:           `spoke_${chainId}`,
      source:       chainId,
      sourceHandle: 'bottom',
      target:       bucket.nodes[0].data.id,
      type:         'smoothstep',
      style:        { stroke: 'rgba(59,130,246,0.4)', strokeWidth: 1.5 },
      markerEnd:    { type: MarkerType.ArrowClosed, color: 'rgba(59,130,246,0.4)', width: 14, height: 14 },
      data:         { edgeType: 'spoke', chainId } as unknown as RFData,
    };

    const temporalEdges: Edge[] = bucket.edges.map(e => ({
      id:        e.data.id,
      source:    e.data.source,
      target:    e.data.target,
      type:      'straight',
      style:     { stroke: '#2A2A2E', strokeWidth: 1 },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#3B82F6', width: 10, height: 10 },
      data:      { edgeType: 'temporal', chainId } as unknown as RFData,
    }));

    setNodes(prev => [...prev, ...evtNodes]);
    setEdges(prev => [...prev, spokeEdge, ...temporalEdges]);
    setExpandedChains(prev => new Set([...prev, chainId]));
  }, [getNode, data.cy.event_map, setNodes, setEdges]);

  const collapse = useCallback((chainId: string) => {
    const bucket = data.cy.event_map[chainId];
    const evtIds = new Set(bucket?.nodes.map(n => n.data.id) ?? []);

    setNodes(prev => prev.filter(n => !evtIds.has(n.id)));
    setEdges(prev => prev.filter(e =>
      e.id !== `spoke_${chainId}` &&
      (e.data as Record<string, unknown> | undefined)?.chainId !== chainId,
    ));
    setExpandedChains(prev => { const next = new Set(prev); next.delete(chainId); return next; });
  }, [data.cy.event_map, setNodes, setEdges]);

  const onNodeClick: NodeMouseHandler = useCallback((_evt, node) => {
    const d = node.data as unknown as AnyNodeData;
    if (d.type === 'chain') {
      const chainId = node.id;
      if (expandedChains.has(chainId)) {
        collapse(chainId);
      } else {
        expand(chainId);
      }
      onNodeSelect({ kind: 'chain', data: d });
    } else {
      onNodeSelect({ kind: 'event', data: d });
    }
  }, [expandedChains, expand, collapse, onNodeSelect]);

  const onPaneClick = useCallback(() => {
    onNodeSelect(null);
    setNodes(ns => ns.map(n => ({ ...n, selected: false })));
  }, [onNodeSelect, setNodes]);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={NODE_TYPES}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={onNodeClick}
      onPaneClick={onPaneClick}
      fitView={false}
      minZoom={0.05}
      maxZoom={3}
      nodesDraggable
      nodesConnectable={false}
      elementsSelectable
      proOptions={{ hideAttribution: true }}
    >
      <Background variant={BackgroundVariant.Dots} gap={24} size={1} color="#2A2A2E" />
      <Controls showInteractive={false} />
    </ReactFlow>
  );
}

export default function GraphCanvas(props: Props) {
  return <GraphCanvasInner {...props} />;
}
