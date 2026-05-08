import dagre from 'dagre';
import type { Node, Edge } from '@xyflow/react';
import type { ApiNode, ApiEdge, EventBucket, EventNodeData } from '../types';

type RFData = Record<string, unknown>;

export const CHAIN_W = 260;
export const CHAIN_H = 116;
export const EVENT_W = 220;
export const EVENT_H = 64;

const H_GAP = 100;
const V_GAP = 180;

export interface LayoutResult {
  nodes: Node<RFData>[];
  edges: Edge[];
}

export function computeLayout(
  apiNodes: ApiNode[],
  apiEdges: ApiEdge[],
  eventMap: Record<string, EventBucket>,
): LayoutResult {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: 'LR', nodesep: V_GAP, ranksep: H_GAP + 80, marginx: 80, marginy: 80 });

  for (const n of apiNodes) {
    g.setNode(n.data.id, { width: CHAIN_W, height: CHAIN_H });
  }
  for (const e of apiEdges) {
    if (g.hasNode(e.data.source) && g.hasNode(e.data.target)) {
      g.setEdge(e.data.source, e.data.target);
    }
  }

  dagre.layout(g);

  const rfNodes: Node<RFData>[] = [];

  for (const apiNode of apiNodes) {
    const pos    = g.node(apiNode.data.id);
    const bucket = eventMap[apiNode.data.id];

    let firstSeen: string | undefined;
    if (bucket?.nodes.length) {
      const timestamps = bucket.nodes
        .map(n => (n.data as EventNodeData).timestamp)
        .filter(Boolean);
      if (timestamps.length) firstSeen = timestamps.reduce((a, b) => (a < b ? a : b));
    }

    rfNodes.push({
      id:       apiNode.data.id,
      type:     'chainNode',
      position: { x: pos.x - CHAIN_W / 2, y: pos.y - CHAIN_H / 2 },
      data:     { ...apiNode.data, firstSeen } as unknown as RFData,
      style:    { width: CHAIN_W, height: CHAIN_H },
    });
  }

  const rfEdges: Edge[] = apiEdges.map(e => ({
    id:           e.data.id,
    source:       e.data.source,
    target:       e.data.target,
    type:         'smoothstep',
    style:        { stroke: '#3B82F6', strokeWidth: 1, strokeDasharray: '5 4' },
    markerEnd:    { type: 'arrowclosed' as const, color: '#3B82F6', width: 12, height: 12 },
    label:        e.data.actor ? `${e.data.actor}` : undefined,
    labelStyle:   { fill: '#71717A', fontSize: 10, fontFamily: 'JetBrains Mono, monospace' },
    labelBgStyle: { fill: '#161618', fillOpacity: 0.9 },
    data:         { edgeType: 'same-actor' } as unknown as RFData,
  }));

  return { nodes: rfNodes, edges: rfEdges };
}
