export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface ChainNodeData {
  id: string;
  label: string;
  type: 'chain';
  chain_type: string;
  severity: Severity;
  actor_ip: string;
  actor_user: string;
  event_count: number;
  compromised: boolean;
  mitre_ids: string;
  mitre_names: string;
  color: string;
  firstSeen?: string;
}

export interface EventNodeData {
  id: string;
  label: string;
  chain_id: string;
  type: 'event';
  severity: Severity;
  timestamp: string;
  action_taken: string;
  source_ip: string;
  user: string;
  hostname: string;
  process: string;
  mitre_id: string;
  mitre_name: string;
  command_line: string;
  is_lolbin: boolean;
  color: string;
}

export type AnyNodeData = ChainNodeData | EventNodeData;

export interface ApiEdge {
  data: {
    id: string;
    source: string;
    target: string;
    type: 'same-actor' | 'temporal' | 'spoke';
    actor?: string;
    chain_id?: string;
  };
  classes?: string;
}

export interface ApiNode {
  data: ChainNodeData | EventNodeData;
  classes?: string;
}

export interface EventBucket {
  nodes: ApiNode[];
  edges: ApiEdge[];
}

export interface AnalysisMetadata {
  file_name: string;
  analyzed_at: string;
  event_count: number;
  chain_count: number;
  severity_distribution: Record<Severity, number>;
  chain_type_distribution: Record<string, number>;
}

export interface AnalysisResponse {
  status: string;
  cy: {
    nodes: ApiNode[];
    edges: ApiEdge[];
    event_map: Record<string, EventBucket>;
  };
  metadata: AnalysisMetadata;
  report_markdown: string;
}

export interface SelectedNode {
  kind: 'chain' | 'event';
  data: ChainNodeData | EventNodeData;
}
