// Shared API types mirroring the SentinelLite backend contract.

export type AlertStatus = "new" | "auto_closed" | "escalated" | "triaged";
export type InvestigationStatus =
  | "running"
  | "awaiting_approval"
  | "approved"
  | "rejected"
  | "closed";
export type ActionStatus =
  | "staged"
  | "awaiting_confirm"
  | "approved"
  | "rejected"
  | "executed"
  | "failed"
  | "expired";

export interface Triage {
  severity: number;
  confidence: number;
  priority: number;
  severity_label: string;
  decision: string;
  reasoning?: string;
  evidence?: string[];
  model?: string;
}

export interface Alert {
  id: string;
  source: string;
  source_event_type: string;
  ts: string;
  severity_hint: string;
  title: string;
  status: AlertStatus;
  actor_identity: string | null;
  source_ip: string | null;
  scenario: string | null;
  triage: Triage | null;
}

export interface AlertDetail extends Alert {
  tenant_id: string;
  asset: Record<string, unknown> | null;
  process: Record<string, unknown> | null;
  package: Record<string, unknown> | null;
  repository: Record<string, unknown> | null;
  cloud_resource: Record<string, unknown> | null;
  raw: Record<string, unknown> | null;
  investigation_id: string | null;
}

export interface AlertsResponse {
  count: number;
  alerts: Alert[];
}

export interface KillChainStep {
  t_offset_s: number;
  stage: string;
  mitre: string;
  mitre_name: string;
  evidence: string[];
  entities: string[];
  summary: string;
}

export interface Scores {
  severity: number;
  confidence: number;
  priority: number;
}

export interface DataProvenance {
  scenario: string | null;
  sources: string[];
  datasets: string[];
}

export interface Investigation {
  id: string;
  status: InvestigationStatus;
  summary: string;
  trigger_alert_id: string | null;
  scores: Scores;
  kill_chain: KillChainStep[];
  data_provenance: DataProvenance;
  created_at: string;
  updated_at: string;
  stage_count: number;
}

export interface Ioc {
  type: string;
  value: string;
}

export type AgentName = "identity" | "endpoint" | "supplychain";

export interface Finding {
  agent: AgentName;
  summary: string;
  iocs: Ioc[];
  tokens: number;
  latency_ms: number;
}

export interface InvestigationDetail extends Investigation {
  tenant_id: string;
  alerts: Alert[];
  findings: Finding[];
  actions: Action[];
}

export interface GraphNode {
  id: string;
  label:
    | "Alert"
    | "Identity"
    | "IP"
    | "Asset"
    | "Process"
    | "Package"
    | "Repository"
    | "CloudResource";
  value: string;
  severity?: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  rel: string;
}

export interface InvestigationGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface InvestigationsResponse {
  count: number;
  investigations: Investigation[];
}

export interface Action {
  id: string;
  investigation_id: string;
  type: string;
  params: Record<string, unknown>;
  rationale: string;
  status: ActionStatus;
  requires_second_confirm: boolean;
  dry_run: boolean;
  result: Record<string, unknown>;
  message?: string;
}

export interface ActionsResponse {
  count: number;
  actions: Action[];
}

export interface AuditEvent {
  id: string;
  seq: number;
  ts: string;
  actor: string;
  event_type: string;
  data: Record<string, unknown>;
  prev_hash: string;
  hash: string;
}

export interface AuditResponse {
  count: number;
  events: AuditEvent[];
}

export interface AuditVerify {
  ok: boolean;
  length: number;
  broken_index: number | null;
  head_hash?: string;
  reason?: string;
}
