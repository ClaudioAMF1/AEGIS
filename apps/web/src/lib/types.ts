// Types mirroring the AEGIS API (packages/api-contracts/openapi.json).

export type Severity = "informational" | "low" | "medium" | "high" | "critical";
export type Scope = "live" | "demo" | "all";
export type IncidentStatus = "new" | "investigating" | "contained" | "resolved" | "false_positive";
export type AlertStatus = "open" | "acknowledged" | "closed";
export type AlertDisposition = "undetermined" | "true_positive" | "false_positive" | "benign";

export interface Page<T> {
  items: T[];
  total: number | null;
  next_cursor: string | null;
}

export interface Me {
  id: string;
  email: string;
  display_name: string;
  role: "administrator" | "analyst" | "viewer";
  permissions: string[];
  mfa_enabled: boolean;
  csrf_token: string;
  session_expires_at: string;
}

export interface LoginResult {
  mfa_required: boolean;
  csrf_token: string;
  user: Me | null;
}

export interface Metric {
  key: string;
  label: string;
  value: number | null;
  unit: string;
  definition: string;
  source: string;
}

export interface Dashboard {
  scope: Scope;
  period: { start: string; end: string };
  metrics: Metric[];
  alerts_by_severity: Partial<Record<Severity, number>>;
  open_incidents_by_severity: Partial<Record<Severity, number>>;
  agents_by_status: Record<string, number>;
  pipeline: { mode: string; backlog: number | null; healthy: boolean };
  recent_alerts: {
    id: string;
    title: string;
    severity: Severity;
    status: AlertStatus;
    created_at: string;
    hit_count: number;
    incident_id: string | null;
  }[];
  recent_incidents: {
    id: string;
    number: number;
    title: string;
    severity: Severity;
    status: IncidentStatus;
    updated_at: string;
  }[];
  recent_events: {
    id: string;
    occurred_at: string;
    category: string;
    action: string;
    hostname: string;
    summary: string;
  }[];
}

export interface Histogram {
  start: string;
  end: string;
  bucket_seconds: number;
  series: ({ start: string } & Record<string, number | string>)[];
}

export interface EndpointSummary {
  id: string;
  hostname: string;
  os: string | null;
  ip_addresses: string[];
  criticality: string;
  tags: string[];
  is_synthetic: boolean;
  first_seen_at: string;
  last_seen_at: string | null;
  isolation_state: string;
  status: "online" | "stale" | "offline" | "never";
  agent_count: number;
  events_24h: number;
  open_alerts: number;
}

export interface Agent {
  id: string;
  name: string;
  endpoint_id: string | null;
  token_prefix: string;
  status: string;
  version: string | null;
  is_synthetic: boolean;
  config: Record<string, unknown>;
  created_at: string;
  last_heartbeat_at: string | null;
  last_seq: number | null;
  events_received: number;
  events_duplicated: number;
  events_rejected: number;
  buffer_depth: number | null;
}

export interface EndpointDetail extends EndpointSummary {
  agents: Agent[];
  activity: { category: string; count: number }[];
}

export interface EventRow {
  id: string;
  occurred_at: string;
  ingested_at: string;
  endpoint_id: string;
  hostname: string;
  category: string;
  action: string;
  user_name: string | null;
  process_pid: number | null;
  process_ppid: number | null;
  process_name: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  file_path: string | null;
  summary: string;
  is_synthetic: boolean;
  dataset: string | null;
  detection_state: string;
}

export interface EventDetail extends EventRow {
  schema_version: string;
  seq: number | null;
  agent_id: string | null;
  payload: Record<string, unknown>;
  enrichment: Record<string, unknown>;
  alert_ids: string[];
  rule_ids: string[];
}

export interface Rule {
  id: string;
  rule_id: string;
  version: number;
  title: string;
  description: string;
  kind: "sigma" | "correlation";
  source: string;
  severity: Severity;
  enabled: boolean;
  generates_alerts: boolean;
  attack_techniques: string[];
  attack_tactics: string[];
  false_positives: string[];
  references: string[];
  created_at: string;
  updated_at: string;
  match_count: number;
  last_matched_at: string | null;
}

export interface RuleDetail extends Rule {
  content: string;
  content_sha256: string;
  versions: { version: number; created_at: string; sha256: string; is_current: boolean }[];
}

export interface DetectionRun {
  id: string;
  started_at: string;
  duration_ms: number;
  trigger: string;
  events_evaluated: number;
  rules_evaluated: number;
  matches: number;
  alerts_created: number;
  errors: string[];
}

export interface Alert {
  id: string;
  rule_id: string;
  rule_version: number;
  title: string;
  severity: Severity;
  status: AlertStatus;
  disposition: AlertDisposition;
  endpoint_id: string;
  hostname: string | null;
  hit_count: number;
  first_event_at: string;
  last_event_at: string;
  created_at: string;
  updated_at: string;
  triaged_at: string | null;
  attack_techniques: string[];
  attack_tactics: string[];
  context: Record<string, unknown>;
  incident_id: string | null;
  is_synthetic: boolean;
}

export interface AlertDetail extends Alert {
  events: EventRow[];
  rule: Rule | null;
}

export interface Incident {
  id: string;
  number: number;
  title: string;
  description: string;
  status: IncidentStatus;
  severity: Severity;
  started_at: string;
  ended_at: string | null;
  detected_at: string;
  first_triaged_at: string | null;
  resolved_at: string | null;
  assignee_id: string | null;
  assignee_name: string | null;
  attack_techniques: string[];
  attack_tactics: string[];
  endpoint_ids: string[];
  is_synthetic: boolean;
  created_at: string;
  updated_at: string;
  alert_count: number;
  event_count: number;
}

export interface JournalEntry {
  id: string;
  entry_type: "comment" | "change" | "action" | "system";
  author_id: string | null;
  author_name: string;
  body: string;
  changes: Record<string, unknown>;
  created_at: string;
}

export interface Evidence {
  id: string;
  kind: string;
  reference: string | null;
  label: string;
  data: Record<string, unknown>;
  created_by: string | null;
  created_at: string;
}

export interface IncidentDetail extends Incident {
  alerts: Alert[];
  endpoints: EndpointSummary[];
  evidence: Evidence[];
  journal: JournalEntry[];
  responses: {
    id: string;
    action_type: string;
    status: string;
    target_type: string;
    target_id: string;
    requested_at: string;
    result: Record<string, unknown>;
  }[];
}

export interface GraphNode {
  id: string;
  kind: "host" | "process" | "user" | "ip" | "file" | "alert";
  label: string;
  data: Record<string, unknown>;
  severity: Severity | null;
  weight: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  kind: string;
  count: number;
  first_seen: string | null;
  last_seen: string | null;
}

export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated: boolean;
  window: { start?: string; end?: string };
}

export interface ProcessNode {
  pid: number;
  ppid: number | null;
  name: string;
  command_line: string | null;
  user: string | null;
  started_at: string | null;
  event_id: string | null;
  flagged: boolean;
  children: ProcessNode[];
}

export interface UserRow {
  id: string;
  email: string;
  display_name: string;
  role: Me["role"];
  is_active: boolean;
  mfa_enabled: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface AuditEntry {
  id: number;
  created_at: string;
  actor_id: string | null;
  actor_email: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  outcome: string;
  ip_address: string | null;
  details: Record<string, unknown>;
}

export interface Scenario {
  id: string;
  title: string;
  description: string;
  duration_seconds: number;
  hosts: string[];
  expected: { rules?: string[]; alerts_min?: number; alerts_max?: number };
  tags: string[];
}

export interface Simulation {
  id: string;
  scenario: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  events_sent: number;
  alerts_created: number;
  details: Record<string, unknown>;
}

export interface Analytics {
  scope: Scope;
  period: { start: string; end: string };
  definitions: Record<string, string>;
  events_by_host: Record<string, number>;
  events_by_category: Record<string, number>;
  alerts_by_severity: Partial<Record<Severity, number>>;
  alerts_timeline: ({ bucket: string } & Partial<Record<Severity, number>>)[];
  top_rules: { rule_id: string; title: string; alerts: number }[];
  false_positive_rate: { value: number | null; labelled: number; false_positives: number };
  time_to_detect_seconds: { median: number | null; mean: number | null; samples: number };
  time_to_triage_seconds: { median: number | null; mean: number | null; samples: number };
  incidents: { opened: number; resolved: number; false_positive: number };
  coverage: { techniques: string[]; tactics: string[]; rules_enabled: number; rules_total: number };
}
