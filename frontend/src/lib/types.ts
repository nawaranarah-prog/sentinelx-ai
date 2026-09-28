export type Role = "ADMIN" | "SOC_ANALYST" | "VIEWER";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface WorkspaceRef { id: number; name: string; mode: "DEMO" | "ANALYST"; role: Role }
export interface Me {
  id: number; email: string; full_name: string; settings: { theme?: string };
  created_at: string; last_login_at: string | null; workspaces: WorkspaceRef[];
}
export interface Workspace extends WorkspaceRef {
  settings: { business_hours?: [number, number]; correlation_window_minutes?: number; anomaly_if_threshold?: number };
  created_at: string; last_pipeline_run_at: string | null; last_pipeline_stats: Record<string, any>;
  counts: { events: number; detections: number; incidents: number }; synthetic_data: boolean;
}
export interface Paged<T> { items: T[]; total: number; page: number; page_size: number }
export interface EventBrief {
  id: number; event_uid: string; timestamp: string; event_type: string; user: string | null; source_ip: string | null;
  destination_ip: string | null; host: string | null; process: string | null; command: string | null;
  action: string | null; status: string | null; severity: Severity; bytes: number | null; resource: string | null;
  source: string | null;
}
export interface MitreRef { id: string; name: string; tactic: string; url: string; description?: string; reason?: string; mapping_confidence?: string }
export interface DetectionBrief {
  id: number; rule_key: string; title: string; severity: Severity; confidence: number; timestamp: string;
  last_seen: string; user: string | null; host: string | null; source_ip: string | null; destination_ip: string | null;
  stage: string; status: string; incident_id: number | null; event_count: number; mitre_ids: string[];
}
export interface DetectionFull extends DetectionBrief {
  description: string; explanation: string; evidence_summary: Record<string, any>; evidence_event_uids: string[];
  mitre: MitreRef[]; false_positives: string[]; recommendations: string[];
}
export interface RiskFactor { factor: string; points: number; max: number; detail: string }
export interface IncidentBrief {
  id: number; number: string; title: string; status: string; severity: Severity; confidence: number;
  risk_score: number; risk_band: string; first_seen: string; last_seen: string; users: string[]; hosts: string[];
  source_ips: string[]; destination_ips: string[]; stages: string[]; tags: string[]; assigned_to_id: number | null;
  assigned_to: string | null; created_at: string; updated_at: string; origin: string; detection_count?: number;
  bookmarked?: boolean;
}
export interface AnomalyItem {
  entity_type: string; entity: string; day: string; if_score: number | null; if_threshold: number | null;
  if_flagged: boolean; is_anomalous: boolean; method: string;
  top_deviations: { feature: string; label: string; value: number; robust_z: number; basis: string; population_median?: number; own_median?: number }[];
}
export interface IncidentFull extends IncidentBrief {
  summary: string; risk_factors: RiskFactor[]; correlation_reason: string; correlation_keys: Record<string, any>;
  anomaly_summary: { windows_checked?: number; anomalous_windows?: number; items?: AnomalyItem[] };
  checklist: { item: string; done: boolean }[]; resolved_at: string | null; created_by: string | null;
  detections: DetectionFull[]; techniques: (MitreRef & { detection_ids: number[]; event_uids: string[] })[];
  status_history: { from: string | null; to: string; by: string; note: string; at: string }[];
  notes: { id: number; kind: string; body: string; author: string; created_at: string }[];
  evidence_event_count: number; context_event_count: number;
}
export interface Member { id: number; email: string; full_name: string; role: Role; is_active: boolean; last_login_at: string | null }
export type CopilotMode = "ask" | "investigate" | "hunt" | "explain" | "compare" | "report" | "simulate";
export interface Citation { type: string; id: string; link: string }
export interface Scorecard {
  evidence_reviewed: number; entities_reviewed: number; timeline_coverage: number | null; open_questions: string[];
  contradicting_evidence: number; missing_telemetry: string[]; confidence: "low" | "medium" | "high"; method: string;
}
export interface AINotice { kind: "info" | "error"; text: string; reference?: string; reason?: string }
export interface AIActivity { tool: string; summary: string; ok: boolean }
export interface AIMessage {
  id: number; role: "user" | "assistant"; content: string; mode: string; provider: string; model: string;
  structured: { mode?: CopilotMode; citations?: Citation[]; notice?: AINotice | null; security_notes?: string[];
    scorecard?: Scorecard | null; usage?: Record<string, number>; focus?: Record<string, unknown>; refs?: string[] };
  activity: AIActivity[]; artifacts: Record<string, any>[];
  validation: { invalid_citations?: string[]; passed?: boolean; verified_citations?: number } | null;
  error_ref: string; latency_ms: number | null; created_at: string;
}
export interface Conversation {
  id: number; title: string; mode: CopilotMode; focus: Record<string, string | { kind: string; name: string }>; recent_refs: string[];
  investigation_id: number | null; updated_at: string;
}
export interface GraphNodeT { id: number; kind: string; key: string; label: string; props: Record<string, any>; first_seen: string | null; last_seen: string | null }
export interface GraphEdgeT { id: number; source: number; target: number; rel: string; count: number; first_seen: string | null; last_seen: string | null; evidence: string[] }
export interface HuntResult {
  spec: Record<string, any>; description: { label: string; value: string }[]; scanned: number; total: number;
  truncated_scan?: boolean; groups: { key: string; count: number }[]; entities: { users: string[]; hosts: string[]; ips: string[] };
  events: EventBrief[]; sequences: { first: EventBrief; followed_by: EventBrief[]; follow_count: number }[];
  time_range: { start: string | null; end: string | null }; hunt?: string | null;
}
export interface Notification { id: number; kind: string; severity: string; title: string; body: string; link: string; is_read: boolean; created_at: string }
