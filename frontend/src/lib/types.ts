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
export interface AIStructured {
  summary: string; evidence: { statement: string; event_ids: string[]; detection_ids: number[]; unverified?: boolean }[];
  inference: string[]; uncertainty: string[]; next_steps: string[]; techniques: { id: string; reason: string }[];
  notices: string[]; security_notes: string[];
}
export interface AIMessage {
  id: number; role: "user" | "assistant"; content: string; structured: AIStructured | Record<string, never>;
  mode: string; provider: string; model: string; sources: { chunk_id: number; document_title: string; heading: string; score: number }[];
  tool_calls: { tool: string; args: Record<string, unknown>; ok: boolean }[];
  validation: { passed?: boolean; removed_event_ids?: string[]; removed_techniques?: string[]; removed_detection_ids?: number[]; unverified_references_in_text?: string[] };
  latency_ms: number; created_at: string;
}
export interface Notification { id: number; kind: string; severity: string; title: string; body: string; link: string; is_read: boolean; created_at: string }
