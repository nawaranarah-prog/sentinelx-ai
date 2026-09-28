import { useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Bookmark, BookmarkCheck, FileText } from "lucide-react";
import { api } from "../lib/api";
import { useWsQuery } from "../lib/hooks";
import { useSession } from "../lib/session";
import { fmtBytes, fmtDuration, fmtTime, STATUS_LABEL } from "../lib/format";
import type { EventBrief, IncidentFull, Member, Paged } from "../lib/types";
import { Card, Empty, ErrorState, KV, Loading, RiskMeter, SeverityBadge, StatusBadge, Tabs, useToast } from "../components/ui";
import { AttackGraph } from "../components/AttackGraph";
import { Copilot } from "../components/Copilot";
import { DnaTab, TimeMachineTab, WhatIfTab } from "../components/IncidentExtras";
import { InvestigateButton } from "../components/InvestigateButton";
import { EventPanel } from "../components/EventPanel";

const TABS = [
  { id: "overview", label: "Overview" }, { id: "timeline", label: "Timeline" }, { id: "evidence", label: "Evidence" },
  { id: "graph", label: "Attack Graph" }, { id: "timemachine", label: "Time machine" }, { id: "dna", label: "Attack DNA" },
  { id: "whatif", label: "What-if" }, { id: "mitre", label: "MITRE ATT&CK" }, { id: "ai", label: "Copilot" },
  { id: "recommendations", label: "Recommendations" }, { id: "case", label: "Case" }, { id: "audit", label: "Audit History" },
];

function Chips({ items, kind }: { items: string[]; kind: "user" | "host" | "ip" }) {
  if (!items.length) return <span className="muted">—</span>;
  return (
    <span className="row">
      {items.slice(0, 20).map((v) => (
        <Link key={v} className="chip mono" to={kind === "ip" ? `/threat-intel?q=${v}` : `/entities/${kind}/${v}`}>{v}</Link>
      ))}
      {items.length > 20 && <span className="muted small">+{items.length - 20} more</span>}
    </span>
  );
}

function Overview({ inc }: { inc: IncidentFull }) {
  const anomalies = inc.anomaly_summary.items ?? [];
  return (
    <div className="stack">
      <div className="grid grid-main-side">
        <Card title="Summary" sub="System-generated from correlated detections">
          <p>{inc.summary}</p>
          <div className="notice info small mt-8"><strong>Why these were correlated:</strong> {inc.correlation_reason}</div>
          <div className="mt-16">
            <KV items={[
              ["Severity", <SeverityBadge key="s" severity={inc.severity} />], ["Confidence", inc.confidence.toFixed(2)],
              ["First seen (UTC)", fmtTime(inc.first_seen)], ["Last seen (UTC)", fmtTime(inc.last_seen)],
              ["Duration", fmtDuration(inc.first_seen, inc.last_seen)], ["Stages", inc.stages.join(" → ")],
              ["Affected users", <Chips key="u" items={inc.users} kind="user" />], ["Affected hosts", <Chips key="h" items={inc.hosts} kind="host" />],
              ["Source IPs", <Chips key="i" items={inc.source_ips} kind="ip" />], ["External destinations", <Chips key="d" items={inc.destination_ips} kind="ip" />],
              ["Detections", String(inc.detections.length)], ["Evidence events", `${inc.evidence_event_count} (+${inc.context_event_count} context)`],
              ["Created by", inc.created_by], ["Owner", inc.assigned_to ?? "Unassigned"],
            ]} />
          </div>
        </Card>
        <Card title="SentinelX Risk Score" sub="Transparent additive heuristic — not an industry standard, not a probability">
          <div className="risk-ring mb-8"><span className="risk-num">{inc.risk_score}</span><span className="muted">/ 100 · <strong>{inc.risk_band}</strong></span></div>
          <table className="table">
            <thead><tr><th>Factor</th><th className="num">Points</th></tr></thead>
            <tbody>
              {inc.risk_factors.map((f) => (
                <tr key={f.factor}>
                  <td><div>{f.factor}</div><div className="small muted">{f.detail}</div>
                    <div className="meter mt-8" aria-hidden="true"><span style={{ width: `${(f.points / f.max) * 100}%`, background: "var(--accent)" }} /></div></td>
                  <td className="num nowrap">{f.points} / {f.max}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="small muted mt-8">Sum is capped at 100. Each factor's detail is computed from this incident's evidence.</p>
        </Card>
      </div>
      <Card title="Detections in this incident" flush>
        <div className="table-wrap"><table className="table responsive">
          <thead><tr><th>Time (UTC)</th><th>Rule</th><th>Detection</th><th>Severity</th><th className="num">Confidence</th><th className="num">Events</th></tr></thead>
          <tbody>{inc.detections.map((d) => (
            <tr key={d.id}>
              <td data-label="Time" className="nowrap small">{fmtTime(d.timestamp)}</td>
              <td data-label="Rule"><span className="badge">{d.rule_key}</span></td>
              <td data-label="Detection"><Link to={`/detections/${d.id}`}>{d.title}</Link><div className="small muted">{d.stage}</div></td>
              <td data-label="Severity"><SeverityBadge severity={d.severity} /></td>
              <td data-label="Confidence" className="num">{d.confidence.toFixed(2)}</td>
              <td data-label="Events" className="num">{d.event_count}</td>
            </tr>))}</tbody>
        </table></div>
      </Card>
      <Card title="Behavioral anomaly results" sub={`${inc.anomaly_summary.anomalous_windows ?? 0} anomalous of ${inc.anomaly_summary.windows_checked ?? 0} entity-day windows for involved users/hosts`} flush>
        {anomalies.length === 0 ? <Empty title="No anomaly windows">No behavior windows were scored for these entities.</Empty> : (
          <div className="table-wrap"><table className="table responsive">
            <thead><tr><th>Entity</th><th>Day</th><th className="num">IF score</th><th className="num">Threshold</th><th>Verdict</th><th>Largest deviations (robust z)</th></tr></thead>
            <tbody>{anomalies.map((a) => (
              <tr key={`${a.entity}-${a.day}`}>
                <td data-label="Entity"><Link to={`/entities/${a.entity_type}/${a.entity}`}>{a.entity}</Link> <span className="muted small">{a.entity_type}</span></td>
                <td data-label="Day" className="nowrap">{a.day}</td>
                <td data-label="IF score" className="num">{a.if_score?.toFixed(3) ?? "n/a"}</td>
                <td data-label="Threshold" className="num">{a.if_threshold?.toFixed(2) ?? "n/a"}</td>
                <td data-label="Verdict">{a.is_anomalous ? <span className="badge st-bad">Anomalous</span> : <span className="badge">Within baseline</span>}</td>
                <td data-label="Deviations" className="small">{a.top_deviations.map((d) => `${d.label} = ${d.value.toLocaleString()} (z ${d.robust_z}, vs ${d.basis})`).join("; ") || "—"}</td>
              </tr>))}</tbody>
          </table></div>
        )}
      </Card>
    </div>
  );
}

function Timeline({ inc, onEvent }: { inc: IncidentFull; onEvent: (id: number) => void }) {
  const [ctx, setCtx] = useState(false);
  const q = useWsQuery<{ items: (EventBrief & { role: string; detection_ids: number[] })[]; detections: any[]; total: number }>(
    ["incident-timeline", inc.id, ctx], `/api/incidents/${inc.id}/timeline?include_context=${ctx}&page_size=500`);
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} />;
  const detById = Object.fromEntries(q.data!.detections.map((d) => [d.id, d]));
  const seen = new Set<number>();
  return (
    <Card title="Timeline" sub={`${q.data!.total} events in chronological order${q.data!.total > 500 ? " (first 500 shown)" : ""}`}
      actions={<label className="row small"><input type="checkbox" checked={ctx} onChange={(e) => setCtx(e.target.checked)} /> Include context events</label>}>
      <ol className="timeline">
        {q.data!.items.map((e) => {
          const firstDets = e.detection_ids.filter((d) => !seen.has(d) && seen.add(d));
          return (
            <li key={e.id} className={firstDets.length ? "det-row" : ""}>
              <span className="mono small nowrap">{fmtTime(e.timestamp)}</span>
              <span className="tl-dot" style={{ background: e.role === "evidence" ? `var(--sev-${e.severity === "info" ? "low" : e.severity})` : "var(--border-strong)" }} aria-hidden="true" />
              <div className="wrap-anywhere">
                {firstDets.map((d) => <div key={d} className="small"><SeverityBadge severity={detById[d]?.severity ?? "info"} /> <strong>{detById[d]?.rule_key}</strong> {detById[d]?.title}</div>)}
                <button className="btn btn-ghost btn-sm" style={{ height: "auto", padding: "2px 4px", whiteSpace: "normal", textAlign: "left" }} onClick={() => onEvent(e.id)}>
                  <span><span className="badge">{e.event_type}</span> {e.action ?? ""} {e.status && <span className={e.status === "failure" ? "badge st-bad" : "muted"}>{e.status}</span>}{" "}
                    {e.user && <strong>{e.user}</strong>} {e.host && <>on {e.host}</>} {e.source_ip && <>from {e.source_ip}</>}{" "}
                    {e.command ? <code>{e.command.slice(0, 140)}</code> : e.resource ? <span className="text-2">{e.resource.slice(0, 120)}</span> : null}
                    {e.bytes ? <span className="muted"> · {fmtBytes(e.bytes)}</span> : null}
                    {e.role === "context" && <span className="muted small"> (context)</span>}</span>
                </button>
              </div>
            </li>
          );
        })}
      </ol>
    </Card>
  );
}

function Evidence({ inc, onEvent }: { inc: IncidentFull; onEvent: (id: number) => void }) {
  const [open, setOpen] = useState<number | null>(inc.detections[0]?.id ?? null);
  const evs = useWsQuery<Paged<EventBrief>>(["det-events", open], open ? `/api/events?detection_id=${open}&page_size=100&sort=timestamp&order=asc` : null);
  return (
    <div className="stack">
      {inc.detections.map((d) => (
        <Card key={d.id} title={<span className="row"><span className="badge">{d.rule_key}</span>{d.title}</span>} sub={`${d.stage} · ${fmtTime(d.timestamp)} UTC · confidence ${d.confidence.toFixed(2)}`}
          actions={<><SeverityBadge severity={d.severity} /><button className="btn btn-sm" onClick={() => setOpen(open === d.id ? null : d.id)} aria-expanded={open === d.id}>{open === d.id ? "Hide events" : `Show ${d.event_count} events`}</button></>}>
          <p><strong>Why did this trigger?</strong> {d.explanation}</p>
          {open === d.id && (evs.isLoading ? <Loading /> : evs.data && (
            <div className="table-wrap mt-8"><table className="table responsive">
              <thead><tr><th>Time (UTC)</th><th>Event ID</th><th>Type</th><th>User / Host</th><th>Source → Dest</th><th>Detail</th></tr></thead>
              <tbody>{evs.data.items.map((e) => (
                <tr key={e.id} className="clickable" onClick={() => onEvent(e.id)}>
                  <td data-label="Time" className="nowrap small">{fmtTime(e.timestamp)}</td>
                  <td data-label="Event ID" className="mono small">{e.event_uid}</td>
                  <td data-label="Type">{e.event_type} <span className="muted small">{e.action} {e.status}</span></td>
                  <td data-label="User / Host" className="small">{e.user}<br /><span className="muted">{e.host}</span></td>
                  <td data-label="Source → Dest" className="small mono">{e.source_ip ?? "—"} → {e.destination_ip ?? "—"}</td>
                  <td data-label="Detail" className="small truncate">{e.command ?? e.resource ?? ""}{e.bytes ? ` (${fmtBytes(e.bytes)})` : ""}</td>
                </tr>))}</tbody>
            </table>
              {evs.data.total > 100 && <p className="small muted">Showing 100 of {evs.data.total}. <Link to={`/events?detection_id=${d.id}`}>Open all in Event Explorer</Link></p>}
            </div>))}
        </Card>
      ))}
    </div>
  );
}

function Mitre({ inc }: { inc: IncidentFull }) {
  if (!inc.techniques.length) return <Empty title="No techniques mapped">None of this incident's detections justify an ATT&CK mapping.</Empty>;
  return (
    <Card title="MITRE ATT&CK techniques" sub="Mapped only when a detection's evidence supports it" flush>
      <div className="table-wrap"><table className="table responsive">
        <thead><tr><th>Technique</th><th>Tactic</th><th>Reason for mapping (from evidence)</th><th>Confidence</th><th>Evidence</th></tr></thead>
        <tbody>{inc.techniques.map((t) => (
          <tr key={t.id}>
            <td data-label="Technique"><a href={t.url} target="_blank" rel="noreferrer noopener"><strong className="mono">{t.id}</strong></a><div>{t.name}</div></td>
            <td data-label="Tactic">{t.tactic}</td>
            <td data-label="Reason" className="small">{t.reason}</td>
            <td data-label="Confidence"><span className="badge">{t.mapping_confidence}</span></td>
            <td data-label="Evidence" className="small mono wrap-anywhere">{t.event_uids.slice(0, 4).join(", ")}{t.event_uids.length > 4 && " …"}<div>{t.detection_ids.map((d) => <Link key={d} to={`/detections/${d}`}>#{d} </Link>)}</div></td>
          </tr>))}</tbody>
      </table></div>
    </Card>
  );
}

function Recommendations({ inc, canEdit }: { inc: IncidentFull; canEdit: boolean }) {
  const qc = useQueryClient();
  const toggle = useMutation({
    mutationFn: (p: { index: number; done: boolean }) => api(`/api/incidents/${inc.id}/checklist`, { method: "PATCH", body: p }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["ws"] }),
  });
  const recs = [...new Set(inc.detections.flatMap((d) => d.recommendations))];
  const fps = inc.detections.map((d) => ({ rule: d.rule_key, title: d.title, items: d.false_positives }));
  return (
    <div className="grid grid-2">
      <Card title="Investigation checklist" sub="Generated from the incident's stages; progress is saved">
        <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
          {inc.checklist.map((c, i) => (
            <li key={c.item} style={{ padding: "6px 0", borderBottom: "1px solid var(--border)" }}>
              <label className="row" style={{ alignItems: "flex-start", flexWrap: "nowrap" }}>
                <input type="checkbox" checked={c.done} disabled={!canEdit || toggle.isPending} onChange={(e) => toggle.mutate({ index: i, done: e.target.checked })} style={{ marginTop: 3 }} />
                <span style={{ textDecoration: c.done ? "line-through" : "none", color: c.done ? "var(--muted)" : undefined }}>{c.item}</span>
              </label>
            </li>))}
        </ul>
      </Card>
      <Card title="Recommended investigation steps" sub="From the rules that fired, filled with this incident's entities">
        <ol>{recs.map((r) => <li key={r} className="mb-8">{r}</li>)}</ol>
      </Card>
      <Card title="Potential false positives" className="" sub="Benign explanations to rule out">
        {fps.map((f) => (<div key={f.rule + f.title} className="mb-8"><strong className="small">{f.rule} · {f.title}</strong><ul className="small">{f.items.map((x) => <li key={x}>{x}</li>)}</ul></div>))}
      </Card>
    </div>
  );
}

function CaseTab({ inc, canEdit }: { inc: IncidentFull; canEdit: boolean }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [note, setNote] = useState("");
  const [kind, setKind] = useState("note");
  const [tags, setTags] = useState(inc.tags.join(", "));
  const refresh = () => qc.invalidateQueries({ queryKey: ["ws"] });
  const addNote = useMutation({
    mutationFn: () => api(`/api/incidents/${inc.id}/notes`, { body: { body: note, kind } }),
    onSuccess: () => { setNote(""); refresh(); toast("Note added"); }, onError: (e) => toast((e as Error).message, "error"),
  });
  const saveTags = useMutation({
    mutationFn: () => api(`/api/incidents/${inc.id}/tags`, { method: "PUT", body: { tags: tags.split(",").map((t) => t.trim()).filter(Boolean) } }),
    onSuccess: () => { refresh(); toast("Tags saved"); }, onError: (e) => toast((e as Error).message, "error"),
  });
  return (
    <div className="grid grid-main-side">
      <Card title="Investigation notes & comments">
        {inc.notes.length === 0 && <p className="muted">No notes yet.</p>}
        <ul style={{ listStyle: "none", padding: 0 }}>
          {inc.notes.map((n) => (
            <li key={n.id} className="mb-8" style={{ borderLeft: "2px solid var(--border-strong)", paddingLeft: 10 }}>
              <div className="small muted">{n.author} · {n.kind} · {fmtTime(n.created_at)} UTC</div>
              <div style={{ whiteSpace: "pre-wrap" }} className="wrap-anywhere">{n.body}</div>
            </li>))}
        </ul>
        {canEdit && (
          <form onSubmit={(e) => { e.preventDefault(); if (note.trim()) addNote.mutate(); }} className="stack mt-8">
            <div className="field"><label htmlFor="note">Add {kind}</label><textarea id="note" className="input" rows={3} maxLength={5000} value={note} onChange={(e) => setNote(e.target.value)} /></div>
            <div className="row"><select className="select" aria-label="Entry type" value={kind} onChange={(e) => setKind(e.target.value)}><option value="note">Investigation note</option><option value="comment">Comment</option></select>
              <button className="btn btn-primary" disabled={!note.trim() || addNote.isPending}>Save note</button></div>
          </form>)}
      </Card>
      <Card title="Tags">
        <div className="row mb-8">{inc.tags.length ? inc.tags.map((t) => <span key={t} className="chip">{t}</span>) : <span className="muted">No tags</span>}</div>
        {canEdit && (<form onSubmit={(e) => { e.preventDefault(); saveTags.mutate(); }} className="row">
          <label htmlFor="tags" className="sr-only">Tags</label>
          <input id="tags" className="input" style={{ flex: 1 }} placeholder="comma, separated" value={tags} onChange={(e) => setTags(e.target.value)} />
          <button className="btn">Save tags</button></form>)}
      </Card>
    </div>
  );
}

function AuditTab({ inc }: { inc: IncidentFull }) {
  const q = useWsQuery<{ id: number; action: string; user: string; details: Record<string, unknown>; at: string }[]>(["incident-history", inc.id], `/api/incidents/${inc.id}/history`);
  return (
    <div className="grid grid-2">
      <Card title="Status history">
        <ol className="timeline">{inc.status_history.map((h, i) => (
          <li key={i} style={{ gridTemplateColumns: "150px minmax(0,1fr)" }}><span className="small mono">{fmtTime(h.at)}</span>
            <span>{h.from ? `${STATUS_LABEL[h.from]} → ` : ""}<strong>{STATUS_LABEL[h.to]}</strong> <span className="muted small">by {h.by}</span>{h.note && <div className="small text-2">{h.note}</div>}</span></li>))}</ol>
      </Card>
      <Card title="Audit trail for this incident" sub="Views, status changes, assignments, notes">
        {q.isLoading ? <Loading /> : (
          <ol className="timeline">{q.data?.map((a) => (
            <li key={a.id} style={{ gridTemplateColumns: "150px minmax(0,1fr)" }}><span className="small mono">{fmtTime(a.at)}</span>
              <span><span className="badge">{a.action}</span> <span className="small">{a.user}</span></span></li>))}</ol>)}
      </Card>
    </div>
  );
}

export function IncidentDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const toast = useToast();
  const { isAnalyst } = useSession();
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") ?? "overview";
  const setTab = (t: string) => setParams(t === "overview" ? {} : { tab: t }, { replace: true });
  const [eventId, setEventId] = useState<number | null>(null);
  const q = useWsQuery<IncidentFull>(["incident", id], `/api/incidents/${id}`);
  const members = useWsQuery<Member[]>(["members"], "/api/members");
  const graph = useWsQuery<any>(["incident-graph", id], tab === "graph" ? `/api/incidents/${id}/graph` : null);
  const refresh = () => qc.invalidateQueries({ queryKey: ["ws"] });
  const setStatus = useMutation({
    mutationFn: (status: string) => api(`/api/incidents/${id}`, { method: "PATCH", body: { status, note: "" } }),
    onSuccess: () => { refresh(); toast("Status updated"); }, onError: (e) => toast((e as Error).message, "error"),
  });
  const assign = useMutation({
    mutationFn: (user_id: number | null) => api(`/api/incidents/${id}/assign`, { body: { user_id } }),
    onSuccess: () => { refresh(); toast("Assignment updated"); }, onError: (e) => toast((e as Error).message, "error"),
  });
  const bookmark = useMutation({ mutationFn: () => api(`/api/incidents/${id}/bookmark`, { method: "POST" }), onSuccess: refresh });
  const report = useMutation({
    mutationFn: (report_type: string) => api<{ id: number }>("/api/reports", { body: { incident_id: q.data!.id, report_type } }),
    onSuccess: (r) => navigate(`/reports/${r.id}`), onError: (e) => toast((e as Error).message, "error"),
  });

  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  const inc = q.data!;
  return (
    <div>
      <div className="page-head">
        <div style={{ minWidth: 0 }}>
          <div className="row small muted"><Link to="/incidents">Incidents</Link> / <span className="mono">{inc.number}</span></div>
          <h1 className="wrap-anywhere" style={{ marginTop: 4 }}>{inc.title}</h1>
          <div className="row mt-8"><SeverityBadge severity={inc.severity} /><StatusBadge status={inc.status} />
            <span className="badge">Confidence {inc.confidence.toFixed(2)}</span><div style={{ width: 140 }}><RiskMeter score={inc.risk_score} band={inc.risk_band} /></div>
            {inc.tags.map((t) => <span key={t} className="chip">{t}</span>)}</div>
        </div>
        <div className="page-actions">
          <button className="btn btn-ghost icon-btn" onClick={() => bookmark.mutate()} aria-label={inc.bookmarked ? "Remove bookmark" : "Bookmark incident"} aria-pressed={inc.bookmarked}>
            {inc.bookmarked ? <BookmarkCheck /> : <Bookmark />}</button>
          {isAnalyst && (<>
            <label className="sr-only" htmlFor="inc-status">Status</label>
            <select id="inc-status" className="select" value={inc.status} onChange={(e) => setStatus.mutate(e.target.value)} disabled={setStatus.isPending}>
              {Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
            <label className="sr-only" htmlFor="inc-owner">Owner</label>
            <select id="inc-owner" className="select" value={inc.assigned_to_id ?? ""} onChange={(e) => assign.mutate(e.target.value ? Number(e.target.value) : null)}>
              <option value="">Unassigned</option>
              {members.data?.filter((m) => m.role !== "VIEWER").map((m) => <option key={m.id} value={m.id}>{m.full_name || m.email}</option>)}
            </select>
            <select className="select" aria-label="Generate report" value="" onChange={(e) => e.target.value && report.mutate(e.target.value)} disabled={report.isPending}>
              <option value="">{report.isPending ? "Generating…" : "Generate report…"}</option>
              <option value="incident">Incident report</option><option value="technical">Technical investigation</option><option value="executive">Executive summary</option>
            </select>
          </>)}
          <InvestigateButton context={[`INC:${inc.number}`]} q={`Investigate ${inc.number}. What happened, what supports it, what contradicts it, and what don't we know?`} />
          {!isAnalyst && <span className="badge"><FileText size={12} /> Read-only (Viewer)</span>}
        </div>
      </div>
      <Tabs label="Incident sections" tabs={TABS} active={tab} onChange={setTab} />
      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
        {tab === "overview" && <Overview inc={inc} />}
        {tab === "timeline" && <Timeline inc={inc} onEvent={setEventId} />}
        {tab === "evidence" && <Evidence inc={inc} onEvent={setEventId} />}
        {tab === "graph" && (graph.isLoading ? <Loading /> : graph.data && (
          <Card title="Attack graph" sub={graph.data.note}><AttackGraph nodes={graph.data.nodes} edges={graph.data.edges} /></Card>))}
        {tab === "mitre" && <Mitre inc={inc} />}
        {tab === "timemachine" && <TimeMachineTab inc={inc} />}
        {tab === "dna" && <DnaTab inc={inc} />}
        {tab === "whatif" && <WhatIfTab inc={inc} />}
        {tab === "ai" && <Copilot context={[`INC:${inc.number}`]} mode="investigate" compact />}
        {tab === "recommendations" && <Recommendations inc={inc} canEdit={isAnalyst} />}
        {tab === "case" && <CaseTab inc={inc} canEdit={isAnalyst} />}
        {tab === "audit" && <AuditTab inc={inc} />}
      </div>
      {eventId !== null && <EventPanel eventId={eventId} onClose={() => setEventId(null)} />}
    </div>
  );
}
