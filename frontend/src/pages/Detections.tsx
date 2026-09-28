import { useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { InvestigateButton } from "../components/InvestigateButton";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, qs } from "../lib/api";
import { useDebounced, useWsQuery } from "../lib/hooks";
import { useSession } from "../lib/session";
import { fmtBytes, fmtTime } from "../lib/format";
import type { DetectionBrief, DetectionFull, EventBrief, Paged } from "../lib/types";
import { Card, Empty, ErrorState, KV, Loading, Pagination, SeverityBadge, useToast } from "../components/ui";
import { EventPanel } from "../components/EventPanel";

export function DetectionsPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [f, setF] = useState({ q: "", severity: "", rule_key: params.get("rule_key") ?? "", correlated: "", page: 1 });
  const q = useDebounced(f.q);
  const path = `/api/detections${qs({ q, severity: f.severity, rule_key: f.rule_key, correlated: f.correlated, page: f.page, page_size: 50 })}`;
  const data = useWsQuery<Paged<DetectionBrief>>(["detections", path], path);
  const rules = useWsQuery<{ rule_key: string; name: string }[]>(["rules"], "/api/rules");
  const set = (k: string, v: string | number) => setF({ ...f, [k]: v, page: k === "page" ? Number(v) : 1 });
  return (
    <div className="stack">
      <div className="page-head"><div><h1>Detections</h1><p>Every rule match, with evidence. Uncorrelated medium/low detections stay here until correlated or promoted.</p></div></div>
      <Card flush>
        <div className="filters" role="search">
          <div className="field"><label htmlFor="dq">Search</label><input id="dq" className="input" placeholder="Title, user, host, IP" value={f.q} onChange={(e) => set("q", e.target.value)} /></div>
          <div className="field"><label htmlFor="dsev">Severity</label><select id="dsev" className="select" value={f.severity} onChange={(e) => set("severity", e.target.value)}>
            <option value="">All</option>{["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}</select></div>
          <div className="field"><label htmlFor="drule">Rule</label><select id="drule" className="select" value={f.rule_key} onChange={(e) => set("rule_key", e.target.value)}>
            <option value="">All rules</option>{rules.data?.map((r) => <option key={r.rule_key} value={r.rule_key}>{r.rule_key} · {r.name}</option>)}</select></div>
          <div className="field"><label htmlFor="dcor">Correlation</label><select id="dcor" className="select" value={f.correlated} onChange={(e) => set("correlated", e.target.value)}>
            <option value="">All</option><option value="true">In an incident</option><option value="false">Standalone</option></select></div>
        </div>
        {data.isLoading ? <Loading /> : data.error ? <div className="card-body"><ErrorState error={data.error} /></div> :
          data.data!.items.length === 0 ? <Empty title="No detections">No rule has matched the current data and filters.</Empty> : (
            <>
              <div className="table-wrap"><table className="table responsive">
                <thead><tr><th>Time (UTC)</th><th>Rule</th><th>Detection</th><th>Severity</th><th className="num">Conf.</th><th>Entities</th><th>Incident</th></tr></thead>
                <tbody>{data.data!.items.map((d) => (
                  <tr key={d.id} className="clickable" onClick={() => navigate(`/detections/${d.id}`)}>
                    <td data-label="Time" className="nowrap small">{fmtTime(d.timestamp)}</td>
                    <td data-label="Rule"><span className="badge">{d.rule_key}</span></td>
                    <td data-label="Detection" className="wrap-anywhere"><Link to={`/detections/${d.id}`} onClick={(e) => e.stopPropagation()}>{d.title}</Link><div className="small muted">{d.stage} · {d.event_count} events</div></td>
                    <td data-label="Severity"><SeverityBadge severity={d.severity} /></td>
                    <td data-label="Confidence" className="num">{d.confidence.toFixed(2)}</td>
                    <td data-label="Entities" className="small">{[d.user, d.host, d.source_ip].filter(Boolean).join(" · ")}</td>
                    <td data-label="Incident">{d.incident_id ? <Link to={`/incidents/${d.incident_id}`} onClick={(e) => e.stopPropagation()}>Open</Link> : <span className="muted small">{d.status === "DISMISSED" ? "Dismissed" : "Standalone"}</span>}</td>
                  </tr>))}</tbody>
              </table></div>
              <Pagination page={f.page} pageSize={50} total={data.data!.total} onPage={(p) => set("page", p)} />
            </>)}
      </Card>
    </div>
  );
}

export function DetectionDetailPage() {
  const { id: rawId = "" } = useParams();
  const id = rawId.replace(/^DET-/i, "");
  const navigate = useNavigate();
  const toast = useToast();
  const qc = useQueryClient();
  const { isAnalyst } = useSession();
  const [eventId, setEventId] = useState<number | null>(null);
  const q = useWsQuery<DetectionFull & { evidence_events: EventBrief[]; incident: { id: number; number: string; title: string; status: string } | null }>(["detection", id], `/api/detections/${id}`);
  const promote = useMutation({
    mutationFn: () => api<{ incident_id: number }>(`/api/detections/${id}/promote`, { method: "POST" }),
    onSuccess: (r) => { qc.invalidateQueries({ queryKey: ["ws"] }); navigate(`/incidents/${r.incident_id}`); },
    onError: (e) => toast((e as Error).message, "error"),
  });
  const setStatus = useMutation({
    mutationFn: (status: string) => api(`/api/detections/${id}`, { method: "PATCH", body: { status } }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["ws"] }); toast("Detection updated"); },
  });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} />;
  const d = q.data!;
  const summary = Object.entries(d.evidence_summary).filter(([k]) => !["event_uids", "mitre_note"].includes(k));
  return (
    <div className="stack">
      <div className="page-head">
        <div style={{ minWidth: 0 }}>
          <div className="small muted"><Link to="/detections">Detections</Link> / #{d.id}</div>
          <h1 className="wrap-anywhere" style={{ marginTop: 4 }}>{d.title}</h1>
          <div className="row mt-8"><span className="badge">{d.rule_key}</span><SeverityBadge severity={d.severity} /><span className="badge">Confidence {d.confidence.toFixed(2)}</span><span className="badge">{d.stage}</span></div>
        </div>
        <div className="page-actions">
          <InvestigateButton context={[`DET:${d.id}`]} mode="explain" label="Explain" q={`Why did detection DET-${d.id} fire? Is it likely a true positive?`} />
          {d.incident ? <Link className="btn btn-primary" to={`/incidents/${d.incident.number}`}>Open {d.incident.number}</Link> : isAnalyst && (<>
            <button className="btn btn-primary" onClick={() => promote.mutate()} disabled={promote.isPending}>Promote to incident</button>
            <button className="btn" onClick={() => setStatus.mutate(d.status === "DISMISSED" ? "OPEN" : "DISMISSED")}>{d.status === "DISMISSED" ? "Re-open" : "Dismiss"}</button>
          </>)}
        </div>
      </div>
      <div className="grid grid-main-side">
        <Card title="Why did this trigger?">
          <p style={{ fontSize: 14.5 }}>{d.explanation}</p>
          <p className="small muted">{d.description}</p>
          <KV items={[["First event (UTC)", fmtTime(d.timestamp)], ["Last event (UTC)", fmtTime(d.last_seen)], ["User", d.user], ["Host", d.host], ["Source IP", d.source_ip], ["Destination IP", d.destination_ip],
            ...summary.map(([k, v]) => [k.replace(/_/g, " "), typeof v === "number" && k.includes("bytes") ? fmtBytes(v) : Array.isArray(v) ? v.slice(0, 12).join(", ") + (v.length > 12 ? " …" : "") : String(v ?? "—")] as [string, string])]} />
        </Card>
        <div className="stack">
          <Card title="MITRE ATT&CK">
            {d.mitre.length === 0 ? <p className="muted small">{d.evidence_summary.mitre_note ?? "No technique mapped."}</p> :
              d.mitre.map((m) => (<div key={m.id} className="mb-8"><a href={m.url} target="_blank" rel="noreferrer noopener" className="mono"><strong>{m.id}</strong></a> {m.name} <span className="badge">{m.mapping_confidence}</span><div className="small text-2">{m.reason}</div></div>))}
          </Card>
          <Card title="Potential false positives"><ul className="small">{d.false_positives.map((x) => <li key={x}>{x}</li>)}</ul></Card>
          <Card title="Recommended investigation"><ol className="small">{d.recommendations.map((x) => <li key={x}>{x}</li>)}</ol></Card>
        </div>
      </div>
      <Card title="Evidence events" sub={`${d.event_count} events satisfied this rule`} flush>
        <div className="table-wrap"><table className="table responsive">
          <thead><tr><th>Time (UTC)</th><th>Event ID</th><th>Type</th><th>User / Host</th><th>Source → Dest</th><th>Detail</th></tr></thead>
          <tbody>{d.evidence_events.map((e) => (
            <tr key={e.id} className="clickable" onClick={() => setEventId(e.id)}>
              <td data-label="Time" className="nowrap small">{fmtTime(e.timestamp)}</td><td data-label="Event ID" className="mono small">{e.event_uid}</td>
              <td data-label="Type">{e.event_type} <span className="muted small">{e.action} {e.status}</span></td>
              <td data-label="User / Host" className="small">{e.user} <span className="muted">{e.host}</span></td>
              <td data-label="Source → Dest" className="mono small">{e.source_ip ?? "—"} → {e.destination_ip ?? "—"}</td>
              <td data-label="Detail" className="small truncate">{e.command ?? e.resource ?? ""}{e.bytes ? ` (${fmtBytes(e.bytes)})` : ""}</td>
            </tr>))}</tbody>
        </table></div>
      </Card>
      {eventId !== null && <EventPanel eventId={eventId} onClose={() => setEventId(null)} />}
    </div>
  );
}
