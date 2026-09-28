import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useWsQuery } from "../lib/hooks";
import { fmtNum, fmtTime } from "../lib/format";
import type { DetectionBrief, EventBrief, IncidentBrief, RiskFactor } from "../lib/types";
import { EntityBehavior } from "../components/EntityBehavior";
import { InvestigateButton } from "../components/InvestigateButton";
import { Card, Empty, ErrorState, KV, Loading, RiskMeter, SeverityBadge, StatusBadge, Tabs } from "../components/ui";

interface EntityRisk {
  entity_type: string; name: string; risk_score: number; risk_band: string; factors: RiskFactor[]; detection_count: number;
  open_incident_count: number; anomalous_days: number; event_count: number; criticality?: string;
}

export function EntitiesPage() {
  const [kind, setKind] = useState<"users" | "hosts">("users");
  const [filter, setFilter] = useState("");
  const navigate = useNavigate();
  const q = useWsQuery<EntityRisk[]>(["entities", kind], `/api/entities/${kind}?limit=500`);
  const rows = (q.data ?? []).filter((r) => r.name.toLowerCase().includes(filter.toLowerCase()));
  return (
    <div className="stack">
      <div className="page-head"><div><h1>Users & Hosts</h1><p>SentinelX User Risk / Host Risk — transparent scores from observed detections, incidents, anomalies and asset criticality. Not probabilities.</p></div></div>
      <Card flush>
        <div style={{ padding: "0 12px" }}><Tabs label="Entity type" active={kind} onChange={(k) => setKind(k as "users" | "hosts")} tabs={[{ id: "users", label: "Users" }, { id: "hosts", label: "Hosts" }]} /></div>
        <div className="filters" style={{ borderTop: 0, paddingTop: 0 }}><div className="field"><label htmlFor="ef">Filter</label><input id="ef" className="input" value={filter} onChange={(e) => setFilter(e.target.value)} /></div></div>
        {q.isLoading ? <Loading /> : q.error ? <ErrorState error={q.error} /> : rows.length === 0 ? <Empty title="No entities" /> : (
          <div className="table-wrap"><table className="table responsive">
            <thead><tr><th>{kind === "users" ? "User" : "Host"}</th><th>Risk</th><th>Top factors</th><th className="num">Detections</th><th className="num">Open incidents</th><th className="num">Anomalous days</th><th className="num">Events</th>{kind === "hosts" && <th>Criticality</th>}</tr></thead>
            <tbody>{rows.map((r) => (
              <tr key={r.name} className="clickable" onClick={() => navigate(`/entities/${kind.slice(0, -1)}/${r.name}`)}>
                <td data-label="Name"><Link to={`/entities/${kind.slice(0, -1)}/${r.name}`} onClick={(e) => e.stopPropagation()}><strong>{r.name}</strong></Link></td>
                <td data-label="Risk"><RiskMeter score={r.risk_score} band={r.risk_band} /></td>
                <td data-label="Top factors" className="small">{r.factors.filter((f) => f.points > 0).sort((a, b) => b.points - a.points).slice(0, 2).map((f) => `${f.factor} +${f.points}`).join(", ") || <span className="muted">none</span>}</td>
                <td data-label="Detections" className="num">{r.detection_count}</td><td data-label="Open incidents" className="num">{r.open_incident_count}</td>
                <td data-label="Anomalous days" className="num">{r.anomalous_days}</td><td data-label="Events" className="num">{fmtNum(r.event_count)}</td>
                {kind === "hosts" && <td data-label="Criticality"><span className="badge">{r.criticality ?? "—"}</span></td>}
              </tr>))}</tbody>
          </table></div>)}
      </Card>
    </div>
  );
}

export function EntityProfilePage() {
  const { kind, name } = useParams();
  const q = useWsQuery<EntityRisk & Record<string, any>>(["entity", kind, name], `/api/entities/${kind}/${encodeURIComponent(name ?? "")}`);
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} />;
  const e = q.data!;
  const related: string[] = kind === "user" ? e.hosts : e.users;
  return (
    <div className="stack">
      <div className="page-head">
        <div><div className="small muted"><Link to="/entities">Users & Hosts</Link> / {kind}</div><h1 className="mono" style={{ marginTop: 4 }}>{e.name}</h1>
          <p>{fmtNum(e.event_count)} events · first seen {fmtTime(e.first_seen, false)} · last seen {fmtTime(e.last_seen, false)} UTC</p></div>
        <div className="page-actions">
          <InvestigateButton context={[`${kind === "user" ? "USER" : "HOST"}:${e.name}`]} q={kind === "user" ? `Is ${e.name} compromised? Compare their recent activity with their baseline and peers.` : `Is host ${e.name} compromised? What unusual activity happened on it?`} />
          <Link className="btn" to={`/graph?q=${encodeURIComponent(e.name)}`}>Graph</Link>
          <Link className="btn" to={`/events?${kind}=${encodeURIComponent(e.name)}`}>View events</Link></div>
      </div>
      <div className="grid grid-main-side">
        <Card title={`SentinelX ${kind === "user" ? "User" : "Host"} Risk: ${e.risk_score}/100 (${e.risk_band})`} sub="Why this score — every factor is computed from observed activity">
          <table className="table"><tbody>{e.factors.map((f) => (
            <tr key={f.factor}><td>{f.factor}<div className="small muted">{f.detail}</div></td><td className="num nowrap">{f.points} / {f.max}</td></tr>))}</tbody></table>
        </Card>
        <Card title="Activity profile">
          <KV items={[["Events by type", Object.entries(e.events_by_type).map(([k, v]) => `${k}: ${v}`).join(", ")],
            [kind === "user" ? "Hosts used" : "Users seen", related.slice(0, 12).map((r) => <Link key={r} className="chip mono" to={`/entities/${kind === "user" ? "host" : "user"}/${r}`}>{r}</Link>)],
            ["Source IPs", e.source_ips.slice(0, 10).join(", ")], ["Criticality", e.criticality ?? (kind === "host" ? "—" : "n/a")]]} />
        </Card>
      </div>
      <EntityBehavior kind={kind!} name={e.name} />
      <Card title="Behavioral anomaly analysis" sub={e.model_info ? `${e.model_info.model} · ${e.model_info.population_windows} entity-day windows in population · ${e.model_info.decision_rule ?? e.model_info.reason ?? ""}` : "Not analysed"} flush>
        {e.anomalies.length === 0 ? <Empty title="No behavior windows" /> : (
          <div className="table-wrap"><table className="table responsive">
            <thead><tr><th>Day</th><th className="num">IF score</th><th className="num">Threshold</th><th>Verdict</th><th>Explanation</th></tr></thead>
            <tbody>{e.anomalies.map((a: any) => (
              <tr key={a.day}><td data-label="Day" className="nowrap">{a.day}</td><td data-label="IF score" className="num">{a.if_score?.toFixed(3) ?? "n/a"}</td>
                <td data-label="Threshold" className="num">{a.if_threshold?.toFixed(2) ?? "n/a"}</td>
                <td data-label="Verdict">{a.is_anomalous ? <span className="badge st-bad">Anomalous</span> : <span className="badge">Normal</span>}</td>
                <td data-label="Explanation" className="small">{a.top_deviations.map((d: any) => `${d.label}=${d.value.toLocaleString()} (z ${d.robust_z} vs ${d.basis})`).join("; ") || "No notable deviation"}</td></tr>))}</tbody>
          </table></div>)}
      </Card>
      <div className="grid grid-2">
        <Card title="Incidents" flush>{e.incidents.length === 0 ? <Empty title="None" /> : (
          <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>{e.incidents.map((i: IncidentBrief) => (
            <li key={i.id} style={{ padding: "8px 16px", borderBottom: "1px solid var(--border)" }}><Link to={`/incidents/${i.number}`}><strong>{i.number}</strong> {i.title}</Link> <SeverityBadge severity={i.severity} /> <StatusBadge status={i.status} /></li>))}</ul>)}</Card>
        <Card title="Detections" flush>{e.detections.length === 0 ? <Empty title="None" /> : (
          <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>{e.detections.slice(0, 20).map((d: DetectionBrief) => (
            <li key={d.id} style={{ padding: "8px 16px", borderBottom: "1px solid var(--border)" }}><Link to={`/detections/${d.id}`}>{d.title}</Link> <SeverityBadge severity={d.severity} /><div className="small muted">{fmtTime(d.timestamp)}</div></li>))}</ul>)}</Card>
      </div>
      <Card title="Recent events" flush>
        <div className="table-wrap"><table className="table responsive"><thead><tr><th>Time (UTC)</th><th>Type</th><th>Detail</th><th>Event ID</th></tr></thead>
          <tbody>{e.recent_events.map((ev: EventBrief) => (<tr key={ev.id}><td data-label="Time" className="small nowrap mono">{fmtTime(ev.timestamp)}</td><td data-label="Type">{ev.event_type} <span className="muted small">{ev.action} {ev.status}</span></td>
            <td data-label="Detail" className="small truncate">{ev.command ?? ev.resource ?? `${ev.source_ip ?? ""} → ${ev.destination_ip ?? ""}`}</td><td data-label="Event ID" className="mono small">{ev.event_uid}</td></tr>))}</tbody></table></div>
      </Card>
    </div>
  );
}
