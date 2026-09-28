import { Link, useParams } from "react-router-dom";
import { useWsQuery } from "../lib/hooks";
import { fmtBytes, fmtTime } from "../lib/format";
import { InvestigateButton, copilotUrl } from "../components/InvestigateButton";
import { Card, ErrorState, JsonBlock, KV, Loading, SeverityBadge, StatusBadge } from "../components/ui";

/** Deep link: /events/<event uid>. */
export function EventDetailPage() {
  const { uid = "" } = useParams();
  const ref = useWsQuery<{ id: number }>(["event-uid", uid], `/api/events/by-uid/${encodeURIComponent(uid)}`);
  const q = useWsQuery<any>(["event", ref.data?.id], ref.data ? `/api/events/${ref.data.id}` : null);
  if (ref.isLoading || q.isLoading) return <Loading />;
  if (ref.error) return <ErrorState error={ref.error} />;
  if (q.error) return <ErrorState error={q.error} />;
  const e = q.data;
  if (!e) return null;
  return (
    <div className="stack">
      <div className="page-head">
        <div><div className="small muted"><Link to="/events">Event Explorer</Link> / event</div><h1 className="mono" style={{ marginTop: 4 }}>{e.event_uid}</h1>
          <p className="row"><SeverityBadge severity={e.severity} /><span className="badge">{e.event_type}</span>{e.status && <span className="badge">{e.status}</span>} {fmtTime(e.timestamp)} UTC</p></div>
        <div className="page-actions">
          <InvestigateButton context={[`EVT:${e.event_uid}`]} mode="explain" label="Explain" q={`Explain event ${e.event_uid}. Is it normal for this user and host?`} />
          <Link className="btn" to={copilotUrl({ context: [`EVT:${e.event_uid}`], mode: "investigate", q: `What happened before and after event ${e.event_uid}?` })}>Before / after</Link>
        </div>
      </div>
      <div className="grid grid-main-side">
        <Card title="Normalized">
          <KV items={[
            ["Type / action", `${e.event_type} / ${e.action ?? "—"}`], ["User", e.user && <Link to={`/entities/user/${e.user}`}>{e.user}</Link>],
            ["Host", e.host && <Link to={`/entities/host/${e.host}`}>{e.host}</Link>], ["Source IP", e.source_ip && <Link to={`/threat-intel?q=${e.source_ip}`}>{e.source_ip}</Link>],
            ["Destination IP", e.destination_ip && <Link to={`/threat-intel?q=${e.destination_ip}`}>{e.destination_ip}</Link>], ["Process", e.process],
            ["Command", e.command && <code className="wrap-anywhere">{e.command}</code>], ["Resource", e.resource && <span className="wrap-anywhere">{e.resource}</span>],
            ["Bytes", e.bytes !== null ? fmtBytes(e.bytes) : null], ["Log source", e.source], ["Ingested", fmtTime(e.ingested_at)],
          ]} />
        </Card>
        <Card title="Related">
          <h3 className="small muted">DETECTIONS</h3>
          {e.detections.length === 0 ? <p className="muted small">No detection references this event.</p> : <ul>{e.detections.map((d: any) => <li key={d.id}><Link to={`/detections/${d.id}`}>{d.rule_key} · {d.title}</Link></li>)}</ul>}
          <h3 className="small muted mt-16">INCIDENTS</h3>
          {e.incidents.length === 0 ? <p className="muted small">Not part of any incident.</p> : <ul>{e.incidents.map((i: any) => <li key={i.id}><Link to={`/incidents/${i.number}`}>{i.number}</Link> <StatusBadge status={i.status} /> <span className="muted small">({i.role})</span></li>)}</ul>}
        </Card>
      </div>
      <div className="grid grid-2">
        <Card title="Raw original" sub="Exactly as received — untrusted content, displayed as text"><JsonBlock value={e.raw} label="Raw event JSON" /></Card>
        <Card title="Metadata"><JsonBlock value={e.metadata} label="Event metadata" /></Card>
      </div>
    </div>
  );
}
