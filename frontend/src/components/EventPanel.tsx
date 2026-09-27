import { useState } from "react";
import { Link } from "react-router-dom";
import { useWsQuery } from "../lib/hooks";
import { fmtBytes, fmtTime } from "../lib/format";
import { ErrorState, JsonBlock, KV, Loading, SeverityBadge, SidePanel, StatusBadge, Tabs } from "./ui";

export function EventPanel({ eventId, onClose }: { eventId: number; onClose: () => void }) {
  const q = useWsQuery<any>(["event", eventId], `/api/events/${eventId}`);
  const [tab, setTab] = useState("normalized");
  const e = q.data;
  return (
    <SidePanel title={e ? <span className="mono">{e.event_uid}</span> : "Event"} onClose={onClose}>
      {q.isLoading && <Loading />}
      {q.error && <ErrorState error={q.error} />}
      {e && (
        <div className="stack">
          <div className="row"><SeverityBadge severity={e.severity} /><span className="badge">{e.event_type}</span>{e.status && <span className="badge">{e.status}</span>}</div>
          <Tabs label="Event views" active={tab} onChange={setTab} tabs={[
            { id: "normalized", label: "Normalized" }, { id: "raw", label: "Raw original" }, { id: "metadata", label: "Metadata" }, { id: "related", label: `Related (${e.detections.length + e.incidents.length})` },
          ]} />
          <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
            {tab === "normalized" && (
              <KV items={[
                ["Timestamp (UTC)", fmtTime(e.timestamp)], ["Type / action", `${e.event_type} / ${e.action ?? "—"}`], ["User", e.user && <Link to={`/entities/user/${e.user}`}>{e.user}</Link>],
                ["Host", e.host && <Link to={`/entities/host/${e.host}`}>{e.host}</Link>], ["Source IP", e.source_ip && <Link to={`/threat-intel?q=${e.source_ip}`}>{e.source_ip}</Link>],
                ["Destination IP", e.destination_ip && <Link to={`/threat-intel?q=${e.destination_ip}`}>{e.destination_ip}</Link>], ["Process", e.process],
                ["Command", e.command && <code className="wrap-anywhere">{e.command}</code>], ["Resource", e.resource && <span className="wrap-anywhere">{e.resource}</span>],
                ["Bytes", e.bytes !== null ? fmtBytes(e.bytes) : null], ["Log source", e.source], ["Ingested", fmtTime(e.ingested_at)],
              ]} />
            )}
            {tab === "raw" && <><p className="muted small">The original record exactly as received (untrusted content, displayed as text).</p><JsonBlock value={e.raw} label="Raw event JSON" /></>}
            {tab === "metadata" && <JsonBlock value={e.metadata} label="Event metadata" />}
            {tab === "related" && (
              <div className="stack">
                <div><h3 className="mb-8">Detections</h3>
                  {e.detections.length === 0 ? <p className="muted">No detection references this event.</p> :
                    <ul>{e.detections.map((d: any) => <li key={d.id}><Link to={`/detections/${d.id}`}>{d.rule_key} · {d.title}</Link></li>)}</ul>}</div>
                <div><h3 className="mb-8">Incidents</h3>
                  {e.incidents.length === 0 ? <p className="muted">Not part of any incident.</p> :
                    <ul>{e.incidents.map((i: any) => <li key={i.id}><Link to={`/incidents/${i.id}`}>{i.number}</Link> <StatusBadge status={i.status} /> <span className="muted small">({i.role})</span></li>)}</ul>}</div>
              </div>
            )}
          </div>
        </div>
      )}
    </SidePanel>
  );
}
