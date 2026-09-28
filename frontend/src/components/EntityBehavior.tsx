import { useWsQuery } from "../lib/hooks";
import { Columns } from "./charts";
import { Card, Loading } from "./ui";

/** Baseline, risk history, peer comparison and day-by-day life story for a user or host. */
export function EntityBehavior({ kind, name }: { kind: string; name: string }) {
  const base = `/api/entities/${kind}/${encodeURIComponent(name)}`;
  const baseline = useWsQuery<any>(["entity-baseline", kind, name], `${base}/baseline`);
  const risk = useWsQuery<any[]>(["entity-risk-history", kind, name], `${base}/risk-history`);
  const story = useWsQuery<any[]>(["entity-story", kind, name], `${base}/life-story`);
  const peers = useWsQuery<any>(["entity-peers", name], kind === "user" ? `/api/entities/user/${encodeURIComponent(name)}/peers` : null);
  const other = kind === "user" ? "hosts" : "users";
  return (
    <div className="stack">
      <div className="grid grid-2">
        <Card title="Normal behavior (baseline)" sub={baseline.data?.events ? `${baseline.data.events} events over ${baseline.data.days_observed} day(s); usual active hours (UTC): ${(baseline.data.usual_active_hours_utc ?? []).join(", ") || "—"}` : undefined}>
          {baseline.isLoading ? <Loading /> : baseline.data?.hour_histogram ? (
            <Columns data={baseline.data.hour_histogram.map((c: number, h: number) => ({ hour: String(h).padStart(2, "0"), count: c }))} xKey="hour" label="Events by hour of day (UTC)" height={170} />
          ) : <p className="muted small">{baseline.data?.note ?? "No baseline."}</p>}
        </Card>
        <Card title="Risk history" sub="Daily SentinelX risk points from detections and anomalies">
          {risk.isLoading ? <Loading /> : !risk.data?.length ? <p className="muted small">No risk recorded.</p> : (<>
            <Columns data={risk.data.map((r) => ({ day: r.day.slice(5), count: r.risk_points }))} xKey="day" label="Risk points per day" height={140} />
            <ul className="small">{risk.data.filter((r) => r.detections.length || r.anomalous_windows).slice(-5).map((r) => (
              <li key={r.day}><span className="mono">{r.day}</span>: {r.detections.join("; ")}{r.anomalous_windows ? ` · ${r.anomalous_windows} anomalous window(s)` : ""}</li>))}</ul>
          </>)}
        </Card>
      </div>
      {kind === "user" && peers.data && (
        <Card title="Peer comparison" sub={`Peers: ${peers.data.peer_basis} (${peers.data.peers.length})`} flush>
          <div className="table-wrap"><table className="table dense">
            <thead><tr><th>Feature</th><th className="num">{name}</th><th className="num">Peer median</th><th className="num">Ratio</th><th>Above all peers</th></tr></thead>
            <tbody>{peers.data.comparison.map((c: any) => (
              <tr key={c.feature} className={c.above_all_peers ? "warn-row" : ""}><td>{c.feature.replace(/_/g, " ")}</td><td className="num">{c.value}</td><td className="num">{c.peer_median}</td>
                <td className="num">{c.ratio_to_peers ?? "—"}</td><td>{c.above_all_peers ? "yes" : "no"}</td></tr>))}</tbody>
          </table></div>
        </Card>)}
      <Card title="Life story" sub="What this entity did each day" flush>
        {story.isLoading ? <Loading /> : (
          <div className="table-wrap"><table className="table dense">
            <thead><tr><th>Day</th><th className="num">Events</th><th>Active</th><th>Activity</th><th>{other}</th><th>Source IPs</th><th>Detections</th><th>Anomaly</th></tr></thead>
            <tbody>{story.data?.map((d) => (
              <tr key={d.day} className={d.detections.length ? "warn-row" : ""}>
                <td className="mono small nowrap">{d.day}</td><td className="num">{d.events}</td><td className="small nowrap">{d.first}–{d.last}</td>
                <td className="small">{Object.entries(d.event_types).map(([k, v]) => `${k} ${v}`).join(", ")}</td>
                <td className="small">{(d[other] ?? []).join(", ")}</td><td className="small mono">{d.source_ips.join(", ")}</td>
                <td className="small">{d.detections.join("; ") || "—"}</td><td className="small">{d.anomalous ? `anomalous (${d.anomaly_score?.toFixed(2)})` : "—"}</td>
              </tr>))}</tbody>
          </table></div>)}
      </Card>
    </div>
  );
}
