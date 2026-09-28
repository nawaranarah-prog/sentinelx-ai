import { Link } from "react-router-dom";
import { useWsQuery } from "../lib/hooks";
import { fmtRelative, fmtTime } from "../lib/format";
import { Card, Empty, ErrorState, KV, Loading } from "../components/ui";

export function DataQualityPage() {
  const pipe = useWsQuery<any>(["pipeline"], "/api/system/pipeline");
  const dq = useWsQuery<any>(["data-quality"], "/api/system/data-quality");
  const unk = useWsQuery<any[]>(["unexplained"], "/api/analytics/unexplained");
  const changes = useWsQuery<any>(["changes-24"], "/api/analytics/changes?hours=24");
  if (pipe.isLoading || dq.isLoading) return <Loading />;
  if (pipe.error) return <ErrorState error={pipe.error} />;
  const stages = pipe.data.stages as { stage: string; count: number; detail: string }[];
  const q = dq.data;
  return (
    <div className="stack">
      <div className="page-head"><div><h1>Pipeline & data quality</h1><p>What arrived, what was kept, and what the analysis can and cannot see. Gaps here limit every detection and every copilot answer.</p></div></div>
      <Card title="Pipeline" sub={pipe.data.last_run.at ? `Last analysis run ${fmtRelative(pipe.data.last_run.at)}` : "No analysis run yet"}>
        <ol className="pipeline">{stages.map((s) => (
          <li key={s.stage}><div className="pipeline-stage">{s.stage}</div><div className="pipeline-count">{s.count.toLocaleString()}</div><div className="small muted">{s.detail}</div></li>))}</ol>
        {pipe.data.recent_jobs.length > 0 && (
          <div className="table-wrap mt-16"><table className="table dense">
            <thead><tr><th>Upload</th><th>Status</th><th className="num">Rows</th><th className="num">Accepted</th><th className="num">Rejected</th><th>Stage timings (ms)</th><th>When</th></tr></thead>
            <tbody>{pipe.data.recent_jobs.map((j: any) => (
              <tr key={j.id}><td className="small">{j.filename}</td><td>{j.status}</td><td className="num">{j.rows}</td><td className="num">{j.accepted}</td><td className="num">{j.rejected}</td>
                <td className="small mono">{Object.entries(j.timings_ms).map(([k, v]) => `${k} ${v}`).join(" · ") || "—"}</td><td className="small">{fmtRelative(j.created_at)}</td></tr>))}</tbody>
          </table></div>)}
      </Card>
      {!q || q.events === 0 ? <Card><Empty title="No telemetry">Upload data to assess its quality.</Empty></Card> : (
        <div className="grid grid-2">
          <Card title="Coverage">
            <KV items={[["Events", q.events.toLocaleString()], ["Time range (UTC)", `${fmtTime(q.time_range.start)} – ${fmtTime(q.time_range.end)}`],
              ["Hours with no events", `${q.hours_without_events} of ${q.hours_in_range}`], ["By type", Object.entries(q.by_event_type).map(([k, v]) => `${k} ${v}`).join(", ")],
              ["Unclassified events", q.unclassified_events], ["Rejected rows", q.rejected_rows], ["Duplicate rows skipped", q.duplicate_rows]]} />
            {q.rejection_reasons.length > 0 && <><h3 className="small muted mt-16">REJECTION REASONS</h3><ul className="small">{q.rejection_reasons.map((r: any) => <li key={r.reason}>{r.reason} ({r.count})</li>)}</ul></>}
          </Card>
          <Card title="Field completeness" sub="Fields below 90% are highlighted" flush>
            <div className="table-wrap"><table className="table dense">
              <thead><tr><th>Event type</th><th>Field</th><th className="num">Present</th></tr></thead>
              <tbody>{q.field_completeness.map((c: any) => (
                <tr key={`${c.event_type}-${c.field}`} className={c.pct < 90 ? "warn-row" : ""}><td>{c.event_type}</td><td className="mono small">{c.field}</td><td className="num">{c.pct}%</td></tr>))}</tbody>
            </table></div>
          </Card>
        </div>)}
      <div className="grid grid-2">
        <Card title="Unexplained behavior and blind spots" sub="Anomalies no detection explains, missing telemetry and unclassified data" flush>
          {unk.data?.length === 0 ? <p className="muted small pad">Nothing found.</p> : (
            <ul className="list">{unk.data?.map((f, i) => (
              <li key={i}><span className="badge">{f.type.replace(/_/g, " ")}</span> {f.entity && <Link className="mono small" to={`/entities/${f.entity_type}/${encodeURIComponent(f.entity)}`}>{f.entity}</Link>} {f.day && <span className="small muted">{f.day}</span>}
                <div className="small">{f.detail}</div></li>))}</ul>)}
        </Card>
        <Card title="What changed (last 24 h of data)">
          {changes.data?.note ? <p className="muted small">{changes.data.note}</p> : changes.data && (
            <KV items={[["New users", changes.data.new_users.join(", ") || "none"], ["New hosts", changes.data.new_hosts.join(", ") || "none"],
              ["New source IPs", changes.data.new_source_ips.join(", ") || "none"], ["New destinations", changes.data.new_destinations.join(", ") || "none"],
              ["New processes", changes.data.new_processes.join(", ") || "none"],
              ["Volume vs. history", changes.data.volume_by_event_type.map((v: any) => `${v.event_type} ${v.recent} (expected ${v.expected_from_history})`).join("; ")]]} />)}
        </Card>
      </div>
    </div>
  );
}
