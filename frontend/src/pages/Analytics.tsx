import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useWsQuery } from "../lib/hooks";
import { fmtNum } from "../lib/format";
import { Card, ErrorState, Loading, Stat } from "../components/ui";
import { Columns, EventsOverTime, HBar, SeverityBars } from "../components/charts";

function DataTable({ rows, cols }: { rows: Record<string, any>[]; cols: [string, string][] }) {
  return (
    <details className="small mt-8"><summary>Show as table</summary>
      <table className="table"><thead><tr>{cols.map(([, l]) => <th key={l}>{l}</th>)}</tr></thead>
        <tbody>{rows.map((r, i) => <tr key={i}>{cols.map(([k]) => <td key={k}>{String(r[k] ?? "")}</td>)}</tr>)}</tbody></table>
    </details>
  );
}

export function AnalyticsPage() {
  const navigate = useNavigate();
  const [days, setDays] = useState("");
  const q = useWsQuery<any>(["analytics", "summary", days], `/api/analytics/summary${days ? `?days=${days}` : ""}`);
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} />;
  const s = q.data;
  const threshold = s.anomaly_score_histogram.find((b: any) => Number(b.bin) >= 0.6)?.bin;
  return (
    <div className="stack">
      <div className="page-head">
        <div><h1>Analytics</h1><p>Computed live from the telemetry currently loaded in this workspace.</p></div>
        <div className="page-actions"><label htmlFor="range" className="small muted">Range</label>
          <select id="range" className="select" value={days} onChange={(e) => setDays(e.target.value)}>
            <option value="">All data</option><option value="1">Last 24 h of data</option><option value="3">Last 3 days of data</option><option value="7">Last 7 days of data</option>
          </select></div>
      </div>
      <div className="grid grid-4">
        <Stat label="Events" value={fmtNum(s.kpis.events)} /><Stat label="Detections" value={fmtNum(s.kpis.detections)} />
        <Stat label="Incidents" value={fmtNum(s.kpis.incidents)} foot={`${s.kpis.open_incidents} open`} />
        <Stat label="Distinct users / hosts" value={`${fmtNum(s.kpis.users)} / ${fmtNum(s.kpis.hosts)}`} />
      </div>
      <Card title="Events over time" sub="Stacked by severity"><EventsOverTime data={s.events_over_time} height={280} />
        <DataTable rows={s.events_over_time} cols={[["bucket", "Bucket (UTC)"], ["total", "Total"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"], ["info", "Info"]]} /></Card>
      <div className="grid grid-3">
        <Card title="Event severity distribution"><SeverityBars data={s.severity_distribution} label="Event severity distribution" /></Card>
        <Card title="Event types"><HBar data={s.event_types} label="Events by type" onSelect={(t) => navigate(`/events?event_type=${t}`)} /></Card>
        <Card title="Detections by severity"><SeverityBars data={s.detections_by_severity} label="Detections by severity" /></Card>
      </div>
      <div className="grid grid-3">
        <Card title="Top users"><HBar data={s.top_users} label="Top users" onSelect={(u) => navigate(`/entities/user/${u}`)} /></Card>
        <Card title="Top hosts"><HBar data={s.top_hosts} label="Top hosts" onSelect={(h) => navigate(`/entities/host/${h}`)} /></Card>
        <Card title="Top source IPs"><HBar data={s.top_source_ips} label="Top source IPs" onSelect={(ip) => navigate(`/threat-intel?q=${ip}`)} /></Card>
      </div>
      <div className="grid grid-3">
        <Card title="Failed logins by user"><HBar data={s.failed_logins_by_user} label="Failed logins by user" /></Card>
        <Card title="Detections by rule"><HBar data={s.detections_by_rule} label="Detections by rule" onSelect={(r) => navigate(`/detections?rule_key=${r}`)} /></Card>
        <Card title="ATT&CK techniques observed"><HBar data={s.techniques.map((t: any) => ({ key: t.id, count: t.count }))} label="Techniques by detection count" onSelect={(t) => navigate(`/mitre?technique=${t}`)} /></Card>
      </div>
      <div className="grid grid-2">
        <Card title="Anomaly score distribution" sub="Isolation Forest scores of entity-day windows; bins at or above the 0.60 decision threshold are highlighted">
          <Columns data={s.anomaly_score_histogram} xKey="bin" label="Anomaly score histogram" threshold={threshold} />
        </Card>
        <Card title="Incident trend" sub="Incidents by first-seen day"><Columns data={s.incidents_over_time} xKey="day" label="Incidents per day" />
          <DataTable rows={s.incidents_by_status} cols={[["key", "Status"], ["count", "Incidents"]]} /></Card>
      </div>
    </div>
  );
}
