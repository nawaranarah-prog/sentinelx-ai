import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Bookmark } from "lucide-react";
import { qs } from "../lib/api";
import { useDebounced, useWsQuery } from "../lib/hooks";
import { fmtTime, STATUS_LABEL } from "../lib/format";
import type { IncidentBrief, Paged } from "../lib/types";
import { Card, Empty, ErrorState, Loading, Pagination, RiskMeter, SeverityBadge, StatusBadge } from "../components/ui";

export function IncidentsPage() {
  const navigate = useNavigate();
  const [f, setF] = useState({ q: "", status: "", severity: "", assigned: "", sort: "risk", page: 1 });
  const q = useDebounced(f.q);
  const path = `/api/incidents${qs({ q, status: f.status, severity: f.severity, assigned: f.assigned, sort: f.sort, page: f.page, page_size: 25 })}`;
  const data = useWsQuery<Paged<IncidentBrief>>(["incidents", path], path, { refetchInterval: 30_000 });
  const set = (k: string, v: string | number) => setF({ ...f, [k]: v, page: k === "page" ? Number(v) : 1 });
  return (
    <div className="stack">
      <div className="page-head"><div><h1>Incidents</h1><p>Correlated detections that require investigation. Sorted by SentinelX Risk Score by default.</p></div></div>
      <Card flush>
        <div className="filters" role="search">
          <div className="field"><label htmlFor="iq">Search</label><input id="iq" className="input" placeholder="Title or INC-number" value={f.q} onChange={(e) => set("q", e.target.value)} /></div>
          <div className="field"><label htmlFor="ist">Status</label>
            <select id="ist" className="select" value={f.status} onChange={(e) => set("status", e.target.value)}>
              <option value="">All</option>{Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select></div>
          <div className="field"><label htmlFor="isev">Severity</label>
            <select id="isev" className="select" value={f.severity} onChange={(e) => set("severity", e.target.value)}>
              <option value="">All</option>{["critical", "high", "medium", "low"].map((s) => <option key={s} value={s}>{s}</option>)}
            </select></div>
          <div className="field"><label htmlFor="ias">Owner</label>
            <select id="ias" className="select" value={f.assigned} onChange={(e) => set("assigned", e.target.value)}>
              <option value="">Anyone</option><option value="me">Assigned to me</option><option value="unassigned">Unassigned</option>
            </select></div>
          <div className="field"><label htmlFor="isort">Sort</label>
            <select id="isort" className="select" value={f.sort} onChange={(e) => set("sort", e.target.value)}>
              <option value="risk">Risk score</option><option value="last_seen">Last activity</option><option value="first_seen">First seen</option><option value="created">Created</option>
            </select></div>
        </div>
        {data.isLoading ? <Loading /> : data.error ? <div className="card-body"><ErrorState error={data.error} /></div> :
          data.data!.items.length === 0 ? <Empty title="No incidents match">Adjust the filters, or upload data to generate detections.</Empty> : (
            <>
              <div className="table-wrap">
                <table className="table responsive">
                  <thead><tr><th>Incident</th><th>Severity</th><th>Risk</th><th>Status</th><th>Stages</th><th className="num">Detections</th><th>Owner</th><th>Last seen (UTC)</th></tr></thead>
                  <tbody>
                    {data.data!.items.map((i) => (
                      <tr key={i.id} className="clickable" onClick={() => navigate(`/incidents/${i.id}`)}>
                        <td data-label="Incident" className="wrap-anywhere">
                          <Link to={`/incidents/${i.id}`} onClick={(e) => e.stopPropagation()}><strong>{i.number}</strong></Link>{i.bookmarked && <Bookmark size={12} aria-label="Bookmarked" style={{ marginLeft: 4 }} />}
                          <div className="text-2">{i.title}</div>
                        </td>
                        <td data-label="Severity"><SeverityBadge severity={i.severity} /></td>
                        <td data-label="Risk"><RiskMeter score={i.risk_score} band={i.risk_band} /></td>
                        <td data-label="Status"><StatusBadge status={i.status} /></td>
                        <td data-label="Stages" className="small">{i.stages.join(" → ")}</td>
                        <td data-label="Detections" className="num">{i.detection_count}</td>
                        <td data-label="Owner" className="small">{i.assigned_to ?? <span className="muted">Unassigned</span>}</td>
                        <td data-label="Last seen" className="nowrap small">{fmtTime(i.last_seen, false)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination page={f.page} pageSize={25} total={data.data!.total} onPage={(p) => set("page", p)} />
            </>
          )}
      </Card>
    </div>
  );
}
