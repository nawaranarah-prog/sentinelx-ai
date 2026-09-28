import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { Download, Printer } from "lucide-react";
import { api, download, fetchBlob } from "../lib/api";
import { useWsQuery } from "../lib/hooks";
import { useSession } from "../lib/session";
import { fmtTime } from "../lib/format";
import type { IncidentBrief, Paged } from "../lib/types";
import { Card, Empty, ErrorState, Loading, useToast } from "../components/ui";

interface ReportRow { id: number; incident_id: number; report_type: string; title: string; ai_mode: string; created_by: string | null; created_at: string }
const TYPE_LABEL: Record<string, string> = { incident: "Incident Report", technical: "Technical Investigation", executive: "Executive Summary" };

export function ReportsPage() {
  const { isAnalyst } = useSession();
  const navigate = useNavigate();
  const toast = useToast();
  const reports = useWsQuery<ReportRow[]>(["reports"], "/api/reports");
  const incidents = useWsQuery<Paged<IncidentBrief>>(["incidents-picker"], "/api/incidents?page_size=100");
  const [form, setForm] = useState({ incident_id: "", report_type: "incident" });
  const create = useMutation({
    mutationFn: () => api<{ id: number }>("/api/reports", { body: { incident_id: Number(form.incident_id), report_type: form.report_type } }),
    onSuccess: (r) => navigate(`/reports/${r.id}`), onError: (e) => toast((e as Error).message, "error"),
  });
  return (
    <div className="stack">
      <div className="page-head"><div><h1>Reports</h1><p>Generated from actual incident data. Export as PDF, HTML (printable) or Markdown.</p></div></div>
      {isAnalyst && (
        <Card title="Generate a report">
          <form className="row" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
            <label htmlFor="rinc" className="sr-only">Incident</label>
            <select id="rinc" className="select" style={{ flex: 2, minWidth: 220 }} required value={form.incident_id} onChange={(e) => setForm({ ...form, incident_id: e.target.value })}>
              <option value="">Select an incident…</option>{incidents.data?.items.map((i) => <option key={i.id} value={i.id}>{i.number} · {i.title.slice(0, 60)}</option>)}
            </select>
            <label htmlFor="rtype" className="sr-only">Report type</label>
            <select id="rtype" className="select" style={{ flex: 1, minWidth: 180 }} value={form.report_type} onChange={(e) => setForm({ ...form, report_type: e.target.value })}>
              {Object.entries(TYPE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
            <button className="btn btn-primary" disabled={!form.incident_id || create.isPending}>{create.isPending ? "Generating…" : "Generate"}</button>
          </form>
        </Card>)}
      <Card title="Generated reports" flush>
        {reports.isLoading ? <Loading /> : reports.data?.length === 0 ? <Empty title="No reports yet">Generate one from an incident.</Empty> : (
          <div className="table-wrap"><table className="table responsive"><thead><tr><th>Report</th><th>Type</th><th>Narrative</th><th>Author</th><th>Created (UTC)</th></tr></thead>
            <tbody>{reports.data?.map((r) => (<tr key={r.id} className="clickable" onClick={() => navigate(`/reports/${r.id}`)}>
              <td data-label="Report"><Link to={`/reports/${r.id}`} onClick={(e) => e.stopPropagation()}>{r.title}</Link></td><td data-label="Type">{TYPE_LABEL[r.report_type]}</td>
              <td data-label="Narrative"><span className={`badge ${r.ai_mode === "LIVE" ? "st-ok" : ""}`}>{r.ai_mode === "LIVE" ? "model-written" : "evidence only"}</span></td>
              <td data-label="Author" className="small">{r.created_by}</td><td data-label="Created" className="small nowrap">{fmtTime(r.created_at, false)}</td></tr>))}</tbody></table></div>)}
      </Card>
    </div>
  );
}

export function ReportViewPage() {
  const { id } = useParams();
  const toast = useToast();
  const frame = useRef<HTMLIFrameElement>(null);
  const [html, setHtml] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const meta = useWsQuery<ReportRow & { content: any }>(["report", id], `/api/reports/${id}`);
  useEffect(() => {
    fetchBlob(`/api/reports/${id}/download?format=html`).then((b) => b.text()).then(setHtml).catch(setErr);
  }, [id]);
  const dl = async (fmt: string) => {
    try { await download(`/api/reports/${id}/download?format=${fmt}`, `sentinelx_report_${id}.${fmt}`); }
    catch (e) { toast((e as Error).message, "error"); }
  };
  if (meta.isLoading) return <Loading />;
  if (meta.error) return <ErrorState error={meta.error} />;
  const r = meta.data!;
  return (
    <div className="stack">
      <div className="page-head">
        <div><div className="small muted"><Link to="/reports">Reports</Link> / #{r.id}</div><h1 style={{ marginTop: 4 }}>{r.title}</h1>
          <p>{TYPE_LABEL[r.report_type]} · by {r.created_by} · {fmtTime(r.created_at, false)} UTC · {r.ai_mode === "LIVE" ? "includes a model-written narrative" : "built from stored evidence"}</p></div>
        <div className="page-actions">
          <button className="btn" onClick={() => frame.current?.contentWindow?.print()}><Printer /> Print</button>
          <button className="btn btn-primary" onClick={() => dl("pdf")}><Download /> PDF</button>
          <button className="btn" onClick={() => dl("html")}><Download /> HTML</button>
          <button className="btn" onClick={() => dl("md")}><Download /> Markdown</button>
          <Link className="btn" to={`/incidents/${r.incident_id}`}>Open incident</Link>
        </div>
      </div>
      {err ? <ErrorState error={err} /> : !html ? <Loading label="Rendering report…" /> : (
        <iframe ref={frame} title={r.title} srcDoc={html} sandbox="allow-modals allow-same-origin"
          style={{ width: "100%", height: "calc(100vh - 220px)", minHeight: 500, border: "1px solid var(--border)", borderRadius: 10, background: "#fff" }} />
      )}
    </div>
  );
}
