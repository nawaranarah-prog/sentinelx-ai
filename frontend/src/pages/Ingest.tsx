import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Download, FileUp, XCircle } from "lucide-react";
import { api, download } from "../lib/api";
import { useWsQuery } from "../lib/hooks";
import { useSession } from "../lib/session";
import { fmtNum, fmtTime } from "../lib/format";
import { Card, Empty, ErrorState, Loading, Tabs, useToast } from "../components/ui";

interface Preview {
  filename: string; file_format: string; columns: string[]; field_mapping: Record<string, string>; unmapped_columns: string[];
  total_rows: number; valid_rows: number; rejected_rows: number; duplicates_in_file: number; warning_count: number;
  errors: { row: number; error: string }[]; warnings: { row: number; warnings: string[] }[]; sample: Record<string, any>[];
}
interface Job {
  id: number; filename: string; file_format: string; status: string; stage: string; total_rows: number; processed_rows: number;
  accepted_rows: number; rejected_rows: number; duplicate_rows: number; errors: { row: number; error: string }[];
  warnings: { row: number; warnings: string[] }[]; detections_created: number; incidents_created: number; incidents_updated: number;
  anomalies_flagged: number; error_message: string | null; created_at: string; finished_at: string | null;
}
const STAGES = ["QUEUED", "VALIDATING", "STORING", "DETECTING", "ANOMALY_ANALYSIS", "CORRELATING", "DONE"];
const STAGE_LABEL: Record<string, string> = { QUEUED: "Queued", VALIDATING: "Validate & normalize", STORING: "Store", DETECTING: "Detect",
  ANOMALY_ANALYSIS: "Anomaly analysis", CORRELATING: "Correlate → incidents", DONE: "Done", FAILED: "Failed" };

function JobProgress({ job }: { job: Job }) {
  const idx = job.stage === "FAILED" ? -1 : STAGES.indexOf(job.stage);
  const pct = job.status === "COMPLETED" || job.status === "COMPLETED_WITH_ERRORS" ? 100 : Math.max(5, (idx / (STAGES.length - 1)) * 100);
  const done = job.status.startsWith("COMPLETED");
  return (
    <Card title={<span className="row">{done ? <CheckCircle2 color="var(--ok)" size={18} /> : job.status === "FAILED" ? <XCircle color="var(--sev-critical)" size={18} /> : <span className="spinner" />} {job.filename}</span>}
      sub={`Job #${job.id} · ${job.status.replace(/_/g, " ")} · stage: ${STAGE_LABEL[job.stage] ?? job.stage}`}>
      <div className="progress" role="progressbar" aria-valuenow={Math.round(pct)} aria-valuemin={0} aria-valuemax={100} aria-label="Ingestion progress"><span style={{ width: `${pct}%`, background: job.status === "FAILED" ? "var(--sev-critical)" : undefined }} /></div>
      <ol className="row small mt-8" style={{ listStyle: "none", padding: 0, gap: 14 }}>
        {STAGES.slice(1).map((s, i) => <li key={s} className={i + 1 <= idx || done ? "" : "muted"}>{i + 1 <= idx || done ? "✓" : "○"} {STAGE_LABEL[s]}</li>)}
      </ol>
      {job.error_message && <div className="error-box mt-8" role="alert">{job.error_message}</div>}
      {(done || job.status === "FAILED") && (
        <div className="grid grid-4 mt-16">
          <div className="card stat"><div className="label">Events ingested</div><div className="value">{fmtNum(job.accepted_rows)}</div><div className="foot">of {fmtNum(job.total_rows)} rows</div></div>
          <div className="card stat"><div className="label">Rejected / duplicates</div><div className="value">{fmtNum(job.rejected_rows)} / {fmtNum(job.duplicate_rows)}</div><div className="foot">see errors below</div></div>
          <div className="card stat"><div className="label">Detections generated</div><div className="value">{fmtNum(job.detections_created)}</div><div className="foot">{job.anomalies_flagged} anomalous windows</div></div>
          <div className="card stat"><div className="label">Incidents generated</div><div className="value">{fmtNum(job.incidents_created)}</div><div className="foot">{job.incidents_updated} existing incident(s) updated</div></div>
        </div>
      )}
      {done && (job.detections_created > 0 || job.incidents_created > 0) && (
        <div className="row mt-16"><Link className="btn btn-primary" to="/incidents">Review incidents</Link><Link className="btn" to="/detections">Review detections</Link><Link className="btn" to="/events">Explore events</Link></div>
      )}
      {job.errors.length > 0 && (
        <details className="mt-16"><summary>{job.errors.length} row error(s){job.errors.length >= 200 ? " (first 200 shown)" : ""}</summary>
          <ul className="small">{job.errors.map((e, i) => <li key={i}>Row {e.row}: {e.error}</li>)}</ul></details>
      )}
      {job.warnings.length > 0 && (
        <details className="mt-8"><summary>{job.warnings.length} row(s) with warnings</summary>
          <ul className="small">{job.warnings.map((w, i) => <li key={i}>Row {w.row}: {w.warnings.join("; ")}</li>)}</ul></details>
      )}
    </Card>
  );
}

export function IngestPage() {
  const { isAnalyst } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [drag, setDrag] = useState(false);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [jobId, setJobId] = useState<number | null>(null);
  const [docTab, setDocTab] = useState("samples");
  const job = useWsQuery<Job>(["job", jobId], jobId ? `/api/ingest/jobs/${jobId}` : null, {
    refetchInterval: (q) => (q.state.data && ["COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"].includes((q.state.data as Job).status) ? false : 1000),
  });
  const jobs = useWsQuery<Job[]>(["jobs"], "/api/ingest/jobs");
  const samples = useWsQuery<{ name: string; description: string }[]>(["samples"], "/api/ingest/samples");
  const schema = useWsQuery<{ fields: { name: string; type: string; description: string; aliases: string[] }[]; formats: string[]; limits: { max_upload_mb: number; max_rows: number } }>(["schema"], "/api/ingest/schema");

  useEffect(() => {
    if (job.data && ["COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"].includes(job.data.status)) {
      qc.invalidateQueries({ queryKey: ["workspace"] });
      qc.invalidateQueries({ queryKey: ["ws"], predicate: (q) => q.queryKey[2] !== "job" });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [job.data?.status]);

  const choose = async (f: File | null) => {
    setFile(f);
    setPreview(null);
    setPreviewError(null);
    setJobId(null);
    if (!f) return;
    const max = (schema.data?.limits.max_upload_mb ?? 25) * 1024 * 1024;
    if (f.size > max) return setPreviewError(`File is ${(f.size / 1e6).toFixed(1)} MB; the limit is ${schema.data?.limits.max_upload_mb ?? 25} MB.`);
    if (!/\.(csv|json|ndjson|jsonl)$/i.test(f.name)) return setPreviewError("Unsupported file type. Use .csv, .json, .ndjson or .jsonl.");
    setBusy(true);
    try {
      const form = new FormData();
      form.append("file", f);
      setPreview(await api<Preview>("/api/ingest/preview", { form }));
    } catch (e) {
      setPreviewError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const upload = async () => {
    if (!file) return;
    setBusy(true);
    try {
      const form = new FormData();
      form.append("file", file);
      const j = await api<Job>("/api/ingest/upload", { form });
      setJobId(j.id);
      toast(`Upload accepted — job #${j.id} is processing.`);
    } catch (e) {
      toast((e as Error).message, "error");
    } finally {
      setBusy(false);
    }
  };

  if (!isAnalyst) return <Empty title="Upload requires the SOC Analyst or Admin role">Viewers have read-only access. The API enforces this.</Empty>;
  return (
    <div className="stack">
      <div className="page-head"><div><h1>Upload security data</h1><p>UPLOAD → VALIDATE → NORMALIZE → STORE → DETECT → ANOMALY ANALYSIS → CORRELATE → INCIDENTS. Files are parsed as data only — never executed.</p></div></div>
      <div className="grid grid-main-side">
        <div className="stack">
          <Card title="1 · Choose a file">
            <div className={`dropzone ${drag ? "drag" : ""}`} role="button" tabIndex={0} aria-label="Drop a CSV or JSON file here, or press Enter to browse"
              onClick={() => inputRef.current?.click()} onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && inputRef.current?.click()}
              onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
              onDrop={(e) => { e.preventDefault(); setDrag(false); choose(e.dataTransfer.files[0] ?? null); }}>
              <FileUp size={28} aria-hidden="true" />
              <p style={{ marginTop: 8 }}><strong>Drag & drop</strong> a file here or <span style={{ color: "var(--accent)" }}>browse</span></p>
              <p className="small muted">CSV · JSON (array or {"{events: [...]}"}) · NDJSON / JSONL — up to {schema.data?.limits.max_upload_mb ?? 25} MB and {fmtNum(schema.data?.limits.max_rows ?? 200000)} rows</p>
              {file && <p className="small">Selected: <strong>{file.name}</strong> ({(file.size / 1024).toFixed(1)} KB)</p>}
            </div>
            <input ref={inputRef} type="file" accept=".csv,.json,.ndjson,.jsonl" hidden onChange={(e) => choose(e.target.files?.[0] ?? null)} data-testid="file-input" />
            {busy && !preview && <Loading label="Validating and previewing…" />}
            {previewError && <div className="mt-8"><ErrorState error={new Error(previewError)} /></div>}
          </Card>
          {preview && (
            <Card title="2 · Validation & normalization preview" sub={`${preview.file_format.toUpperCase()} · ${preview.columns.length} columns detected`}
              actions={<button className="btn btn-primary" onClick={upload} disabled={busy || preview.valid_rows === 0 || !!jobId}>{busy ? "Uploading…" : `Ingest ${fmtNum(preview.valid_rows)} valid rows`}</button>}>
              <div className="grid grid-4 mb-8">
                <div className="card stat"><div className="label">Rows</div><div className="value">{fmtNum(preview.total_rows)}</div></div>
                <div className="card stat"><div className="label">Accepted</div><div className="value" style={{ color: "var(--ok)" }}>{fmtNum(preview.valid_rows)}</div></div>
                <div className="card stat"><div className="label">Rejected</div><div className="value" style={{ color: preview.rejected_rows ? "var(--sev-critical)" : undefined }}>{fmtNum(preview.rejected_rows)}</div></div>
                <div className="card stat"><div className="label">Duplicates / warnings</div><div className="value">{preview.duplicates_in_file} / {preview.warning_count}</div></div>
              </div>
              <h3 className="mb-8">Field mapping</h3>
              <div className="row mb-8">{Object.entries(preview.field_mapping).map(([col, canon]) => <span key={col} className="chip mono">{col} → <strong>{canon}</strong></span>)}</div>
              {preview.unmapped_columns.length > 0 && <p className="small muted">Kept in metadata: {preview.unmapped_columns.join(", ")}</p>}
              {preview.errors.length > 0 && (<details open className="mb-8"><summary className="field-error">{preview.rejected_rows} rejected row(s)</summary>
                <ul className="small">{preview.errors.slice(0, 20).map((e, i) => <li key={i}>Row {e.row}: {e.error}</li>)}</ul></details>)}
              {preview.warnings.length > 0 && (<details className="mb-8"><summary>Warnings</summary><ul className="small">{preview.warnings.slice(0, 20).map((w, i) => <li key={i}>Row {w.row}: {w.warnings.join("; ")}</li>)}</ul></details>)}
              <h3 className="mb-8 mt-8">First normalized rows</h3>
              <div className="table-wrap"><table className="table">
                <thead><tr>{["timestamp", "event_type", "user", "host", "source_ip", "destination_ip", "action", "status", "command/resource"].map((h) => <th key={h}>{h}</th>)}</tr></thead>
                <tbody>{preview.sample.map((r, i) => (
                  <tr key={i}><td className="nowrap small mono">{fmtTime(r.timestamp)}</td><td>{r.event_type}</td><td>{r.user}</td><td className="nowrap">{r.host}</td>
                    <td className="mono small">{r.source_ip}</td><td className="mono small">{r.destination_ip}</td><td>{r.action}</td><td>{r.status}</td>
                    <td className="small truncate">{r.command ?? r.resource}</td></tr>))}</tbody>
              </table></div>
            </Card>
          )}
          {job.data && <JobProgress job={job.data} />}
        </div>
        <div className="stack">
          <Card flush>
            <div style={{ padding: "0 12px" }}><Tabs label="Upload help" active={docTab} onChange={setDocTab} tabs={[{ id: "samples", label: "Sample datasets" }, { id: "schema", label: "Event schema" }]} /></div>
            <div className="card-body" style={{ paddingTop: 0 }}>
              {docTab === "samples" && (
                <>
                  <p className="small muted">Synthetic Nova Bank telemetry for testing. The "mixed" set uses alternate field names (src_ip, username…) to exercise normalization.</p>
                  <ul style={{ listStyle: "none", padding: 0 }}>
                    {samples.data?.map((s) => (
                      <li key={s.name} className="mb-8" style={{ borderBottom: "1px solid var(--border)", paddingBottom: 8 }}>
                        <strong>{s.name.replace("_", " ")}</strong><div className="small muted">{s.description}</div>
                        <div className="row mt-8">
                          <button className="btn btn-sm" onClick={() => download(`/api/ingest/samples/${s.name}.csv`, `sentinelx_sample_${s.name}.csv`)}><Download /> CSV</button>
                          <button className="btn btn-sm" onClick={() => download(`/api/ingest/samples/${s.name}.json`, `sentinelx_sample_${s.name}.json`)}><Download /> JSON</button>
                        </div>
                      </li>))}
                  </ul>
                  <button className="btn btn-sm" onClick={() => download("/api/ingest/schema.md", "sentinelx_event_schema.md")}><Download /> Event schema (Markdown)</button>
                </>
              )}
              {docTab === "schema" && schema.data && (
                <div className="small">
                  <ul>{schema.data.formats.map((f) => <li key={f}>{f}</li>)}</ul>
                  <table className="table"><thead><tr><th>Field</th><th>Description & aliases</th></tr></thead>
                    <tbody>{schema.data.fields.map((f) => (<tr key={f.name}><td className="mono"><strong>{f.name}</strong><div className="muted">{f.type}</div></td>
                      <td>{f.description}{f.aliases.length > 0 && <div className="muted mono" style={{ fontSize: 11 }}>{f.aliases.slice(0, 10).join(", ")}</div>}</td></tr>))}</tbody></table>
                </div>
              )}
            </div>
          </Card>
          <Card title="Ingestion history" flush>
            {jobs.data?.length === 0 ? <Empty title="No uploads yet" /> : (
              <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
                {jobs.data?.slice(0, 10).map((j) => (
                  <li key={j.id} style={{ padding: "8px 16px", borderBottom: "1px solid var(--border)" }}>
                    <button className="btn btn-ghost" style={{ height: "auto", padding: 0, whiteSpace: "normal", textAlign: "left" }} onClick={() => setJobId(j.id)}>
                      <span><strong className="wrap-anywhere">{j.filename}</strong> <span className={`badge ${j.status === "FAILED" ? "st-bad" : j.status.startsWith("COMPLETED") ? "st-ok" : ""}`}>{j.status.replace(/_/g, " ")}</span>
                        <div className="small muted">{fmtTime(j.created_at, false)} · {fmtNum(j.accepted_rows)} events · {j.detections_created} detections · {j.incidents_created} incidents</div></span>
                    </button>
                  </li>))}
              </ul>)}
          </Card>
        </div>
      </div>
    </div>
  );
}
