import { useState, type FormEvent } from "react";
import { InvestigateButton } from "../components/InvestigateButton";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Search, Upload } from "lucide-react";
import { api } from "../lib/api";
import { useWsQuery } from "../lib/hooks";
import { useSession } from "../lib/session";
import { fmtTime } from "../lib/format";
import type { EventBrief, IncidentBrief, Paged } from "../lib/types";
import { Card, Empty, ErrorState, HealthBadge, Loading, SeverityBadge, useToast } from "../components/ui";

interface Indicator { id: number; value: string; indicator_type: string; source: string; is_synthetic: boolean; confidence: number; severity: string; description: string; first_seen: string | null; last_seen: string | null; active: boolean }

function SourceLabel({ i }: { i: Indicator }) {
  return i.is_synthetic ? <span className="badge st-warn" title="Fictional demo data, not from a real provider">SYNTHETIC / DEMO</span> : <span className="badge">LOCAL</span>;
}

export function ThreatIntelPage() {
  const [params, setParams] = useSearchParams();
  const { isAnalyst } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const [input, setInput] = useState(params.get("q") ?? "");
  const q = params.get("q") ?? "";
  const result = useWsQuery<any>(["intel-search", q], q ? `/api/intel/search?q=${encodeURIComponent(q)}` : null);
  const providers = useWsQuery<{ name: string; status: string; indicators: number; label: string; detail: string }[]>(["intel-providers"], "/api/intel/providers");
  const list = useWsQuery<Paged<Indicator>>(["indicators"], "/api/intel/indicators?page_size=100");
  const [form, setForm] = useState({ value: "", severity: "medium", confidence: "0.7", description: "" });
  const add = useMutation({
    mutationFn: () => api<{ retro_hunt: { detections_created: number } }>("/api/intel/indicators", { body: { ...form, confidence: Number(form.confidence) } }),
    onSuccess: (r) => { setForm({ value: "", severity: "medium", confidence: "0.7", description: "" }); qc.invalidateQueries({ queryKey: ["ws"] }); toast(`Indicator added. Retro-hunt created ${r.retro_hunt.detections_created} detection(s).`); },
    onError: (e) => toast((e as Error).message, "error"),
  });
  const importFile = async (f: File | undefined) => {
    if (!f) return;
    const fd = new FormData();
    fd.append("file", f);
    try {
      const r = await api<{ imported: number; retro_hunt: { detections_created: number } }>("/api/intel/indicators/import", { form: fd });
      qc.invalidateQueries({ queryKey: ["ws"] });
      toast(`Imported ${r.imported} indicators; retro-hunt created ${r.retro_hunt.detections_created} detection(s).`);
    } catch (e) { toast((e as Error).message, "error"); }
  };
  const search = (e: FormEvent) => { e.preventDefault(); if (input.trim()) setParams({ q: input.trim() }); };
  const r = result.data;
  return (
    <div className="stack">
      <div className="page-head"><div><h1>Threat Intelligence</h1><p>Search IPs, domains, hashes, hostnames and usernames against workspace intelligence and your own telemetry.</p></div></div>
      <Card>
        <form onSubmit={search} className="row" role="search">
          <label htmlFor="tiq" className="sr-only">Indicator</label>
          <input id="tiq" className="input" style={{ flex: 1, minWidth: 200 }} placeholder="e.g. 203.0.113.45, mega.nz, t.nguyen, NB-DC01, SHA-256…" value={input} onChange={(e) => setInput(e.target.value)} />
          <button className="btn btn-primary"><Search /> Search</button>
        </form>
      </Card>
      {result.isLoading && <Loading />}
      {result.error && <ErrorState error={result.error} />}
      {r && (
        <div className="grid grid-main-side">
          <Card title={<span className="row"><span className="mono">{r.value}</span><span className="badge">{r.detected_type}</span></span>} sub={r.verdict}>
            {r.matches.length === 0 ? <p className="muted">No indicator in this workspace's intelligence matches exactly. Local sightings are shown below.</p> : r.matches.map((i: Indicator) => (
              <div key={i.id} className="notice mb-8">
                <div className="row"><SeverityBadge severity={i.severity} /><SourceLabel i={i} /><span className="badge">confidence {i.confidence.toFixed(2)}</span></div>
                <p className="mt-8">{i.description}</p>
                <div className="small muted">Source: {i.source} · first seen {fmtTime(i.first_seen, false)} · last seen {fmtTime(i.last_seen, false)}</div>
              </div>))}
            <h3 className="mt-16 mb-8">Sightings in telemetry</h3>
            <p className="small">{r.sightings.event_count} event(s){r.sightings.first_observed && ` between ${fmtTime(r.sightings.first_observed, false)} and ${fmtTime(r.sightings.last_observed, false)} UTC`}. <Link to={`/events?q=${encodeURIComponent(r.value)}`}>Open in Event Explorer</Link></p>
            <div className="row mb-8"><InvestigateButton small context={r.detected_type === "ip" && r.sightings.event_count ? [`IP:${r.value}`] : []} q={`Where has ${r.value} appeared in our environment, which entities touched it, and is it malicious?`} /></div>
            <div className="table-wrap"><table className="table responsive"><thead><tr><th>Time (UTC)</th><th>Type</th><th>User / Host</th><th>Src → Dst</th></tr></thead>
              <tbody>{r.sightings.events.map((e: EventBrief) => (<tr key={e.id}><td data-label="Time" className="small nowrap mono">{fmtTime(e.timestamp)}</td><td data-label="Type">{e.event_type} <span className="muted small">{e.action}</span></td>
                <td data-label="User / Host" className="small">{e.user} {e.host}</td><td data-label="Src → Dst" className="mono small">{e.source_ip ?? "—"} → {e.destination_ip ?? "—"}</td></tr>))}</tbody></table></div>
          </Card>
          <Card title="Related incidents">
            {r.sightings.incidents.length === 0 ? <p className="muted">None.</p> : r.sightings.incidents.map((i: IncidentBrief) => (
              <div key={i.id} className="mb-8"><Link to={`/incidents/${i.number}`}><strong>{i.number}</strong> {i.title}</Link> <SeverityBadge severity={i.severity} /></div>))}
            {r.partial_matches.length > 0 && (<><h3 className="mt-16 mb-8">Partial matches</h3>{r.partial_matches.map((i: Indicator) => <div key={i.id} className="small mono">{i.value} <SourceLabel i={i} /></div>)}</>)}
          </Card>
        </div>
      )}
      <div className="grid grid-main-side">
        <Card title="Indicators" sub={`${list.data?.total ?? 0} in this workspace`} flush>
          {list.data?.items.length === 0 ? <Empty title="No indicators">Add indicators manually or import a CSV/JSON list.</Empty> : (
            <div className="table-wrap"><table className="table responsive"><thead><tr><th>Indicator</th><th>Type</th><th>Severity</th><th className="num">Conf.</th><th>Source</th></tr></thead>
              <tbody>{list.data?.items.map((i) => (<tr key={i.id} style={{ opacity: i.active ? 1 : 0.5 }}>
                <td data-label="Indicator" className="mono wrap-anywhere"><Link to={`/threat-intel?q=${encodeURIComponent(i.value)}`}>{i.value}</Link></td><td data-label="Type">{i.indicator_type}</td>
                <td data-label="Severity"><SeverityBadge severity={i.severity} /></td><td data-label="Confidence" className="num">{i.confidence.toFixed(2)}</td>
                <td data-label="Source" className="small"><SourceLabel i={i} /> {i.source}</td></tr>))}</tbody></table></div>)}
        </Card>
        <div className="stack">
          <Card title="Intelligence sources">
            {providers.data?.map((p) => (<div key={p.name} className="mb-8"><div className="row between"><strong className="small">{p.name}</strong><HealthBadge status={p.status} /></div>
              <div className="small muted">{p.indicators} indicators · {p.label}. {p.detail}</div></div>))}
          </Card>
          {isAnalyst && (
            <Card title="Add indicator" sub="Adding an indicator re-hunts all stored telemetry">
              <form className="stack" onSubmit={(e) => { e.preventDefault(); add.mutate(); }}>
                <div className="field"><label htmlFor="iv">Value</label><input id="iv" className="input" required value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} /></div>
                <div className="row">
                  <div className="field" style={{ flex: 1 }}><label htmlFor="isv">Severity</label><select id="isv" className="select" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>{["low", "medium", "high", "critical"].map((s) => <option key={s}>{s}</option>)}</select></div>
                  <div className="field" style={{ flex: 1 }}><label htmlFor="icf">Confidence</label><input id="icf" className="input" type="number" min={0} max={1} step={0.05} value={form.confidence} onChange={(e) => setForm({ ...form, confidence: e.target.value })} /></div>
                </div>
                <div className="field"><label htmlFor="ids">Description</label><input id="ids" className="input" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></div>
                <button className="btn btn-primary" disabled={!form.value.trim() || add.isPending}>{add.isPending ? "Adding & re-hunting…" : "Add indicator"}</button>
              </form>
              <label className="btn mt-8" style={{ cursor: "pointer" }}><Upload /> Import CSV / JSON<input type="file" accept=".csv,.txt,.json" hidden onChange={(e) => importFile(e.target.files?.[0])} /></label>
            </Card>)}
        </div>
      </div>
    </div>
  );
}
