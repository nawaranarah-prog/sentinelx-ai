import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowDown, ArrowUp, Save, Trash2 } from "lucide-react";
import { api, qs } from "../lib/api";
import { useDebounced, useWsQuery } from "../lib/hooks";
import { fmtBytes, fmtNum, fmtTime } from "../lib/format";
import type { EventBrief, Paged } from "../lib/types";
import { Card, Empty, ErrorState, Loading, Pagination, SeverityBadge, useToast } from "../components/ui";
import { EventPanel } from "../components/EventPanel";

const KEYS = ["q", "start", "end", "severity", "event_type", "user", "host", "ip", "source", "status", "incident_id", "detection_id"] as const;
type Filters = Record<(typeof KEYS)[number], string> & { sort: string; order: string; page: number };

function fromParams(p: URLSearchParams): Filters {
  const f: any = { sort: p.get("sort") ?? "timestamp", order: p.get("order") ?? "desc", page: Number(p.get("page") ?? 1) };
  KEYS.forEach((k) => (f[k] = p.get(k) ?? ""));
  return f;
}

export function EventsPage() {
  const [params, setParams] = useSearchParams();
  const [f, setF] = useState<Filters>(() => fromParams(params));
  const [eventId, setEventId] = useState<number | null>(params.get("event") ? Number(params.get("event")) : null);
  const [saveName, setSaveName] = useState("");
  const toast = useToast();
  const qc = useQueryClient();
  const text = useDebounced(f.q);
  const hostD = useDebounced(f.host);
  const userD = useDebounced(f.user);
  const ipD = useDebounced(f.ip);
  const query = { ...f, q: text, host: hostD, user: userD, ip: ipD };
  const path = `/api/events${qs({ ...query, page_size: 50 })}`;
  const data = useWsQuery<Paged<EventBrief>>(["events", path], path, { placeholderData: (prev) => prev });
  const facets = useWsQuery<{ event_types: string[]; sources: string[]; time_range: { min: string; max: string } }>(["event-facets"], "/api/events/facets");
  const saved = useWsQuery<{ id: number; name: string; query: Record<string, string> }[]>(["saved-searches"], "/api/saved-searches");

  useEffect(() => {
    const next = new URLSearchParams();
    Object.entries(query).forEach(([k, v]) => v && !(k === "page" && v === 1) && !(k === "sort" && v === "timestamp") && !(k === "order" && v === "desc") && next.set(k, String(v)));
    if (eventId) next.set("event", String(eventId));
    setParams(next, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, eventId]);

  const set = (k: keyof Filters, v: string | number) => setF((prev) => ({ ...prev, [k]: v, page: k === "page" ? Number(v) : 1 }));
  const sortBy = (col: string) => setF((p) => ({ ...p, sort: col, order: p.sort === col && p.order === "desc" ? "asc" : "desc", page: 1 }));
  const saveSearch = useMutation({
    mutationFn: () => api("/api/saved-searches", { body: { name: saveName, query: Object.fromEntries(Object.entries(query).filter(([k, v]) => v && k !== "page")) } }),
    onSuccess: () => { setSaveName(""); qc.invalidateQueries({ queryKey: ["ws"] }); toast("Search saved"); },
  });
  const delSearch = useMutation({ mutationFn: (sid: number) => api(`/api/saved-searches/${sid}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["ws"] }) });
  const Sort = ({ col, label }: { col: string; label: string }) => (
    <button onClick={() => sortBy(col)} aria-label={`Sort by ${label}`}>{label}{f.sort === col && (f.order === "desc" ? <ArrowDown size={12} /> : <ArrowUp size={12} />)}</button>
  );
  const active = KEYS.filter((k) => f[k]);

  return (
    <div className="stack">
      <div className="page-head"><div><h1>Event Explorer</h1><p>Server-side filtered, sorted and paginated search over normalized events{facets.data?.time_range.min && ` (${fmtTime(facets.data.time_range.min, false)} – ${fmtTime(facets.data.time_range.max, false)} UTC)`}.</p></div></div>
      <Card flush>
        <div className="filters" role="search">
          <div className="field" style={{ maxWidth: 320, flexBasis: 260 }}><label htmlFor="eq">Search</label><input id="eq" className="input" placeholder="Event ID, command, file, IP…" value={f.q} onChange={(e) => set("q", e.target.value)} /></div>
          <div className="field"><label htmlFor="estart">From (UTC)</label><input id="estart" className="input" type="datetime-local" value={f.start} onChange={(e) => set("start", e.target.value)} /></div>
          <div className="field"><label htmlFor="eend">To (UTC)</label><input id="eend" className="input" type="datetime-local" value={f.end} onChange={(e) => set("end", e.target.value)} /></div>
          <div className="field"><label htmlFor="esev">Severity</label><select id="esev" className="select" value={f.severity} onChange={(e) => set("severity", e.target.value)}>
            <option value="">All</option>{["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}</select></div>
          <div className="field"><label htmlFor="etype">Event type</label><select id="etype" className="select" value={f.event_type} onChange={(e) => set("event_type", e.target.value)}>
            <option value="">All</option>{facets.data?.event_types.map((t) => <option key={t}>{t}</option>)}</select></div>
          <div className="field"><label htmlFor="euser">User</label><input id="euser" className="input" value={f.user} onChange={(e) => set("user", e.target.value)} /></div>
          <div className="field"><label htmlFor="ehost">Host</label><input id="ehost" className="input" value={f.host} onChange={(e) => set("host", e.target.value)} /></div>
          <div className="field"><label htmlFor="eip">IP (src or dst)</label><input id="eip" className="input" value={f.ip} onChange={(e) => set("ip", e.target.value)} /></div>
          <div className="field"><label htmlFor="esrc">Log source</label><select id="esrc" className="select" value={f.source} onChange={(e) => set("source", e.target.value)}>
            <option value="">All</option>{facets.data?.sources.map((t) => <option key={t}>{t}</option>)}</select></div>
          <div className="field"><label htmlFor="estatus">Status</label><select id="estatus" className="select" value={f.status} onChange={(e) => set("status", e.target.value)}>
            <option value="">All</option><option value="success">success</option><option value="failure">failure</option></select></div>
        </div>
        <div className="filters" style={{ alignItems: "center" }}>
          <span className="small muted">{data.data ? `${fmtNum(data.data.total)} matching events` : ""}</span>
          {(f.incident_id || f.detection_id) && <span className="chip">{f.incident_id ? `Incident #${f.incident_id}` : `Detection #${f.detection_id}`}</span>}
          {active.length > 0 && <button className="btn btn-sm" onClick={() => setF({ ...fromParams(new URLSearchParams()) })}>Clear filters</button>}
          <span style={{ flex: 1 }} />
          <form className="row" onSubmit={(e) => { e.preventDefault(); if (saveName.trim()) saveSearch.mutate(); }}>
            <label htmlFor="sname" className="sr-only">Saved search name</label>
            <input id="sname" className="input" placeholder="Save search as…" value={saveName} onChange={(e) => setSaveName(e.target.value)} style={{ width: 170 }} />
            <button className="btn btn-sm" disabled={!saveName.trim()}><Save /> Save</button>
          </form>
          {saved.data && saved.data.length > 0 && (
            <select className="select" aria-label="Saved searches" value="" onChange={(e) => { const s = saved.data!.find((x) => x.id === Number(e.target.value)); if (s) setF({ ...fromParams(new URLSearchParams(s.query as Record<string, string>)) }); }}>
              <option value="">Saved searches…</option>{saved.data.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>)}
        </div>
        {saved.data && saved.data.length > 0 && (
          <div className="filters" style={{ paddingTop: 6, paddingBottom: 6 }}>{saved.data.map((s) => (
            <span key={s.id} className="chip">{s.name}<button className="btn btn-ghost btn-sm" aria-label={`Delete saved search ${s.name}`} onClick={() => delSearch.mutate(s.id)} style={{ height: 18 }}><Trash2 size={11} /></button></span>))}</div>
        )}
        {data.isLoading ? <Loading /> : data.error ? <div className="card-body"><ErrorState error={data.error} /></div> :
          data.data!.items.length === 0 ? <Empty title="No events match">Try widening the time range or clearing filters.</Empty> : (
            <>
              <div className="table-wrap"><table className="table responsive">
                <thead><tr><th><Sort col="timestamp" label="Time (UTC)" /></th><th><Sort col="severity" label="Sev" /></th><th><Sort col="event_type" label="Type" /></th>
                  <th><Sort col="user" label="User" /></th><th><Sort col="host" label="Host" /></th><th><Sort col="source_ip" label="Source → Dest" /></th><th>Detail</th><th>Event ID</th></tr></thead>
                <tbody>{data.data!.items.map((e) => (
                  <tr key={e.id} className="clickable" onClick={() => setEventId(e.id)} tabIndex={0} onKeyDown={(ev) => ev.key === "Enter" && setEventId(e.id)}>
                    <td data-label="Time" className="nowrap small mono">{fmtTime(e.timestamp)}</td>
                    <td data-label="Severity"><SeverityBadge severity={e.severity} /></td>
                    <td data-label="Type">{e.event_type}<div className="small muted">{e.action} {e.status}</div></td>
                    <td data-label="User">{e.user ?? "—"}</td><td data-label="Host">{e.host ?? "—"}</td>
                    <td data-label="Source → Dest" className="mono small nowrap">{e.source_ip ?? "—"} → {e.destination_ip ?? "—"}</td>
                    <td data-label="Detail" className="small truncate">{e.command ?? e.resource ?? e.process ?? ""}{e.bytes ? ` (${fmtBytes(e.bytes)})` : ""}</td>
                    <td data-label="Event ID" className="mono small">{e.event_uid}</td>
                  </tr>))}</tbody>
              </table></div>
              <Pagination page={f.page} pageSize={50} total={data.data!.total} onPage={(p) => set("page", p)} />
            </>)}
      </Card>
      {eventId !== null && <EventPanel eventId={eventId} onClose={() => setEventId(null)} />}
    </div>
  );
}
