import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { useWsQuery } from "../lib/hooks";
import { fmtTime } from "../lib/format";
import type { EventBrief, IncidentFull } from "../lib/types";
import { Artifact } from "./Artifacts";
import { AttackGraph, type GraphEdge, type GraphNode } from "./AttackGraph";
import { Card, Empty, ErrorState, KV, Loading, useToast } from "./ui";

export function DnaTab({ inc }: { inc: IncidentFull }) {
  const q = useWsQuery<any>(["incident-similar", inc.id], `/api/incidents/${inc.number}/similar`);
  const fam = useWsQuery<any>(["families"], "/api/analytics/families");
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} />;
  const dna = q.data.dna ?? {};
  const family = fam.data?.families.find((f: any) => f.incidents.some((m: any) => m.number === inc.number));
  return (
    <div className="stack">
      <div className="grid grid-main-side">
        <Card title="Attack DNA" sub="A fingerprint of the attack computed from its detections, techniques and stage order">
          {!dna.signature ? <p className="muted small">Not computed for this incident.</p> : (
            <KV items={[["Signature", <span key="s" className="mono">{dna.signature}</span>], ["Stage sequence", (dna.stages ?? []).join(" → ")],
              ["Techniques", (dna.techniques ?? []).join(", ")], ["Rules", (dna.rules ?? []).join(", ")], ["Tactics", (dna.tactics ?? []).join(", ")],
              ...Object.entries(dna.traits ?? {}).map(([k, v]) => [k.replace(/_/g, " "), String(v)] as [string, string])]} />)}
        </Card>
        <Card title="Attack family" sub={`Incidents with similarity ≥ ${Math.round((fam.data?.threshold ?? 0.55) * 100)}%`}>
          {fam.isLoading ? <Loading /> : !family || family.size < 2 ? <p className="small">No other incident is similar enough to form a family.</p> : (<>
            <p className="small"><span className="mono">{family.family}</span> — {family.size} incidents: {family.incidents.map((m: any) => <Link key={m.number} className="chip mono" to={`/incidents/${m.number}`}>{m.number}</Link>)}</p>
            <p className="small">Shared techniques: {family.shared_techniques.join(", ") || "none"}</p>
            {family.evolution?.length > 0 && <ul className="small">{family.evolution.map((e: any, i: number) => (
              <li key={i}>{e.from} → {e.to}: {e.added_techniques.length ? `added ${e.added_techniques.join(", ")}` : "no new techniques"}{e.removed_techniques.length ? `; dropped ${e.removed_techniques.join(", ")}` : ""}</li>))}</ul>}
          </>)}
        </Card>
      </div>
      <Card title="Most similar incidents" sub={`Weights: ${Object.entries(q.data.weights).map(([k, v]) => `${k} ${Math.round((v as number) * 100)}%`).join(", ")}`}>
        <Artifact a={{ type: "similar", incident: inc.number, dna, similar: q.data.similar }} />
      </Card>
    </div>
  );
}

export function TimeMachineTab({ inc }: { inc: IncidentFull }) {
  const graph = useWsQuery<{ nodes: GraphNode[]; edges: GraphEdge[]; note?: string }>(["incident-graph", String(inc.id)], `/api/incidents/${inc.id}/graph`);
  const tl = useWsQuery<{ items: EventBrief[] }>(["incident-timeline-tm", inc.id], `/api/incidents/${inc.id}/timeline?page_size=500`);
  const times = useMemo(() => [...new Set((tl.data?.items ?? []).map((e) => e.timestamp))].sort(), [tl.data]);
  const [idx, setIdx] = useState<number | null>(null);
  if (graph.isLoading || tl.isLoading) return <Loading />;
  if (graph.error) return <ErrorState error={graph.error} />;
  if (!times.length) return <Empty title="No evidence events" />;
  const i = idx ?? times.length - 1;
  const t = times[i];
  const nodes = graph.data!.nodes, edges = graph.data!.edges;
  const visibleDet = new Set(nodes.filter((n) => n.type === "detection" && n.timestamp && n.timestamp <= t).map((n) => n.id));
  const detIds = new Set(nodes.filter((n) => n.type === "detection").map((n) => n.id));
  const touching = new Set(edges.filter((e) => visibleDet.has(e.source) || visibleDet.has(e.target)).flatMap((e) => [e.source, e.target]));
  const keep = new Set(nodes.filter((n) => (detIds.has(n.id) ? visibleDet.has(n.id) : touching.has(n.id))).map((n) => n.id));
  const vNodes = nodes.filter((n) => keep.has(n.id));
  const vEdges = edges.filter((e) => keep.has(e.source) && keep.has(e.target));
  const seen = (tl.data!.items).filter((e) => e.timestamp <= t);
  return (
    <div className="stack">
      <Card title="Attack time machine" sub="Replays the incident: detections, entities and relationships appear as the evidence timeline reaches them">
        <label htmlFor="tm" className="small">State at <strong className="mono">{fmtTime(t)}</strong> UTC — {seen.length} of {tl.data!.items.length} evidence events, {visibleDet.size} of {detIds.size} detections</label>
        <input id="tm" type="range" min={0} max={times.length - 1} value={i} onChange={(e) => setIdx(Number(e.target.value))} style={{ width: "100%" }} />
        <div className="row small muted between"><span>{fmtTime(times[0])}</span><span>{fmtTime(times[times.length - 1])}</span></div>
      </Card>
      {vNodes.length ? <Card title="Graph at this moment"><AttackGraph nodes={vNodes} edges={vEdges} /></Card> : <Card><p className="muted small">No detection has fired yet at this point in the timeline.</p></Card>}
      <Card title="Latest events at this moment" flush>
        <div className="table-wrap"><table className="table dense"><thead><tr><th>Time (UTC)</th><th>Event</th><th>Type</th><th>Detail</th></tr></thead>
          <tbody>{seen.slice(-12).reverse().map((e) => (
            <tr key={e.id}><td className="mono small nowrap">{fmtTime(e.timestamp)}</td><td className="mono small"><Link to={`/events/${encodeURIComponent(e.event_uid)}`}>{e.event_uid}</Link></td>
              <td className="small">{e.event_type} {e.action}</td><td className="small truncate">{e.command ?? e.resource ?? `${e.user ?? ""} ${e.source_ip ?? ""} → ${e.destination_ip ?? ""}`}</td></tr>))}</tbody></table></div>
      </Card>
    </div>
  );
}

export function WhatIfTab({ inc }: { inc: IncidentFull }) {
  const toast = useToast();
  const cat = useWsQuery<{ controls: { id: string; label: string; blocks: string; gate: boolean }[] }>(["sim-scenarios"], "/api/sim/scenarios", { staleTime: Infinity });
  const [controls, setControls] = useState<string[]>([]);
  const [removed, setRemoved] = useState<number[]>([]);
  const [wi, setWi] = useState<any>(null);
  const [cf, setCf] = useState<any>(null);
  const runWi = async () => { try { setWi(await api(`/api/incidents/${inc.number}/what-if`, { body: { controls } })); } catch (e) { toast((e as Error).message, "error"); } };
  const runCf = async () => { try { setCf(await api(`/api/incidents/${inc.number}/counterfactual`, { body: { remove_detection_ids: removed } })); } catch (e) { toast((e as Error).message, "error"); } };
  return (
    <div className="grid grid-2">
      <Card title="Defense what-if" sub="Which steps of this incident would each control have blocked? (modeled, not a guarantee)">
        <div className="stack-sm">{cat.data?.controls.map((c) => (
          <label key={c.id} className="row small"><input type="checkbox" checked={controls.includes(c.id)} onChange={(e) => setControls(e.target.checked ? [...controls, c.id] : controls.filter((x) => x !== c.id))} />
            <span><strong>{c.label}</strong> — {c.blocks}</span></label>))}</div>
        <button className="btn btn-primary mt-8" disabled={!controls.length} onClick={runWi}>Evaluate</button>
        {wi && <div className="mt-16"><Artifact a={{ type: "what_if", ...wi }} /></div>}
      </Card>
      <Card title="Counterfactual" sub="Remove evidence and recompute correlation and risk">
        <div className="stack-sm">{inc.detections.map((d) => (
          <label key={d.id} className="row small"><input type="checkbox" checked={removed.includes(d.id)} onChange={(e) => setRemoved(e.target.checked ? [...removed, d.id] : removed.filter((x) => x !== d.id))} />
            <span><span className="mono">{d.rule_key}</span> {d.title}</span></label>))}</div>
        <button className="btn btn-primary mt-8" disabled={!removed.length} onClick={runCf}>Recompute</button>
        {cf && (
          <div className="mt-16 stack-sm">
            <p className="small">{cf.explanation}</p>
            {cf.recomputed_risk !== undefined && <KV items={[["Risk", `${cf.original_risk} → ${cf.recomputed_risk} (${cf.recomputed_band})`], ["Stages", (cf.stages ?? []).join(" → ") || "—"],
              ["Correlation groups", (cf.correlation_groups ?? []).map((g: string[]) => g.join("+")).join(" | ")]]} />}
          </div>)}
      </Card>
    </div>
  );
}
