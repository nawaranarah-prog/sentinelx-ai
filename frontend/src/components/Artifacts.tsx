import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import { fmtBytes, fmtTime } from "../lib/format";
import { useSession } from "../lib/session";
import type { EventBrief, HuntResult } from "../lib/types";
import { KV, SeverityBadge, useToast } from "./ui";

const pct = (v: number | null | undefined) => (v === null || v === undefined ? "n/a" : `${Math.round(v * 100)}%`);

export function EventRows({ events, max = 12 }: { events: EventBrief[]; max?: number }) {
  if (!events.length) return <p className="muted small">No events.</p>;
  return (
    <div className="table-wrap"><table className="table dense">
      <thead><tr><th>Time (UTC)</th><th>Event</th><th>Type</th><th>User</th><th>Host</th><th>Detail</th></tr></thead>
      <tbody>{events.slice(0, max).map((e) => (
        <tr key={e.event_uid}>
          <td className="mono small nowrap">{fmtTime(e.timestamp)}</td>
          <td className="mono small"><Link to={`/events/${encodeURIComponent(e.event_uid)}`}>{e.event_uid}</Link></td>
          <td className="small">{e.event_type} <span className="muted">{e.action} {e.status}</span></td>
          <td className="small">{e.user && <Link to={`/entities/user/${e.user}`}>{e.user}</Link>}</td>
          <td className="small">{e.host && <Link to={`/entities/host/${e.host}`}>{e.host}</Link>}</td>
          <td className="small truncate" style={{ maxWidth: 320 }}>{e.command ?? e.resource ?? [e.source_ip, e.destination_ip].filter(Boolean).join(" → ")}{e.bytes ? ` · ${fmtBytes(e.bytes)}` : ""}</td>
        </tr>))}</tbody>
    </table>{events.length > max && <p className="muted small">{events.length - max} more not shown.</p>}</div>
  );
}

export function HuntResultView({ r, huntNumber }: { r: HuntResult; huntNumber?: string | null }) {
  const { isAnalyst } = useSession();
  const toast = useToast();
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const createIncident = async () => {
    const title = window.prompt("Incident title", `Hunt finding: ${huntNumber}`);
    if (!title) return;
    setBusy(true);
    try {
      const inc = await api<{ number: string }>(`/api/hunts/${huntNumber}/incident`, { body: { title } });
      toast(`Created ${inc.number}`);
      navigate(`/incidents/${inc.number}`);
    } catch (e) { toast((e as Error).message, "error"); } finally { setBusy(false); }
  };
  return (
    <div className="stack-sm">
      <div className="artifact-head">
        <strong>Generated search</strong>{huntNumber && <Link className="chip mono" to={`/hunts/${huntNumber}`}>{huntNumber}</Link>}
        <span className="muted small">{r.total.toLocaleString()} match{r.total === 1 ? "" : "es"} · {r.scanned.toLocaleString()} events scanned{r.truncated_scan ? " (scan limit reached)" : ""}</span>
      </div>
      <table className="table dense spec"><tbody>{r.description.map((d, i) => <tr key={i}><th>{d.label}</th><td>{d.value}</td></tr>)}</tbody></table>
      {r.groups.length > 0 && (
        <div className="row small"><span className="muted">By {String(r.spec.group_by)}:</span>
          {r.groups.slice(0, 10).map((g) => <span key={g.key} className="chip mono">{g.key} · {g.count}</span>)}</div>)}
      {r.sequences.length > 0 && <p className="small muted">{r.sequences.length} sequence(s) matched the "followed by" condition.</p>}
      <EventRows events={r.events} max={10} />
      {huntNumber && (
        <div className="row">
          <Link className="btn btn-sm" to={`/hunts/${huntNumber}`}>Open in Hunt Builder</Link>
          {isAnalyst && r.total > 0 && <button className="btn btn-sm" disabled={busy} onClick={createIncident}>Create incident from results</button>}
        </div>)}
    </div>
  );
}

function Chain({ path }: { path: { node: any; via: any }[] }) {
  return (
    <div className="chain">{path.map((p, i) => (
      <span key={i} className="row" style={{ gap: 4 }}>
        {p.via && <span className="rel">— {p.via.rel.replace(/_/g, " ")} ({p.via.count}) →</span>}
        <span className="chip mono" title={p.node.kind}>{p.node.kind}: {p.node.label}</span>
      </span>))}</div>
  );
}

function SandboxView({ a }: { a: any }) {
  const b = a.baseline;
  return (
    <div className="stack-sm">
      <div className="artifact-head"><strong>Simulation · {a.scenario}</strong><span className="badge">synthetic telemetry</span>{a.run_id && <span className="muted small">run #{a.run_id}</span>}</div>
      {Object.keys(a.variations ?? {}).length > 0 && <div className="small">Variations: <span className="mono">{JSON.stringify(a.variations)}</span></div>}
      <KV items={[["Rules fired", b.rules_fired.join(", ") || "none"], ["Stages detected", b.stages_detected.join(" → ") || "none"],
        ["Techniques", b.techniques.join(", ") || "none"], ["Estimated risk", `${b.estimated_risk}/100`],
        ["Data uploaded externally", fmtBytes(b.attack_bytes_uploaded)]]} />
      {a.with_controls && <div className="notice info small">{a.summary}</div>}
      {a.blocked_steps?.length > 0 && <ul className="small">{a.blocked_steps.slice(0, 8).map((s: any, i: number) => <li key={i}><span className="mono">{s.event_uid}</span> {s.event_type}: {s.detail} — blocked by {s.control}</li>)}</ul>}
    </div>
  );
}

export function Artifact({ a }: { a: Record<string, any> }) {
  switch (a.type) {
    case "hunt":
      return <HuntResultView r={a as HuntResult} huntNumber={a.hunt} />;
    case "paths":
      return (
        <div className="stack-sm">
          <div className="artifact-head"><strong>Graph paths</strong><span className="muted small">{a.source} → {a.target} · {a.found} found</span></div>
          {a.paths.length === 0 ? <p className="muted small">No path within {a.max_depth} hops.</p> : a.paths.map((p: any, i: number) => <Chain key={i} path={p} />)}
          <p className="muted small">{a.note}</p>
        </div>);
    case "similar":
      return (
        <div className="stack-sm">
          <div className="artifact-head"><strong>Similar incidents to {a.incident}</strong><span className="mono small">{a.dna?.signature}</span></div>
          {a.similar.length === 0 ? <p className="muted small">No other incidents to compare with.</p> : (
            <table className="table dense"><thead><tr><th>Incident</th><th className="num">Similarity</th><th>Techniques / sequence / rules / entities / traits</th><th>Shared techniques</th></tr></thead>
              <tbody>{a.similar.map((s: any) => (
                <tr key={s.number}><td><Link to={`/incidents/${s.number}`}>{s.number}</Link> <span className="small muted">{s.title}</span></td>
                  <td className="num">{pct(s.score)}</td>
                  <td className="small mono">{["techniques", "sequence", "rules", "entities", "traits"].map((k) => pct(s.components?.[k])).join(" / ")}</td>
                  <td className="small">{s.shared_techniques.join(", ") || "—"}</td></tr>))}</tbody></table>)}
        </div>);
    case "backtest":
      return (
        <div className="stack-sm">
          <div className="artifact-head"><strong>Backtest · {a.rule_key}</strong><span className="muted small">{a.events_scanned.toLocaleString()} stored events</span></div>
          <KV items={[["Alerts on stored telemetry", a.alerts], ["…inside existing incidents", a.alerts_overlapping_incidents],
            ["…outside incidents (review for false positives)", a.alerts_outside_incidents],
            ["Alerts on benign baseline", `${a.benign_baseline_alerts} (of ${a.benign_baseline_events} benign events)`],
            ["Scenario coverage", Object.entries(a.scenario_coverage).map(([k, v]) => `${k}: ${v}`).join(", ")]]} />
          <p className="muted small">{a.interpretation}</p>
        </div>);
    case "regression":
      return (
        <div className="stack-sm">
          <div className="artifact-head"><strong>Regression tests</strong><span className={`badge ${a.passed ? "st-ok" : "st-bad"}`}>{a.passed ? "all passed" : "failures"}</span></div>
          <table className="table dense"><thead><tr><th>Dataset</th><th>Result</th><th>Missing rules</th><th>Unexpected on benign</th></tr></thead>
            <tbody>{a.datasets.map((d: any) => <tr key={d.dataset}><td>{d.dataset}</td><td>{d.passed ? "pass" : "fail"}</td><td className="small">{d.missing.join(", ") || "—"}</td><td className="small">{d.unexpected_on_benign.join(", ") || "—"}</td></tr>)}</tbody></table>
        </div>);
    case "sandbox": case "simulation":
      return <SandboxView a={a} />;
    case "what_if":
      return (
        <div className="stack-sm">
          <div className="artifact-head"><strong>Defense what-if · {a.incident}</strong><span className="muted small">risk {a.original_risk} → {a.residual_risk_estimate} (modeled)</span></div>
          <table className="table dense"><thead><tr><th>Step</th><th>Outcome</th><th>Why</th></tr></thead>
            <tbody>{a.steps.map((s: any) => <tr key={s.detection_id}><td className="small">{s.title}</td><td><span className={`badge ${s.status === "unaffected" ? "" : "st-ok"}`}>{s.status}</span></td><td className="small">{s.reason}</td></tr>)}</tbody></table>
          <p className="muted small">{a.note}</p>
        </div>);
    case "counterfactual":
      return <div className="stack-sm"><div className="artifact-head"><strong>Counterfactual · {a.incident}</strong></div><p className="small">{a.explanation}</p></div>;
    case "rule_quality":
      return (
        <div className="stack-sm">
          <div className="artifact-head"><strong>Detection rule quality</strong><Link className="small" to="/detection-lab">Open Detection Lab</Link></div>
          <table className="table dense"><thead><tr><th>Rule</th><th className="num">Detections</th><th className="num">FP / dismissed</th><th>Weaknesses</th></tr></thead>
            <tbody>{a.rows.slice(0, 12).map((r: any) => <tr key={r.rule_key}><td className="small"><span className="mono">{r.rule_key}</span> {r.name}</td><td className="num">{r.detections}</td><td className="num">{r.false_positive_or_dismissed}</td><td className="small">{r.weaknesses.join("; ") || "—"}</td></tr>)}</tbody></table>
        </div>);
    case "candidate_rule":
      return (
        <div className="stack-sm">
          <div className="artifact-head"><strong>Candidate detection {a.rule_key}</strong><span className="badge">disabled until an admin activates it</span></div>
          <p className="small">{a.spec.name} — {a.spec.description}</p>
          <Link className="btn btn-sm" to={`/detection-lab?rule=${a.rule_key}`}>Review in Detection Lab</Link>
        </div>);
    case "incident_created":
      return <div className="row"><strong>Incident created:</strong><Link to={`/incidents/${a.number}`}>{a.number} · {a.title}</Link></div>;
    case "report":
      return <div className="row"><strong>Report:</strong><Link to={`/reports/${a.id}`}>{a.title}</Link></div>;
    case "graph":
      return <div className="row small"><strong>Knowledge graph · {a.incident}</strong><span className="muted">{a.nodes?.length ?? 0} nodes, {a.edges?.length ?? 0} relationships</span><Link to={`/incidents/${a.incident}?tab=graph`}>Open graph</Link></div>;
    default:
      return null;
  }
}

export function Artifacts({ items }: { items: Record<string, any>[] }) {
  const shown = items.filter((a) => a.type !== "source");
  const sources = items.filter((a) => a.type === "source");
  if (!shown.length && !sources.length) return null;
  return (
    <div className="stack-sm">
      {shown.map((a, i) => <div key={i} className="artifact"><Artifact a={a} /></div>)}
      {sources.length > 0 && <div className="small muted">Knowledge base: {[...new Set(sources.map((s) => `${s.document} — ${s.heading}`))].join("; ")}</div>}
    </div>
  );
}

export { SeverityBadge };
