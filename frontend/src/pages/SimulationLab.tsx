import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useWsQuery } from "../lib/hooks";
import { fmtRelative } from "../lib/format";
import { useSession } from "../lib/session";
import { Artifact } from "../components/Artifacts";
import { Card, ErrorState, Loading, useToast } from "../components/ui";

type Param = { type: "int" | "float" | "str" | "bool"; default: any; min?: number; max?: number; label: string };
export type Scenario = { id: string; description: string; parameters: Record<string, Param> };
export type Control = { id: string; label: string; blocks: string; gate: boolean };

export function ParamForm({ scenario, values, onChange }: { scenario?: Scenario; values: Record<string, any>; onChange: (v: Record<string, any>) => void }) {
  if (!scenario) return null;
  const entries = Object.entries(scenario.parameters);
  if (!entries.length) return <p className="muted small">This scenario has no adjustable parameters.</p>;
  return (
    <div className="form-grid">
      {entries.map(([k, p]) => (
        <label key={k} className="field">
          <span>{p.label}</span>
          {p.type === "bool" ? (
            <input type="checkbox" checked={values[k] ?? p.default} onChange={(e) => onChange({ ...values, [k]: e.target.checked })} />
          ) : (
            <input className="input" type={p.type === "str" ? "text" : "number"} step={p.type === "float" ? "any" : 1} min={p.min} max={p.max} value={values[k] ?? p.default}
              onChange={(e) => onChange({ ...values, [k]: p.type === "str" ? e.target.value : Number(e.target.value) })} />
          )}
        </label>))}
    </div>
  );
}

export function changedOnly(scenario: Scenario | undefined, values: Record<string, any>) {
  if (!scenario) return {};
  return Object.fromEntries(Object.entries(values).filter(([k, v]) => scenario.parameters[k] && v !== scenario.parameters[k].default));
}

export function SimulationLabPage() {
  const qc = useQueryClient();
  const toast = useToast();
  const { isAnalyst, workspace } = useSession();
  const cat = useWsQuery<{ scenarios: Scenario[]; controls: Control[] }>(["sim-scenarios"], "/api/sim/scenarios", { staleTime: Infinity });
  const runs = useWsQuery<any[]>(["sim-runs"], "/api/sim/runs");
  const [scenario, setScenario] = useState("credential_compromise");
  const [values, setValues] = useState<Record<string, any>>({});
  const [controls, setControls] = useState<string[]>([]);
  const [result, setResult] = useState<Record<string, any> | null>(null);
  const [gap, setGap] = useState<any>(null);
  const [busy, setBusy] = useState("");
  useEffect(() => { setValues({}); setResult(null); setGap(null); }, [scenario]);
  const sc = cat.data?.scenarios.find((s) => s.id === scenario);
  const variations = changedOnly(sc, values);

  const run = async (label: string, fn: () => Promise<void>) => {
    setBusy(label);
    try { await fn(); qc.invalidateQueries({ queryKey: ["ws"] }); } catch (e) { toast((e as Error).message, "error"); } finally { setBusy(""); }
  };
  const sandbox = () => run("sandbox", async () => setResult({ type: "sandbox", ...(await api("/api/lab/sandbox", { body: { scenario, variations, controls } })) }));
  const gapCheck = () => run("gap", async () => setGap(await api("/api/sim/gap", { body: { scenario, variations } })));
  const persist = () => run("persist", async () => {
    if (!window.confirm("Inject this simulated attack into the demo workspace? It runs through the real pipeline and may create incidents.")) return;
    const r = await api<any>("/api/sim/persist", { body: { scenario, variations } });
    setResult({ type: "persisted", ...r });
    toast(`${r.events} simulated events ingested.`);
  });

  if (cat.isLoading) return <Loading />;
  if (cat.error) return <ErrorState error={cat.error} />;
  return (
    <div className="stack">
      <div className="page-head"><div><h1>Simulation Lab</h1><p>Replay attack scenarios on synthetic telemetry against this workspace's current rules. Vary the attacker's behavior, model defensive controls, and find detection gaps. Sandbox runs never touch stored data.</p></div></div>
      <div className="grid grid-main-side">
        <Card title="Scenario">
          <label className="field"><span>Attack scenario</span>
            <select className="select" value={scenario} onChange={(e) => setScenario(e.target.value)}>
              {cat.data!.scenarios.map((s) => <option key={s.id} value={s.id}>{s.id.replace(/_/g, " ")}</option>)}
            </select></label>
          <p className="small muted">{sc?.description}</p>
          <h3 className="small muted mt-16">ATTACKER VARIATIONS</h3>
          <ParamForm scenario={sc} values={values} onChange={setValues} />
          <h3 className="small muted mt-16">DEFENSIVE CONTROLS (MODELED)</h3>
          <div className="stack-sm">{cat.data!.controls.map((c) => (
            <label key={c.id} className="row small"><input type="checkbox" checked={controls.includes(c.id)} onChange={(e) => setControls(e.target.checked ? [...controls, c.id] : controls.filter((x) => x !== c.id))} />
              <span><strong>{c.label}</strong> — blocks {c.blocks}{c.gate ? " (stops the rest of the chain)" : ""}</span></label>))}</div>
          <div className="row mt-16">
            <button className="btn btn-primary" disabled={!!busy} onClick={sandbox}>{busy === "sandbox" ? "Running…" : "Run in sandbox"}</button>
            <button className="btn" disabled={!!busy || !Object.keys(variations).length} title="Compare the default scenario with your variations" onClick={gapCheck}>{busy === "gap" ? "Comparing…" : "Find detection gaps"}</button>
            {isAnalyst && workspace?.mode === "DEMO" && <button className="btn" disabled={!!busy} onClick={persist}>{busy === "persist" ? "Ingesting…" : "Inject into demo data"}</button>}
          </div>
        </Card>
        <Card title="Recent runs" flush>
          {runs.data?.length === 0 ? <p className="muted small pad">No runs yet.</p> : (
            <ul className="list">{runs.data?.map((r) => (
              <li key={r.id}><div><span className="small">{r.scenario.replace(/_/g, " ")}</span> <span className="badge">{r.kind}</span></div>
                <div className="small muted">{fmtRelative(r.created_at)} · rules {(r.rules_fired ?? []).join(", ") || "—"}{r.incidents?.length ? ` · ${r.incidents.join(", ")}` : ""}</div></li>))}</ul>)}
        </Card>
      </div>
      {gap && (
        <Card title="Detection gap analysis" sub={`Default scenario vs. your variations ${JSON.stringify(gap.variations)}`}>
          {gap.gap_found ? (<>
            <div className="notice warn small">With these variations the following rules no longer fire: <strong>{gap.rules_evaded.join(", ")}</strong>{gap.stages_lost.length ? `; stages lost: ${gap.stages_lost.join(", ")}` : ""}.</div>
            <p className="small mt-8">Build a candidate detection for the gap in the <Link to="/investigate-attack">attack investigation workflow</Link> or the <Link to="/detection-lab?tab=candidates">Detection Lab</Link>.</p>
          </>) : <p className="small">No gap: the same rules fire ({gap.variation_rules.join(", ") || "none"}).</p>}
        </Card>)}
      {result && result.type !== "persisted" && <Card title="Sandbox result"><Artifact a={result} /></Card>}
      {result?.type === "persisted" && (
        <Card title="Injected into demo data">
          <p className="small">{result.events} events ingested through the pipeline ({result.pipeline?.detections_created ?? 0} new detections).</p>
          {result.incidents.length ? <ul>{result.incidents.map((i: any) => <li key={i.id}><Link to={`/incidents/${i.number}`}>{i.number}</Link> {i.title} {i.new ? <span className="badge">new</span> : <span className="badge">updated</span>} risk {i.risk_score}</li>)}</ul>
            : <p className="muted small">No incident was created or updated — the rules did not correlate this activity.</p>}
        </Card>)}
    </div>
  );
}
