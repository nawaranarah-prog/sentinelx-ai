import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { Check, Circle, Loader2, Minus, X } from "lucide-react";
import { api } from "../lib/api";
import { useWsQuery } from "../lib/hooks";
import { useSession } from "../lib/session";
import type { AIMessage } from "../lib/types";
import { Artifact } from "../components/Artifacts";
import { AssistantMessage } from "../components/Copilot";
import { Card, ErrorState, KV, Loading } from "../components/ui";
import { ParamForm, changedOnly, type Scenario } from "./SimulationLab";

type Status = "pending" | "running" | "done" | "skipped" | "failed";
type Step = { id: string; title: string; status: Status; body?: ReactNode };

const STEPS: [string, string][] = [
  ["simulate", "Simulate the attack and ingest its telemetry through the pipeline"],
  ["incident", "Detections, anomalies and correlation into an incident"],
  ["dna", "Attack DNA and similar past incidents"],
  ["graph", "Knowledge-graph relationships for the incident"],
  ["copilot", "Copilot investigation of the incident"],
  ["hypothesis", "Record evidence and a hypothesis"],
  ["gap", "Find the detection gap the variation exploits"],
  ["candidate", "Propose a candidate detection for the gap"],
  ["backtest", "Backtest the candidate on stored and benign telemetry"],
  ["replay", "Replay the attack with the candidate enabled"],
  ["measure", "Measure: regression tests and before/after coverage"],
  ["report", "Generate the technical report"],
];

const ICON: Record<Status, ReactNode> = {
  pending: <Circle size={14} aria-label="pending" />, running: <Loader2 size={14} className="spin" aria-label="running" />,
  done: <Check size={14} aria-label="done" />, skipped: <Minus size={14} aria-label="skipped" />, failed: <X size={14} aria-label="failed" />,
};

export function AttackInvestigationPage() {
  const qc = useQueryClient();
  const { isAnalyst, workspace } = useSession();
  const cat = useWsQuery<{ scenarios: Scenario[] }>(["sim-scenarios"], "/api/sim/scenarios", { staleTime: Infinity });
  const [scenario, setScenario] = useState("credential_compromise");
  const [values, setValues] = useState<Record<string, any>>({ attempt_interval_s: 400 });
  const [steps, setSteps] = useState<Step[]>(STEPS.map(([id, title]) => ({ id, title, status: "pending" })));
  const [running, setRunning] = useState(false);
  const sc = cat.data?.scenarios.find((s) => s.id === scenario);
  const variations = changedOnly(sc, values);
  const isDemo = workspace?.mode === "DEMO";

  const set = (id: string, status: Status, body?: ReactNode) =>
    setSteps((all) => all.map((s) => (s.id === id ? { ...s, status, body: body ?? s.body } : s)));

  const runAll = async () => {
    setRunning(true);
    setSteps(STEPS.map(([id, title]) => ({ id, title, status: "pending" })));
    let current = "simulate";
    const step = async <T,>(id: string, fn: () => Promise<T>): Promise<T> => { current = id; set(id, "running"); return fn(); };
    try {
      // 1. Simulation → telemetry → pipeline.
      const persisted = await step("simulate", () => api<any>("/api/sim/persist", { body: { scenario, variations } }));
      const inc = persisted.incidents.find((i: any) => i.new) ?? persisted.incidents[0];
      set("simulate", "done", <p className="small">{persisted.events} synthetic events ingested; pipeline created {persisted.pipeline?.detections_created ?? 0} detection(s)
        {inc ? <> and {inc.new ? "created" : "updated"} <Link to={`/incidents/${inc.number}`}>{inc.number}</Link> (risk {inc.risk_score}).</> : ", but no incident — the remaining steps need one."}</p>);
      if (!inc) { STEPS.slice(1).forEach(([id]) => set(id, "skipped")); return; }

      // 2. Incident: detections, anomalies, correlation.
      const detail = await step("incident", () => api<any>(`/api/incidents/${inc.number}`));
      set("incident", "done", <KV items={[["Detections", detail.detections.map((d: any) => d.rule_key).join(", ")], ["Stages", detail.stages.join(" → ")],
        ["Anomalous windows", `${detail.anomaly_summary?.anomalous_windows ?? 0} of ${detail.anomaly_summary?.windows_checked ?? 0}`], ["Correlation", detail.correlation_reason]]} />);

      // 3. Attack DNA.
      const sim = await step("dna", () => api<any>(`/api/incidents/${inc.number}/similar`));
      set("dna", "done", <Artifact a={{ type: "similar", incident: inc.number, dna: sim.dna, similar: sim.similar.slice(0, 4) }} />);

      // 4. Knowledge graph.
      const g = await step("graph", () => api<any>(`/api/incidents/${inc.number}/knowledge-graph`));
      set("graph", "done", <p className="small">{g.nodes.length} nodes and {g.edges.length} relationships link the incident to users, hosts, IPs, processes and techniques. <Link to={`/incidents/${inc.number}?tab=timemachine`}>Open the time machine</Link></p>);

      // 5. Copilot investigation.
      const chat = await step("copilot", () => api<{ message: AIMessage; conversation: { id: number } }>("/api/ai/chat", {
        body: { message: `Investigate ${inc.number}. What happened, what evidence supports it, and what don't we know?`, mode: "investigate", context: [`INC:${inc.number}`] } }));
      set("copilot", "done", <><AssistantMessage m={chat.message} /><Link className="small" to={`/assistant?conversation=${chat.conversation.id}`}>Continue this conversation</Link></>);

      // 6. Evidence + hypothesis in an investigation.
      const inv = await step("hypothesis", async () => {
        const created = await api<any>("/api/investigations", { body: { title: `Attack investigation: ${inc.number}`, incident: inc.number } });
        const dets = detail.detections as any[];
        await api(`/api/investigations/${created.number}/items`, { body: { kind: "fact", text: `${dets.length} detections correlated into ${inc.number}: ${dets.map((d) => d.rule_key).join(", ")}.`, supporting: dets.slice(0, 20).map((d) => `DET:${d.id}`) } });
        await api(`/api/investigations/${created.number}/items`, { body: { kind: "hypothesis", text: `${detail.users.join(", ") || "The account"} was compromised and used for: ${detail.stages.join(" → ")}.`, supporting: dets.slice(0, 20).map((d) => `DET:${d.id}`) } });
        return created;
      });
      set("hypothesis", "done", <p className="small">Recorded in <Link to={`/investigations/${inv.number}`}>{inv.number}</Link> with the detections as supporting evidence.</p>);

      // 7. Gap analysis.
      const sug = await step("gap", () => api<any>("/api/lab/suggest-candidate", { body: { scenario, variations } }));
      if (!sug.gap.gap_found) {
        set("gap", "done", <p className="small">No gap: these variations are detected by the same rules as the default scenario ({sug.gap.variation_rules.join(", ")}).</p>);
        ["candidate", "backtest", "replay", "measure"].forEach((id) => set(id, "skipped"));
      } else {
        await api(`/api/investigations/${inv.number}/items`, { body: { kind: "fact", text: `Gap analysis: with ${JSON.stringify(variations)} the rule(s) ${sug.gap.rules_evaded.join(", ")} no longer fire.` } });
        set("gap", "done", <div className="notice warn small">Evaded: <strong>{sug.gap.rules_evaded.join(", ")}</strong>{sug.gap.stages_lost.length ? ` — stages no longer detected: ${sug.gap.stages_lost.join(", ")}` : ""}.</div>);

        // 8. Candidate.
        if (!sug.suggested_spec) {
          set("candidate", "skipped", <p className="small">No template exists for this gap; write a candidate in the <Link to="/detection-lab?tab=candidates">Detection Lab</Link>.</p>);
          ["backtest", "replay", "measure"].forEach((id) => set(id, "skipped"));
        } else {
          const cand = await step("candidate", () => api<any>("/api/lab/candidates", { body: { spec: sug.suggested_spec } }));
          set("candidate", "done", <Artifact a={{ type: "candidate_rule", rule_key: cand.rule_key, spec: cand.spec }} />);
          // 9. Backtest.
          const bt = await step("backtest", () => api<any>(`/api/lab/rules/${cand.rule_key}/backtest`, { method: "POST" }));
          set("backtest", "done", <Artifact a={{ type: "backtest", ...bt }} />);
          // 10. Replay with the candidate.
          const replay = await step("replay", () => api<any>("/api/lab/sandbox", { body: { scenario, variations, candidate_rule: cand.rule_key } }));
          const caught = replay.baseline.rules_fired.includes(cand.rule_key);
          set("replay", caught ? "done" : "failed", <p className="small">{caught ? `${cand.rule_key} fires on the replayed attack.` : `${cand.rule_key} did not fire on the replayed attack — tune the threshold.`} Rules fired: {replay.baseline.rules_fired.join(", ")}.</p>);
          // 11. Measure.
          const reg = await step("measure", () => api<any>(`/api/lab/regression?candidate=${cand.rule_key}`, { method: "POST" }));
          set("measure", reg.passed ? "done" : "failed", <>
            <KV items={[["Rules firing on this variation before", sug.gap.variation_rules.join(", ")], ["…after adding the candidate", replay.baseline.rules_fired.join(", ")],
              ["Alerts on benign baseline", String(bt.benign_baseline_alerts)], ["Regression suite", reg.passed ? "all datasets pass" : "failures — see Detection Lab"]]} />
            <p className="small muted">The candidate stays disabled until an administrator activates it in the Detection Lab.</p></>);
        }
      }
      // 12. Report.
      const rep = await step("report", () => api<any>("/api/reports", { body: { incident_id: inc.id, report_type: "technical", include_ai_summary: true } }));
      set("report", "done", <p className="small"><Link to={`/reports/${rep.id}`}>{rep.title}</Link>{rep.ai_mode === "LIVE" ? " (includes a model-written narrative)" : " (built from stored evidence; no model narrative)"}.</p>);
    } catch (e) {
      set(current, "failed", <ErrorState error={e} />);
    } finally {
      setRunning(false);
      qc.invalidateQueries({ queryKey: ["ws"] });
    }
  };

  if (cat.isLoading) return <Loading />;
  return (
    <div className="stack">
      <div className="page-head"><div><h1>Investigate an attack</h1><p>End-to-end: simulate an attack variation, let the pipeline detect and correlate it, investigate the incident, find the detection gap, build and test a candidate rule, and report. Every step calls the same APIs as the rest of the product.</p></div></div>
      <div className="grid grid-main-side">
        <Card title="Attack">
          <label className="field"><span>Scenario</span>
            <select className="select" value={scenario} disabled={running} onChange={(e) => { setScenario(e.target.value); setValues({}); }}>
              {cat.data?.scenarios.filter((s) => Object.keys(s.parameters).length).map((s) => <option key={s.id} value={s.id}>{s.id.replace(/_/g, " ")}</option>)}
            </select></label>
          <p className="small muted">{sc?.description}</p>
          <ParamForm scenario={sc} values={values} onChange={setValues} />
          <p className="small mt-8">Variations from the default: <span className="mono">{JSON.stringify(variations)}</span></p>
          <div className="row mt-8">
            <button className="btn btn-primary" disabled={running || !isAnalyst || !isDemo} onClick={runAll}>{running ? "Running…" : "Run the workflow"}</button>
            {!isDemo && <span className="small muted">Requires the demo workspace (the simulation adds synthetic telemetry).</span>}
            {!isAnalyst && <span className="small muted">Requires the SOC Analyst or Admin role.</span>}
          </div>
        </Card>
        <Card title="Steps">
          <ol className="steps-mini">{steps.map((s) => <li key={s.id} className={`st-${s.status}`}>{ICON[s.status]} {s.title}</li>)}</ol>
        </Card>
      </div>
      {steps.filter((s) => s.status !== "pending").map((s, i) => (
        <Card key={s.id} title={<span className="row">{ICON[s.status]} {i + 1}. {s.title}</span>}>{s.status === "running" ? <Loading label="Working…" /> : s.body ?? <p className="muted small">Skipped.</p>}</Card>))}
    </div>
  );
}
