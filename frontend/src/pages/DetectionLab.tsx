import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useWsQuery } from "../lib/hooks";
import { fmtRelative } from "../lib/format";
import { useSession } from "../lib/session";
import { Artifact } from "../components/Artifacts";
import { Card, Empty, ErrorState, Loading, Tabs, useToast } from "../components/ui";

const TEMPLATE = {
  name: "Many failed logins for one account",
  description: "Password guessing against a single account over a longer window than SX-001.",
  severity: "high", stage: "Credential Access", mitre: ["T1110.001"],
  match: { event_types: ["authentication"], status: "failure" },
  threshold: { count: 20, window_minutes: 120, group_by: "user" },
};

type Candidate = { rule_key: string; name: string; kind: string; enabled: boolean; severity: string; spec: any; last_backtest: any; updated_at: string };

function Candidates() {
  const [params, setParams] = useSearchParams();
  const selected = params.get("rule");
  const qc = useQueryClient();
  const toast = useToast();
  const { isAnalyst, isAdmin } = useSession();
  const list = useWsQuery<Candidate[]>(["lab-candidates"], "/api/lab/candidates");
  const [spec, setSpec] = useState(JSON.stringify(TEMPLATE, null, 2));
  const [result, setResult] = useState<Record<string, any> | null>(null);
  const [busy, setBusy] = useState("");
  const refresh = () => qc.invalidateQueries({ queryKey: ["ws"] });
  const act = async (label: string, fn: () => Promise<any>) => {
    setBusy(label);
    try { await fn(); refresh(); } catch (e) { toast((e as Error).message, "error"); } finally { setBusy(""); }
  };
  const create = () => act("create", async () => {
    let parsed;
    try { parsed = JSON.parse(spec); } catch { throw new Error("The rule specification is not valid JSON."); }
    const r = await api<{ rule_key: string }>("/api/lab/candidates", { body: { spec: parsed } });
    toast(`Candidate ${r.rule_key} created (disabled).`);
    setParams({ tab: "candidates", rule: r.rule_key });
  });
  const backtest = (key: string) => act(`bt-${key}`, async () => setResult({ type: "backtest", ...(await api(`/api/lab/rules/${key}/backtest`, { method: "POST" })) }));
  const regress = (key: string) => act(`rg-${key}`, async () => setResult({ type: "regression", ...(await api(`/api/lab/regression?candidate=${key}`, { method: "POST" })) }));
  const activate = (key: string) => act(`ac-${key}`, async () => {
    if (!window.confirm(`Activate ${key}? It will run on all stored telemetry and future uploads.`)) return;
    const r = await api<{ detections_created: number }>(`/api/lab/rules/${key}/activate`, { method: "POST" });
    toast(`${key} activated; ${r.detections_created} new detection(s).`);
  });
  const discard = (key: string) => act(`dc-${key}`, async () => {
    if (!window.confirm(`Discard candidate ${key}?`)) return;
    await api(`/api/lab/rules/${key}`, { method: "DELETE" });
    setParams({ tab: "candidates" });
  });
  return (
    <div className="stack">
      <Card title="Candidate and custom detections" flush>
        {list.isLoading ? <Loading /> : list.data?.length === 0 ? <Empty title="No candidates">Create one below, from a hunt, or ask the copilot to propose one.</Empty> : (
          <div className="table-wrap"><table className="table dense">
            <thead><tr><th>Rule</th><th>Status</th><th>Last backtest</th><th>Updated</th><th /></tr></thead>
            <tbody>{list.data?.map((r) => (
              <tr key={r.rule_key} className={r.rule_key === selected ? "selected" : ""}>
                <td><span className="mono">{r.rule_key}</span> {r.name}<div className="small muted">{r.spec?.description}</div></td>
                <td>{r.kind === "candidate" ? <span className="badge">candidate · disabled</span> : <span className="badge st-ok">active</span>}</td>
                <td className="small">{r.last_backtest ? `${r.last_backtest.alerts} alerts · ${r.last_backtest.benign_baseline_alerts} on benign` : "not run"}</td>
                <td className="small">{fmtRelative(r.updated_at)}</td>
                <td className="nowrap">
                  {isAnalyst && <button className="btn btn-sm" disabled={!!busy} onClick={() => backtest(r.rule_key)}>{busy === `bt-${r.rule_key}` ? "Running…" : "Backtest"}</button>}
                  <button className="btn btn-sm" disabled={!!busy} onClick={() => regress(r.rule_key)}>Regression</button>
                  {isAdmin && r.kind === "candidate" && <button className="btn btn-sm" disabled={!!busy || !r.last_backtest} title={r.last_backtest ? "" : "Backtest first"} onClick={() => activate(r.rule_key)}>Activate</button>}
                  {isAdmin && r.kind === "candidate" && <button className="btn btn-sm btn-ghost" disabled={!!busy} onClick={() => discard(r.rule_key)}>Discard</button>}
                </td>
              </tr>))}</tbody>
          </table></div>)}
      </Card>
      {result && <Card title="Result" actions={<button className="btn btn-sm btn-ghost" onClick={() => setResult(null)}>Close</button>}><Artifact a={result} /></Card>}
      {isAnalyst && (
        <Card title="New candidate" sub="match: event_types, status, actions, text_any, text_all, users, hosts, behaviors (off_hours | external_destination | large_transfer); threshold: count, window_minutes, group_by (user | host | source_ip | destination_ip), distinct">
          <label htmlFor="rule-spec" className="sr-only">Rule specification</label>
          <textarea id="rule-spec" className="input mono" rows={14} value={spec} onChange={(e) => setSpec(e.target.value)} spellCheck={false} />
          <div className="row mt-8"><button className="btn btn-primary" disabled={!!busy} onClick={create}>Create candidate</button><span className="muted small">Candidates never alert until an administrator activates them after a backtest.</span></div>
        </Card>)}
    </div>
  );
}

function Quality() {
  const q = useWsQuery<any[]>(["lab-quality"], "/api/lab/quality");
  if (q.isLoading) return <Loading label="Running regression and evasion tests…" />;
  if (q.error) return <ErrorState error={q.error} />;
  return (
    <Card title="Rule quality" sub="Detections produced, analyst verdicts, regression failures on the scenario datasets, and evasion-test results" flush>
      <div className="table-wrap"><table className="table dense">
        <thead><tr><th>Rule</th><th>Enabled</th><th className="num">Detections</th><th className="num">FP / dismissed</th><th className="num">Evasion tests</th><th>Weaknesses</th></tr></thead>
        <tbody>{q.data!.map((r) => (
          <tr key={r.rule_key}><td><span className="mono">{r.rule_key}</span> {r.name}</td><td>{r.enabled ? "yes" : "no"}</td><td className="num">{r.detections}</td>
            <td className="num">{r.false_positive_or_dismissed}</td><td className="num">{r.evasion_tests - r.evaded.length}/{r.evasion_tests} detected</td>
            <td className="small">{r.weaknesses.join("; ") || "—"}</td></tr>))}</tbody>
      </table></div>
    </Card>
  );
}

function Regression() {
  const [res, setRes] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const run = async () => { setBusy(true); try { setRes({ type: "regression", ...(await api("/api/lab/regression", { method: "POST" })) }); } catch (e) { toast((e as Error).message, "error"); } finally { setBusy(false); } };
  return (
    <Card title="Regression tests" sub="Runs all enabled rules against every scenario dataset and the benign baseline" actions={<button className="btn btn-primary btn-sm" disabled={busy} onClick={run}>{busy ? "Running…" : "Run"}</button>}>
      {res ? <Artifact a={res} /> : <p className="muted small">Not run yet in this session.</p>}
    </Card>
  );
}

function Evasion() {
  const q = useWsQuery<any[]>(["lab-evasion"], "/api/lab/evasion");
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} />;
  return (
    <Card title="Attack variation tests" sub="Each test replays a scenario with an evasive variation and checks whether the targeted rule still fires" flush>
      <div className="table-wrap"><table className="table dense">
        <thead><tr><th>Rule</th><th>Variation</th><th>Parameters</th><th>Targeted rule</th><th>Other rules that fired</th></tr></thead>
        <tbody>{q.data!.map((t, i) => (
          <tr key={i}><td className="mono">{t.rule}</td><td>{t.test}</td><td className="mono small">{JSON.stringify(t.variations)}</td>
            <td>{t.detected ? <span className="badge st-ok">detected</span> : <span className="badge st-bad">evaded</span>}</td>
            <td className="small">{t.other_rules_fired.join(", ") || "none"}</td></tr>))}</tbody>
      </table></div>
    </Card>
  );
}

export function DetectionLabPage() {
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") ?? (params.get("rule") ? "candidates" : "quality");
  return (
    <div className="stack">
      <div className="page-head"><div><h1>Detection Lab</h1><p>Measure rule quality, build candidate detections, backtest them on stored telemetry and the benign baseline, and run regression and evasion tests before activation.</p></div></div>
      <Tabs label="Detection lab sections" active={tab} onChange={(t) => setParams({ tab: t })}
        tabs={[{ id: "quality", label: "Rule quality" }, { id: "candidates", label: "Candidates" }, { id: "regression", label: "Regression" }, { id: "evasion", label: "Variation tests" }]} />
      <div role="tabpanel">
        {tab === "quality" && <Quality />}
        {tab === "candidates" && <Candidates />}
        {tab === "regression" && <Regression />}
        {tab === "evasion" && <Evasion />}
      </div>
    </div>
  );
}
