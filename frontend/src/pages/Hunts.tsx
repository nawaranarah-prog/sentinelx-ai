import { useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { Play, Wand2 } from "lucide-react";
import { api } from "../lib/api";
import { useWsQuery } from "../lib/hooks";
import { fmtRelative } from "../lib/format";
import { useSession } from "../lib/session";
import type { HuntResult } from "../lib/types";
import { HuntResultView } from "../components/Artifacts";
import { copilotUrl } from "../components/InvestigateButton";
import { Card, Empty, ErrorState, Loading, useToast } from "../components/ui";

type Hunt = { number: string; name: string; natural_language: string; spec: Record<string, any>; translation: string; last_run_at: string | null; last_result_count: number; description: { label: string; value: string }[] };

const EXAMPLES = [
  "Find unusual authentication from new locations involving privileged accounts",
  "Find privileged accounts logging in outside normal hours",
  "Find rare outbound connections from servers",
  "Find PowerShell activity followed by internal connections",
  "Find large uploads to external destinations",
  "Find failed logins in the last 48 hours",
];

function CandidateForm({ hunt, onDone }: { hunt: string; onDone: () => void }) {
  const toast = useToast();
  const navigate = useNavigate();
  const [f, setF] = useState({ name: "", severity: "medium", count: 5, window_minutes: 60, group_by: "host" });
  const save = async () => {
    try {
      const r = await api<{ rule_key: string }>(`/api/hunts/${hunt}/candidate-rule`, { body: f });
      toast(`Candidate ${r.rule_key} created (disabled). Backtest it before activation.`);
      onDone();
      navigate(`/detection-lab?rule=${r.rule_key}`);
    } catch (e) { toast((e as Error).message, "error"); }
  };
  return (
    <div className="form-grid">
      <label className="field"><span>Rule name</span><input className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="e.g. Off-hours privileged logins" /></label>
      <label className="field"><span>Severity</span><select className="select" value={f.severity} onChange={(e) => setF({ ...f, severity: e.target.value })}>{["low", "medium", "high", "critical"].map((s) => <option key={s}>{s}</option>)}</select></label>
      <label className="field"><span>Alert when count ≥</span><input className="input" type="number" min={1} value={f.count} onChange={(e) => setF({ ...f, count: Number(e.target.value) })} /></label>
      <label className="field"><span>Within minutes</span><input className="input" type="number" min={1} value={f.window_minutes} onChange={(e) => setF({ ...f, window_minutes: Number(e.target.value) })} /></label>
      <label className="field"><span>Per</span><select className="select" value={f.group_by} onChange={(e) => setF({ ...f, group_by: e.target.value })}>{["user", "host", "source_ip", "destination_ip"].map((s) => <option key={s}>{s}</option>)}</select></label>
      <div className="field"><span>&nbsp;</span><button className="btn btn-primary" disabled={f.name.length < 3} onClick={save}>Create candidate detection</button></div>
    </div>
  );
}

export function HuntsPage() {
  const { ref } = useParams();
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const { isAnalyst } = useSession();
  const list = useWsQuery<Hunt[]>(["hunts"], "/api/hunts");
  const saved = useWsQuery<Hunt & { result: HuntResult }>(["hunt", ref], ref ? `/api/hunts/${ref}` : null);
  const [params] = useSearchParams();
  const [text, setText] = useState(params.get("q") ?? "");
  const [specText, setSpecText] = useState("");
  const [description, setDescription] = useState<{ label: string; value: string }[]>([]);
  const [method, setMethod] = useState("");
  const [result, setResult] = useState<HuntResult | null>(null);
  const [number, setNumber] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [showRule, setShowRule] = useState(false);

  useEffect(() => {
    if (saved.data) {
      setText(saved.data.natural_language);
      setSpecText(JSON.stringify(saved.data.spec, null, 2));
      setDescription(saved.data.description);
      setMethod(saved.data.translation);
      setResult(saved.data.result);
      setNumber(saved.data.number);
    }
  }, [saved.data]);

  const translate = async () => {
    setBusy(true);
    try {
      const t = await api<{ spec: any; description: any[]; method: string }>("/api/hunts/translate", { body: { text } });
      setSpecText(JSON.stringify(t.spec, null, 2));
      setDescription(t.description);
      setMethod(t.method);
      setResult(null);
      setNumber(null);
    } catch (e) { toast((e as Error).message, "error"); } finally { setBusy(false); }
  };
  const run = async () => {
    let spec;
    try { spec = JSON.parse(specText); } catch { toast("The hunt specification is not valid JSON.", "error"); return; }
    setBusy(true);
    try {
      const r = await api<HuntResult>("/api/hunts/run", { body: { spec, natural_language: text, name: text.slice(0, 120) || "Manual hunt", translation: method || "manual", save: isAnalyst } });
      setResult(r);
      setDescription(r.description);
      setNumber(r.hunt ?? null);
      qc.invalidateQueries({ queryKey: ["ws"] });
      if (r.hunt) navigate(`/hunts/${r.hunt}`, { replace: !!ref });
    } catch (e) { toast((e as Error).message, "error"); } finally { setBusy(false); }
  };

  return (
    <div className="stack">
      <div className="page-head"><div><h1>Hunt Builder</h1><p>Describe a hunt in plain language, review and edit the generated search, then run it over stored telemetry. Saved hunts can become incidents or candidate detections.</p></div></div>
      <div className="split">
        <Card title="Saved hunts" flush className="split-side">
          {list.isLoading ? <Loading /> : list.data?.length === 0 ? <p className="muted small pad">No hunts yet.</p> : (
            <ul className="list">{list.data?.map((h) => (
              <li key={h.number} className={h.number === ref ? "active" : ""}><Link to={`/hunts/${h.number}`}><span className="mono small">{h.number}</span> {h.name}
                <div className="small muted">{h.last_result_count} matches · {h.last_run_at ? fmtRelative(h.last_run_at) : "never run"}</div></Link></li>))}</ul>)}
        </Card>
        <div className="stack split-main">
          {saved.error && <ErrorState error={saved.error} />}
          <Card title="1. Describe">
            <label htmlFor="hunt-nl" className="sr-only">Hunt description</label>
            <textarea id="hunt-nl" className="input" rows={2} value={text} onChange={(e) => setText(e.target.value)} placeholder="e.g. Find privileged accounts logging in outside normal hours" />
            <div className="row mt-8">
              <button className="btn" disabled={busy || text.trim().length < 3} onClick={translate}><Wand2 /> Generate search</button>
              <span className="muted small">Translation here is keyword-based and fully editable. In the copilot's Hunt mode a connected model can build the spec instead.</span>
            </div>
            <div className="row mt-8">{EXAMPLES.map((x) => <button key={x} className="chip" onClick={() => setText(x)}>{x}</button>)}</div>
          </Card>
          <Card title="2. Review the generated search" sub={method ? `Built by: ${method}` : "Write or generate a spec"}>
            <div className="grid grid-2">
              <div>
                {description.length > 0 ? <table className="table dense spec"><tbody>{description.map((d, i) => <tr key={i}><th>{d.label}</th><td>{d.value}</td></tr>)}</tbody></table>
                  : <p className="muted small">The plain-language summary of the spec appears here.</p>}
              </div>
              <div>
                <label htmlFor="hunt-spec" className="small muted">Specification (JSON, editable)</label>
                <textarea id="hunt-spec" className="input mono" rows={12} value={specText} onChange={(e) => setSpecText(e.target.value)} spellCheck={false} />
              </div>
            </div>
            <div className="row mt-8"><button className="btn btn-primary" disabled={busy || !specText.trim()} onClick={run}><Play /> Run hunt</button>
              {!isAnalyst && <span className="muted small">Viewer role: hunts run but are not saved.</span>}</div>
          </Card>
          {busy && <Loading label="Running…" />}
          {result && (
            <Card title="3. Results" actions={number && (<>
              <Link className="btn btn-sm" to={copilotUrl({ context: [`HUNT:${number}`], mode: "investigate", q: `Explain the results of ${number}. What stands out and what should I check next?` })}>Discuss in copilot</Link>
              {isAnalyst && <button className="btn btn-sm" onClick={() => setShowRule(!showRule)}>Create candidate detection</button>}</>)}>
              {showRule && number && <div className="mb-8"><CandidateForm hunt={number} onDone={() => setShowRule(false)} /></div>}
              {result.total === 0 ? <Empty title="No matches">The available telemetry contains no events matching this hunt.</Empty> : <HuntResultView r={result} huntNumber={number} />}
            </Card>)}
        </div>
      </div>
    </div>
  );
}
