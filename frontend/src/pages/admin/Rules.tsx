import { useState } from "react";
import { Link } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useWsQuery } from "../../lib/hooks";
import { fmtTime } from "../../lib/format";
import { Card, Loading, Modal, SeverityBadge, useToast } from "../../components/ui";

interface Rule {
  id: number; rule_key: string; name: string; description: string; severity: string; enabled: boolean; parameters: Record<string, any>;
  default_parameters: Record<string, any>; mitre_techniques: string[]; stage: string; version: number; updated_at: string; detection_count: number; false_positives: string[];
}

function RuleEditor({ rule, onClose }: { rule: Rule; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [params, setParams] = useState<Record<string, string>>(() => Object.fromEntries(Object.entries(rule.parameters).map(([k, v]) => [k, Array.isArray(v) ? v.join("\n") : String(v)])));
  const [severity, setSeverity] = useState(rule.severity);
  const save = async () => {
    const body: Record<string, any> = {};
    for (const [k, v] of Object.entries(params)) {
      const def = rule.default_parameters[k];
      body[k] = Array.isArray(def) ? v.split("\n").map((x) => x.trim()).filter(Boolean) : Number(v);
    }
    try {
      await api(`/api/rules/${rule.id}`, { method: "PATCH", body: { parameters: body, severity } });
      qc.invalidateQueries({ queryKey: ["ws"] });
      toast(`${rule.rule_key} updated. Re-run analysis (Settings) to apply to stored data.`);
      onClose();
    } catch (e) { toast((e as Error).message, "error"); }
  };
  const reset = async () => {
    await api(`/api/rules/${rule.id}/reset`, { method: "POST" });
    qc.invalidateQueries({ queryKey: ["ws"] });
    toast("Parameters reset to defaults");
    onClose();
  };
  return (
    <Modal title={`${rule.rule_key} · ${rule.name}`} onClose={onClose}>
      <p className="small text-2">{rule.description}</p>
      <div className="stack">
        <div className="field"><label htmlFor="rsev">Default severity</label><select id="rsev" className="select" value={severity} onChange={(e) => setSeverity(e.target.value)}>{["low", "medium", "high", "critical"].map((s) => <option key={s}>{s}</option>)}</select>
          <span className="hint">Individual detections may escalate based on evidence (e.g. external source, volume).</span></div>
        {Object.entries(params).map(([k, v]) => {
          const isList = Array.isArray(rule.default_parameters[k]);
          return (
            <div className="field" key={k}><label htmlFor={`p-${k}`}>{k.replace(/_/g, " ")}</label>
              {isList ? <textarea id={`p-${k}`} className="input mono" rows={4} value={v} onChange={(e) => setParams({ ...params, [k]: e.target.value })} />
                : <input id={`p-${k}`} className="input" type="number" min={0} value={v} onChange={(e) => setParams({ ...params, [k]: e.target.value })} />}
              <span className="hint">Default: {Array.isArray(rule.default_parameters[k]) ? `${rule.default_parameters[k].length} entries (one per line)` : String(rule.default_parameters[k])}</span></div>
          );
        })}
        <div className="row"><button className="btn btn-primary" onClick={save}>Save changes</button><button className="btn" onClick={reset}>Reset to defaults</button></div>
      </div>
    </Modal>
  );
}

export function AdminRulesPage() {
  const qc = useQueryClient();
  const toast = useToast();
  const rules = useWsQuery<Rule[]>(["rules"], "/api/rules");
  const [editing, setEditing] = useState<Rule | null>(null);
  const toggle = async (r: Rule) => {
    try { await api(`/api/rules/${r.id}`, { method: "PATCH", body: { enabled: !r.enabled } }); qc.invalidateQueries({ queryKey: ["ws"] }); toast(`${r.rule_key} ${r.enabled ? "disabled" : "enabled"}`); }
    catch (e) { toast((e as Error).message, "error"); }
  };
  return (
    <div className="stack">
      <div className="page-head"><div><h1>Detection rules</h1><p>Tune thresholds per workspace. Every change is versioned and written to the audit log.</p></div></div>
      <Card flush>
        {rules.isLoading ? <Loading /> : (
          <div className="table-wrap"><table className="table responsive"><thead><tr><th>Rule</th><th>Stage</th><th>Severity</th><th>ATT&CK</th><th className="num">Detections</th><th>Version</th><th>Enabled</th><th /></tr></thead>
            <tbody>{rules.data?.map((r) => (<tr key={r.id}>
              <td data-label="Rule"><span className="badge">{r.rule_key}</span> <strong>{r.name}</strong><div className="small muted">{r.description}</div></td>
              <td data-label="Stage" className="small">{r.stage}</td><td data-label="Severity"><SeverityBadge severity={r.severity} /></td>
              <td data-label="ATT&CK" className="small mono">{r.mitre_techniques.join(", ") || "—"}</td>
              <td data-label="Detections" className="num"><Link to={`/detections?rule_key=${r.rule_key}`}>{r.detection_count}</Link></td>
              <td data-label="Version" className="small">v{r.version}<div className="muted">{fmtTime(r.updated_at, false)}</div></td>
              <td data-label="Enabled"><label className="row small"><input type="checkbox" checked={r.enabled} onChange={() => toggle(r)} aria-label={`Enable ${r.rule_key}`} />{r.enabled ? "On" : "Off"}</label></td>
              <td data-label=""><button className="btn btn-sm" onClick={() => setEditing(r)}>Tune</button></td>
            </tr>))}</tbody></table></div>)}
      </Card>
      {editing && <RuleEditor rule={editing} onClose={() => setEditing(null)} />}
    </div>
  );
}
