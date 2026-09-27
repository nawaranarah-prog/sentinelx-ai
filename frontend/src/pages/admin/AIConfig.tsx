import { useState } from "react";
import { api } from "../../lib/api";
import { useWsQuery } from "../../lib/hooks";
import { fmtRelative } from "../../lib/format";
import { Card, HealthBadge, KV, Loading, useToast } from "../../components/ui";

export function AdminAIPage() {
  const toast = useToast();
  const status = useWsQuery<{ mode: string; label: string; status: string; provider: string | null; model: string | null; detail: string; checked_at?: number }>(["ai-status"], "/api/ai/status");
  const cfg = useWsQuery<Record<string, any>>(["system-config"], "/api/system/config");
  const [testing, setTesting] = useState(false);
  const test = async () => {
    setTesting(true);
    try { const r = await api<{ status: string; detail: string }>("/api/ai/test", { method: "POST" }); status.refetch(); toast(`Provider check: ${r.status} — ${r.detail}`, r.status === "CONNECTED" ? "info" : "error"); }
    catch (e) { toast((e as Error).message, "error"); } finally { setTesting(false); }
  };
  if (status.isLoading || cfg.isLoading) return <Loading />;
  const s = status.data!;
  const c = cfg.data!;
  return (
    <div className="stack">
      <div className="page-head"><div><h1>AI configuration</h1><p>The provider is configured through environment variables so credentials never pass through the UI or database.</p></div>
        <div className="page-actions"><button className="btn btn-primary" onClick={test} disabled={testing || s.status === "NOT CONFIGURED"}>{testing ? "Testing…" : "Test provider connection"}</button></div></div>
      <div className="grid grid-2">
        <Card title="Active mode" actions={<HealthBadge status={s.status} />}>
          <p><span className={`badge ${s.mode === "LIVE" ? "st-ok" : "st-warn"}`}>{s.label}</span></p>
          <p className="text-2">{s.detail}</p>
          <KV items={[["LLM_PROVIDER", c.llm_provider], ["LLM_MODEL", c.llm_model ?? "—"], ["LLM_API_KEY", c.llm_api_key], ["Timeout", `${c.llm_timeout_seconds} s`],
            ["Max tool rounds", String(c.llm_max_tool_rounds)], ["Context limits", `${c.ai_context_max_events} events · ${c.ai_context_max_chars.toLocaleString()} chars`],
            ["Last provider check", s.checked_at ? fmtRelative(new Date(s.checked_at * 1000).toISOString()) : "never"]]} />
        </Card>
        <Card title="How to enable LIVE AI">
          <ol className="small">
            <li>Set <code>LLM_PROVIDER=anthropic</code> (official Anthropic SDK) or <code>openai</code> (OpenAI-compatible endpoint; optional <code>LLM_BASE_URL</code>).</li>
            <li>Set <code>LLM_API_KEY</code> in the backend environment (never commit it).</li>
            <li>Optionally set <code>LLM_MODEL</code> (defaults: <code>claude-opus-5</code> / <code>gpt-4o-mini</code>).</li>
            <li>Restart the backend and press "Test provider connection".</li>
          </ol>
          <h3 className="mt-16 mb-8">Safety controls (always on)</h3>
          <ul className="small">
            <li>System instructions, trusted app context, untrusted data and the analyst question are separated with delimiters; untrusted text is escaped.</li>
            <li>Prompt-injection phrases in logs are detected and reported as findings, never followed.</li>
            <li>Only read-only, workspace-scoped tools; no shell, file, network or write tools exist.</li>
            <li>Output is validated: event IDs, detection IDs and ATT&CK techniques not present in retrieved context are removed and reported.</li>
            <li>If the live model fails or times out, the answer falls back to LOCAL analysis and says so.</li>
          </ul>
        </Card>
      </div>
    </div>
  );
}
