import { useState } from "react";
import { api } from "../../lib/api";
import { useWsQuery } from "../../lib/hooks";
import { fmtRelative } from "../../lib/format";
import { Card, HealthBadge, KV, Loading, useToast } from "../../components/ui";

type Status = { mode: string; label: string; status: string; provider: string | null; model: string | null; detail: string; checked_at?: number };
type AIErr = { reference: string; provider: string; model: string; category: string; detail: string; at: string };

export function AdminAIPage() {
  const toast = useToast();
  const status = useWsQuery<Status>(["ai-status"], "/api/ai/status");
  const cfg = useWsQuery<Record<string, any>>(["system-config"], "/api/system/config");
  const errors = useWsQuery<AIErr[]>(["ai-errors"], "/api/ai/errors");
  const tools = useWsQuery<{ name: string; description: string }[]>(["ai-tools"], "/api/ai/tools");
  const [testing, setTesting] = useState(false);
  const test = async () => {
    setTesting(true);
    try { const r = await api<{ status: string; detail: string }>("/api/ai/test", { method: "POST" }); status.refetch(); errors.refetch(); toast(`Provider check: ${r.status} — ${r.detail}`, r.status === "CONNECTED" ? "info" : "error"); }
    catch (e) { toast((e as Error).message, "error"); } finally { setTesting(false); }
  };
  if (status.isLoading || cfg.isLoading) return <Loading />;
  const s = status.data!;
  const c = cfg.data!;
  return (
    <div className="stack">
      <div className="page-head"><div><h1>Model provider</h1><p>The language model is configured through server environment variables; keys never reach the browser or the database.</p></div>
        <div className="page-actions"><button className="btn btn-primary" onClick={test} disabled={testing || s.status === "NOT CONFIGURED"}>{testing ? "Testing…" : "Test connection"}</button></div></div>
      <div className="grid grid-2">
        <Card title="Current provider" actions={<HealthBadge status={s.status} />}>
          <p className="text-2">{s.detail}</p>
          <KV items={[["LLM_PROVIDER", c.llm_provider], ["Resolved provider", c.llm_resolved_provider ?? "none"], ["Model", c.llm_model ?? "—"], ["LLM_API_KEY", c.llm_api_key],
            ["Timeout", `${c.llm_timeout_seconds} s`], ["Max tool rounds per answer", String(c.llm_max_tool_rounds)],
            ["Last check", s.checked_at ? fmtRelative(new Date(s.checked_at * 1000).toISOString()) : "never"]]} />
        </Card>
        <Card title="Configuration">
          <ol className="small">
            <li><strong>Vercel AI Gateway</strong> (auto-detected on Vercel through the project's OIDC token, or set <code>AI_GATEWAY_API_KEY</code>). Default model <code>anthropic/claude-opus-5</code>. The team must have AI Gateway billing enabled.</li>
            <li><strong>Anthropic</strong>: <code>LLM_PROVIDER=anthropic</code> and <code>LLM_API_KEY</code>. Default model <code>claude-opus-5</code>.</li>
            <li><strong>OpenAI-compatible</strong>: <code>LLM_PROVIDER=openai</code>, <code>LLM_API_KEY</code>, optional <code>LLM_BASE_URL</code> and <code>LLM_MODEL</code>.</li>
          </ol>
          <h3 className="mt-16 mb-8">Always on</h3>
          <ul className="small">
            <li>The model only reaches data through workspace-scoped tools; each tool checks the caller's role. Tools that create records need the analyst role, audit-log search needs admin.</li>
            <li>Tool results are wrapped as untrusted data; injection phrases found in logs are reported as findings.</li>
            <li>Every citation in an answer is checked against the database; unverifiable references are removed and counted.</li>
            <li>When no model is connected or a call fails, answers come from the rule-based planner using the same tools and are labeled that way. Failures get an investigation ID listed below.</li>
          </ul>
        </Card>
      </div>
      <Card title="Recent model errors" sub="Raw provider details are visible only here" flush>
        {errors.data?.length === 0 ? <p className="muted small pad">None.</p> : (
          <div className="table-wrap"><table className="table dense"><thead><tr><th>Investigation ID</th><th>When</th><th>Provider / model</th><th>Category</th><th>Detail</th></tr></thead>
            <tbody>{errors.data?.map((e) => <tr key={e.reference}><td className="mono small">{e.reference}</td><td className="small">{fmtRelative(e.at)}</td><td className="small">{e.provider} / {e.model}</td><td>{e.category}</td><td className="small wrap-anywhere">{e.detail}</td></tr>)}</tbody></table></div>)}
      </Card>
      <Card title={`Tools available to the copilot (${tools.data?.length ?? 0})`} flush>
        <div className="table-wrap"><table className="table dense"><tbody>{tools.data?.map((t) => <tr key={t.name}><td className="mono small nowrap">{t.name}</td><td className="small">{t.description}</td></tr>)}</tbody></table></div>
      </Card>
    </div>
  );
}
