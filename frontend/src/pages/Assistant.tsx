import { Fragment, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import { api } from "../lib/api";
import { useWsQuery } from "../lib/hooks";
import { fmtRelative } from "../lib/format";
import { linkFor } from "../lib/refs";
import type { AIMessage, Conversation, CopilotMode } from "../lib/types";
import { Copilot, ScorecardView } from "../components/Copilot";
import { useToast } from "../components/ui";

const FOCUS_KIND: Record<string, string> = { incident: "INC", event: "EVT", entity: "", detection: "DET", investigation: "INV", hunt: "HUNT", technique: "TECH" };

type FocusValue = string | { kind: string; name: string };

function focusText(value: FocusValue): string {
  return typeof value === "string" ? value : `${value.kind}:${value.name}`;
}

function focusLink(kind: string, value: FocusValue): string {
  if (typeof value !== "string") return linkFor(value.kind.toUpperCase(), value.name);
  return linkFor(FOCUS_KIND[kind] ?? "", value);
}

export function AssistantPage() {
  const qc = useQueryClient();
  const toast = useToast();
  const [params, setParams] = useSearchParams();
  const [conv, setConv] = useState<number | null>(params.get("conversation") ? Number(params.get("conversation")) : null);
  const [key, setKey] = useState(0);
  const [active, setActive] = useState<Conversation | null>(null);
  const [last, setLast] = useState<AIMessage | null>(null);
  const status = useWsQuery<{ mode: string; status: string; label: string; detail: string; model: string | null; provider: string | null }>(["ai-status"], "/api/ai/status", { staleTime: 60_000 });
  const convs = useWsQuery<Conversation[]>(["conversations"], "/api/ai/conversations", { refetchInterval: 30_000 });
  const startNew = () => { setConv(null); setActive(null); setLast(null); setParams({}); setKey((k) => k + 1); };
  const open = (c: Conversation) => { setConv(c.id); setActive(c); setLast(null); setParams({ conversation: String(c.id) }); setKey((k) => k + 1); };
  const remove = async (id: number) => {
    try {
      await api(`/api/ai/conversations/${id}`, { method: "DELETE" });
      if (conv === id) startNew();
      qc.invalidateQueries({ queryKey: ["ws"] });
    } catch (e) { toast((e as Error).message, "error"); }
  };
  const focus = active?.focus ?? {};
  const live = status.data?.mode === "LIVE";

  return (
    <div className="console">
      <aside className="console-side hide-sm" aria-label="Conversations">
        <div className="row between console-side-head"><strong>Conversations</strong><button className="btn btn-sm" onClick={startNew}><Plus /> New</button></div>
        <ul className="conv-list">
          {convs.data?.length === 0 && <li className="muted small pad">No conversations yet.</li>}
          {convs.data?.map((c) => (
            <li key={c.id} className={conv === c.id ? "active" : ""}>
              <button className="conv-open" onClick={() => open(c)}>
                <span className="small">{c.title}</span>
                <span className="small muted">{c.mode} · {fmtRelative(c.updated_at)}</span>
              </button>
              <button className="btn btn-ghost btn-sm" aria-label={`Delete conversation ${c.title}`} onClick={() => remove(c.id)}><Trash2 /></button>
            </li>))}
        </ul>
      </aside>
      <div className="console-main">
        <div className="console-head">
          <h1>Copilot</h1>
          {status.data && (live
            ? <span className="badge st-ok" title={status.data.detail}>Model: {status.data.model} · {status.data.provider}</span>
            : <span className="badge" title={status.data.detail}>No language model connected — rule-based analysis</span>)}
          <button className="btn btn-sm show-sm" onClick={startNew}><Plus /> New</button>
        </div>
        <Copilot key={key} conversationId={conv}
          context={conv ? [] : params.getAll("context")} mode={(params.get("mode") as CopilotMode) || "ask"}
          question={conv ? undefined : params.get("q") ?? undefined} investigation={params.get("investigation") ?? undefined}
          onConversation={(c) => { setActive(c); convs.refetch(); }}
          onMessage={setLast} />
      </div>
      <aside className="console-context hide-sm" aria-label="Investigation context">
        <h2 className="small muted">FOCUS</h2>
        {Object.keys(focus).length === 0 ? <p className="muted small">Objects you mention (INC-…, users, hosts, IPs, event IDs, DET-…, techniques) become the focus for follow-up questions like "who is affected in it?".</p> : (
          <dl className="kv small">{Object.entries(focus).map(([k, v]) => <Fragment key={k}><dt>{k}</dt><dd><Link to={focusLink(k, v as FocusValue)} className="mono">{focusText(v as FocusValue)}</Link></dd></Fragment>)}</dl>)}
        {active?.recent_refs?.length ? (<>
          <h2 className="small muted mt-16">RECENTLY DISCUSSED</h2>
          <div className="row">{active.recent_refs.slice(0, 10).map((r) => { const [k, ...rest] = r.split(":"); return <Link key={r} className="chip mono" to={linkFor(k, rest.join(":"))}>{r}</Link>; })}</div>
        </>) : null}
        {last?.structured?.scorecard && <div className="mt-16"><ScorecardView s={last.structured.scorecard} /></div>}
        {!live && status.data && (
          <div className="notice small mt-16">
            <strong>{status.data.label}.</strong> {status.data.detail}
          </div>)}
      </aside>
    </div>
  );
}
