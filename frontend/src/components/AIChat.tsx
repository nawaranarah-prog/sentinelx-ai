import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import Markdown from "react-markdown";
import { AlertTriangle, Bot, Send, ShieldAlert, User } from "lucide-react";
import { api } from "../lib/api";
import { useWsQuery } from "../lib/hooks";
import { useSession } from "../lib/session";
import type { AIMessage, AIStructured } from "../lib/types";
import { useToast } from "./ui";

function ModeBadge({ m }: { m: AIMessage }) {
  if (m.mode === "LIVE") return <span className="badge st-ok" title={`${m.provider} · ${m.model}`}><Bot size={12} /> LIVE AI · {m.model}</span>;
  return <span className="badge st-warn" title="Deterministic local analysis - no language model"><Bot size={12} /> DEMO AI / LOCAL ANALYSIS</span>;
}

function EventLink({ uid }: { uid: string }) {
  return <Link to={`/events?q=${encodeURIComponent(uid)}`} className="mono">{uid}</Link>;
}

function AssistantMessage({ m }: { m: AIMessage }) {
  const s = m.structured as AIStructured;
  const [showMeta, setShowMeta] = useState(false);
  if (!s || !("summary" in s)) return <div className="msg assistant"><div className="md"><Markdown skipHtml>{m.content}</Markdown></div></div>;
  const v = m.validation || {};
  const removed = [...(v.removed_event_ids ?? []), ...(v.removed_techniques ?? []), ...(v.unverified_references_in_text ?? [])];
  return (
    <div className="msg assistant" aria-label="Assistant answer">
      <div className="row between mb-8"><ModeBadge m={m} /><span className="muted small">{m.latency_ms} ms</span></div>
      {s.notices?.map((n, i) => <div key={i} className="notice warn small mb-8">{n}</div>)}
      {s.security_notes?.map((n, i) => <div key={i} className="notice warn small mb-8 row"><ShieldAlert size={14} aria-hidden="true" /><span style={{ flex: 1 }}>{n}</span></div>)}
      <h3 className="small muted">SUMMARY</h3>
      <div className="md"><Markdown skipHtml>{s.summary}</Markdown></div>
      {s.evidence?.length > 0 && (<>
        <h3 className="small muted mt-8">EVIDENCE</h3>
        <ul className="md">{s.evidence.map((e, i) => (
          <li key={i}>
            <span className="wrap-anywhere">{e.statement}</span>
            {(e.event_ids.length > 0 || e.detection_ids.length > 0) && (
              <span className="small"> — {e.event_ids.map((u, j) => <span key={u}>{j > 0 && ", "}<EventLink uid={u} /></span>)}
                {e.detection_ids.map((d) => <span key={d}> <Link to={`/detections/${d}`}>detection #{d}</Link></span>)}</span>
            )}
            {e.unverified && <span className="badge st-bad" style={{ marginLeft: 6 }}>unverified reference removed</span>}
          </li>))}
        </ul></>)}
      {s.inference?.length > 0 && (<><h3 className="small muted mt-8">INFERENCE</h3><ul className="md">{s.inference.map((x, i) => <li key={i}><Markdown skipHtml>{x}</Markdown></li>)}</ul></>)}
      {s.uncertainty?.length > 0 && (<><h3 className="small muted mt-8">UNCERTAINTY</h3><ul className="md">{s.uncertainty.map((x, i) => <li key={i}>{x}</li>)}</ul></>)}
      {s.next_steps?.length > 0 && (<><h3 className="small muted mt-8">RECOMMENDED NEXT STEPS</h3><ol className="md">{s.next_steps.map((x, i) => <li key={i}>{x}</li>)}</ol></>)}
      {s.techniques?.length > 0 && (<><h3 className="small muted mt-8">TECHNIQUES</h3>
        <div className="row">{s.techniques.map((t) => <Link key={t.id} to={`/mitre?technique=${t.id}`} className="chip" title={t.reason}>{t.id}</Link>)}</div></>)}
      <div className="row mt-8 small">
        <span className={`badge ${v.passed ? "st-ok" : "st-warn"}`}>{v.passed ? "Grounding check passed" : "Grounding check: references removed"}</span>
        {m.sources?.length > 0 && <span className="muted">Sources: {m.sources.map((x) => x.document_title).filter((t, i, a) => a.indexOf(t) === i).join("; ")}</span>}
        <button className="btn btn-ghost btn-sm" onClick={() => setShowMeta(!showMeta)} aria-expanded={showMeta}>{showMeta ? "Hide" : "Show"} details</button>
      </div>
      {showMeta && (
        <div className="small muted mt-8">
          <div>Tools used (read-only): {m.tool_calls.map((t) => t.tool).join(", ") || "none"}</div>
          {removed.length > 0 && <div className="row"><AlertTriangle size={12} /> Removed / unverified references: {removed.join(", ")}</div>}
          <div>Provider: {m.provider} · model: {m.model}</div>
        </div>
      )}
    </div>
  );
}

export function AIChat({ incidentId, initialConversation }: { incidentId?: number; initialConversation?: number | null }) {
  const { isAnalyst } = useSession();
  const toast = useToast();
  const [conversationId, setConversationId] = useState<number | null>(initialConversation ?? null);
  const [messages, setMessages] = useState<AIMessage[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  const suggestions = useWsQuery<{ suggestions: string[] }>(["ai-suggestions", incidentId ?? 0], `/api/ai/suggestions${incidentId ? `?incident_id=${incidentId}` : ""}`);
  const status = useWsQuery<{ mode: string; label: string; detail: string }>(["ai-status"], "/api/ai/status", { staleTime: 60_000 });

  useEffect(() => {
    setConversationId(initialConversation ?? null);
    if (!initialConversation) { setMessages([]); return; }
    api<{ messages: AIMessage[] }>(`/api/ai/conversations/${initialConversation}`).then((c) => setMessages(c.messages)).catch(() => setMessages([]));
  }, [initialConversation]);
  useEffect(() => { logRef.current?.scrollTo({ top: logRef.current.scrollHeight }); }, [messages, busy]);

  const ask = async (text: string) => {
    const message = text.trim();
    if (!message || busy) return;
    setBusy(true);
    setInput("");
    const optimistic = { id: -Date.now(), role: "user", content: message } as AIMessage;
    setMessages((m) => [...m, optimistic]);
    try {
      const r = await api<{ conversation_id: number; user_message: AIMessage; message: AIMessage }>("/api/ai/chat", {
        body: { message, conversation_id: conversationId, incident_id: conversationId ? undefined : incidentId },
      });
      setConversationId(r.conversation_id);
      setMessages((m) => [...m.filter((x) => x.id !== optimistic.id), r.user_message, r.message]);
    } catch (e) {
      setMessages((m) => m.filter((x) => x.id !== optimistic.id));
      setInput(message);
      toast((e as Error).message, "error");
    } finally {
      setBusy(false);
    }
  };
  const submit = (e: FormEvent) => { e.preventDefault(); ask(input); };

  return (
    <div className="card chat">
      <div className="card-head">
        <div><h2>SentinelX AI Security Assistant</h2>
          <div className="sub">{incidentId ? "Grounded in this incident's evidence" : "Ask about your environment or general security topics"}</div></div>
        {status.data && <span className={`badge ${status.data.mode === "LIVE" ? "st-ok" : "st-warn"}`} title={status.data.detail}>{status.data.label}</span>}
      </div>
      <div className="chat-log" ref={logRef} aria-live="polite">
        {messages.length === 0 && (
          <div className="stack">
            {status.data?.mode !== "LIVE" && (
              <div className="notice warn small">No language model is configured, so answers come from <strong>deterministic local analysis</strong> of your data (clearly labelled). Set LLM_PROVIDER and LLM_API_KEY to enable LIVE AI.</div>
            )}
            <p className="muted">Answers separate <strong>evidence</strong> (with real event IDs), <strong>inference</strong> and <strong>uncertainty</strong>. Log content is treated as untrusted data.</p>
            <div className="suggestions">{suggestions.data?.suggestions.map((q) => <button key={q} onClick={() => ask(q)} disabled={!isAnalyst}>{q}</button>)}</div>
          </div>
        )}
        {messages.map((m) => m.role === "user"
          ? <div key={m.id} className="msg user row"><User size={14} aria-hidden="true" /><span className="wrap-anywhere">{m.content}</span></div>
          : <AssistantMessage key={m.id} m={m} />)}
        {busy && <div className="loading"><span className="spinner" /> Investigating with read-only tools…</div>}
        {messages.length > 0 && !busy && (
          <div className="suggestions">{suggestions.data?.suggestions.slice(0, 6).map((q) => <button key={q} onClick={() => ask(q)}>{q}</button>)}</div>
        )}
      </div>
      {isAnalyst ? (
        <form className="chat-input" onSubmit={submit}>
          <label htmlFor="chat-q" className="sr-only">Ask the assistant</label>
          <textarea id="chat-q" className="input" rows={1} maxLength={4000} placeholder={incidentId ? "Ask about this incident…" : "Ask a question…"}
            value={input} onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); ask(input); } }} />
          <button className="btn btn-primary" type="submit" disabled={busy || !input.trim()} aria-label="Send"><Send /></button>
        </form>
      ) : (
        <div className="chat-input muted small">The AI assistant requires the SOC Analyst or Admin role.</div>
      )}
    </div>
  );
}
