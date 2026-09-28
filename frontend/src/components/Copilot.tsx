import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import Markdown from "react-markdown";
import { ChevronDown, ChevronRight, Send, ShieldAlert, X } from "lucide-react";
import { api } from "../lib/api";
import { useWsQuery } from "../lib/hooks";
import { citationsToMarkdown } from "../lib/refs";
import { useSession } from "../lib/session";
import type { AIMessage, Conversation, CopilotMode, Scorecard } from "../lib/types";
import { Artifacts } from "./Artifacts";
import { useToast } from "./ui";

export const MODES: { id: CopilotMode; label: string; hint: string }[] = [
  { id: "ask", label: "Ask", hint: "Questions about the environment, answered from stored data" },
  { id: "investigate", label: "Investigate", hint: "Multi-step investigation with evidence, hypotheses and a scorecard" },
  { id: "hunt", label: "Hunt", hint: "Turn a description into a structured hunt and run it" },
  { id: "explain", label: "Explain", hint: "Explain an event, detection, entity, path or technique" },
  { id: "compare", label: "Compare", hint: "Compare incidents, attack DNA and attack families" },
  { id: "report", label: "Report", hint: "Generate an incident report from stored evidence" },
  { id: "simulate", label: "Simulate", hint: "Attack simulation, defense what-if and counterfactuals" },
];

function MdLink({ href, title, children }: { href?: string; title?: string; children?: React.ReactNode }) {
  if (href?.startsWith("/")) return <Link to={href} className={title ? "cite" : undefined} title={title ? `${title} — open` : undefined}>{children}</Link>;
  return <a href={href} target="_blank" rel="noreferrer noopener">{children}</a>;
}

export function Answer({ text }: { text: string }) {
  return <div className="md"><Markdown skipHtml components={{ a: MdLink as any }}>{citationsToMarkdown(text)}</Markdown></div>;
}

export function ScorecardView({ s }: { s: Scorecard }) {
  return (
    <div className="scorecard">
      <div className="row between"><strong>Investigation scorecard</strong><span className={`badge ${s.confidence === "high" ? "st-ok" : s.confidence === "medium" ? "st-warn" : ""}`}>confidence: {s.confidence}</span></div>
      <dl className="kv small mt-8">
        <dt>Evidence events reviewed</dt><dd>{s.evidence_reviewed}</dd>
        <dt>Entities reviewed</dt><dd>{s.entities_reviewed}</dd>
        <dt>Timeline coverage</dt><dd>{s.timeline_coverage === null ? "n/a (no incident in focus)" : `${Math.round(s.timeline_coverage * 100)}%`}</dd>
        <dt>Contradicting evidence</dt><dd>{s.contradicting_evidence}</dd>
        <dt>Open questions</dt><dd>{s.open_questions.length ? s.open_questions.join("; ") : "none recorded"}</dd>
        <dt>Missing telemetry</dt><dd>{s.missing_telemetry.length ? s.missing_telemetry.join("; ") : "none identified"}</dd>
      </dl>
      <p className="muted small">{s.method}</p>
    </div>
  );
}

function SourceBadge({ m }: { m: AIMessage }) {
  if (m.mode === "LIVE") return <span className="badge st-ok" title={`Provider: ${m.provider}`}>Model: {m.model}</span>;
  return <span className="badge" title="Answer produced by SentinelX's rule-based planner calling the same tools. No language model was used.">Rule-based analysis</span>;
}

export function AssistantMessage({ m }: { m: AIMessage }) {
  const [open, setOpen] = useState(false);
  const s = m.structured ?? {};
  const invalid = m.validation?.invalid_citations ?? [];
  return (
    <article className="msg assistant" aria-label="Copilot answer">
      <div className="row between msg-meta">
        <span className="row"><SourceBadge m={m} />{s.mode && <span className="badge">{s.mode}</span>}</span>
        <span className="muted small">{m.latency_ms !== null ? `${(m.latency_ms / 1000).toFixed(1)} s` : ""}</span>
      </div>
      {s.notice?.kind === "error" && (
        <div className="notice bad small" role="alert">
          <strong>{s.notice.text}</strong>
          <div>Investigation ID: <span className="mono">{s.notice.reference}</span>{s.notice.reason ? ` — ${s.notice.reason}` : ""} <Link to="/health">Check System Health</Link></div>
        </div>)}
      {s.notice?.kind === "info" && <div className="notice small">{s.notice.text}</div>}
      {s.security_notes?.map((n, i) => <div key={i} className="notice warn small row"><ShieldAlert size={14} aria-hidden="true" /><span style={{ flex: 1 }}>{n}</span></div>)}
      <Answer text={m.content} />
      {m.artifacts?.length > 0 && <Artifacts items={m.artifacts} />}
      {s.scorecard && <ScorecardView s={s.scorecard} />}
      <div className="msg-foot small">
        <button className="linkish" onClick={() => setOpen(!open)} aria-expanded={open}>
          {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />} Investigation activity ({m.activity.length} step{m.activity.length === 1 ? "" : "s"})
        </button>
        <span className="muted">{m.validation?.verified_citations ?? 0} citation(s) verified</span>
        {invalid.length > 0 && <span className="badge st-warn" title={invalid.join(", ")}>{invalid.length} unverifiable reference(s) removed</span>}
      </div>
      {open && (
        <ol className="activity small">
          {m.activity.map((a, i) => <li key={i} className={a.ok ? "" : "failed"}><span className="mono">{a.tool}</span>{a.summary ? ` — ${a.summary}` : ""}</li>)}
          {m.activity.length === 0 && <li className="muted">No tools were called.</li>}
        </ol>)}
    </article>
  );
}

type Props = {
  conversationId?: number | null; context?: string[]; mode?: CopilotMode; question?: string; investigation?: string;
  onConversation?: (c: Conversation) => void; onMessage?: (m: AIMessage) => void; compact?: boolean;
};

export function Copilot({ conversationId: initialConv = null, context: initialContext = [], mode: initialMode = "ask",
  question, investigation, onConversation, onMessage, compact }: Props) {
  const { isAnalyst } = useSession();
  const toast = useToast();
  const navigate = useNavigate();
  const [conversationId, setConversationId] = useState<number | null>(initialConv);
  const [messages, setMessages] = useState<AIMessage[]>([]);
  const [mode, setMode] = useState<CopilotMode>(initialMode);
  const [context, setContext] = useState<string[]>(initialContext);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  const asked = useRef(false);
  const suggestions = useWsQuery<{ suggestions: string[] }>(["ai-suggestions", mode], `/api/ai/suggestions?mode=${mode}`, { staleTime: 300_000 });

  useEffect(() => {
    if (!initialConv) return;
    api<{ messages: AIMessage[]; mode: CopilotMode }>(`/api/ai/conversations/${initialConv}`)
      .then((c) => { setMessages(c.messages); setMode(c.mode ?? "ask"); }).catch(() => setMessages([]));
  }, [initialConv]);
  useEffect(() => { logRef.current?.scrollTo({ top: logRef.current.scrollHeight }); }, [messages, busy]);

  const ask = async (text: string) => {
    const message = text.trim();
    if (!message || busy) return;
    setBusy(true);
    setInput("");
    const optimistic = { id: -Date.now(), role: "user", content: message, activity: [], artifacts: [], structured: {} } as unknown as AIMessage;
    setMessages((m) => [...m, optimistic]);
    try {
      const r = await api<{ conversation: Conversation; user_message: AIMessage; message: AIMessage }>("/api/ai/chat", {
        body: { message, conversation_id: conversationId, mode, context, investigation },
      });
      setConversationId(r.conversation.id);
      setMessages((m) => [...m.filter((x) => x.id !== optimistic.id), r.user_message, r.message]);
      onConversation?.(r.conversation);
      onMessage?.(r.message);
    } catch (e) {
      setMessages((m) => m.filter((x) => x.id !== optimistic.id));
      setInput(message);
      toast((e as Error).message, "error");
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (question && !asked.current && isAnalyst && !initialConv) { asked.current = true; ask(question); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [question, isAnalyst]);

  const submit = (e: FormEvent) => { e.preventDefault(); ask(input); };
  const current = MODES.find((m) => m.id === mode)!;

  return (
    <section className={`copilot ${compact ? "compact" : ""}`} aria-label="Security copilot">
      <div className="mode-bar" role="tablist" aria-label="Copilot mode">
        {MODES.map((m) => (
          <button key={m.id} role="tab" aria-selected={mode === m.id} className={mode === m.id ? "active" : ""} title={m.hint} onClick={() => setMode(m.id)}>{m.label}</button>
        ))}
      </div>
      <div className="chat-log" ref={logRef} aria-live="polite">
        {messages.length === 0 && (
          <div className="stack-sm">
            <p className="muted small">{current.hint}. Answers cite the events, incidents and entities they rely on; each citation links to the object.</p>
            <div className="suggestions">{suggestions.data?.suggestions.map((q) => <button key={q} onClick={() => ask(q)} disabled={!isAnalyst || busy}>{q}</button>)}</div>
          </div>
        )}
        {messages.map((m) => m.role === "user"
          ? <div key={m.id} className="msg user"><span className="wrap-anywhere">{m.content}</span></div>
          : <AssistantMessage key={m.id} m={m} />)}
        {busy && <div className="loading"><span className="spinner" /> Querying SentinelX data…</div>}
      </div>
      {context.length > 0 && (
        <div className="context-bar small">
          <span className="muted">Context:</span>
          {context.map((c) => (
            <span key={c} className="chip mono">{c}<button aria-label={`Remove context ${c}`} onClick={() => setContext(context.filter((x) => x !== c))}><X size={11} /></button></span>))}
          {investigation && <span className="chip mono">{investigation}</span>}
        </div>)}
      {isAnalyst ? (
        <form className="chat-input" onSubmit={submit}>
          <label htmlFor="copilot-q" className="sr-only">Question</label>
          <textarea id="copilot-q" className="input" rows={2} maxLength={4000}
            placeholder={mode === "hunt" ? "Describe what to hunt for, e.g. privileged accounts logging in outside business hours" : "Ask about incidents, users, hosts, detections… (Enter to send, Shift+Enter for a new line)"}
            value={input} onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); ask(input); } }} />
          <button className="btn btn-primary" type="submit" disabled={busy || !input.trim()} aria-label="Send"><Send /></button>
        </form>
      ) : (
        <div className="chat-input muted small">Viewers can read conversations; asking questions requires the SOC Analyst or Admin role.
          <button className="btn btn-sm" onClick={() => navigate("/settings")}>Account</button></div>
      )}
    </section>
  );
}
