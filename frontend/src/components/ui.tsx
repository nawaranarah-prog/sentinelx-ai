import { Fragment, createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { AlertTriangle, ChevronLeft, ChevronRight, X } from "lucide-react";
import { STATUS_LABEL } from "../lib/format";

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`badge sev-${severity}`} title={`Severity: ${severity}`}>
      <span className="dot" aria-hidden="true" />
      {severity}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const cls = status === "RESOLVED" ? "st-ok" : status === "FALSE_POSITIVE" ? "" : status === "NEW" ? "badge-accent" : status === "CONTAINED" ? "st-warn" : "";
  return <span className={`badge ${cls}`}>{STATUS_LABEL[status] ?? status}</span>;
}

export function HealthBadge({ status }: { status: string }) {
  const cls = status === "CONNECTED" ? "st-ok" : status === "DEGRADED" ? "st-warn" : status === "ERROR" ? "st-bad" : "";
  return <span className={`badge ${cls}`}><span className="dot" aria-hidden="true" />{status}</span>;
}

export function RiskMeter({ score, band }: { score: number; band: string }) {
  const color = score >= 75 ? "var(--sev-critical)" : score >= 50 ? "var(--sev-high)" : score >= 25 ? "var(--sev-medium)" : "var(--sev-low)";
  return (
    <div title={`SentinelX Risk ${score}/100 (${band})`} style={{ minWidth: 90 }}>
      <div className="row between small"><strong>{score}</strong><span className="muted">{band}</span></div>
      <div className="meter" role="meter" aria-valuenow={score} aria-valuemin={0} aria-valuemax={100} aria-label="Risk score">
        <span style={{ width: `${score}%`, background: color }} />
      </div>
    </div>
  );
}

export function Card({ title, sub, actions, children, flush, className = "" }: {
  title?: ReactNode; sub?: ReactNode; actions?: ReactNode; children: ReactNode; flush?: boolean; className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <div className="card-head">
          <div>{title && <h2>{title}</h2>}{sub && <div className="sub">{sub}</div>}</div>
          {actions && <div className="row">{actions}</div>}
        </div>
      )}
      <div className={`card-body ${flush ? "flush" : ""}`}>{children}</div>
    </section>
  );
}

export function Stat({ label, value, foot }: { label: string; value: ReactNode; foot?: ReactNode }) {
  return (
    <div className="card stat">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {foot && <div className="foot">{foot}</div>}
    </div>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return <div className="loading" role="status"><span className="spinner" aria-hidden="true" />{label}</div>;
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <div className="error-box row" role="alert">
      <AlertTriangle size={16} aria-hidden="true" />
      <span style={{ flex: 1 }}>{msg}</span>
      {onRetry && <button className="btn btn-sm" onClick={onRetry}>Retry</button>}
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return <div className="empty"><h3>{title}</h3>{children}</div>;
}

export function Pagination({ page, pageSize, total, onPage }: { page: number; pageSize: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  return (
    <nav className="pagination" aria-label="Pagination">
      <span>{from.toLocaleString()}–{Math.min(total, page * pageSize).toLocaleString()} of {total.toLocaleString()}</span>
      <span className="row">
        <button className="btn btn-sm" disabled={page <= 1} onClick={() => onPage(page - 1)} aria-label="Previous page"><ChevronLeft /></button>
        <span>Page {page} / {pages}</span>
        <button className="btn btn-sm" disabled={page >= pages} onClick={() => onPage(page + 1)} aria-label="Next page"><ChevronRight /></button>
      </span>
    </nav>
  );
}

export function Tabs({ tabs, active, onChange, label }: { tabs: { id: string; label: string }[]; active: string; onChange: (id: string) => void; label: string }) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const onKey = (e: React.KeyboardEvent, i: number) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    const n = (i + (e.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
    refs.current[n]?.focus();
    onChange(tabs[n].id);
  };
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map((t, i) => (
        <button key={t.id} ref={(el) => { refs.current[i] = el; }} role="tab" id={`tab-${t.id}`}
          aria-selected={active === t.id} aria-controls={`panel-${t.id}`} tabIndex={active === t.id ? 0 : -1}
          onClick={() => onChange(t.id)} onKeyDown={(e) => onKey(e, i)}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function Modal({ title, onClose, children, labelledBy = "modal-title" }: { title: string; onClose: () => void; children: ReactNode; labelledBy?: string }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby={labelledBy}>
        <div className="modal-head"><h2 id={labelledBy}>{title}</h2><button className="btn btn-ghost icon-btn" onClick={onClose} aria-label="Close"><X /></button></div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

export function SidePanel({ title, onClose, children }: { title: ReactNode; onClose: () => void; children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    ref.current?.focus();
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <>
      <div className="drawer-backdrop open" style={{ display: "block", position: "fixed", inset: 0, zIndex: 54 }} onClick={onClose} />
      <aside className="side-panel" role="dialog" aria-modal="true" aria-label="Details" tabIndex={-1} ref={ref}>
        <div className="modal-head"><h2>{title}</h2><button className="btn btn-ghost icon-btn" onClick={onClose} aria-label="Close panel"><X /></button></div>
        <div className="panel-body">{children}</div>
      </aside>
    </>
  );
}

export function KV({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="kv">
      {items.map(([k, v]) => (<Fragment key={k}><dt>{k}</dt><dd>{v ?? "—"}</dd></Fragment>))}
    </dl>
  );
}

export function JsonBlock({ value, label }: { value: unknown; label: string }) {
  return <pre className="code" aria-label={label} tabIndex={0}>{JSON.stringify(value, null, 2)}</pre>;
}

// ------------------------------------------------------------------ toasts
type Toast = { id: number; text: string; kind: "info" | "error" };
const ToastCtx = createContext<(text: string, kind?: "info" | "error") => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((text: string, kind: "info" | "error" = "info") => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, text, kind }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 5000);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((t) => <div key={t.id} className={`toast ${t.kind}`}>{t.text}</div>)}
      </div>
    </ToastCtx.Provider>
  );
}

export function useToast() {
  return useContext(ToastCtx);
}
