import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import { api } from "../lib/api";
import { useWsQuery } from "../lib/hooks";
import { fmtRelative } from "../lib/format";
import type { IncidentBrief, Paged } from "../lib/types";
import { AIChat } from "../components/AIChat";
import { Card } from "../components/ui";

export function AssistantPage() {
  const qc = useQueryClient();
  const [conv, setConv] = useState<number | null>(null);
  const [incident, setIncident] = useState<number | undefined>(undefined);
  const [key, setKey] = useState(0);
  const convs = useWsQuery<{ id: number; title: string; incident_id: number | null; updated_at: string }[]>(["conversations"], "/api/ai/conversations", { refetchInterval: 15_000 });
  const incidents = useWsQuery<Paged<IncidentBrief>>(["incidents-picker"], "/api/incidents?page_size=50");
  const startNew = (inc?: number) => { setConv(null); setIncident(inc); setKey((k) => k + 1); };
  const remove = async (id: number) => {
    await api(`/api/ai/conversations/${id}`, { method: "DELETE" });
    if (conv === id) startNew();
    qc.invalidateQueries({ queryKey: ["ws"] });
  };
  return (
    <div className="stack">
      <div className="page-head"><div><h1>AI Security Assistant</h1><p>Environment-aware investigation help. Uses read-only, workspace-scoped tools; log content is treated as untrusted data.</p></div></div>
      <div className="grid assistant-grid">
        <div className="stack hide-sm">
          <Card title="Context">
            <label htmlFor="ctx-inc" className="small muted">Ground the next conversation in an incident</label>
            <select id="ctx-inc" className="select mt-8" style={{ width: "100%" }} value={incident ?? ""} onChange={(e) => startNew(e.target.value ? Number(e.target.value) : undefined)}>
              <option value="">Whole workspace / general</option>
              {incidents.data?.items.map((i) => <option key={i.id} value={i.id}>{i.number} · {i.title.slice(0, 40)}</option>)}
            </select>
            <button className="btn btn-sm mt-8" onClick={() => startNew(incident)}><Plus /> New conversation</button>
          </Card>
          <Card title="Conversations" flush>
            <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
              {convs.data?.length === 0 && <li className="muted small" style={{ padding: 16 }}>No conversations yet.</li>}
              {convs.data?.map((c) => (
                <li key={c.id} className="row" style={{ padding: "6px 10px", borderBottom: "1px solid var(--border)", flexWrap: "nowrap", background: conv === c.id ? "var(--accent-soft)" : undefined }}>
                  <button className="btn btn-ghost" style={{ flex: 1, height: "auto", whiteSpace: "normal", textAlign: "left", padding: 4 }} onClick={() => { setConv(c.id); setIncident(c.incident_id ?? undefined); setKey((k) => k + 1); }}>
                    <span><span className="small">{c.title}</span><div className="small muted">{fmtRelative(c.updated_at)}</div></span>
                  </button>
                  <button className="btn btn-ghost btn-sm" aria-label={`Delete conversation ${c.title}`} onClick={() => remove(c.id)}><Trash2 /></button>
                </li>))}
            </ul>
          </Card>
        </div>
        <div className="stack">
          <div className="show-sm row">
            <select className="select" aria-label="Incident context" value={incident ?? ""} onChange={(e) => startNew(e.target.value ? Number(e.target.value) : undefined)} style={{ flex: 1 }}>
              <option value="">Whole workspace / general</option>
              {incidents.data?.items.map((i) => <option key={i.id} value={i.id}>{i.number}</option>)}
            </select>
          </div>
          <AIChat key={key} incidentId={incident} initialConversation={conv} />
        </div>
      </div>
    </div>
  );
}
