import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useWsQuery } from "../lib/hooks";
import { fmtRelative } from "../lib/format";
import { useSession } from "../lib/session";
import type { Scorecard } from "../lib/types";
import { Answer, ScorecardView } from "../components/Copilot";
import { copilotUrl } from "../components/InvestigateButton";
import { Card, Empty, ErrorState, Loading, useToast } from "../components/ui";

type Item = { id: number; kind: string; text: string; status: string; supporting: string[]; contradicting: string[]; source: string; created_at: string };
type Inv = { id: number; number: string; title: string; status: string; incident: { id: number; number: string; title: string } | null;
  scorecard: Scorecard | Record<string, never>; created_at: string; updated_at: string; counts: Record<string, number>; items?: Item[];
  conversations?: { id: number; title: string }[] };

const SECTIONS: { kind: string; label: string; statuses: string[] }[] = [
  { kind: "hypothesis", label: "Hypotheses", statuses: ["open", "supported", "refuted"] },
  { kind: "fact", label: "Facts", statuses: ["open"] },
  { kind: "question", label: "Open questions", statuses: ["open", "resolved"] },
  { kind: "conclusion", label: "Conclusions", statuses: ["open"] },
  { kind: "note", label: "Notes", statuses: ["open"] },
];

const refText = (refs: string[]) => refs.map((r) => (r.includes(":") ? `[${r}]` : r)).join(" ");

function ItemRow({ inv, item, canEdit }: { inv: string; item: Item; canEdit: boolean }) {
  const qc = useQueryClient();
  const toast = useToast();
  const statuses = SECTIONS.find((s) => s.kind === item.kind)?.statuses ?? ["open"];
  const set = async (status: string) => {
    try { await api(`/api/investigations/${inv}/items/${item.id}`, { method: "PATCH", body: { status } }); qc.invalidateQueries({ queryKey: ["ws"] }); }
    catch (e) { toast((e as Error).message, "error"); }
  };
  return (
    <li className="inv-item">
      <div className="row between">
        <span className="row"><span className="badge">{item.source === "ai" ? "copilot" : item.source}</span>{statuses.length > 1 && (
          canEdit ? <select className="select select-sm" aria-label="Status" value={item.status} onChange={(e) => set(e.target.value)}>{statuses.map((s) => <option key={s}>{s}</option>)}</select>
            : <span className="badge">{item.status}</span>)}</span>
        <span className="muted small">{fmtRelative(item.created_at)}</span>
      </div>
      <Answer text={item.text} />
      {item.supporting.length > 0 && <div className="small"><strong>Supporting:</strong> <Answer text={refText(item.supporting)} /></div>}
      {item.contradicting.length > 0 && <div className="small"><strong>Contradicting:</strong> <Answer text={refText(item.contradicting)} /></div>}
    </li>
  );
}

function AddItem({ inv }: { inv: string }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [kind, setKind] = useState("hypothesis");
  const [text, setText] = useState("");
  const [supporting, setSupporting] = useState("");
  const [contradicting, setContradicting] = useState("");
  const split = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  const add = async () => {
    try {
      await api(`/api/investigations/${inv}/items`, { body: { kind, text, supporting: split(supporting), contradicting: split(contradicting) } });
      setText(""); setSupporting(""); setContradicting("");
      qc.invalidateQueries({ queryKey: ["ws"] });
    } catch (e) { toast((e as Error).message, "error"); }
  };
  return (
    <Card title="Add to the investigation">
      <div className="form-grid">
        <label className="field"><span>Type</span><select className="select" value={kind} onChange={(e) => setKind(e.target.value)}>{SECTIONS.map((s) => <option key={s.kind} value={s.kind}>{s.kind}</option>)}</select></label>
        <label className="field" style={{ gridColumn: "span 2" }}><span>Statement</span><input className="input" value={text} onChange={(e) => setText(e.target.value)} /></label>
        <label className="field"><span>Supporting evidence (IDs, e.g. EVT:NB-000123)</span><input className="input mono" value={supporting} onChange={(e) => setSupporting(e.target.value)} /></label>
        <label className="field"><span>Contradicting evidence</span><input className="input mono" value={contradicting} onChange={(e) => setContradicting(e.target.value)} /></label>
        <div className="field"><span>&nbsp;</span><button className="btn btn-primary" disabled={!text.trim()} onClick={add}>Add</button></div>
      </div>
    </Card>
  );
}

function Detail({ ref_ }: { ref_: string }) {
  const { isAnalyst } = useSession();
  const qc = useQueryClient();
  const q = useWsQuery<Inv>(["investigation", ref_], `/api/investigations/${ref_}`);
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} />;
  const inv = q.data!;
  const toggle = async () => { await api(`/api/investigations/${inv.number}`, { method: "PATCH", body: { status: inv.status === "OPEN" ? "CLOSED" : "OPEN" } }); qc.invalidateQueries({ queryKey: ["ws"] }); };
  const card = inv.scorecard && "confidence" in inv.scorecard ? inv.scorecard as Scorecard : null;
  return (
    <div className="stack">
      <div className="page-head">
        <div><div className="small muted"><Link to="/investigations">Investigations</Link> / {inv.number}</div><h1 style={{ marginTop: 4 }}>{inv.title}</h1>
          <p>{inv.status} · updated {fmtRelative(inv.updated_at)}{inv.incident && <> · incident <Link to={`/incidents/${inv.incident.number}`}>{inv.incident.number}</Link></>}</p></div>
        <div className="page-actions">
          <Link className="btn btn-primary" to={copilotUrl({ investigation: inv.number, mode: "investigate", context: inv.incident ? [`INC:${inv.incident.number}`] : [], q: "What should I investigate next in this investigation?" })}>Continue in copilot</Link>
          {isAnalyst && <button className="btn" onClick={toggle}>{inv.status === "OPEN" ? "Close" : "Reopen"}</button>}
        </div>
      </div>
      <div className="grid grid-main-side">
        <div className="stack">
          {SECTIONS.map((s) => {
            const items = (inv.items ?? []).filter((i) => i.kind === s.kind);
            if (!items.length && s.kind === "note") return null;
            return (
              <Card key={s.kind} title={`${s.label} (${items.length})`}>
                {items.length === 0 ? <p className="muted small">None recorded.</p> : <ul className="inv-items">{items.map((i) => <ItemRow key={i.id} inv={inv.number} item={i} canEdit={isAnalyst} />)}</ul>}
              </Card>);
          })}
          {isAnalyst && <AddItem inv={inv.number} />}
        </div>
        <div className="stack">
          {card ? <Card title="Scorecard"><ScorecardView s={card} /></Card> : <Card title="Scorecard"><p className="muted small">Computed when the copilot works on this investigation in Investigate mode.</p></Card>}
          <Card title="Copilot conversations" flush>
            {inv.conversations?.length ? <ul className="list">{inv.conversations.map((c) => <li key={c.id}><Link to={`/assistant?conversation=${c.id}`}>{c.title}</Link></li>)}</ul> : <p className="muted small pad">None linked yet.</p>}
          </Card>
          <p className="muted small">Items from earlier investigations are historical memory: they record what was concluded then and are shown separately from current evidence.</p>
        </div>
      </div>
    </div>
  );
}

export function InvestigationsPage() {
  const { ref } = useParams();
  const { isAnalyst } = useSession();
  const navigate = useNavigate();
  const toast = useToast();
  const list = useWsQuery<Inv[]>(["investigations"], ref ? null : "/api/investigations");
  const [title, setTitle] = useState("");
  const [incident, setIncident] = useState("");
  if (ref) return <Detail ref_={ref} />;
  const create = async () => {
    try {
      const inv = await api<Inv>("/api/investigations", { body: { title, incident: incident.trim() || null } });
      navigate(`/investigations/${inv.number}`);
    } catch (e) { toast((e as Error).message, "error"); }
  };
  return (
    <div className="stack">
      <div className="page-head"><div><h1>Investigations</h1><p>Working notes for an investigation: facts, hypotheses with supporting and contradicting evidence, open questions and conclusions. The copilot records its findings here too.</p></div></div>
      {isAnalyst && (
        <Card title="New investigation">
          <div className="form-grid">
            <label className="field" style={{ gridColumn: "span 2" }}><span>Question or title</span><input className="input" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. Is t.nguyen's account compromised?" /></label>
            <label className="field"><span>Incident (optional)</span><input className="input mono" value={incident} onChange={(e) => setIncident(e.target.value)} placeholder="INC-0006" /></label>
            <div className="field"><span>&nbsp;</span><button className="btn btn-primary" disabled={title.trim().length < 3} onClick={create}>Create</button></div>
          </div>
        </Card>)}
      <Card flush>
        {list.isLoading ? <Loading /> : list.error ? <ErrorState error={list.error} /> : list.data!.length === 0 ? <Empty title="No investigations yet" /> : (
          <div className="table-wrap"><table className="table dense">
            <thead><tr><th>ID</th><th>Title</th><th>Incident</th><th>Status</th><th className="num">Hypotheses</th><th className="num">Open questions</th><th>Updated</th></tr></thead>
            <tbody>{list.data!.map((i) => (
              <tr key={i.id}><td className="mono"><Link to={`/investigations/${i.number}`}>{i.number}</Link></td><td>{i.title}</td>
                <td>{i.incident ? <Link to={`/incidents/${i.incident.number}`}>{i.incident.number}</Link> : "—"}</td><td>{i.status}</td>
                <td className="num">{i.counts.hypothesis}</td><td className="num">{i.counts.question}</td><td className="small">{fmtRelative(i.updated_at)}</td></tr>))}</tbody>
          </table></div>)}
      </Card>
    </div>
  );
}
