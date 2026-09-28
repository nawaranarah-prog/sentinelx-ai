import { useState, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Upload } from "lucide-react";
import { api } from "../../lib/api";
import { useWsQuery } from "../../lib/hooks";
import { fmtTime } from "../../lib/format";
import { Card, Loading, SidePanel, useToast } from "../../components/ui";

interface Doc { id: number; title: string; filename: string; content_type: string; category: string; origin: string; char_count: number; chunk_count: number; created_at: string }

export function AdminKnowledgePage() {
  const qc = useQueryClient();
  const toast = useToast();
  const docs = useWsQuery<{ documents: Doc[]; embedding: string; vector_store: string }>(["kb-docs"], "/api/knowledge/documents");
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<{ document_title: string; heading: string; content: string; score: number }[] | null>(null);
  const [viewing, setViewing] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const doc = useWsQuery<Doc & { chunks: { id: number; ordinal: number; heading: string; content: string }[] }>(["kb-doc", viewing], viewing ? `/api/knowledge/documents/${viewing}` : null);
  const upload = async (f: File | undefined) => {
    if (!f) return;
    setBusy(true);
    const fd = new FormData();
    fd.append("file", f);
    try { const d = await api<Doc>("/api/knowledge/documents", { form: fd }); qc.invalidateQueries({ queryKey: ["ws"] }); toast(`Indexed "${d.title}" into ${d.chunk_count} chunks.`); }
    catch (e) { toast((e as Error).message, "error"); } finally { setBusy(false); }
  };
  const remove = async (d: Doc) => {
    if (!confirm(`Delete "${d.title}" from the knowledge base?`)) return;
    await api(`/api/knowledge/documents/${d.id}`, { method: "DELETE" });
    qc.invalidateQueries({ queryKey: ["ws"] });
  };
  const search = async (e: FormEvent) => {
    e.preventDefault();
    const r = await api<{ results: typeof results }>(`/api/knowledge/search?q=${encodeURIComponent(query)}`);
    setResults(r.results);
  };
  return (
    <div className="stack">
      <div className="page-head"><div><h1>Knowledge base (RAG)</h1><p>UPLOAD → EXTRACT → CHUNK → EMBED → STORE → RETRIEVE. Retrieved passages are given to the copilot as untrusted context and cited as sources.</p></div>
        <div className="page-actions"><label className="btn btn-primary" style={{ cursor: "pointer" }}><Upload /> {busy ? "Indexing…" : "Upload document"}<input type="file" hidden accept=".md,.markdown,.txt,.pdf" onChange={(e) => upload(e.target.files?.[0])} disabled={busy} /></label></div></div>
      {docs.data && <div className="notice small">Embedding: {docs.data.embedding}. {docs.data.vector_store}</div>}
      <div className="grid grid-main-side">
        <Card title="Documents" flush>
          {docs.isLoading ? <Loading /> : (
            <div className="table-wrap"><table className="table responsive"><thead><tr><th>Document</th><th>Origin</th><th className="num">Chunks</th><th>Added</th><th /></tr></thead>
              <tbody>{docs.data?.documents.map((d) => (<tr key={d.id}>
                <td data-label="Document"><button className="btn btn-ghost" style={{ padding: 0, height: "auto", whiteSpace: "normal", textAlign: "left" }} onClick={() => setViewing(d.id)}><strong>{d.title}</strong></button><div className="small muted">{d.filename} · {d.char_count.toLocaleString()} chars</div></td>
                <td data-label="Origin"><span className="badge">{d.origin}</span></td><td data-label="Chunks" className="num">{d.chunk_count}</td>
                <td data-label="Added" className="small">{fmtTime(d.created_at, false)}</td>
                <td data-label=""><button className="btn btn-sm btn-danger" onClick={() => remove(d)}>Delete</button></td></tr>))}</tbody></table></div>)}
        </Card>
        <Card title="Test retrieval">
          <form className="row" onSubmit={search}><label htmlFor="kbq" className="sr-only">Query</label><input id="kbq" className="input" style={{ flex: 1 }} placeholder="e.g. how to contain password spraying" value={query} onChange={(e) => setQuery(e.target.value)} /><button className="btn" disabled={!query.trim()}>Search</button></form>
          {results && (results.length === 0 ? <p className="muted mt-8">No passage above the relevance floor.</p> : results.map((r, i) => (
            <div key={i} className="notice small mt-8"><div className="row between"><strong>{r.document_title}{r.heading && ` › ${r.heading}`}</strong><span className="badge">{r.score.toFixed(3)}</span></div><p className="mt-8" style={{ whiteSpace: "pre-wrap" }}>{r.content.slice(0, 500)}{r.content.length > 500 && "…"}</p></div>)))}
        </Card>
      </div>
      {viewing !== null && (
        <SidePanel title={doc.data?.title ?? "Document"} onClose={() => setViewing(null)}>
          {doc.isLoading ? <Loading /> : doc.data?.chunks.map((c) => (<div key={c.id} className="mb-8"><div className="small muted">Chunk {c.ordinal + 1}{c.heading && ` · ${c.heading}`}</div><pre className="code" style={{ maxHeight: 220 }}>{c.content}</pre></div>))}
        </SidePanel>)}
    </div>
  );
}
