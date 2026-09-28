import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../lib/api";
import { useDebounced, useWsQuery } from "../lib/hooks";
import { fmtTime } from "../lib/format";
import type { GraphEdgeT, GraphNodeT } from "../lib/types";
import { Artifact } from "../components/Artifacts";
import { copilotUrl } from "../components/InvestigateButton";
import { Card, Empty, Loading, useToast } from "../components/ui";

function nodeLink(n: GraphNodeT): string | null {
  switch (n.kind) {
    case "user": return `/entities/user/${encodeURIComponent(n.key)}`;
    case "host": return `/entities/host/${encodeURIComponent(n.key)}`;
    case "ip": case "domain": return `/threat-intel?q=${encodeURIComponent(n.key)}`;
    case "incident": return `/incidents/${n.key}`;
    case "detection": return `/detections/${n.key}`;
    case "technique": return `/mitre?technique=${n.key}`;
    default: return null;
  }
}

export function GraphExplorerPage() {
  const toast = useToast();
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState(params.get("q") ?? "");
  const dq = useDebounced(q.trim(), 250);
  const [selected, setSelected] = useState<number | null>(params.get("node") ? Number(params.get("node")) : null);
  const [rel, setRel] = useState("");
  const [src, setSrc] = useState("");
  const [dst, setDst] = useState("");
  const [paths, setPaths] = useState<Record<string, any> | null>(null);
  const results = useWsQuery<GraphNodeT[]>(["graph-search", dq], dq.length >= 2 ? `/api/graph/search?q=${encodeURIComponent(dq)}` : null);
  const node = useWsQuery<{ node: GraphNodeT; nodes: GraphNodeT[]; edges: GraphEdgeT[] }>(["graph-node", selected, rel], selected ? `/api/graph/nodes/${selected}${rel ? `?rel=${rel}` : ""}` : null);
  const relations = useWsQuery<{ relations: Record<string, string>; kinds: string[] }>(["graph-relations"], "/api/graph/relations", { staleTime: Infinity });
  useEffect(() => { if (results.data?.length === 1 && !selected) setSelected(results.data[0].id); }, [results.data, selected]);

  const findPaths = async () => {
    try {
      const r = await api<any>(`/api/graph/paths?source=${encodeURIComponent(src)}&target=${encodeURIComponent(dst)}`);
      setPaths({ type: "paths", source: `${r.source.kind}:${r.source.label}`, target: `${r.target.kind}:${r.target.label}`, ...r });
    } catch (e) { toast((e as Error).message, "error"); setPaths(null); }
  };
  const byId = Object.fromEntries((node.data?.nodes ?? []).map((n) => [n.id, n]));
  const center = node.data?.node;

  return (
    <div className="stack">
      <div className="page-head"><div><h1>Knowledge graph</h1><p>Users, hosts, IPs, processes, domains, shares, groups, detections, incidents and techniques, linked by relationships observed in stored telemetry. Every relationship keeps sample event IDs as evidence.</p></div></div>
      <div className="split">
        <Card title="Find a node" className="split-side">
          <label htmlFor="g-q" className="sr-only">Search nodes</label>
          <input id="g-q" className="input" value={q} onChange={(e) => { setQ(e.target.value); setParams(e.target.value ? { q: e.target.value } : {}); }} placeholder="user, host, IP, process, domain…" />
          {results.isFetching && <Loading />}
          <ul className="list mt-8">{results.data?.map((n) => (
            <li key={n.id} className={selected === n.id ? "active" : ""}><button className="linkish" onClick={() => setSelected(n.id)}><span className="badge">{n.kind}</span> <span className="mono small">{n.label}</span></button></li>))}</ul>
          {dq.length >= 2 && results.data?.length === 0 && <p className="muted small">No node matches.</p>}
          <h3 className="small muted mt-16">PATH FINDER</h3>
          <div className="stack-sm">
            <input className="input" aria-label="Source node" placeholder="from (e.g. t.nguyen)" value={src} onChange={(e) => setSrc(e.target.value)} />
            <input className="input" aria-label="Target node" placeholder="to (e.g. a server name)" value={dst} onChange={(e) => setDst(e.target.value)} />
            <button className="btn" disabled={!src.trim() || !dst.trim()} onClick={findPaths}>Find paths</button>
          </div>
        </Card>
        <div className="stack split-main">
          {paths && <Card title="Paths"><Artifact a={paths} /></Card>}
          {!selected ? <Card><Empty title="Select a node">Search for an entity to see its relationships.</Empty></Card> : node.isLoading ? <Loading /> : center && (
            <Card title={<span><span className="badge">{center.kind}</span> <span className="mono">{center.label}</span></span>}
              sub={`first seen ${fmtTime(center.first_seen)} · last seen ${fmtTime(center.last_seen)}`}
              actions={<>
                {nodeLink(center) && <Link className="btn btn-sm" to={nodeLink(center)!}>Open</Link>}
                <Link className="btn btn-sm" to={copilotUrl({ mode: "explain", q: `Explain the relationships of ${center.kind} ${center.label} in the knowledge graph. What is unusual?` })}>Explain</Link>
                <select className="select select-sm" aria-label="Relationship filter" value={rel} onChange={(e) => setRel(e.target.value)}>
                  <option value="">All relationships</option>{Object.keys(relations.data?.relations ?? {}).map((r) => <option key={r} value={r}>{r.replace(/_/g, " ")}</option>)}
                </select></>}>
              {node.data!.edges.length === 0 ? <p className="muted small">No relationships.</p> : (
                <div className="table-wrap"><table className="table dense">
                  <thead><tr><th>Relationship</th><th>Node</th><th className="num">Count</th><th>First / last seen</th><th>Evidence</th></tr></thead>
                  <tbody>{node.data!.edges.map((e) => {
                    const outgoing = e.source === center.id;
                    const other = byId[outgoing ? e.target : e.source];
                    return (
                      <tr key={e.id}>
                        <td className="small">{outgoing ? "" : "← "}{e.rel.replace(/_/g, " ")}{outgoing ? " →" : ""}</td>
                        <td>{other && <button className="linkish" onClick={() => setSelected(other.id)}><span className="badge">{other.kind}</span> <span className="mono small">{other.label}</span></button>}</td>
                        <td className="num">{e.count}</td>
                        <td className="small nowrap">{fmtTime(e.first_seen)}<br />{fmtTime(e.last_seen)}</td>
                        <td className="small">{e.evidence.slice(0, 3).map((u) => <Link key={u} className="mono" to={`/events/${encodeURIComponent(u)}`} style={{ marginRight: 6 }}>{u}</Link>)}</td>
                      </tr>);
                  })}</tbody>
                </table></div>)}
            </Card>)}
        </div>
      </div>
    </div>
  );
}
