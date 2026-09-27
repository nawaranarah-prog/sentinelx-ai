import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { SeverityBadge } from "./ui";

export interface GraphNode {
  id: string; type: string; label: string; layer: number; row: number; sublabel?: string; severity?: string;
  detection_id?: number; timestamp?: string; external?: boolean; items?: string[]; stage?: string;
}
export interface GraphEdge { id: string; source: string; target: string; label: string; kind: string }

const COL_W = 290;
const LABELLED_KINDS = new Set(["auth", "auth_failure", "logon", "exfil", "intel", "target"]);
const NODE_W = 190;
const NODE_H = 46;
const ROW_H = 74;
const TYPE_LABEL: Record<string, string> = {
  ip: "Source IP", user: "User", host: "Host", detection: "Detection", files: "Files", destination: "Destination",
  indicator: "Indicator", group: "Group",
};
const LAYER_TITLES = ["Source addresses", "Accounts", "Hosts", "Activity (chronological)", "Targets & outcomes"];

function nodeColor(n: GraphNode): string {
  if (n.type === "detection") return `var(--sev-${n.severity ?? "info"})`;
  if (n.type === "ip" && n.external) return "var(--sev-high)";
  if (n.type === "destination" || n.type === "indicator") return "var(--sev-critical)";
  return "var(--accent)";
}

export function AttackGraph({ nodes, edges }: { nodes: GraphNode[]; edges: GraphEdge[] }) {
  const [selected, setSelected] = useState<string | null>(null);
  const layout = useMemo(() => {
    const layers = [...new Set(nodes.map((n) => n.layer))].sort();
    const pos: Record<string, { x: number; y: number }> = {};
    for (const n of nodes) pos[n.id] = { x: 20 + layers.indexOf(n.layer) * COL_W, y: 44 + n.row * ROW_H };
    const width = 40 + layers.length * COL_W;
    const height = 60 + Math.max(1, ...nodes.map((n) => n.row + 1)) * ROW_H;
    return { pos, width, height, layers };
  }, [nodes]);
  const sel = nodes.find((n) => n.id === selected) ?? null;
  const related = new Set(edges.filter((e) => e.source === selected || e.target === selected).flatMap((e) => [e.source, e.target]));

  const ordered = [...nodes].sort((a, b) => a.layer - b.layer || a.row - b.row);
  return (
    <div className="stack">
      <div className="graph-wrap has-fallback" style={{ border: "1px solid var(--border)" }}>
        <svg width={layout.width} height={layout.height} role="img" aria-label="Attack graph derived from incident evidence">
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--axis)" />
            </marker>
          </defs>
          {layout.layers.map((l, i) => (
            <text key={l} x={20 + i * COL_W} y={22} className="graph-edge-label" style={{ fontWeight: 600, fontSize: 11 }}>{LAYER_TITLES[l] ?? ""}</text>
          ))}
          {edges.map((e) => {
            const a = layout.pos[e.source];
            const b = layout.pos[e.target];
            if (!a || !b) return null;
            const sameCol = a.x === b.x;
            const x1 = sameCol ? a.x + NODE_W / 2 : a.x + NODE_W;
            const y1 = sameCol ? a.y + NODE_H : a.y + NODE_H / 2;
            const x2 = sameCol ? b.x + NODE_W / 2 : b.x;
            const y2 = sameCol ? b.y : b.y + NODE_H / 2;
            const d = sameCol ? `M${x1},${y1} L${x2},${y2 - 2}` : `M${x1},${y1} C${x1 + 40},${y1} ${x2 - 40},${y2} ${x2 - 2},${y2}`;
            const dim = selected && !(e.source === selected || e.target === selected);
            return (
              <g key={e.id} opacity={dim ? 0.2 : 1}>
                <path d={d} className={`graph-edge ${e.kind === "sequence" ? "seq" : ""}`} markerEnd="url(#arrow)" />
                {!sameCol && (LABELLED_KINDS.has(e.kind) || selected) && !dim && (
                  <text x={(x1 + x2) / 2} y={(y1 + y2) / 2 - 5} textAnchor="middle" className="graph-edge-label">{e.label}</text>)}
              </g>
            );
          })}
          {nodes.map((n) => {
            const p = layout.pos[n.id];
            const dim = selected && selected !== n.id && !related.has(n.id);
            return (
              <g key={n.id} className={`graph-node ${selected === n.id ? "selected" : ""}`} transform={`translate(${p.x},${p.y})`}
                opacity={dim ? 0.3 : 1} tabIndex={0} role="button" aria-label={`${TYPE_LABEL[n.type] ?? n.type}: ${n.label}`}
                onClick={() => setSelected(selected === n.id ? null : n.id)}
                onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && setSelected(selected === n.id ? null : n.id)} style={{ cursor: "pointer" }}>
                <rect width={NODE_W} height={NODE_H} rx={7} />
                <rect width={4} height={NODE_H} rx={2} fill={nodeColor(n)} stroke="none" />
                <text x={12} y={18} style={{ fontSize: 10, fill: "var(--muted)", textTransform: "uppercase" }}>{TYPE_LABEL[n.type] ?? n.type}</text>
                <text x={12} y={35} style={{ fontWeight: 600 }}>{n.label.length > 24 ? n.label.slice(0, 23) + "…" : n.label}</text>
              </g>
            );
          })}
        </svg>
      </div>
      {sel && (
        <div className="notice">
          <div className="row"><strong>{TYPE_LABEL[sel.type] ?? sel.type}: {sel.label}</strong>{sel.severity && <SeverityBadge severity={sel.severity} />}</div>
          {sel.sublabel && <div className="text-2 mt-8">{sel.sublabel}</div>}
          {sel.detection_id && <Link to={`/detections/${sel.detection_id}`} className="small">Open detection #{sel.detection_id}</Link>}
          {sel.items && <ul className="small">{sel.items.slice(0, 12).map((i) => <li key={i} className="wrap-anywhere">{i}</li>)}</ul>}
          <div className="small muted mt-8">Connections: {edges.filter((e) => e.source === sel.id || e.target === sel.id).map((e) => e.label).join(" · ")}</div>
        </div>
      )}
      <div className="graph-fallback">
        <p className="muted small">Graph shown as a list on small screens.</p>
        <ol className="timeline">
          {ordered.map((n) => (
            <li key={n.id} style={{ gridTemplateColumns: "1fr" }}>
              <div><span className="badge">{TYPE_LABEL[n.type] ?? n.type}</span> <strong className="wrap-anywhere">{n.label}</strong> {n.severity && <SeverityBadge severity={n.severity} />}</div>
              <div className="small muted">{edges.filter((e) => e.source === n.id).map((e) => `${e.label} → ${nodes.find((x) => x.id === e.target)?.label}`).join("; ")}</div>
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}
