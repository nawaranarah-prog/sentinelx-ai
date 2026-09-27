import { useSearchParams, Link } from "react-router-dom";
import { useWsQuery } from "../lib/hooks";
import type { IncidentBrief, DetectionBrief } from "../lib/types";
import { Card, ErrorState, Loading, SeverityBadge, SidePanel } from "../components/ui";

interface Tech { id: string; name: string; tactic: string; description: string; detection_guidance: string; url: string; incident_count: number; detection_count: number }

function TechniquePanel({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useWsQuery<Tech & { incidents: (IncidentBrief & { reason: string; event_uids: string[] })[]; detections: DetectionBrief[] }>(["mitre-tech", id], `/api/mitre/techniques/${id}`);
  return (
    <SidePanel title={<span className="mono">{id}</span>} onClose={onClose}>
      {q.isLoading ? <Loading /> : q.data && (
        <div className="stack">
          <div><h2>{q.data.name}</h2><div className="muted">{q.data.tactic}</div></div>
          <p>{q.data.description}</p>
          <p className="small"><strong>Detection guidance:</strong> {q.data.detection_guidance}</p>
          <a href={q.data.url} target="_blank" rel="noreferrer noopener">View on attack.mitre.org</a>
          <h3>Observed in incidents ({q.data.incidents.length})</h3>
          {q.data.incidents.map((i) => (<div key={i.id} className="notice small"><Link to={`/incidents/${i.id}`}><strong>{i.number}</strong> {i.title}</Link><div className="mt-8">{i.reason}</div>
            <div className="mono muted">{i.event_uids.slice(0, 5).join(", ")}</div></div>))}
          <h3>Detections ({q.data.detections.length})</h3>
          {q.data.detections.slice(0, 20).map((d) => <div key={d.id} className="small"><Link to={`/detections/${d.id}`}>{d.title}</Link> <SeverityBadge severity={d.severity} /></div>)}
        </div>)}
    </SidePanel>
  );
}

export function MitrePage() {
  const [params, setParams] = useSearchParams();
  const q = useWsQuery<{ tactics: string[]; techniques: Tech[]; note: string }>(["mitre"], "/api/mitre/techniques");
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} />;
  const { tactics, techniques, note } = q.data!;
  const byTactic = tactics.map((t) => ({ tactic: t, items: techniques.filter((x) => x.tactic === t) })).filter((g) => g.items.length);
  const observed = techniques.filter((t) => t.incident_count || t.detection_count).length;
  const selected = params.get("technique");
  return (
    <div className="stack">
      <div className="page-head"><div><h1>MITRE ATT&CK coverage</h1><p>{observed} of {techniques.length} catalogued techniques observed in this workspace. {note}</p></div></div>
      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(230px, 1fr))" }}>
        {byTactic.map((g) => (
          <Card key={g.tactic} title={g.tactic} sub={`${g.items.filter((i) => i.detection_count).length} observed`}>
            <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
              {g.items.map((t) => (
                <li key={t.id} className="mb-8">
                  <button className="btn btn-ghost" onClick={() => setParams({ technique: t.id })}
                    style={{ height: "auto", width: "100%", textAlign: "left", whiteSpace: "normal", padding: "6px 8px", justifyContent: "flex-start",
                      border: t.detection_count ? "1px solid color-mix(in srgb, var(--sev-high) 50%, transparent)" : "1px solid var(--border)",
                      background: t.detection_count ? "color-mix(in srgb, var(--sev-high) 10%, transparent)" : undefined }}>
                    <span><span className="mono small">{t.id}</span> {t.name}
                      <div className="small muted">{t.detection_count ? `${t.detection_count} detection(s) · ${t.incident_count} incident(s)` : "Not observed"}</div></span>
                  </button>
                </li>))}
            </ul>
          </Card>))}
      </div>
      {selected && <TechniquePanel id={selected} onClose={() => setParams({})} />}
    </div>
  );
}
