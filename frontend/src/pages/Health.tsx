import { useWsQuery } from "../lib/hooks";
import { fmtTime } from "../lib/format";
import { Card, ErrorState, HealthBadge, Loading } from "../components/ui";

export function HealthPage() {
  const q = useWsQuery<{ components: { name: string; status: string; detail: string; label?: string | null }[]; checked_at: string }>(["health"], "/api/system/health", { refetchInterval: 20_000 });
  return (
    <div className="stack">
      <div className="page-head"><div><h1>System health</h1><p>Real component checks for this deployment. Statuses: CONNECTED · DEGRADED · NOT CONFIGURED · ERROR.</p></div></div>
      {q.isLoading ? <Loading /> : q.error ? (
        <Card title="Components"><div className="row mb-8"><strong>Frontend</strong><HealthBadge status="CONNECTED" /></div><ErrorState error={q.error} onRetry={() => q.refetch()} />
          <p className="small muted mt-8">Backend: ERROR — the API did not respond, so no other component can be verified.</p></Card>
      ) : (
        <Card title="Components" sub={`Checked ${fmtTime(q.data!.checked_at)} UTC`} flush>
          <div className="table-wrap"><table className="table responsive"><thead><tr><th>Component</th><th>Status</th><th>Detail</th></tr></thead>
            <tbody>
              <tr><td data-label="Component"><strong>Frontend</strong></td><td data-label="Status"><HealthBadge status="CONNECTED" /></td><td data-label="Detail" className="small">This page is being served and rendered.</td></tr>
              {q.data!.components.map((c) => (<tr key={c.name}><td data-label="Component"><strong>{c.name}</strong></td><td data-label="Status"><HealthBadge status={c.status} /></td>
                <td data-label="Detail" className="small">{c.detail}{c.label && <> <span className="badge st-warn">{c.label}</span></>}</td></tr>))}
            </tbody></table></div>
        </Card>)}
    </div>
  );
}
