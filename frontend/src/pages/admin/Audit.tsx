import { useState } from "react";
import { Download } from "lucide-react";
import { download, qs } from "../../lib/api";
import { useDebounced, useWsQuery } from "../../lib/hooks";
import { fmtTime } from "../../lib/format";
import type { Paged } from "../../lib/types";
import { Card, JsonBlock, Loading, Pagination, SidePanel } from "../../components/ui";

interface Entry { id: number; action: string; user: string; target_type: string; target_id: string; details: Record<string, unknown>; ip_address: string; user_agent: string; created_at: string }

export function AdminAuditPage() {
  const [f, setF] = useState({ action: "", user: "", page: 1 });
  const [sel, setSel] = useState<Entry | null>(null);
  const user = useDebounced(f.user);
  const path = `/api/audit${qs({ action: f.action, user, page: f.page, page_size: 50 })}`;
  const q = useWsQuery<Paged<Entry> & { actions: string[] }>(["audit", path], path, { refetchInterval: 15_000, placeholderData: (p) => p });
  return (
    <div className="stack">
      <div className="page-head"><div><h1>Audit log</h1><p>Security-relevant actions in this workspace. Passwords, tokens and API keys are never recorded.</p></div>
        <div className="page-actions"><button className="btn" onClick={() => download(`/api/audit/export.csv${qs({ action: f.action, user })}`, "sentinelx_audit_log.csv")}><Download /> Export CSV</button></div></div>
      <Card flush>
        <div className="filters">
          <div className="field"><label htmlFor="aa">Action</label><select id="aa" className="select" value={f.action} onChange={(e) => setF({ ...f, action: e.target.value, page: 1 })}>
            <option value="">All actions</option>{q.data?.actions.map((a) => <option key={a}>{a}</option>)}</select></div>
          <div className="field"><label htmlFor="au">User</label><input id="au" className="input" value={f.user} onChange={(e) => setF({ ...f, user: e.target.value, page: 1 })} /></div>
        </div>
        {q.isLoading ? <Loading /> : (<>
          <div className="table-wrap"><table className="table responsive"><thead><tr><th>Time (UTC)</th><th>Action</th><th>User</th><th>Target</th><th>Source IP</th><th>Details</th></tr></thead>
            <tbody>{q.data?.items.map((a) => (<tr key={a.id} className="clickable" onClick={() => setSel(a)}>
              <td data-label="Time" className="small nowrap mono">{fmtTime(a.created_at)}</td><td data-label="Action"><span className="badge">{a.action}</span></td>
              <td data-label="User" className="small">{a.user || "—"}</td><td data-label="Target" className="small">{a.target_type} {a.target_id}</td>
              <td data-label="Source IP" className="small mono">{a.ip_address}</td><td data-label="Details" className="small truncate">{JSON.stringify(a.details)}</td></tr>))}</tbody></table></div>
          <Pagination page={f.page} pageSize={50} total={q.data?.total ?? 0} onPage={(p) => setF({ ...f, page: p })} /></>)}
      </Card>
      {sel && <SidePanel title={`${sel.action} · #${sel.id}`} onClose={() => setSel(null)}><p className="small muted">{fmtTime(sel.created_at)} UTC · {sel.user} · {sel.ip_address}</p><p className="small">{sel.user_agent}</p><JsonBlock value={sel.details} label="Audit details" /></SidePanel>}
    </div>
  );
}
