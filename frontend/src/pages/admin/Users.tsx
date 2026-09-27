import { useState, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useWsQuery } from "../../lib/hooks";
import { useSession } from "../../lib/session";
import { fmtRelative, ROLE_LABEL } from "../../lib/format";
import type { Member, Role } from "../../lib/types";
import { Card, Loading, useToast } from "../../components/ui";

export function AdminUsersPage() {
  const { me } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const members = useWsQuery<Member[]>(["members"], "/api/members");
  const roles = useWsQuery<{ name: Role; description: string; permissions: string[] }[]>(["roles"], "/api/members/roles");
  const [form, setForm] = useState({ email: "", full_name: "", role: "SOC_ANALYST", password: "" });
  const refresh = () => qc.invalidateQueries({ queryKey: ["ws"] });
  const run = async (fn: () => Promise<unknown>, ok: string) => { try { await fn(); refresh(); toast(ok); } catch (e) { toast((e as Error).message, "error"); } };
  const add = (e: FormEvent) => { e.preventDefault(); run(() => api("/api/members", { body: { ...form, password: form.password || undefined } }), "Member added").then(() => setForm({ email: "", full_name: "", role: "SOC_ANALYST", password: "" })); };
  return (
    <div className="stack">
      <div className="page-head"><div><h1>Users & roles</h1><p>Role-based access is enforced by the API on every request; the UI only mirrors it.</p></div></div>
      <div className="grid grid-main-side">
        <Card title="Workspace members" flush>
          {members.isLoading ? <Loading /> : (
            <div className="table-wrap"><table className="table responsive"><thead><tr><th>User</th><th>Role</th><th>Last login</th><th /></tr></thead>
              <tbody>{members.data?.map((m) => (<tr key={m.id}>
                <td data-label="User"><strong>{m.full_name}</strong><div className="small muted">{m.email}</div></td>
                <td data-label="Role"><label className="sr-only" htmlFor={`role-${m.id}`}>Role for {m.email}</label>
                  <select id={`role-${m.id}`} className="select" value={m.role} onChange={(e) => run(() => api(`/api/members/${m.id}`, { method: "PATCH", body: { role: e.target.value } }), "Role changed")}>
                    {Object.entries(ROLE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></td>
                <td data-label="Last login" className="small">{fmtRelative(m.last_login_at)}</td>
                <td data-label="">{m.email !== me?.email && <button className="btn btn-sm btn-danger" onClick={() => confirm(`Remove ${m.email} from this workspace?`) && run(() => api(`/api/members/${m.id}`, { method: "DELETE" }), "Member removed")}>Remove</button>}</td>
              </tr>))}</tbody></table></div>)}
        </Card>
        <div className="stack">
          <Card title="Add member" sub="Existing accounts are added directly; new emails need an initial password">
            <form className="stack" onSubmit={add}>
              <div className="field"><label htmlFor="memail">Email</label><input id="memail" className="input" type="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></div>
              <div className="field"><label htmlFor="mname">Full name</label><input id="mname" className="input" value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} /></div>
              <div className="field"><label htmlFor="mrole">Role</label><select id="mrole" className="select" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
                {Object.entries(ROLE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></div>
              <div className="field"><label htmlFor="mpw">Initial password (new accounts only)</label><input id="mpw" className="input" type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></div>
              <button className="btn btn-primary" disabled={!form.email}>Add member</button>
            </form>
          </Card>
          <Card title="Roles">
            {roles.data?.map((r) => (<div key={r.name} className="mb-8"><strong>{ROLE_LABEL[r.name]}</strong><div className="small text-2">{r.description}</div>
              <div className="row mt-8">{r.permissions.map((p) => <span key={p} className="chip mono" style={{ fontSize: 11 }}>{p}</span>)}</div></div>))}
          </Card>
        </div>
      </div>
    </div>
  );
}
