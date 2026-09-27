import { useState, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useSession } from "../lib/session";
import { fmtTime, ROLE_LABEL } from "../lib/format";
import { Card, KV, Loading, useToast } from "../components/ui";

export function SettingsPage() {
  const { me, workspace } = useSession();
  if (!me || !workspace) return <Loading />;
  return <SettingsForm key={`${me.id}-${workspace.id}`} />;
}

function SettingsForm() {
  const { me, refreshMe, theme, setTheme, workspace, isAdmin, role } = useSession();
  const toast = useToast();
  const qc = useQueryClient();
  const [name, setName] = useState(me?.full_name ?? "");
  const [pw, setPw] = useState({ current: "", next: "", confirm: "" });
  const [wsForm, setWsForm] = useState({
    name: workspace?.name ?? "", start: workspace?.settings.business_hours?.[0] ?? 7, end: workspace?.settings.business_hours?.[1] ?? 20,
    window: workspace?.settings.correlation_window_minutes ?? 120, threshold: workspace?.settings.anomaly_if_threshold ?? 0.6,
  });
  const [newWs, setNewWs] = useState("");

  const saveProfile = async (e: FormEvent) => {
    e.preventDefault();
    try { await api("/api/auth/me", { method: "PATCH", body: { full_name: name, theme } }); await refreshMe(); toast("Profile saved"); }
    catch (err) { toast((err as Error).message, "error"); }
  };
  const changePw = async (e: FormEvent) => {
    e.preventDefault();
    if (pw.next !== pw.confirm) return toast("New passwords do not match", "error");
    try { await api("/api/auth/change-password", { body: { current_password: pw.current, new_password: pw.next } }); setPw({ current: "", next: "", confirm: "" }); toast("Password changed. Other sessions were signed out."); }
    catch (err) { toast((err as Error).message, "error"); }
  };
  const saveWs = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await api("/api/workspaces/current/settings", { method: "PATCH", body: { name: wsForm.name, business_hours: [Number(wsForm.start), Number(wsForm.end)], correlation_window_minutes: Number(wsForm.window), anomaly_if_threshold: Number(wsForm.threshold) } });
      await refreshMe(); qc.invalidateQueries(); toast("Workspace settings saved. Re-run analysis to apply them to existing data.");
    } catch (err) { toast((err as Error).message, "error"); }
  };
  const reanalyze = async () => {
    try { const s = await api<{ detections_created: number; incidents_created: number }>("/api/workspaces/current/reanalyze", { method: "POST" }); qc.invalidateQueries(); toast(`Analysis re-run: ${s.detections_created} new detections, ${s.incidents_created} new incidents.`); }
    catch (err) { toast((err as Error).message, "error"); }
  };
  const createWs = async (e: FormEvent) => {
    e.preventDefault();
    try { await api("/api/workspaces", { body: { name: newWs } }); setNewWs(""); await refreshMe(); toast("Workspace created — switch to it from the top bar."); }
    catch (err) { toast((err as Error).message, "error"); }
  };
  return (
    <div className="stack">
      <div className="page-head"><div><h1>Settings</h1><p>Profile, security and workspace configuration.</p></div></div>
      <div className="grid grid-2">
        <Card title="Profile">
          <KV items={[["Email", me?.email], ["Role in this workspace", role ? ROLE_LABEL[role] : "—"], ["Member since", fmtTime(me?.created_at, false)], ["Last login", fmtTime(me?.last_login_at, false)]]} />
          <form className="stack mt-16" onSubmit={saveProfile}>
            <div className="field"><label htmlFor="pname">Full name</label><input id="pname" className="input" value={name} onChange={(e) => setName(e.target.value)} /></div>
            <div className="field"><label htmlFor="ptheme">Theme</label><select id="ptheme" className="select" value={theme} onChange={(e) => setTheme(e.target.value as "dark" | "light")}><option value="dark">Dark</option><option value="light">Light</option></select></div>
            <button className="btn btn-primary" style={{ alignSelf: "flex-start" }}>Save profile</button>
          </form>
        </Card>
        <Card title="Change password" sub="Changing your password signs out all other sessions">
          <form className="stack" onSubmit={changePw}>
            <div className="field"><label htmlFor="pwc">Current password</label><input id="pwc" className="input" type="password" autoComplete="current-password" value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} /></div>
            <div className="field"><label htmlFor="pwn">New password</label><input id="pwn" className="input" type="password" autoComplete="new-password" value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} /><span className="hint">At least 10 characters with a letter and a digit.</span></div>
            <div className="field"><label htmlFor="pwr">Confirm new password</label><input id="pwr" className="input" type="password" autoComplete="new-password" value={pw.confirm} onChange={(e) => setPw({ ...pw, confirm: e.target.value })} /></div>
            <button className="btn btn-primary" style={{ alignSelf: "flex-start" }} disabled={!pw.current || !pw.next}>Change password</button>
          </form>
        </Card>
        <Card title="Workspace" sub={`${workspace?.mode} mode${workspace?.synthetic_data ? " · synthetic demo data" : ""}`}>
          {isAdmin ? (
            <form className="stack" onSubmit={saveWs}>
              <div className="field"><label htmlFor="wsn">Name</label><input id="wsn" className="input" value={wsForm.name} onChange={(e) => setWsForm({ ...wsForm, name: e.target.value })} /></div>
              <div className="row">
                <div className="field" style={{ flex: 1 }}><label htmlFor="bhs">Business hours start (UTC)</label><input id="bhs" className="input" type="number" min={0} max={23} value={wsForm.start} onChange={(e) => setWsForm({ ...wsForm, start: Number(e.target.value) })} /></div>
                <div className="field" style={{ flex: 1 }}><label htmlFor="bhe">End (UTC)</label><input id="bhe" className="input" type="number" min={1} max={24} value={wsForm.end} onChange={(e) => setWsForm({ ...wsForm, end: Number(e.target.value) })} /></div>
              </div>
              <div className="field"><label htmlFor="cw">Correlation window (minutes between related detections)</label><input id="cw" className="input" type="number" min={5} max={1440} value={wsForm.window} onChange={(e) => setWsForm({ ...wsForm, window: Number(e.target.value) })} /></div>
              <div className="field"><label htmlFor="ift">Isolation Forest decision threshold</label><input id="ift" className="input" type="number" min={0.4} max={0.9} step={0.01} value={wsForm.threshold} onChange={(e) => setWsForm({ ...wsForm, threshold: Number(e.target.value) })} /><span className="hint">Anomaly score above which a window is flagged (with a corroborating deviation). Default 0.60.</span></div>
              <div className="row"><button className="btn btn-primary">Save workspace settings</button><button type="button" className="btn" onClick={reanalyze}>Re-run analysis</button></div>
            </form>
          ) : <p className="muted">Only workspace admins can change these settings.</p>}
        </Card>
        <Card title="New workspace" sub="A separate, isolated tenant for another dataset">
          <form className="row" onSubmit={createWs}><label htmlFor="nws" className="sr-only">Workspace name</label>
            <input id="nws" className="input" style={{ flex: 1 }} placeholder="e.g. Production SIEM export" value={newWs} onChange={(e) => setNewWs(e.target.value)} />
            <button className="btn" disabled={newWs.trim().length < 2}>Create</button></form>
        </Card>
      </div>
    </div>
  );
}
