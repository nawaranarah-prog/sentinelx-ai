import { useEffect, useState, type ReactNode } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  BarChart3, Bell, Bot, BookOpen, Crosshair, Database, FileText, Grid3x3, HeartPulse, LayoutDashboard,
  ListChecks, LogOut, Menu, Moon, Radar, ScrollText, Search, Settings, Shield, ShieldAlert, Sun, Upload, Users, Server,
} from "lucide-react";
import { useSession } from "../lib/session";
import { useWsQuery } from "../lib/hooks";
import { api } from "../lib/api";
import { fmtRelative, ROLE_LABEL } from "../lib/format";
import type { Notification } from "../lib/types";
import { CommandPalette } from "./CommandPalette";
import { SidePanel } from "./ui";

export function Logo({ size = 30 }: { size?: number }) {
  return (
    <svg className="brand-mark" width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <rect width="32" height="32" rx="7" fill="#12233b" />
      <path d="M16 5l9 3.5v6.8c0 5.6-3.8 9.9-9 11.7-5.2-1.8-9-6.1-9-11.7V8.5L16 5z" fill="none" stroke="#5598e7" strokeWidth="2" />
      <path d="M11.5 16.5l3 3 6-6.5" fill="none" stroke="#e6edf6" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

type NavItem = { to: string; label: string; icon: ReactNode; admin?: boolean };
const NAV: { section: string; items: NavItem[] }[] = [
  { section: "Operations", items: [
    { to: "/", label: "Dashboard", icon: <LayoutDashboard /> },
    { to: "/incidents", label: "Incidents", icon: <ShieldAlert /> },
    { to: "/detections", label: "Detections", icon: <Crosshair /> },
    { to: "/events", label: "Event Explorer", icon: <Database /> },
  ] },
  { section: "Investigate", items: [
    { to: "/assistant", label: "AI Assistant", icon: <Bot /> },
    { to: "/entities", label: "Users & Hosts", icon: <Users /> },
    { to: "/threat-intel", label: "Threat Intelligence", icon: <Radar /> },
    { to: "/mitre", label: "MITRE ATT&CK", icon: <Grid3x3 /> },
    { to: "/analytics", label: "Analytics", icon: <BarChart3 /> },
  ] },
  { section: "Data & Reporting", items: [
    { to: "/ingest", label: "Upload Security Data", icon: <Upload /> },
    { to: "/reports", label: "Reports", icon: <FileText /> },
    { to: "/health", label: "System Health", icon: <HeartPulse /> },
  ] },
  { section: "Administration", items: [
    { to: "/admin/users", label: "Users & Roles", icon: <Users />, admin: true },
    { to: "/admin/rules", label: "Detection Rules", icon: <ListChecks />, admin: true },
    { to: "/admin/knowledge", label: "Knowledge Base", icon: <BookOpen />, admin: true },
    { to: "/admin/audit", label: "Audit Log", icon: <ScrollText />, admin: true },
    { to: "/admin/ai", label: "AI Configuration", icon: <Bot />, admin: true },
    { to: "/admin/system", label: "System Configuration", icon: <Server />, admin: true },
  ] },
];

function Sidebar({ open, onNavigate }: { open: boolean; onNavigate: () => void }) {
  const { isAdmin, workspace } = useSession();
  return (
    <aside className={`sidebar ${open ? "open" : ""}`} aria-label="Primary">
      <div className="brand">
        <Logo />
        <div><div className="brand-name">SENTINELX AI</div><div className="brand-tag">Detect. Investigate. Understand.</div></div>
      </div>
      <nav className="nav">
        {NAV.map((sec) => {
          const items = sec.items.filter((i) => !i.admin || isAdmin);
          if (!items.length) return null;
          return (
            <div key={sec.section}>
              <div className="nav-section">{sec.section}</div>
              {items.map((i) => (
                <NavLink key={i.to} to={i.to} end={i.to === "/"} onClick={onNavigate}>{i.icon}<span>{i.label}</span></NavLink>
              ))}
            </div>
          );
        })}
      </nav>
      <div className="sidebar-foot">
        {workspace?.mode === "DEMO" ? (
          <span><strong>DEMO MODE</strong> · Nova Bank is fictional; all telemetry in this workspace is synthetic.</span>
        ) : (<span>ANALYST MODE · your uploaded telemetry</span>)}
      </div>
    </aside>
  );
}

function Notifications({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const q = useWsQuery<{ unread: number; items: Notification[] }>(["notifications"], "/api/notifications");
  const readAll = useMutation({
    mutationFn: () => api("/api/notifications/read-all", { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["ws"] }),
  });
  const open = async (n: Notification) => {
    if (!n.is_read) await api(`/api/notifications/${n.id}/read`, { method: "POST" });
    qc.invalidateQueries({ queryKey: ["ws"] });
    onClose();
    if (n.link) navigate(n.link);
  };
  return (
    <SidePanel title="Notifications" onClose={onClose}>
      <div className="row between mb-8">
        <span className="muted small">{q.data?.unread ?? 0} unread</span>
        <button className="btn btn-sm" onClick={() => readAll.mutate()} disabled={!q.data?.unread}>Mark all read</button>
      </div>
      {q.data?.items.length === 0 && <p className="muted">No notifications yet.</p>}
      <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
        {q.data?.items.map((n) => (
          <li key={n.id}>
            <button className="btn btn-ghost" style={{ height: "auto", width: "100%", justifyContent: "flex-start", textAlign: "left", padding: 10, whiteSpace: "normal", opacity: n.is_read ? 0.65 : 1 }}
              onClick={() => open(n)}>
              <span style={{ flex: 1 }}>
                <span className="row"><span className={`badge sev-${n.severity}`}>{n.kind.replace(/_/g, " ")}</span><span className="muted small">{fmtRelative(n.created_at)}</span></span>
                <strong style={{ display: "block", marginTop: 4 }}>{n.title}</strong>
                <span className="muted small">{n.body}</span>
              </span>
            </button>
          </li>
        ))}
      </ul>
    </SidePanel>
  );
}

function Topbar({ onMenu, onSearch }: { onMenu: () => void; onSearch: () => void }) {
  const { me, workspaceId, switchWorkspace, logout, theme, setTheme, role } = useSession();
  const navigate = useNavigate();
  const [notifOpen, setNotifOpen] = useState(false);
  const notif = useWsQuery<{ unread: number }>(["notifications"], "/api/notifications?unread_only=true", { refetchInterval: 30_000 });
  const ai = useWsQuery<{ mode: string; label: string }>(["ai-status"], "/api/ai/status", { staleTime: 60_000 });
  return (
    <header className="topbar">
      <button className="btn btn-ghost icon-btn menu-btn" onClick={onMenu} aria-label="Open navigation"><Menu /></button>
      <label className="sr-only" htmlFor="ws-switch">Workspace</label>
      <select id="ws-switch" className="select ws-switch" value={workspaceId ?? ""} onChange={(e) => { switchWorkspace(Number(e.target.value)); navigate("/"); }}>
        {me?.workspaces.map((w) => <option key={w.id} value={w.id}>{w.mode === "DEMO" ? "[DEMO] " : ""}{w.name}</option>)}
      </select>
      <span className="badge hide-sm">{role ? ROLE_LABEL[role] : ""}</span>
      <div className="spacer" />
      <button className="btn hide-sm" onClick={onSearch} aria-label="Search (Ctrl+K)"><Search /> Search <span className="muted small">Ctrl K</span></button>
      <button className="btn btn-ghost icon-btn show-sm" onClick={onSearch} aria-label="Search"><Search /></button>
      {ai.data && (
        <NavLink to="/assistant" className={`badge ${ai.data.mode === "LIVE" ? "st-ok" : "st-warn"} hide-sm`} title={ai.data.label}>
          <Bot size={13} aria-hidden="true" /> {ai.data.mode === "LIVE" ? "LIVE AI" : "LOCAL AI"}
        </NavLink>
      )}
      <button className="btn btn-ghost icon-btn" onClick={() => setNotifOpen(true)} aria-label={`Notifications, ${notif.data?.unread ?? 0} unread`}>
        <Bell />{!!notif.data?.unread && <span className="notif-count">{notif.data.unread > 99 ? "99+" : notif.data.unread}</span>}
      </button>
      <button className="btn btn-ghost icon-btn" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}>
        {theme === "dark" ? <Sun /> : <Moon />}
      </button>
      <NavLink to="/settings" className="btn btn-ghost icon-btn" aria-label="Settings"><Settings /></NavLink>
      <button className="btn btn-ghost icon-btn" onClick={async () => { await logout(); navigate("/login"); }} aria-label="Sign out"><LogOut /></button>
      {notifOpen && <Notifications onClose={() => setNotifOpen(false)} />}
    </header>
  );
}

export function Layout() {
  const [drawer, setDrawer] = useState(false);
  const [palette, setPalette] = useState(false);
  const location = useLocation();
  const { workspace } = useSession();
  useEffect(() => setDrawer(false), [location.pathname]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((p) => !p);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return (
    <div className="shell">
      <a className="skip-link" href="#main">Skip to content</a>
      <Sidebar open={drawer} onNavigate={() => setDrawer(false)} />
      <div className={`drawer-backdrop ${drawer ? "open" : ""}`} onClick={() => setDrawer(false)} aria-hidden="true" />
      <div className="main">
        <Topbar onMenu={() => setDrawer(true)} onSearch={() => setPalette(true)} />
        {workspace?.mode === "DEMO" && (
          <div className="notice info" style={{ borderRadius: 0, borderLeft: 0, borderRight: 0, borderTop: 0, display: "flex", gap: 8, alignItems: "center" }}>
            <Shield size={15} aria-hidden="true" /> <span><strong>DEMO MODE</strong> — Nova Bank (fictional). Every event, indicator and incident here is synthetic and generated for demonstration; detections were produced by the live engine.</span>
          </div>
        )}
        <main id="main" className="content" tabIndex={-1}><Outlet /></main>
      </div>
      {palette && <CommandPalette onClose={() => setPalette(false)} />}
    </div>
  );
}
