import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, setWorkspaceId } from "./api";
import type { Me, Role, Workspace } from "./types";

interface SessionValue {
  me: Me | null;
  loading: boolean;
  workspace: Workspace | null;
  workspaceId: number | null;
  role: Role | null;
  isAdmin: boolean;
  isAnalyst: boolean;
  refreshMe: () => Promise<Me | null>;
  switchWorkspace: (id: number) => void;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, fullName: string) => Promise<void>;
  logout: () => Promise<void>;
  theme: "dark" | "light";
  setTheme: (t: "dark" | "light") => void;
}

const SessionContext = createContext<SessionValue | null>(null);
const WS_KEY = "sx-ws";

function readStored(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}
function writeStored(key: string, value: string | null) {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch {
    /* storage unavailable (private mode) */
  }
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const [workspaceId, setWsState] = useState<number | null>(() => Number(readStored(WS_KEY)) || null);
  const [theme, setThemeState] = useState<"dark" | "light">(
    () => (document.documentElement.getAttribute("data-theme") as "dark" | "light") || "dark",
  );

  const chooseWorkspace = useCallback((user: Me | null, preferred: number | null) => {
    if (!user || user.workspaces.length === 0) return null;
    const ok = user.workspaces.find((w) => w.id === preferred);
    return ok ? ok.id : user.workspaces[0].id;
  }, []);

  const applyWorkspace = useCallback((id: number | null) => {
    setWorkspaceId(id);
    setWsState(id);
    writeStored(WS_KEY, id ? String(id) : null);
  }, []);

  const refreshMe = useCallback(async () => {
    try {
      const user = await api<Me>("/api/auth/me", { workspace: false });
      setMe(user);
      applyWorkspace(chooseWorkspace(user, Number(readStored(WS_KEY)) || null));
      return user;
    } catch {
      setMe(null);
      applyWorkspace(null);
      return null;
    } finally {
      setLoading(false);
    }
  }, [applyWorkspace, chooseWorkspace]);

  useEffect(() => {
    refreshMe();
    const onUnauthorized = () => {
      setMe(null);
      qc.clear();
    };
    window.addEventListener("sx:unauthorized", onUnauthorized);
    return () => window.removeEventListener("sx:unauthorized", onUnauthorized);
  }, [refreshMe, qc]);

  const wsQuery = useQuery({
    queryKey: ["workspace", workspaceId],
    queryFn: () => api<Workspace>("/api/workspaces/current"),
    enabled: !!me && !!workspaceId,
    refetchInterval: 30_000,
  });

  const switchWorkspace = useCallback((id: number) => {
    applyWorkspace(id);
    qc.invalidateQueries();
  }, [applyWorkspace, qc]);

  const login = useCallback(async (email: string, password: string) => {
    await api("/api/auth/login", { body: { email, password }, workspace: false });
    qc.clear();
    await refreshMe();
  }, [qc, refreshMe]);

  const register = useCallback(async (email: string, password: string, fullName: string) => {
    await api("/api/auth/register", { body: { email, password, full_name: fullName }, workspace: false });
    qc.clear();
    await refreshMe();
  }, [qc, refreshMe]);

  const logout = useCallback(async () => {
    try {
      await api("/api/auth/logout", { method: "POST" });
    } finally {
      setMe(null);
      qc.clear();
    }
  }, [qc]);

  const setTheme = useCallback((t: "dark" | "light") => {
    document.documentElement.setAttribute("data-theme", t);
    writeStored("sx-theme", t);
    setThemeState(t);
  }, []);

  const role = (me?.workspaces.find((w) => w.id === workspaceId)?.role ?? null) as Role | null;
  const value = useMemo<SessionValue>(() => ({
    me, loading, workspace: wsQuery.data ?? null, workspaceId, role,
    isAdmin: role === "ADMIN", isAnalyst: role === "ADMIN" || role === "SOC_ANALYST",
    refreshMe, switchWorkspace, login, register, logout, theme, setTheme,
  }), [me, loading, wsQuery.data, workspaceId, role, refreshMe, switchWorkspace, login, register, logout, theme, setTheme]);

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionValue {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSession must be used inside SessionProvider");
  return ctx;
}
