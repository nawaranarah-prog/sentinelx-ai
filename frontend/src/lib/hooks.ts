import { useQuery, type UseQueryOptions } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api } from "./api";
import { useSession } from "./session";

/** Workspace-scoped query: the active workspace id is part of the cache key. */
export function useWsQuery<T = any>(key: unknown[], path: string | null, opts: Partial<UseQueryOptions<T>> = {}) {
  const { workspaceId } = useSession();
  return useQuery<T>({
    queryKey: ["ws", workspaceId, ...key],
    queryFn: () => api<T>(path as string),
    enabled: !!workspaceId && !!path && (opts.enabled ?? true),
    ...opts,
  } as UseQueryOptions<T>);
}

export function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

export function useMediaQuery(query: string): boolean {
  const [match, setMatch] = useState(() => typeof window !== "undefined" && !!window.matchMedia?.(query).matches);
  useEffect(() => {
    const mq = window.matchMedia?.(query);
    if (!mq) return;
    const on = () => setMatch(mq.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, [query]);
  return match;
}
