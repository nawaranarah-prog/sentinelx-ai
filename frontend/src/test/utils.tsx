import type { ReactElement } from "react";
import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { vi } from "vitest";
import { SessionProvider } from "../lib/session";
import { ToastProvider } from "../components/ui";

export const ME = {
  id: 1, email: "ana@example.com", full_name: "Ana Analyst", settings: {}, created_at: "2026-09-01T00:00:00Z",
  last_login_at: null, workspaces: [{ id: 7, name: "Nova Bank (Demo)", mode: "DEMO", role: "SOC_ANALYST" }],
};
export const WORKSPACE = {
  ...ME.workspaces[0], settings: {}, created_at: "2026-09-01T00:00:00Z", last_pipeline_run_at: null,
  last_pipeline_stats: {}, counts: { events: 10, detections: 2, incidents: 1 }, synthetic_data: true,
};

type Handler = (url: string, init?: RequestInit) => unknown;

/** Mock fetch with a route table: keys are URL prefixes (longest match wins). */
export function mockApi(routes: Record<string, unknown | Handler>) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    const key = Object.keys(routes).filter((k) => url.startsWith(k)).sort((a, b) => b.length - a.length)[0];
    if (!key) return new Response(JSON.stringify({ detail: "Not found" }), { status: 404, headers: { "content-type": "application/json" } });
    const value = routes[key];
    const body = typeof value === "function" ? (value as Handler)(url, init) : value;
    if (body instanceof Response) return body;
    return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  });
  vi.stubGlobal("fetch", fn);
  return calls;
}

export function renderApp(ui: ReactElement, path = "/") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <ToastProvider><SessionProvider>{ui}</SessionProvider></ToastProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
