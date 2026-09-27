export class ApiError extends Error {
  status: number;
  errors?: { field: string; message: string }[];
  constructor(status: number, message: string, errors?: { field: string; message: string }[]) {
    super(message);
    this.status = status;
    this.errors = errors;
  }
}

const BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? "";
let workspaceId: number | null = null;

export function setWorkspaceId(id: number | null) {
  workspaceId = id;
}
export function getWorkspaceId() {
  return workspaceId;
}

type Options = { method?: string; body?: unknown; form?: FormData; signal?: AbortSignal; workspace?: boolean };

function headers(opts: Options): Record<string, string> {
  const h: Record<string, string> = { Accept: "application/json", "X-SentinelX-CSRF": "1" };
  if (opts.body !== undefined) h["Content-Type"] = "application/json";
  if (opts.workspace !== false && workspaceId) h["X-Workspace-ID"] = String(workspaceId);
  return h;
}

async function toError(res: Response): Promise<ApiError> {
  let message = `Request failed (${res.status})`;
  let errors;
  try {
    const data = await res.json();
    if (typeof data.detail === "string") message = data.detail;
    if (Array.isArray(data.errors)) {
      errors = data.errors;
      message = data.errors.map((e: { field: string; message: string }) => `${e.field || "input"}: ${e.message}`).join("; ");
    }
  } catch {
    /* non-JSON error body */
  }
  if (res.status === 401) window.dispatchEvent(new CustomEvent("sx:unauthorized"));
  return new ApiError(res.status, message, errors);
}

export async function api<T = any>(path: string, opts: Options = {}): Promise<T> {
  let res: Response;
  try {
    res = await fetch(BASE + path, {
      method: opts.method ?? (opts.body !== undefined || opts.form ? "POST" : "GET"),
      headers: headers(opts),
      body: opts.form ?? (opts.body !== undefined ? JSON.stringify(opts.body) : undefined),
      credentials: "same-origin",
      signal: opts.signal,
    });
  } catch (e) {
    if ((e as Error).name === "AbortError") throw e;
    throw new ApiError(0, "Cannot reach the SentinelX backend. Check that the API is running.");
  }
  if (!res.ok) throw await toError(res);
  if (res.status === 204) return undefined as T;
  const type = res.headers.get("content-type") ?? "";
  return (type.includes("application/json") ? res.json() : res.text()) as Promise<T>;
}

export async function fetchBlob(path: string): Promise<Blob> {
  const res = await fetch(BASE + path, { headers: headers({}), credentials: "same-origin" });
  if (!res.ok) throw await toError(res);
  return res.blob();
}

export async function download(path: string, filename: string) {
  const blob = await fetchBlob(path);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function qs(params: Record<string, unknown>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    if (Array.isArray(v)) v.forEach((x) => sp.append(k, String(x)));
    else sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}
