export function fmtTime(iso?: string | null, withSeconds = true): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}${withSeconds ? ":" + pad(d.getUTCSeconds()) : ""}`;
}

export function fmtRelative(iso?: string | null): string {
  if (!iso) return "never";
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} h ago`;
  return `${Math.floor(diff / 86400)} d ago`;
}

export function fmtBytes(n?: number | null): string {
  if (n === null || n === undefined) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return i === 0 ? `${v} B` : `${v.toFixed(1)} ${units[i]}`;
}

export function fmtNum(n?: number | null): string {
  return n === null || n === undefined ? "—" : n.toLocaleString("en-US");
}

export function fmtDuration(fromIso: string, toIso: string): string {
  const s = Math.max(0, (new Date(toIso).getTime() - new Date(fromIso).getTime()) / 1000);
  if (s < 60) return `${Math.round(s)} s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  if (s < 86400) return `${(s / 3600).toFixed(1)} h`;
  return `${(s / 86400).toFixed(1)} d`;
}

export const STATUS_LABEL: Record<string, string> = {
  NEW: "New", IN_PROGRESS: "In progress", CONTAINED: "Contained", RESOLVED: "Resolved", FALSE_POSITIVE: "False positive",
};
export const ROLE_LABEL: Record<string, string> = { ADMIN: "Admin", SOC_ANALYST: "SOC Analyst", VIEWER: "Viewer" };
