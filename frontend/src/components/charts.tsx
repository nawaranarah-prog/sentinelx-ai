import { Area, AreaChart, Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { fmtTime } from "../lib/format";

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const sevVar = (s: string) => `var(--sev-${s})`;

const axisProps = {
  stroke: "var(--axis)",
  tick: { fill: "var(--muted)", fontSize: 11 },
  tickLine: false,
};
const tooltipStyle = {
  contentStyle: { background: "var(--surface)", border: "1px solid var(--border-strong)", borderRadius: 8, fontSize: 12, color: "var(--text)" },
  labelStyle: { color: "var(--text)", fontWeight: 600 },
  itemStyle: { color: "var(--text-2)" },
  cursor: { stroke: "var(--axis)", strokeWidth: 1 },
};

/** Events over time, stacked by severity (legend + hover tooltip; severity always named in text). */
export function EventsOverTime({ data, height = 240 }: { data: Record<string, any>[]; height?: number }) {
  const present = SEVERITY_ORDER.filter((s) => data.some((d) => d[s])).slice().reverse();
  return (
    <div role="img" aria-label="Events over time stacked by severity">
      <ResponsiveContainer width="100%" height={height}>
        <AreaChart data={data} margin={{ top: 8, right: 8, left: -12, bottom: 0 }}>
          <CartesianGrid stroke="var(--grid)" vertical={false} />
          <XAxis dataKey="bucket" {...axisProps} tickFormatter={(v) => fmtTime(v, false).slice(5, 13)} minTickGap={40} />
          <YAxis {...axisProps} allowDecimals={false} width={48} />
          <Tooltip {...tooltipStyle} labelFormatter={(v) => `${fmtTime(String(v), false)} UTC`} />
          <Legend wrapperStyle={{ fontSize: 12, color: "var(--text-2)" }} />
          {present.map((s) => (
            <Area key={s} type="monotone" dataKey={s} name={s} stackId="1" stroke={sevVar(s)} strokeWidth={2}
              fill={sevVar(s)} fillOpacity={0.28} isAnimationActive={false} />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

/** Horizontal single-series bar chart (no legend - the card title names the series). */
export function HBar({ data, height, label, onSelect }: {
  data: { key: string; count: number }[]; height?: number; label: string; onSelect?: (key: string) => void;
}) {
  const h = height ?? Math.max(120, data.length * 28 + 20);
  return (
    <div role="img" aria-label={label}>
      <ResponsiveContainer width="100%" height={h}>
        <BarChart data={data} layout="vertical" margin={{ top: 0, right: 16, left: 0, bottom: 0 }} barCategoryGap={4}>
          <CartesianGrid stroke="var(--grid)" horizontal={false} />
          <XAxis type="number" {...axisProps} allowDecimals={false} />
          <YAxis type="category" dataKey="key" {...axisProps} width={130} interval={0}
            tickFormatter={(v: string) => (v.length > 18 ? v.slice(0, 17) + "…" : v)} />
          <Tooltip {...tooltipStyle} cursor={{ fill: "var(--surface-3)" }} />
          <Bar dataKey="count" name="Count" fill="var(--series-1)" radius={[0, 4, 4, 0]} maxBarSize={18}
            isAnimationActive={false} onClick={(d: any) => onSelect?.(d.key)} style={{ cursor: onSelect ? "pointer" : "default" }} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/** Severity distribution as bars with severity colors and text labels on the axis. */
export function SeverityBars({ data, label }: { data: { key: string; count: number }[]; label: string }) {
  const ordered = SEVERITY_ORDER.map((s) => ({ key: s, count: data.find((d) => d.key === s)?.count ?? 0 })).filter((d) => d.count > 0);
  return (
    <div role="img" aria-label={label}>
      <ResponsiveContainer width="100%" height={Math.max(110, ordered.length * 30 + 16)}>
        <BarChart data={ordered} layout="vertical" margin={{ top: 0, right: 16, left: 0, bottom: 0 }}>
          <XAxis type="number" {...axisProps} allowDecimals={false} />
          <YAxis type="category" dataKey="key" {...axisProps} width={70} />
          <Tooltip {...tooltipStyle} cursor={{ fill: "var(--surface-3)" }} />
          <Bar dataKey="count" name="Count" radius={[0, 4, 4, 0]} maxBarSize={18} isAnimationActive={false}
            shape={(p: any) => <rect x={p.x} y={p.y} width={Math.max(0, p.width)} height={p.height} rx={3} fill={sevVar(p.payload.key)} />} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/** Vertical single-series column chart (e.g. anomaly score histogram, per-day counts). */
export function Columns({ data, xKey, label, height = 200, threshold }: {
  data: Record<string, any>[]; xKey: string; label: string; height?: number; threshold?: string;
}) {
  return (
    <div role="img" aria-label={label}>
      <ResponsiveContainer width="100%" height={height}>
        <BarChart data={data} margin={{ top: 8, right: 8, left: -12, bottom: 0 }} barCategoryGap={2}>
          <CartesianGrid stroke="var(--grid)" vertical={false} />
          <XAxis dataKey={xKey} {...axisProps} minTickGap={8} />
          <YAxis {...axisProps} allowDecimals={false} width={44} />
          <Tooltip {...tooltipStyle} cursor={{ fill: "var(--surface-3)" }} />
          <Bar dataKey="count" name="Count" radius={[4, 4, 0, 0]} maxBarSize={36} isAnimationActive={false}
            shape={(p: any) => (
              <rect x={p.x} y={p.y} width={Math.max(0, p.width)} height={Math.max(0, p.height)} rx={3}
                fill={threshold && Number(p.payload[xKey]) >= Number(threshold) ? "var(--sev-high)" : "var(--series-1)"} />
            )} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
