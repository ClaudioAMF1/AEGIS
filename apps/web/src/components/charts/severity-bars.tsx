"use client";

import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { SEVERITIES, severityLabel } from "@/lib/format";
import type { Severity } from "@/lib/types";

const FILL: Record<Severity, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  informational: "var(--sev-info)",
};

/** Alerts over time stacked by severity (reserved status colours, always with a legend). */
export function SeverityBars({ data }: { data: ({ bucket: string } & Partial<Record<Severity, number>>)[] }) {
  const present = SEVERITIES.filter((s) => data.some((d) => d[s]));
  return (
    <div style={{ height: 220 }} role="img" aria-label="Alertas por período e severidade">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 6, right: 4, bottom: 0, left: -18 }}>
          <CartesianGrid stroke="var(--border)" strokeOpacity={0.5} vertical={false} />
          <XAxis dataKey="bucket" tick={{ fill: "var(--muted)", fontSize: 9 }} tickFormatter={(v: string) => v.slice(5)} axisLine={{ stroke: "var(--border)" }} tickLine={false} />
          <YAxis allowDecimals={false} tick={{ fill: "var(--muted)", fontSize: 9 }} axisLine={false} tickLine={false} width={44} />
          <Tooltip
            cursor={{ fill: "var(--raised)" }}
            content={({ active, payload, label }) =>
              active && payload?.length ? (
                <div className="border border-dim bg-ground px-2 py-1 text-2xs">
                  <p className="m-0 text-muted">{String(label)}</p>
                  {payload.map((p) => (
                    <p key={String(p.dataKey)} className="m-0 text-text">{severityLabel[p.dataKey as Severity]}: {String(p.value)}</p>
                  ))}
                </div>
              ) : null
            }
          />
          <Legend formatter={(value: string) => <span className="text-2xs text-muted">{severityLabel[value as Severity]}</span>} iconSize={7} />
          {present.map((s) => (
            <Bar key={s} dataKey={s} stackId="sev" fill={FILL[s]} stroke="var(--surface)" strokeWidth={1} isAnimationActive={false} maxBarSize={28} />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
