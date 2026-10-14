"use client";

import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { formatNumber, formatTime } from "@/lib/format";

export interface VolumePoint {
  start: string;
  total: number;
}

/** Single-series volume over time: sage line, faint fill, crosshair tooltip, recessive axes. */
export function VolumeChart({ data, height = 160, label = "eventos" }: { data: VolumePoint[]; height?: number; label?: string }) {
  return (
    <div style={{ height }} role="img" aria-label={`${label} por intervalo`}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 6, right: 4, bottom: 0, left: -18 }}>
          <defs>
            <linearGradient id="volume-fill" x1="0" x2="0" y1="0" y2="1">
              <stop offset="0%" stopColor="var(--plot)" stopOpacity={0.28} />
              <stop offset="100%" stopColor="var(--plot)" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="var(--border)" strokeOpacity={0.5} vertical={false} />
          <XAxis
            dataKey="start"
            tickFormatter={(v: string) => formatTime(v).slice(0, 5)}
            tick={{ fill: "var(--muted)", fontSize: 9 }}
            axisLine={{ stroke: "var(--border)" }}
            tickLine={false}
            minTickGap={36}
          />
          <YAxis
            allowDecimals={false}
            tick={{ fill: "var(--muted)", fontSize: 9 }}
            axisLine={false}
            tickLine={false}
            width={44}
          />
          <Tooltip
            cursor={{ stroke: "var(--dim)", strokeWidth: 1 }}
            content={({ active, payload }) =>
              active && payload?.length ? (
                <div className="border border-dim bg-ground px-2 py-1 text-2xs">
                  <p className="m-0 text-muted">{formatTime(String(payload[0].payload.start))}</p>
                  <p className="m-0 text-text">
                    {formatNumber(Number(payload[0].value))} {label}
                  </p>
                </div>
              ) : null
            }
          />
          <Area
            type="monotone"
            dataKey="total"
            stroke="var(--plot)"
            strokeWidth={2}
            fill="url(#volume-fill)"
            isAnimationActive={false}
            activeDot={{ r: 4, stroke: "var(--surface)", strokeWidth: 2, fill: "var(--plot)" }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
