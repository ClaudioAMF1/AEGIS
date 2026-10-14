"use client";

import { useSyncExternalStore } from "react";

import type { RealtimeState } from "@/lib/realtime";
import { type Theme, useUi } from "@/lib/store";
import type { Dashboard, Me } from "@/lib/types";
import { cn } from "@/lib/utils";

const THEMES: { value: Theme; label: string }[] = [
  { value: "noite", label: "noite" },
  { value: "fosforo", label: "fósforo" },
  { value: "papel", label: "papel" },
];

function subscribeClock(onTick: () => void) {
  const id = setInterval(onTick, 1000);
  return () => clearInterval(id);
}

const clockSnapshot = () => Math.floor(Date.now() / 1000);

function Clock() {
  const seconds = useSyncExternalStore(subscribeClock, clockSnapshot, () => null);
  const now = seconds === null ? null : new Date(seconds * 1000);
  return (
    <time className="tabular text-text" suppressHydrationWarning>
      {now ? now.toISOString().slice(11, 19) : "--:--:--"}
      <span className="text-dim"> utc</span>
    </time>
  );
}

export function StatusBar({
  me,
  dashboard,
  realtime,
  lastEventAt,
}: {
  me: Me;
  dashboard: Dashboard | undefined;
  realtime: RealtimeState;
  lastEventAt: number | null;
}) {
  const { theme, setTheme, motion, setMotion } = useUi();
  const eps = dashboard?.metrics.find((m) => m.key === "events_per_second")?.value;
  const pipeline = dashboard?.pipeline;
  const realtimeLabel = { open: "conectado", connecting: "conectando", closed: "offline" }[realtime];

  return (
    <footer className="mt-auto flex flex-wrap items-center justify-between gap-x-6 gap-y-2 border-t border-border px-4 py-2 text-2xs lg:px-6">
      <div className="flex flex-col">
        <span className="text-sm">
          {me.email.split("@")[0]}
          <span className="text-muted">@aegis</span>
        </span>
        <span className="text-dim">atalhos: g+d central · g+a alertas · g+i incidentes</span>
      </div>
      <dl className="m-0 flex flex-wrap gap-x-7 gap-y-1">
        <div>
          <dt className="tracking-[0.6px] text-muted">TEMPO REAL</dt>
          <dd className="m-0 flex items-center gap-1.5 text-warm">
            <i
              className={cn(
                "block size-1 rounded-full",
                realtime === "open" ? "animate-pulse-dot bg-accent" : "bg-dim",
              )}
            />
            {realtimeLabel}
            {lastEventAt ? <span className="text-dim">· {new Date(lastEventAt).toISOString().slice(11, 19)}</span> : null}
          </dd>
        </div>
        <div>
          <dt className="tracking-[0.6px] text-muted">PIPELINE</dt>
          <dd className={cn("m-0", pipeline && !pipeline.healthy ? "text-critical" : "text-warm")}>
            {pipeline ? `${pipeline.mode}${pipeline.backlog !== null ? ` · fila ${pipeline.backlog}` : ""}` : "—"}
          </dd>
        </div>
        <div>
          <dt className="tracking-[0.6px] text-muted">EVENTOS/S</dt>
          <dd className="m-0 text-warm tabular">{eps ?? "—"}</dd>
        </div>
        <div>
          <dt className="tracking-[0.6px] text-muted">RELÓGIO</dt>
          <dd className="m-0">
            <Clock />
          </dd>
        </div>
      </dl>
      <div className="flex items-center gap-4">
        <button
          onClick={() => setMotion(!motion)}
          className="flex items-center gap-1.5 text-muted hover:text-text"
          aria-pressed={motion}
        >
          <i className={cn("block size-1 rounded-full", motion ? "bg-accent" : "bg-dim")} />
          movimento {motion ? "on" : "off"}
        </button>
        <div role="radiogroup" aria-label="Tema" className="flex gap-2">
          {THEMES.map((t) => (
            <button
              key={t.value}
              role="radio"
              aria-checked={theme === t.value}
              onClick={() => setTheme(t.value)}
              className={cn(theme === t.value ? "text-text" : "text-dim hover:text-muted")}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>
    </footer>
  );
}
