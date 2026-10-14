import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

/** Metric tile. The definition/source are always shown on hover/focus: no number without context. */
export function Stat({
  label,
  value,
  unit,
  definition,
  source,
  tone = "text",
  children,
}: {
  label: string;
  value: ReactNode;
  unit?: string;
  definition?: string;
  source?: string;
  tone?: "text" | "warm" | "accent" | "critical";
  children?: ReactNode;
}) {
  const color = {
    text: "text-text",
    warm: "text-warm",
    accent: "text-accent",
    critical: "text-critical",
  }[tone];
  return (
    <div
      className="group relative flex min-w-0 flex-col border border-border bg-surface px-3 py-2.5"
      tabIndex={definition ? 0 : undefined}
      aria-describedby={undefined}
    >
      <p className="eyebrow m-0 truncate">{label}</p>
      <p className={cn("m-0 mt-1 text-[22px] leading-none tracking-[-0.5px] tabular", color)}>
        {value}
        {unit ? <span className="ml-1 text-2xs tracking-normal text-muted">{unit}</span> : null}
      </p>
      {children}
      {definition ? (
        <p className="pointer-events-none absolute top-full right-0 left-0 z-20 mt-1 hidden border border-dim bg-ground p-2 text-2xs text-muted group-hover:block group-focus:block">
          {definition}
          {source ? <span className="mt-1 block text-dim">fonte: {source}</span> : null}
        </p>
      ) : null}
    </div>
  );
}
