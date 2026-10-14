import type { ReactNode } from "react";

import { formatNumber } from "@/lib/format";
import { cn } from "@/lib/utils";

export interface BarItem {
  key: string;
  label: ReactNode;
  value: number;
  /** Optional reserved status color class (severity); nominal lists use the single accent hue. */
  barClass?: string;
  href?: string;
}

/** Horizontal labelled bars: nominal categories share one hue; values always printed as text. */
export function BarList({ items, emptyLabel = "sem dados no período" }: { items: BarItem[]; emptyLabel?: string }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  if (items.length === 0) return <p className="text-2xs text-dim">{emptyLabel}</p>;
  return (
    <ul className="m-0 flex list-none flex-col gap-1.5 p-0">
      {items.map((item) => (
        <li key={item.key} className="grid grid-cols-[minmax(0,140px)_minmax(0,1fr)_auto] items-center gap-2 text-xs" title={`${item.key}: ${item.value}`}>
          <span className="truncate text-muted">{item.label}</span>
          <span className="h-2 bg-raised">
            <span
              className={cn("block h-full rounded-r-[2px]", item.barClass ?? "bg-accent")}
              style={{ width: `${(item.value / max) * 100}%` }}
            />
          </span>
          <span className="tabular text-text">{formatNumber(item.value)}</span>
        </li>
      ))}
    </ul>
  );
}
