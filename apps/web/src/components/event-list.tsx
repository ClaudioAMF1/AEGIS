import Link from "next/link";

import { DemoBadge } from "@/components/ui/badge";
import { categoryLabel, formatDateTime } from "@/lib/format";
import type { EventRow } from "@/lib/types";

/** Compact chronological list of events (timeline style). */
export function EventTimeline({ events, highlight }: { events: EventRow[]; highlight?: Set<string> }) {
  return (
    <ol className="m-0 list-none border-l border-border p-0 pl-3 text-2xs">
      {events.map((e) => (
        <li key={e.id} className="relative py-1">
          <span
            className={`absolute top-[9px] -left-[16px] block size-[7px] rounded-full border ${
              highlight?.has(e.id) ? "border-warm bg-warm" : "border-dim bg-ground"
            }`}
            aria-hidden
          />
          <div className="flex flex-wrap items-baseline gap-x-2">
            <span className="text-dim tabular">{formatDateTime(e.occurred_at)}</span>
            <span className="text-muted">{e.hostname}</span>
            <span className="text-accent">{categoryLabel[e.category] ?? e.category}.{e.action}</span>
            {e.is_synthetic ? <DemoBadge /> : null}
          </div>
          <Link href={`/events?focus=${e.id}`} className="block break-all text-text hover:text-accent">
            {e.summary}
          </Link>
        </li>
      ))}
    </ol>
  );
}
