import { severityDot } from "@/components/ui/badge";
import { SEVERITIES, severityLabel } from "@/lib/format";
import type { Severity } from "@/lib/types";
import { cn } from "@/lib/utils";

/** Proportional strip of counts per severity, with a labelled legend (never color alone). */
export function SeverityStrip({ counts }: { counts: Partial<Record<Severity, number>> }) {
  const total = SEVERITIES.reduce((sum, s) => sum + (counts[s] ?? 0), 0);
  return (
    <div>
      <div className="flex h-2 gap-[2px] bg-raised" aria-hidden>
        {total > 0
          ? SEVERITIES.filter((s) => counts[s]).map((s) => (
              <span key={s} className={cn("block h-full", severityDot[s])} style={{ flex: counts[s] }} />
            ))
          : null}
      </div>
      <ul className="m-0 mt-2 flex list-none flex-wrap gap-x-4 gap-y-1 p-0 text-2xs">
        {SEVERITIES.map((s) => (
          <li key={s} className="flex items-center gap-1.5">
            <i className={cn("block size-[6px] rounded-full", severityDot[s])} aria-hidden />
            <span className="text-muted">{severityLabel[s]}</span>
            <span className="tabular text-text">{counts[s] ?? 0}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
