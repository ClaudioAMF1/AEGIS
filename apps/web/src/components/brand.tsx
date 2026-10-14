import { cn } from "@/lib/utils";

/** AEGIS mark: a shield built from the same hairline geometry as the rest of the interface. */
export function AegisMark({ className, title = "AEGIS" }: { className?: string; title?: string }) {
  return (
    <svg viewBox="0 0 64 64" className={cn("size-6", className)} role="img" aria-label={title}>
      <path
        d="M32 5 L54 13 V31 C54 45 44 54 32 59 C20 54 10 45 10 31 V13 Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinejoin="miter"
      />
      <path d="M32 15 L45 20 V31 C45 40 39 46 32 49 C25 46 19 40 19 31 V20 Z" fill="none"
        stroke="var(--accent)" strokeWidth="2" />
      <path d="M32 22 V42 M24 32 H40" stroke="currentColor" strokeWidth="2" />
    </svg>
  );
}

export function Wordmark({ className }: { className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-2.5", className)}>
      <AegisMark />
      <span className="text-sm">
        aegis<span className="text-muted">.soc</span>
      </span>
    </span>
  );
}
