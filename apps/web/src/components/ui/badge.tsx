import type { ReactNode } from "react";

import { alertStatusLabel, incidentStatusLabel, severityLabel } from "@/lib/format";
import type { AlertStatus, IncidentStatus, Severity } from "@/lib/types";
import { cn } from "@/lib/utils";

const severityText: Record<Severity, string> = {
  critical: "text-critical border-critical/50",
  high: "text-high border-high/50",
  medium: "text-medium border-medium/50",
  low: "text-low border-low/50",
  informational: "text-info border-info/50",
};

export const severityDot: Record<Severity, string> = {
  critical: "bg-critical",
  high: "bg-high",
  medium: "bg-medium",
  low: "bg-low",
  informational: "bg-info",
};

export function Badge({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 border border-border px-1.5 text-2xs leading-[16px] whitespace-nowrap",
        className,
      )}
    >
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge className={severityText[severity]}>
      <i className={cn("block size-[5px] rounded-full", severityDot[severity])} aria-hidden />
      {severityLabel[severity]}
    </Badge>
  );
}

const incidentTone: Record<IncidentStatus, string> = {
  new: "text-warm",
  investigating: "text-medium",
  contained: "text-accent",
  resolved: "text-muted",
  false_positive: "text-dim",
};

export function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  return <Badge className={incidentTone[status]}>{incidentStatusLabel[status]}</Badge>;
}

const alertTone: Record<AlertStatus, string> = {
  open: "text-warm",
  acknowledged: "text-medium",
  closed: "text-dim",
};

export function AlertStatusBadge({ status }: { status: AlertStatus }) {
  return <Badge className={alertTone[status]}>{alertStatusLabel[status]}</Badge>;
}

export function DemoBadge({ className }: { className?: string }) {
  return (
    <Badge className={cn("border-demo/60 text-demo", className)}>
      <span aria-hidden>◆</span> demo
    </Badge>
  );
}

export function AttackTag({ technique }: { technique: string }) {
  const path = technique.replace(".", "/");
  return (
    <a
      href={`https://attack.mitre.org/techniques/${path}/`}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex border border-border px-1.5 text-2xs leading-[16px] text-muted hover:border-accent hover:text-accent"
      title={`MITRE ATT&CK ${technique}`}
    >
      {technique}
    </a>
  );
}
