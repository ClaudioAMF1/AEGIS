import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

interface PanelProps {
  title: ReactNode;
  meta?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  scanlines?: boolean;
  id?: string;
}

/** Terminal-style panel: a 27px title bar with "lights", hairline border, quiet surface. */
export function Panel({
  title,
  meta,
  actions,
  children,
  className,
  bodyClassName,
  scanlines,
  id,
}: PanelProps) {
  return (
    <section
      id={id}
      className={cn("flex min-w-0 flex-col border border-border bg-surface", className)}
    >
      <header className="flex h-[27px] shrink-0 items-center gap-2.5 border-b border-border px-3 text-xs text-muted">
        <span className="flex gap-1" aria-hidden="true">
          <i className="block size-[5px] rounded-full border border-dim" />
          <i className="block size-[5px] rounded-full border border-dim" />
          <i className="block size-[5px] rounded-full border border-dim" />
        </span>
        <h2 className="truncate text-xs font-normal text-muted">{title}</h2>
        {meta ? <span className="truncate text-2xs text-dim">{meta}</span> : null}
        {actions ? <div className="ml-auto flex items-center gap-2">{actions}</div> : null}
      </header>
      <div className={cn("min-h-0 flex-1 p-3", scanlines && "scanlines", bodyClassName)}>
        {children}
      </div>
    </section>
  );
}

export function PageHeader({
  path,
  title,
  description,
  actions,
}: {
  path: string;
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <p className="text-sm">
          <span className="text-accent">→</span> <span className="text-muted">~/aegis/</span>
          {path}
        </p>
        <h1 className="mt-1 text-[22px] leading-tight font-medium tracking-[-0.7px]">{title}</h1>
        {description ? <p className="mt-1 max-w-3xl text-sm text-muted">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}
