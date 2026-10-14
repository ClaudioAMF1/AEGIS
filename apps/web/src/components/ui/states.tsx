import type { ReactNode } from "react";

import { ApiError } from "@/lib/api";
import { cn } from "@/lib/utils";

export function Loading({ label = "carregando", className }: { label?: string; className?: string }) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn("flex items-center gap-2 py-6 text-xs text-muted", className)}
    >
      <span className="text-accent">$</span> {label}
      <span className="inline-block h-3 w-[7px] animate-blink bg-text align-[-2px]" aria-hidden />
    </div>
  );
}

export function ErrorState({
  error,
  onRetry,
  className,
}: {
  error: unknown;
  onRetry?: () => void;
  className?: string;
}) {
  const status = error instanceof ApiError ? error.status : null;
  const message =
    status === 403
      ? "Seu perfil não tem permissão para ver este conteúdo."
      : error instanceof Error
        ? error.message
        : "Erro inesperado.";
  return (
    <div role="alert" className={cn("border-l border-critical/60 py-2 pl-3 text-xs", className)}>
      <p className="text-critical">
        erro{status ? ` ${status}` : ""}: <span className="text-text">{message}</span>
      </p>
      {onRetry ? (
        <button onClick={onRetry} className="mt-1 text-2xs text-muted hover:text-text">
          ↻ tentar novamente
        </button>
      ) : null}
    </div>
  );
}

export function Empty({
  title,
  hint,
  action,
  className,
}: {
  title: string;
  hint?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("border-l border-border py-3 pl-3 text-xs", className)}>
      <p className="text-muted">{title}</p>
      {hint ? <p className="mt-1 text-2xs text-dim">{hint}</p> : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}

/** Renders the right state for a TanStack Query result. */
export function QueryState<T>({
  query,
  empty,
  isEmpty,
  children,
  loadingLabel,
}: {
  query: { data: T | undefined; error: unknown; isPending: boolean; refetch: () => unknown };
  empty?: ReactNode;
  isEmpty?: (data: T) => boolean;
  children: (data: T) => ReactNode;
  loadingLabel?: string;
}) {
  if (query.isPending) return <Loading label={loadingLabel} />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => query.refetch()} />;
  if (query.data === undefined) return null;
  if (isEmpty?.(query.data) && empty) return <>{empty}</>;
  return <>{children(query.data)}</>;
}
