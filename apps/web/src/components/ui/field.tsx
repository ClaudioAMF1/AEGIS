import type { InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

const control =
  "h-7 w-full min-w-0 border border-border bg-ground px-2 text-xs text-text placeholder:text-dim focus:border-accent focus:outline-none";

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn(control, className)} {...props} />;
}

export function Textarea({ className, ...props }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={cn(control, "h-auto py-1.5 leading-relaxed", className)} {...props} />;
}

export function Select({ className, children, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={cn(control, "pr-6", className)} {...props}>
      {children}
    </select>
  );
}

export function Field({
  label,
  hint,
  children,
  className,
  htmlFor,
}: {
  label: string;
  hint?: ReactNode;
  children: ReactNode;
  className?: string;
  htmlFor?: string;
}) {
  return (
    <div className={cn("flex min-w-0 flex-col gap-1", className)}>
      <label htmlFor={htmlFor} className="eyebrow">
        {label}
      </label>
      {children}
      {hint ? <span className="text-2xs text-dim">{hint}</span> : null}
    </div>
  );
}

export function Facts({ items, className }: { items: [string, ReactNode][]; className?: string }) {
  return (
    <dl className={cn("text-sm", className)}>
      {items.map(([term, value]) => (
        <div key={term} className="grid grid-cols-[minmax(96px,128px)_minmax(0,1fr)] gap-2.5 py-0.5">
          <dt className="text-muted">{term}</dt>
          <dd className="m-0 min-w-0 break-words">{value ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}
