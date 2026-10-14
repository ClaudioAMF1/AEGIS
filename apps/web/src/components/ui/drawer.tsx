"use client";

import { X } from "lucide-react";
import { type ReactNode, useEffect } from "react";

/** Right-hand detail panel. Overlay on small screens, docked column on large ones. */
export function Drawer({
  open,
  title,
  onClose,
  children,
}: {
  open: boolean;
  title: ReactNode;
  onClose: () => void;
  children: ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <aside
      aria-label="Detalhes"
      className="fixed inset-y-0 right-0 z-40 flex w-[min(560px,100%)] flex-col border-l border-dim bg-ground shadow-2xl shadow-black/50"
    >
      <header className="flex h-11 shrink-0 items-center gap-3 border-b border-border px-4">
        <div className="min-w-0 flex-1 truncate text-sm">{title}</div>
        <button onClick={onClose} aria-label="Fechar detalhes" className="text-muted hover:text-text">
          <X className="size-4" />
        </button>
      </header>
      <div className="min-h-0 flex-1 overflow-y-auto p-4">{children}</div>
    </aside>
  );
}
