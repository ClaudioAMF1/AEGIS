"use client";

import Link from "next/link";
import { useState } from "react";

import { formatTime } from "@/lib/format";
import type { ProcessNode } from "@/lib/types";
import { cn } from "@/lib/utils";

function hasFlag(node: ProcessNode): boolean {
  return node.flagged || node.children.some(hasFlag);
}

function Node({ node, depth }: { node: ProcessNode; depth: number }) {
  const flaggedBranch = hasFlag(node);
  const [open, setOpen] = useState(flaggedBranch || depth < 2);
  return (
    <li className="relative">
      <div className={cn("flex items-baseline gap-2 py-[2px]", node.flagged && "text-warm")}>
        {node.children.length ? (
          <button onClick={() => setOpen(!open)} aria-expanded={open} className="w-3 text-dim hover:text-text" aria-label={open ? "Recolher" : "Expandir"}>
            {open ? "▾" : "▸"}
          </button>
        ) : (
          <span className="w-3 text-dim">·</span>
        )}
        <span className={cn("text-xs", node.flagged ? "text-warm" : flaggedBranch ? "text-text" : "text-muted")}>{node.name}</span>
        <span className="text-2xs text-dim tabular">pid {node.pid}</span>
        {node.user ? <span className="text-2xs text-dim">{node.user}</span> : null}
        {node.started_at ? <span className="text-2xs text-dim tabular">{formatTime(node.started_at)}</span> : null}
        {node.flagged ? <span className="text-2xs text-warm">◆ detecção</span> : null}
      </div>
      {node.command_line ? (
        <p className="m-0 ml-5 truncate text-2xs text-muted" title={node.command_line}>
          {node.event_id ? <Link href={`/events?focus=${node.event_id}`} className="hover:text-accent">$ {node.command_line}</Link> : `$ ${node.command_line}`}
        </p>
      ) : null}
      {open && node.children.length ? (
        <ul className="m-0 ml-[5px] list-none border-l border-border p-0 pl-3">
          {node.children.map((child) => <Node key={`${child.pid}-${child.event_id}`} node={child} depth={depth + 1} />)}
        </ul>
      ) : null}
    </li>
  );
}

export function ProcessTree({ roots, onlyFlagged }: { roots: ProcessNode[]; onlyFlagged?: boolean }) {
  const visible = onlyFlagged ? roots.filter(hasFlag) : roots;
  if (visible.length === 0) return <p className="text-2xs text-dim">nenhum processo no intervalo.</p>;
  return (
    <ul className="m-0 list-none p-0">
      {visible.map((root) => <Node key={`${root.pid}-${root.event_id}`} node={root} depth={0} />)}
    </ul>
  );
}
