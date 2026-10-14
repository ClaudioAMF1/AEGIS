"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import { categoryLabel, formatDateTime, formatTime } from "@/lib/format";
import type { EventRow } from "@/lib/types";

const LANE = 34;
const PAD_LEFT = 110;
const PAD_RIGHT = 16;
const AXIS = 22;

/**
 * Swimlane timeline: one lane per host, one mark per event. Events that are evidence of
 * detections are drawn in the warm accent; context events are dim. Drag horizontally to select
 * a time window, which filters the event list.
 */
export function TimelineChart({
  events,
  evidence,
  onWindow,
  onSelect,
}: {
  events: EventRow[];
  evidence: Set<string>;
  onWindow: (window: [number, number] | null) => void;
  onSelect: (id: string) => void;
}) {
  const ref = useRef<SVGSVGElement>(null);
  const [width, setWidth] = useState(900);
  const [drag, setDrag] = useState<[number, number] | null>(null);
  const [brush, setBrush] = useState<[number, number] | null>(null);
  const [hover, setHover] = useState<EventRow | null>(null);

  useEffect(() => {
    const element = ref.current;
    if (!element) return;
    const observer = new ResizeObserver(([entry]) => setWidth(entry.contentRect.width));
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const hosts = useMemo(() => [...new Set(events.map((e) => e.hostname))].sort(), [events]);
  const [t0, t1] = useMemo(() => {
    const times = events.map((e) => new Date(e.occurred_at).getTime());
    const min = Math.min(...times);
    const max = Math.max(...times);
    const pad = Math.max(30_000, (max - min) * 0.03);
    return [min - pad, max + pad];
  }, [events]);
  const height = AXIS + hosts.length * LANE + 8;
  const x = (t: number) => PAD_LEFT + ((t - t0) / (t1 - t0)) * (width - PAD_LEFT - PAD_RIGHT);
  const tAt = (px: number) => t0 + ((px - PAD_LEFT) / (width - PAD_LEFT - PAD_RIGHT)) * (t1 - t0);
  const ticks = Array.from({ length: 6 }, (_, i) => t0 + ((t1 - t0) * i) / 5);

  const localX = (clientX: number) => {
    const rect = ref.current?.getBoundingClientRect();
    return rect ? clientX - rect.left : 0;
  };

  if (events.length === 0) return null;

  return (
    <div className="relative">
      <svg
        ref={ref}
        width="100%"
        height={height}
        className="block cursor-crosshair select-none"
        onPointerDown={(e) => {
          const px = localX(e.clientX);
          if (px < PAD_LEFT) return;
          setDrag([px, px]);
        }}
        onPointerMove={(e) => drag && setDrag([drag[0], localX(e.clientX)])}
        onPointerUp={() => {
          if (!drag) return;
          const [a, b] = [Math.min(...drag), Math.max(...drag)];
          setDrag(null);
          if (b - a < 6) {
            setBrush(null);
            onWindow(null);
            return;
          }
          setBrush([a, b]);
          onWindow([tAt(a), tAt(b)]);
        }}
        role="img"
        aria-label={`Linha do tempo com ${events.length} eventos em ${hosts.length} host(s)`}
      >
        {ticks.map((t) => (
          <g key={t}>
            <line x1={x(t)} x2={x(t)} y1={AXIS - 4} y2={height} stroke="var(--border)" strokeOpacity={0.5} />
            <text x={x(t)} y={12} textAnchor="middle" fontSize={9} fill="var(--muted)">{formatTime(new Date(t).toISOString())}</text>
          </g>
        ))}
        {hosts.map((host, i) => (
          <g key={host} transform={`translate(0 ${AXIS + i * LANE})`}>
            <line x1={PAD_LEFT} x2={width - PAD_RIGHT} y1={LANE / 2} y2={LANE / 2} stroke="var(--border)" />
            <text x={0} y={LANE / 2 + 3} fontSize={10} fill="var(--text)">{host.length > 15 ? `${host.slice(0, 14)}…` : host}</text>
          </g>
        ))}
        {events.map((e) => {
          const lane = hosts.indexOf(e.hostname);
          const cx = x(new Date(e.occurred_at).getTime());
          const cy = AXIS + lane * LANE + LANE / 2;
          const isEvidence = evidence.has(e.id);
          return (
            <circle
              key={e.id}
              cx={cx}
              cy={cy + (isEvidence ? 0 : ((e.id.charCodeAt(0) % 5) - 2) * 2.5)}
              r={isEvidence ? 4.5 : 2.5}
              fill={isEvidence ? "var(--warm)" : "var(--dim)"}
              stroke="var(--surface)"
              strokeWidth={isEvidence ? 2 : 0}
              className="cursor-pointer"
              onPointerEnter={() => setHover(e)}
              onPointerLeave={() => setHover(null)}
              onClick={(ev) => {
                ev.stopPropagation();
                onSelect(e.id);
              }}
            />
          );
        })}
        {drag ? (
          <rect x={Math.min(...drag)} y={AXIS - 4} width={Math.abs(drag[1] - drag[0])} height={height - AXIS + 4} fill="var(--accent)" fillOpacity={0.1} stroke="var(--accent)" strokeOpacity={0.5} />
        ) : brush ? (
          <rect x={brush[0]} y={AXIS - 4} width={brush[1] - brush[0]} height={height - AXIS + 4} fill="var(--accent)" fillOpacity={0.07} stroke="var(--accent)" strokeOpacity={0.4} />
        ) : null}
      </svg>
      {hover ? (
        <div className="pointer-events-none absolute top-0 right-0 max-w-[60%] border border-dim bg-ground px-2 py-1 text-2xs">
          <p className="m-0 text-muted">{formatDateTime(hover.occurred_at)} · {hover.hostname}</p>
          <p className="m-0 text-accent">{categoryLabel[hover.category] ?? hover.category}.{hover.action}</p>
          <p className="m-0 truncate">{hover.summary}</p>
        </div>
      ) : null}
      <ul className="m-0 mt-2 flex list-none gap-4 p-0 text-2xs text-muted">
        <li className="flex items-center gap-1.5"><i className="block size-2 rounded-full bg-warm" /> evidência de detecção</li>
        <li className="flex items-center gap-1.5"><i className="block size-1.5 rounded-full bg-dim" /> contexto</li>
        <li className="text-dim">arraste para filtrar um intervalo · clique para abrir o evento</li>
      </ul>
    </div>
  );
}
