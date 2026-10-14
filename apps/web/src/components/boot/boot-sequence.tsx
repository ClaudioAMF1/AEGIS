"use client";

import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { useCallback, useEffect, useMemo, useState } from "react";

interface Health {
  status: string;
  version: string;
  checks: Record<string, string>;
  pipeline_mode: string;
}

// Shield outline split into fragments that fly in and lock together.
const FRAGMENTS = [
  "M200 60 L290 92",
  "M290 92 L290 170",
  "M290 170 C290 225 250 262 200 282",
  "M200 282 C150 262 110 225 110 170",
  "M110 170 L110 92",
  "M110 92 L200 60",
];

// Circuit traces converging on the shield from the edges of the viewport.
const TRACES = [
  "M0 120 H70 L95 145 H110",
  "M0 230 H60 L90 200 H118",
  "M400 110 H330 L305 135 H290",
  "M400 240 H345 L318 212 H282",
  "M140 0 V30 L165 55 V70",
  "M260 0 V25 L238 48 V68",
  "M200 340 V300 L200 282",
];

const NODES: [number, number][] = [
  [70, 120], [60, 230], [330, 110], [345, 240], [140, 30], [260, 25], [200, 300],
];

function useHealth() {
  const [health, setHealth] = useState<Health | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    fetch("/api/v1/health", { signal: controller.signal, cache: "no-store" })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
      .then((data: Health) => setHealth(data))
      .catch(() => {
        if (!controller.signal.aborted) setFailed(true);
      });
    return () => controller.abort();
  }, []);
  return { health, failed };
}

/**
 * Opening sequence. Never blocks: it is an overlay that can be skipped with a click, Enter,
 * Escape or the "pular" button, and it is reduced to a short fade when the user prefers
 * reduced motion.
 */
export function BootSequence({ onDone }: { onDone: () => void }) {
  const reduce = useReducedMotion();
  const [phase, setPhase] = useState<"build" | "log" | "exit">("build");
  const { health, failed } = useHealth();
  const finish = useCallback(() => setPhase("exit"), []);

  useEffect(() => {
    const timers = reduce
      ? [setTimeout(() => setPhase("exit"), 600)]
      : [setTimeout(() => setPhase("log"), 1700), setTimeout(() => setPhase("exit"), 3500)];
    return () => timers.forEach(clearTimeout);
  }, [reduce]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (["Escape", "Enter", " "].includes(event.key)) finish();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [finish]);

  const scatter = useMemo(
    () =>
      FRAGMENTS.map((_, i) => {
        const angle = (i / FRAGMENTS.length) * Math.PI * 2 + 0.6;
        return { x: Math.cos(angle) * 170, y: Math.sin(angle) * 150, rotate: (i % 2 ? 1 : -1) * 40 };
      }),
    [],
  );

  const lines = [
    ["kernel", "aegis console", "ok"],
    ["api", health ? `v${health.version} · ${health.status}` : failed ? "indisponível" : "…", health ? "ok" : failed ? "fail" : "wait"],
    ["database", health?.checks.database ?? (failed ? "—" : "…"), health?.checks.database === "ok" ? "ok" : failed ? "fail" : "wait"],
    ["pipeline", health?.pipeline_mode ?? (failed ? "—" : "…"), health ? "ok" : failed ? "fail" : "wait"],
  ] as const;

  return (
    <AnimatePresence onExitComplete={onDone}>
      {phase !== "exit" ? (
        <motion.div
          key="boot"
          className="fixed inset-0 z-50 grid cursor-pointer place-items-center overflow-hidden bg-ground"
          onClick={finish}
          initial={{ opacity: 1 }}
          exit={{ opacity: 0, transition: { duration: reduce ? 0.2 : 0.55, ease: [0.7, 0, 0.3, 1] } }}
          role="dialog"
          aria-label="Inicialização do AEGIS"
        >
          <motion.div
            className="hairline-grid pointer-events-none absolute inset-0"
            initial={{ opacity: 0 }}
            animate={{ opacity: 0.18 }}
            transition={{ duration: 1.2 }}
          />
          <motion.div
            className="relative flex flex-col items-center"
            exit={reduce ? undefined : { scale: 7, opacity: 0, transition: { duration: 0.6, ease: [0.7, 0, 0.84, 0] } }}
          >
            <svg viewBox="0 0 400 340" className="w-[min(420px,80vw)]" aria-hidden>
              {TRACES.map((d, i) => (
                <motion.path
                  key={d}
                  d={d}
                  fill="none"
                  stroke="var(--dim)"
                  strokeWidth={1}
                  initial={{ pathLength: 0, opacity: 0 }}
                  animate={{ pathLength: 1, opacity: 1 }}
                  transition={{ duration: reduce ? 0 : 0.9, delay: reduce ? 0 : 0.08 * i, ease: "easeOut" }}
                />
              ))}
              {NODES.map(([cx, cy], i) => (
                <motion.circle
                  key={`${cx}-${cy}`}
                  cx={cx}
                  cy={cy}
                  r={2}
                  fill="var(--accent)"
                  initial={{ opacity: 0, scale: 0 }}
                  animate={{ opacity: [0, 1, 0.5], scale: 1 }}
                  transition={{ duration: 0.6, delay: reduce ? 0 : 0.5 + 0.07 * i }}
                />
              ))}
              {FRAGMENTS.map((d, i) => (
                <motion.path
                  key={d}
                  d={d}
                  fill="none"
                  stroke="var(--text)"
                  strokeWidth={3}
                  initial={reduce ? false : { x: scatter[i].x, y: scatter[i].y, rotate: scatter[i].rotate, opacity: 0 }}
                  animate={{ x: 0, y: 0, rotate: 0, opacity: 1 }}
                  transition={{ duration: 0.85, delay: 0.35 + i * 0.06, ease: [0.16, 1, 0.3, 1] }}
                  style={{ transformBox: "fill-box", transformOrigin: "center" }}
                />
              ))}
              <motion.path
                d="M200 92 L262 114 V170 C262 208 236 234 200 250 C164 234 138 208 138 170 V114 Z"
                fill="none"
                stroke="var(--accent)"
                strokeWidth={2}
                initial={{ pathLength: 0 }}
                animate={{ pathLength: 1 }}
                transition={{ duration: reduce ? 0 : 0.7, delay: reduce ? 0 : 1.05, ease: "easeInOut" }}
              />
              <motion.path
                d="M200 128 V214 M168 171 H232"
                stroke="var(--text)"
                strokeWidth={2}
                initial={{ pathLength: 0, opacity: 0 }}
                animate={{ pathLength: 1, opacity: 1 }}
                transition={{ duration: reduce ? 0 : 0.4, delay: reduce ? 0 : 1.45 }}
              />
            </svg>
            <motion.p
              className="mt-2 text-[28px] leading-none font-medium tracking-[10px] text-text"
              initial={{ opacity: 0, letterSpacing: "24px" }}
              animate={{ opacity: 1, letterSpacing: "10px" }}
              transition={{ duration: reduce ? 0 : 0.8, delay: reduce ? 0 : 1.2 }}
            >
              AEGIS
            </motion.p>
            <motion.p
              className="eyebrow mt-2"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: reduce ? 0 : 1.5 }}
            >
              autonomous cyber defense platform
            </motion.p>
            <div className="mt-5 h-[76px] w-[min(340px,80vw)] text-2xs" aria-live="polite">
              {phase === "log" || reduce
                ? lines.map(([name, value, state], i) => (
                    <motion.p
                      key={name}
                      className="m-0 flex justify-between gap-4 border-b border-border/50 py-[2px]"
                      initial={{ opacity: 0, x: -6 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.12 }}
                    >
                      <span className="text-muted">{name}</span>
                      <span className="truncate text-text">{value}</span>
                      <span
                        className={
                          state === "ok" ? "text-accent" : state === "fail" ? "text-critical" : "text-dim"
                        }
                      >
                        [{state === "ok" ? " ok " : state === "fail" ? "fail" : " .. "}]
                      </span>
                    </motion.p>
                  ))
                : null}
            </div>
          </motion.div>
          <button
            onClick={(event) => {
              event.stopPropagation();
              finish();
            }}
            className="absolute right-5 bottom-5 text-2xs text-muted hover:text-text"
          >
            pular ↵
          </button>
        </motion.div>
      ) : null}
    </AnimatePresence>
  );
}
