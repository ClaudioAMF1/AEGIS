"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Play, RotateCcw } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/field";
import { ErrorState, Loading } from "@/components/ui/states";
import { api } from "@/lib/api";
import { formatTime } from "@/lib/format";
import { usePermission } from "@/lib/session";
import { useUi } from "@/lib/store";
import type { Scenario, Simulation } from "@/lib/types";

/** Runs synthetic scenarios through the real pipeline. Visible in Demo mode only. */
export function DemoLauncher({ compact = false }: { compact?: boolean }) {
  const client = useQueryClient();
  const allowed = usePermission("demo:run");
  const setMode = useUi((s) => s.setMode);
  const [speed, setSpeed] = useState(0);
  const scenarios = useQuery({
    queryKey: ["scenarios"],
    queryFn: () => api.get<Scenario[]>("/demo/scenarios"),
  });
  const simulations = useQuery({
    queryKey: ["simulations"],
    queryFn: () => api.get<Simulation[]>("/demo/simulations"),
    refetchInterval: (q) => (q.state.data?.some((s) => s.status === "running") ? 2000 : false),
  });
  const run = useMutation({
    mutationFn: (scenario: string) => api.post<Simulation>("/demo/run", { scenario, speed }),
    onSuccess: () => {
      setMode("demo");
      void client.invalidateQueries();
    },
  });
  const reset = useMutation({
    mutationFn: () => api.post<Record<string, number>>("/demo/reset"),
    onSuccess: () => void client.invalidateQueries(),
  });

  if (scenarios.isPending) return <Loading label="carregando cenários" />;
  if (scenarios.error) return <ErrorState error={scenarios.error} />;

  return (
    <div className="flex flex-col gap-3">
      {!allowed ? (
        <p className="text-2xs text-muted">Seu perfil (viewer) pode explorar dados demo, mas não carregar cenários.</p>
      ) : null}
      <div className="flex flex-wrap items-center gap-3 text-2xs">
        <label className="flex items-center gap-2 text-muted">
          reprodução
          <Select value={speed} onChange={(e) => setSpeed(Number(e.target.value))} className="w-auto">
            <option value={0}>instantânea</option>
            <option value={30}>tempo real ×30</option>
            <option value={120}>tempo real ×120</option>
          </Select>
        </label>
        <Button size="sm" variant="ghost" disabled={!allowed || reset.isPending} onClick={() => reset.mutate()}>
          <RotateCcw className="size-3" /> reiniciar dados demo
        </Button>
        {reset.data ? <span className="text-dim">removidos: {reset.data.events ?? 0} eventos</span> : null}
      </div>
      <ul className={compact ? "m-0 grid list-none gap-2 p-0 md:grid-cols-3" : "m-0 grid list-none gap-2 p-0"}>
        {scenarios.data.map((s) => (
          <li key={s.id} className="flex flex-col border border-border p-3">
            <p className="m-0 text-xs">{s.title}</p>
            <p className="m-0 mt-1 line-clamp-3 text-2xs text-muted">{s.description}</p>
            <p className="m-0 mt-2 text-2xs text-dim">
              {s.hosts.join(" · ")} · {Math.round(s.duration_seconds / 60)} min ·{" "}
              {s.expected.alerts_max === 0 ? "esperado: 0 alertas" : `${s.expected.rules?.length ?? 0} regras esperadas`}
            </p>
            <Button
              size="sm"
              variant="outline"
              className="mt-2 self-start"
              disabled={!allowed || run.isPending}
              onClick={() => run.mutate(s.id)}
            >
              <Play className="size-3" /> executar
            </Button>
          </li>
        ))}
      </ul>
      {run.error ? <ErrorState error={run.error} /> : null}
      {simulations.data && simulations.data.length > 0 ? (
        <div>
          <p className="eyebrow mb-1">execuções</p>
          <ul className="m-0 list-none p-0 text-2xs">
            {simulations.data.slice(0, compact ? 3 : 8).map((s) => (
              <li key={s.id} className="flex gap-3 border-b border-border/50 py-0.5">
                <span className="text-dim tabular">{formatTime(s.started_at)}</span>
                <span className="flex-1 truncate">{s.scenario}</span>
                <span className={s.status === "running" ? "text-medium" : s.status === "failed" ? "text-critical" : "text-muted"}>
                  {s.status}
                </span>
                <span className="text-muted tabular">{s.events_sent} ev</span>
                <span className="text-warm tabular">{s.alerts_created} al</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
