"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { BarList } from "@/components/charts/bar-list";
import { SeverityBars } from "@/components/charts/severity-bars";
import { AttackTag } from "@/components/ui/badge";
import { PageHeader, Panel } from "@/components/ui/panel";
import { Stat } from "@/components/ui/stat";
import { QueryState } from "@/components/ui/states";
import { api } from "@/lib/api";
import { categoryLabel, formatDateTime, formatDuration } from "@/lib/format";
import { useScope } from "@/lib/queries";
import type { Analytics } from "@/lib/types";
import { cn } from "@/lib/utils";

const PERIODS = [
  { hours: 24, label: "24h" },
  { hours: 168, label: "7d" },
  { hours: 720, label: "30d" },
];

const DEFINITIONS_PT: Record<string, string> = {
  events_by_host: "Eventos por host com horário de ocorrência no período.",
  alerts_by_severity: "Alertas criados no período, agrupados pela severidade da regra.",
  top_rules: "Regras ordenadas pelo número de alertas criados no período.",
  false_positive_rate: "Alertas rotulados como falso positivo ÷ alertas com qualquer rótulo (indeterminados excluídos).",
  time_to_detect: "alerts.created_at − alerts.first_event_at. Somente dados live (replays demo usam horários históricos).",
  time_to_triage: "alerts.triaged_at − alerts.created_at.",
  coverage: "Técnicas/táticas ATT&CK referenciadas por regras ativas. Indica intenção de cobertura, não eficácia validada.",
};

export function AnalyticsView() {
  const scope = useScope();
  const [hours, setHours] = useState(168);
  const query = useQuery({ queryKey: ["analytics", scope, hours], queryFn: () => api.get<Analytics>("/analytics", { scope, hours }) });
  return (
    <>
      <PageHeader
        path="metricas"
        title="Métricas de detecção"
        description="Cada métrica declara definição, fonte e período. Taxas exibem também o tamanho da amostra."
        actions={
          <div role="radiogroup" aria-label="Período" className="flex border border-border text-2xs">
            {PERIODS.map((p) => (
              <button key={p.hours} role="radio" aria-checked={hours === p.hours} onClick={() => setHours(p.hours)} className={cn("px-2 py-0.5", hours === p.hours ? "bg-raised text-text" : "text-muted hover:text-text")}>{p.label}</button>
            ))}
          </div>
        }
      />
      <QueryState query={query} loadingLabel="calculando métricas">
        {(a) => (
          <div className="flex flex-col gap-4">
            <p className="m-0 text-2xs text-dim">período: {formatDateTime(a.period.start)} → {formatDateTime(a.period.end)} · escopo {a.scope}</p>
            <dl className="m-0 grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-6">
              <Stat label="incidentes abertos no período" value={a.incidents.opened} definition="Incidentes cuja detecção ocorreu no período." source="incidents.detected_at" />
              <Stat label="incidentes resolvidos" value={a.incidents.resolved} definition="Incidentes do período hoje com status resolvido." source="incidents.status" />
              <Stat label="taxa de falso positivo" value={a.false_positive_rate.value === null ? "—" : `${a.false_positive_rate.value}%`} definition={`${DEFINITIONS_PT.false_positive_rate} Amostra: ${a.false_positive_rate.labelled} alerta(s) rotulado(s).`} source="alerts.disposition" />
              <Stat label="mediana até detecção" value={formatDuration(a.time_to_detect_seconds.median)} definition={`${DEFINITIONS_PT.time_to_detect} Amostras: ${a.time_to_detect_seconds.samples}.`} source="alerts" />
              <Stat label="mediana até triagem" value={formatDuration(a.time_to_triage_seconds.median)} definition={`${DEFINITIONS_PT.time_to_triage} Amostras: ${a.time_to_triage_seconds.samples}.`} source="alerts" />
              <Stat label="regras ativas" value={`${a.coverage.rules_enabled}/${a.coverage.rules_total}`} definition="Versões atuais habilitadas sobre o total carregado." source="detection_rules" />
            </dl>
            <div className="grid gap-4 xl:grid-cols-[2fr_1fr]">
              <Panel title="alertas por período" meta={DEFINITIONS_PT.alerts_by_severity}>
                <SeverityBars data={a.alerts_timeline} />
              </Panel>
              <Panel title="regras mais acionadas" meta="alertas no período">
                <BarList items={a.top_rules.map((r) => ({ key: r.rule_id, label: <span title={r.rule_id}>{r.title}</span>, value: r.alerts }))} />
              </Panel>
            </div>
            <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
              <Panel title="eventos por host" meta="top 20">
                <BarList items={Object.entries(a.events_by_host).map(([k, v]) => ({ key: k, label: k, value: v }))} />
              </Panel>
              <Panel title="eventos por categoria">
                <BarList items={Object.entries(a.events_by_category).map(([k, v]) => ({ key: k, label: categoryLabel[k] ?? k, value: v }))} />
              </Panel>
              <Panel title="cobertura att&ck" meta={`${a.coverage.techniques.length} técnicas · ${a.coverage.tactics.length} táticas`} className="lg:col-span-2 xl:col-span-1">
                <div className="flex flex-wrap gap-1.5">{a.coverage.techniques.map((t) => <AttackTag key={t} technique={t} />)}</div>
                <p className="m-0 mt-2 text-2xs text-muted">táticas: {a.coverage.tactics.join(" · ")}</p>
                <p className="m-0 mt-2 text-2xs text-dim">{DEFINITIONS_PT.coverage}</p>
              </Panel>
            </div>
          </div>
        )}
      </QueryState>
    </>
  );
}
