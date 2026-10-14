"use client";

import Link from "next/link";
import { useState } from "react";

import { BarList } from "@/components/charts/bar-list";
import { SeverityStrip } from "@/components/charts/severity-strip";
import { VolumeChart } from "@/components/charts/volume-chart";
import { DemoLauncher } from "@/components/demo-launcher";
import { MiniGraph } from "@/components/graph/mini-graph";
import { AlertStatusBadge, IncidentStatusBadge, SeverityBadge } from "@/components/ui/badge";
import { PageHeader, Panel } from "@/components/ui/panel";
import { Stat } from "@/components/ui/stat";
import { Empty, QueryState } from "@/components/ui/states";
import { categoryLabel, formatNumber, formatTime, metricText, relative } from "@/lib/format";
import { useDashboard, useHistogram, useScope } from "@/lib/queries";
import { cn } from "@/lib/utils";

const RANGES = [
  { hours: 1, label: "1h" },
  { hours: 6, label: "6h" },
  { hours: 24, label: "24h" },
  { hours: 168, label: "7d" },
];

export function DashboardView() {
  const [hours, setHours] = useState(24);
  const scope = useScope();
  const dashboard = useDashboard(hours);
  const histogram = useHistogram(hours, hours <= 1 ? 30 : 48);

  const rangePicker = (
    <div role="radiogroup" aria-label="Período" className="flex border border-border text-2xs">
      {RANGES.map((r) => (
        <button
          key={r.hours}
          role="radio"
          aria-checked={hours === r.hours}
          onClick={() => setHours(r.hours)}
          className={cn("px-2 py-0.5", hours === r.hours ? "bg-raised text-text" : "text-muted hover:text-text")}
        >
          {r.label}
        </button>
      ))}
    </div>
  );

  return (
    <>
      <PageHeader
        path="central"
        title="Central de operações"
        description={
          scope === "demo"
            ? "Dados sintéticos do modo demo. Os números abaixo são calculados a partir dos eventos persistidos do cenário."
            : "Telemetria real dos endpoints autorizados. Passe o cursor sobre um indicador para ver definição e fonte."
        }
        actions={rangePicker}
      />
      <QueryState query={dashboard} loadingLabel="calculando indicadores">
        {(data) => {
          const metric = (key: string) => data.metrics.find((m) => m.key === key);
          const tiles = ["endpoints", "endpoints_online", "events_per_second", "events_period", "open_alerts", "rules_enabled"];
          const noData = (metric("events_period")?.value ?? 0) === 0 && (metric("endpoints")?.value ?? 0) === 0;
          return (
            <div className="flex flex-col gap-4">
              <dl className="m-0 grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-6">
                {tiles.map((key) => {
                  const m = metric(key);
                  if (!m) return null;
                  return (
                    <Stat
                      key={key}
                      label={metricText[key]?.label ?? m.label}
                      value={formatNumber(m.value)}
                      unit={m.unit === "count" ? undefined : m.unit}
                      definition={metricText[key]?.definition ?? m.definition}
                      source={m.source}
                      tone={key === "open_alerts" && (m.value ?? 0) > 0 ? "warm" : "text"}
                    />
                  );
                })}
              </dl>

              {noData ? (
                <Panel title={scope === "demo" ? "modo demo vazio" : "nenhuma telemetria ainda"}>
                  {scope === "demo" ? (
                    <DemoLauncher compact />
                  ) : (
                    <Empty
                      title="Nenhum endpoint enviou eventos."
                      hint={
                        <>
                          Cadastre um agente em <Link className="link-underline" href="/endpoints">endpoints</Link>{" "}
                          e execute o agente Linux, ou alterne para o modo demo.
                        </>
                      }
                    />
                  )}
                </Panel>
              ) : null}

              <div className="grid gap-4 xl:grid-cols-[2fr_1fr]">
                <Panel title="telemetria" meta={`eventos por intervalo · ${hours >= 24 ? `${hours / 24}d` : `${hours}h`}`} scanlines>
                  <QueryState query={histogram}>
                    {(h) => {
                      const points = h.series.map((b) => ({
                        start: b.start,
                        total: ["process", "network", "file", "authentication", "system"].reduce(
                          (sum, k) => sum + Number(b[k] ?? 0),
                          0,
                        ),
                      }));
                      const byCategory = ["process", "network", "file", "authentication", "system"].map((k) => ({
                        key: k,
                        label: categoryLabel[k],
                        value: h.series.reduce((sum, b) => sum + Number(b[k] ?? 0), 0),
                      }));
                      return (
                        <div className="grid gap-4 md:grid-cols-[1fr_220px]">
                          <VolumeChart data={points} />
                          <div>
                            <p className="eyebrow mb-2">por categoria</p>
                            <BarList items={byCategory} />
                          </div>
                        </div>
                      );
                    }}
                  </QueryState>
                </Panel>
                <Panel title="severidade" meta="alertas no período · incidentes abertos">
                  <p className="eyebrow mb-2">alertas criados</p>
                  <SeverityStrip counts={data.alerts_by_severity} />
                  <p className="eyebrow mt-5 mb-2">incidentes abertos</p>
                  <SeverityStrip counts={data.open_incidents_by_severity} />
                  <p className="eyebrow mt-5 mb-1">ingestão</p>
                  <dl className="m-0 grid grid-cols-2 gap-1 text-xs">
                    <dt className="text-muted">pipeline</dt>
                    <dd className={cn("m-0", data.pipeline.healthy ? "text-warm" : "text-critical")}>
                      {data.pipeline.mode}
                      {data.pipeline.backlog !== null ? ` · fila ${data.pipeline.backlog}` : ""}
                    </dd>
                    {Object.entries(data.agents_by_status).map(([status, count]) => (
                      <div key={status} className="contents">
                        <dt className="text-muted">agentes {status}</dt>
                        <dd className="m-0 tabular">{count}</dd>
                      </div>
                    ))}
                  </dl>
                </Panel>
              </div>

              <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
                <Panel title="alertas recentes" actions={<Link href="/alerts" className="text-2xs hover:text-text">ver todos →</Link>}>
                  {data.recent_alerts.length === 0 ? (
                    <Empty title="Nenhum alerta." />
                  ) : (
                    <ul className="m-0 flex list-none flex-col p-0">
                      {data.recent_alerts.map((a) => (
                        <li key={a.id} className="border-b border-border/60 py-1.5 last:border-0">
                          <Link href={`/alerts?focus=${a.id}`} className="flex items-start gap-2 hover:text-accent">
                            <SeverityBadge severity={a.severity} />
                            <span className="min-w-0 flex-1 truncate text-xs">{a.title}</span>
                            <span className="text-2xs text-dim tabular">{formatTime(a.created_at)}</span>
                          </Link>
                          <div className="mt-0.5 flex gap-2 pl-1 text-2xs text-muted">
                            <AlertStatusBadge status={a.status} />
                            <span>{a.hit_count} ocorrência(s)</span>
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}
                </Panel>
                <Panel title="investigações" actions={<Link href="/incidents" className="text-2xs hover:text-text">fila →</Link>}>
                  {data.recent_incidents.length === 0 ? (
                    <Empty title="Nenhum incidente aberto." hint="Alertas de severidade alta abrem incidentes automaticamente." />
                  ) : (
                    <ul className="m-0 flex list-none flex-col p-0">
                      {data.recent_incidents.map((i) => (
                        <li key={i.id} className="border-b border-border/60 py-1.5 last:border-0">
                          <Link href={`/incidents/${i.id}`} className="block hover:text-accent">
                            <span className="text-2xs text-dim">INC-{String(i.number).padStart(4, "0")}</span>{" "}
                            <span className="text-xs">{i.title}</span>
                          </Link>
                          <div className="mt-1 flex items-center gap-2">
                            <SeverityBadge severity={i.severity} />
                            <IncidentStatusBadge status={i.status} />
                            <span className="ml-auto text-2xs text-dim">{relative(i.updated_at)}</span>
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}
                </Panel>
                <Panel title="atividade" meta="últimos eventos ingeridos" className="lg:col-span-2 xl:col-span-1">
                  {data.recent_events.length === 0 ? (
                    <Empty title="Sem eventos." />
                  ) : (
                    <ol className="m-0 flex list-none flex-col gap-1 p-0 text-2xs">
                      {data.recent_events.map((e) => (
                        <li key={e.id} className="grid grid-cols-[52px_70px_minmax(0,1fr)] gap-2">
                          <span className="text-dim tabular">{formatTime(e.occurred_at)}</span>
                          <span className="truncate text-muted">{e.hostname}</span>
                          <Link href={`/events?focus=${e.id}`} className="truncate hover:text-accent" title={e.summary}>
                            <span className="text-accent">{categoryLabel[e.category] ?? e.category}</span> {e.summary}
                          </Link>
                        </li>
                      ))}
                    </ol>
                  )}
                </Panel>
              </div>

              <Panel
                title="rede"
                meta="entidades das últimas horas com alertas"
                actions={<Link href="/network" className="text-2xs hover:text-text">abrir grafo →</Link>}
              >
                <MiniGraph hours={hours} />
              </Panel>
            </div>
          );
        }}
      </QueryState>
    </>
  );
}
