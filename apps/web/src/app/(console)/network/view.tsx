"use client";

import { useQuery } from "@tanstack/react-query";
import dynamic from "next/dynamic";
import Link from "next/link";
import { useState } from "react";

import { EntityGraph, GraphLegend, KIND_LABEL } from "@/components/graph/entity-graph";
import { SeverityBadge } from "@/components/ui/badge";
import { Select } from "@/components/ui/field";
import { PageHeader, Panel } from "@/components/ui/panel";
import { Empty, QueryState } from "@/components/ui/states";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { useScope } from "@/lib/queries";
import { useUi } from "@/lib/store";
import type { EndpointSummary, Graph, GraphNode } from "@/lib/types";
import { cn } from "@/lib/utils";

const Graph3D = dynamic(() => import("@/components/graph/graph-3d").then((m) => m.Graph3D), {
  ssr: false,
  loading: () => <p className="p-4 text-2xs text-muted">carregando visualização 3D…</p>,
});

const WINDOWS = [
  { value: 1, label: "1h" },
  { value: 6, label: "6h" },
  { value: 24, label: "24h" },
  { value: 72, label: "3d" },
  { value: 168, label: "7d" },
];
const KINDS: GraphNode["kind"][] = ["host", "process", "user", "ip", "file", "alert"];

function webglAvailable(): boolean {
  try {
    const canvas = document.createElement("canvas");
    return Boolean(canvas.getContext("webgl2") ?? canvas.getContext("webgl"));
  } catch {
    return false;
  }
}

export function NetworkView() {
  const scope = useScope();
  const { graph3d, setGraph3d } = useUi();
  const [hours, setHours] = useState(24);
  const [endpoint, setEndpoint] = useState("");
  const [onlyFlagged, setOnlyFlagged] = useState(false);
  const [group, setGroup] = useState(false);
  const [hidden, setHidden] = useState<Set<GraphNode["kind"]>>(new Set());
  const [view, setView] = useState<"graph" | "list">("graph");
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [canWebgl] = useState(() => typeof window !== "undefined" && webglAvailable());

  const endpoints = useQuery({ queryKey: ["endpoints", scope], queryFn: () => api.get<EndpointSummary[]>("/endpoints", { scope }) });
  const query = useQuery({
    queryKey: ["graph", scope, hours, endpoint, onlyFlagged],
    queryFn: () =>
      api.get<Graph>("/graph", {
        scope,
        start: new Date(Date.now() - hours * 3600_000).toISOString(),
        endpoint_id: endpoint || undefined,
        only_flagged: onlyFlagged,
        limit: 2000,
      }),
  });

  const toggleKind = (kind: GraphNode["kind"]) =>
    setHidden((prev) => {
      const next = new Set(prev);
      if (next.has(kind)) next.delete(kind);
      else next.add(kind);
      return next;
    });

  const use3d = graph3d && canWebgl && view === "graph";

  return (
    <>
      <PageHeader
        path="rede"
        title="Grafo de entidades"
        description="Hosts, processos, usuários, endereços e alertas observados na janela selecionada. Processos são agregados por nome e host; arestas acumulam contagem e primeira/última ocorrência."
      />
      <div className="mb-3 flex flex-wrap items-center gap-x-5 gap-y-2 text-2xs">
        <div role="radiogroup" aria-label="Janela temporal" className="flex border border-border">
          {WINDOWS.map((w) => (
            <button key={w.value} role="radio" aria-checked={hours === w.value} onClick={() => setHours(w.value)} className={cn("px-2 py-0.5", hours === w.value ? "bg-raised text-text" : "text-muted hover:text-text")}>
              {w.label}
            </button>
          ))}
        </div>
        <Select aria-label="Endpoint" className="h-6 w-auto text-2xs" value={endpoint} onChange={(e) => setEndpoint(e.target.value)}>
          <option value="">todos os hosts</option>
          {endpoints.data?.map((e) => <option key={e.id} value={e.id}>{e.hostname}</option>)}
        </Select>
        <label className="flex items-center gap-1.5"><input type="checkbox" checked={onlyFlagged} onChange={(e) => setOnlyFlagged(e.target.checked)} className="accent-[var(--accent)]" /> só hosts com alertas</label>
        <label className="flex items-center gap-1.5"><input type="checkbox" checked={group} onChange={(e) => setGroup(e.target.checked)} className="accent-[var(--accent)]" /> agrupar por host</label>
        <fieldset className="flex items-center gap-2 border-0 p-0">
          <legend className="sr-only">Tipos de entidade</legend>
          {KINDS.map((k) => (
            <label key={k} className="flex items-center gap-1">
              <input type="checkbox" checked={!hidden.has(k)} onChange={() => toggleKind(k)} className="accent-[var(--accent)]" />
              {KIND_LABEL[k]}
            </label>
          ))}
        </fieldset>
        <div className="ml-auto flex border border-border">
          <button onClick={() => { setView("graph"); setGraph3d(false); }} aria-pressed={view === "graph" && !graph3d} className={cn("px-2 py-0.5", view === "graph" && !graph3d ? "bg-raised text-text" : "text-muted")}>2D</button>
          <button
            onClick={() => { setView("graph"); setGraph3d(true); }}
            disabled={!canWebgl}
            title={canWebgl ? "Visualização 3D (WebGL)" : "WebGL indisponível neste dispositivo"}
            aria-pressed={use3d}
            className={cn("px-2 py-0.5", use3d ? "bg-raised text-text" : "text-muted")}
          >
            3D
          </button>
          <button onClick={() => setView("list")} aria-pressed={view === "list"} className={cn("px-2 py-0.5", view === "list" ? "bg-raised text-text" : "text-muted")}>lista</button>
        </div>
      </div>
      <div className="grid gap-4 xl:grid-cols-[1fr_300px]">
        <Panel
          title={view === "list" ? "entidades (tabela acessível)" : use3d ? "grafo 3d" : "grafo 2d"}
          meta={query.data ? `${query.data.nodes.length} nós · ${query.data.edges.length} arestas${query.data.truncated ? " · truncado" : ""}` : undefined}
          bodyClassName="p-0"
        >
          <QueryState query={query} isEmpty={(g) => g.nodes.length === 0} empty={<Empty className="m-3" title="Nenhuma entidade na janela." />}>
            {(graph) =>
              view === "list" ? (
                <div className="p-3">
                  <Table>
                    <thead><tr><Th>tipo</Th><Th>entidade</Th><Th>severidade</Th><Th className="text-right">peso</Th><Th>conexões</Th></tr></thead>
                    <tbody>
                      {graph.nodes.filter((n) => !hidden.has(n.kind)).map((n) => {
                        const links = graph.edges.filter((e) => e.source === n.id || e.target === n.id);
                        return (
                          <Tr key={n.id}>
                            <Td className="text-muted">{KIND_LABEL[n.kind]}</Td>
                            <Td className="break-all">{n.label}</Td>
                            <Td>{n.severity ? <SeverityBadge severity={n.severity} /> : "—"}</Td>
                            <Td className="text-right tabular">{n.weight}</Td>
                            <Td className="text-2xs text-muted">{links.length}</Td>
                          </Tr>
                        );
                      })}
                    </tbody>
                  </Table>
                </div>
              ) : use3d ? (
                <Graph3D graph={graph} hiddenKinds={hidden} onSelect={setSelected} />
              ) : (
                <div className="p-2">
                  <EntityGraph graph={graph} height={620} groupByHost={group} hiddenKinds={hidden} onSelect={setSelected} />
                </div>
              )
            }
          </QueryState>
          <div className="border-t border-border px-3 py-2"><GraphLegend /></div>
        </Panel>
        <Panel title="detalhes">
          {selected ? (
            <div className="text-xs">
              <p className="m-0 text-2xs text-muted">{KIND_LABEL[selected.kind]}</p>
              <p className="m-0 text-sm break-all">{selected.label}</p>
              {selected.severity ? <div className="mt-2"><SeverityBadge severity={selected.severity} /></div> : null}
              <p className="eyebrow mt-3 mb-1">relações</p>
              <ul className="m-0 list-none p-0 text-2xs">
                {query.data?.edges.filter((e) => e.source === selected.id || e.target === selected.id).slice(0, 30).map((e) => {
                  const other = query.data?.nodes.find((n) => n.id === (e.source === selected.id ? e.target : e.source));
                  return (
                    <li key={e.id} className="border-b border-border/50 py-0.5">
                      <span className="text-accent">{e.kind}</span> {e.source === selected.id ? "→" : "←"} {other?.label ?? "?"}{" "}
                      <span className="text-dim">×{e.count} · {formatDateTime(e.last_seen)}</span>
                    </li>
                  );
                })}
              </ul>
              <div className="mt-3 flex flex-col gap-1 text-2xs">
                {selected.kind === "ip" ? <Link className="link-underline" href={`/events?ip=${encodeURIComponent(selected.label)}`}>eventos com este ip</Link> : null}
                {selected.kind === "process" ? <Link className="link-underline" href={`/events?process=${encodeURIComponent(selected.label)}`}>eventos deste processo</Link> : null}
                {selected.kind === "user" ? <Link className="link-underline" href={`/events?user=${encodeURIComponent(selected.label)}`}>eventos deste usuário</Link> : null}
                {selected.kind === "host" ? <Link className="link-underline" href={`/endpoints?focus=${String(selected.data.endpoint_id)}`}>abrir endpoint</Link> : null}
                {selected.kind === "alert" ? <Link className="link-underline" href={`/alerts?focus=${String(selected.data.alert_id)}`}>abrir alerta</Link> : null}
              </div>
            </div>
          ) : <p className="text-2xs text-dim">Clique em um nó. A vizinhança fica destacada no grafo.</p>}
        </Panel>
      </div>
    </>
  );
}
