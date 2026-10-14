"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { type FormEvent, useMemo, useState } from "react";

import { EventTimeline } from "@/components/event-list";
import { EntityGraph, GraphLegend, KIND_LABEL } from "@/components/graph/entity-graph";
import { ProcessTree } from "@/components/process-tree";
import { TimelineChart } from "@/components/timeline-chart";
import { AlertStatusBadge, AttackTag, DemoBadge, IncidentStatusBadge, SeverityBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Facts, Input, Select, Textarea } from "@/components/ui/field";
import { Panel } from "@/components/ui/panel";
import { Empty, ErrorState, Loading, QueryState } from "@/components/ui/states";
import { TabPanel, Tabs } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import { formatDateTime, formatDuration, incidentStatusLabel, relative, SEVERITIES, severityLabel } from "@/lib/format";
import { useMe, usePermission } from "@/lib/session";
import type { EventRow, Graph, GraphNode, IncidentDetail, IncidentStatus, JournalEntry, ProcessNode, UserRow } from "@/lib/types";
import { cn } from "@/lib/utils";

const TRANSITIONS: Record<IncidentStatus, IncidentStatus[]> = {
  new: ["investigating", "contained", "resolved", "false_positive"],
  investigating: ["contained", "resolved", "false_positive"],
  contained: ["investigating", "resolved"],
  resolved: ["investigating"],
  false_positive: ["investigating"],
};

function useIncidentMutation(id: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: Record<string, unknown>) => api.patch(`/incidents/${id}`, body),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["incident", id] });
      void client.invalidateQueries({ queryKey: ["incidents"] });
    },
  });
}

function Controls({ incident }: { incident: IncidentDetail }) {
  const me = useMe();
  const canWrite = usePermission("incidents:write");
  const update = useIncidentMutation(incident.id);
  const users = useQuery({ queryKey: ["users"], queryFn: () => api.get<UserRow[]>("/users"), enabled: canWrite });
  if (!canWrite) return null;
  return (
    <div className="flex flex-wrap items-center gap-2">
      {TRANSITIONS[incident.status].map((s) => (
        <Button key={s} size="sm" variant={s === "resolved" ? "solid" : s === "false_positive" ? "danger" : "outline"} disabled={update.isPending} onClick={() => update.mutate({ status: s })}>
          → {incidentStatusLabel[s]}
        </Button>
      ))}
      <Select aria-label="Responsável" className="h-6 w-auto text-2xs" value={incident.assignee_id ?? ""} onChange={(e) => update.mutate(e.target.value ? { assignee_id: e.target.value } : { unassign: true })}>
        <option value="">sem responsável</option>
        {users.data?.filter((u) => u.role !== "viewer" && u.is_active).map((u) => (
          <option key={u.id} value={u.id}>{u.display_name}{u.id === me.data?.id ? " (eu)" : ""}</option>
        ))}
      </Select>
      <Select aria-label="Severidade" className="h-6 w-auto text-2xs" value={incident.severity} onChange={(e) => update.mutate({ severity: e.target.value })}>
        {SEVERITIES.map((s) => <option key={s} value={s}>{severityLabel[s]}</option>)}
      </Select>
      {update.error ? <ErrorState error={update.error} /> : null}
    </div>
  );
}

function Overview({ incident }: { incident: IncidentDetail }) {
  const ttd = (new Date(incident.detected_at).getTime() - new Date(incident.started_at).getTime()) / 1000;
  const ttt = incident.first_triaged_at ? (new Date(incident.first_triaged_at).getTime() - new Date(incident.detected_at).getTime()) / 1000 : null;
  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_1fr]">
      <Panel title="resumo">
        <p className="m-0 mb-3 text-xs whitespace-pre-wrap text-muted">{incident.description || "Sem descrição."}</p>
        <Facts
          items={[
            ["início", formatDateTime(incident.started_at)],
            ["término", formatDateTime(incident.ended_at)],
            ["detectado", formatDateTime(incident.detected_at)],
            ["primeira triagem", incident.first_triaged_at ? formatDateTime(incident.first_triaged_at) : "pendente"],
            ["tempo até detecção", incident.is_synthetic ? "n/a (demo)" : formatDuration(ttd)],
            ["tempo até triagem", formatDuration(ttt)],
            ["encerrado", formatDateTime(incident.resolved_at)],
            ["responsável", incident.assignee_name],
            ["hosts", incident.endpoints.map((e) => e.hostname).join(", ")],
            ["alertas / eventos", `${incident.alert_count} / ${incident.event_count}`],
          ]}
        />
        <p className="eyebrow mt-4 mb-1">mitre att&ck</p>
        <div className="flex flex-wrap gap-1.5">
          {incident.attack_techniques.length ? incident.attack_techniques.map((t) => <AttackTag key={t} technique={t} />) : <span className="text-2xs text-dim">nenhuma técnica associada</span>}
        </div>
        {incident.attack_tactics.length ? <p className="m-0 mt-2 text-2xs text-muted">táticas: {incident.attack_tactics.join(" → ")}</p> : null}
      </Panel>
      <Panel title="alertas vinculados" meta={`${incident.alerts.length}`}>
        {incident.alerts.length === 0 ? <Empty title="Nenhum alerta vinculado." /> : (
          <ul className="m-0 list-none p-0">
            {incident.alerts.map((a) => (
              <li key={a.id} className="border-b border-border/60 py-1.5 last:border-0">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={a.severity} />
                  <Link href={`/alerts?focus=${a.id}`} className="min-w-0 flex-1 truncate text-xs hover:text-accent">{a.title}</Link>
                  <AlertStatusBadge status={a.status} />
                </div>
                <p className="m-0 mt-0.5 text-2xs text-dim">{a.rule_id} · {a.hit_count} ocorrência(s) · {a.hostname} · {formatDateTime(a.first_event_at)}</p>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}

function TimelineTab({ incident, onSelect }: { incident: IncidentDetail; onSelect: (id: string) => void }) {
  const [context, setContext] = useState(15);
  const [range, setRange] = useState<[number, number] | null>(null);
  const linked = useQuery({ queryKey: ["incident", incident.id, "events", 0], queryFn: () => api.get<EventRow[]>(`/incidents/${incident.id}/events`) });
  const events = useQuery({
    queryKey: ["incident", incident.id, "events", context],
    queryFn: () => api.get<EventRow[]>(`/incidents/${incident.id}/events`, { context_minutes: context }),
  });
  const evidence = useMemo(() => new Set(linked.data?.map((e) => e.id)), [linked.data]);
  const filtered = (events.data ?? []).filter((e) => {
    if (!range) return true;
    const t = new Date(e.occurred_at).getTime();
    return t >= range[0] && t <= range[1];
  });
  return (
    <Panel
      title="linha do tempo"
      meta={events.data ? `${filtered.length} de ${events.data.length} evento(s)` : undefined}
      actions={
        <label className="flex items-center gap-2 text-2xs">
          contexto
          <Select className="h-6 w-auto text-2xs" value={context} onChange={(e) => setContext(Number(e.target.value))}>
            <option value={0}>somente evidências</option>
            <option value={15}>± 15 min</option>
            <option value={60}>± 60 min</option>
          </Select>
        </label>
      }
    >
      <QueryState query={events} isEmpty={(d) => d.length === 0} empty={<Empty title="Nenhum evento vinculado." />}>
        {(data) => (
          <>
            <TimelineChart events={data} evidence={evidence} onWindow={setRange} onSelect={onSelect} />
            {range ? (
              <p className="mt-2 text-2xs text-muted">
                intervalo: {formatDateTime(new Date(range[0]).toISOString())} → {formatDateTime(new Date(range[1]).toISOString())}{" "}
                <button className="text-accent" onClick={() => setRange(null)}>limpar</button>
              </p>
            ) : null}
            <div className="mt-4 max-h-[520px] overflow-y-auto">
              <EventTimeline events={filtered} highlight={evidence} />
            </div>
          </>
        )}
      </QueryState>
    </Panel>
  );
}

function ProcessTab({ id }: { id: string }) {
  const [onlyFlagged, setOnlyFlagged] = useState(true);
  const query = useQuery({ queryKey: ["incident", id, "tree"], queryFn: () => api.get<Record<string, ProcessNode[]>>(`/incidents/${id}/process-tree`) });
  return (
    <Panel
      title="árvore de processos"
      meta="1h antes do início até 30 min após o término"
      actions={
        <label className="flex items-center gap-1.5 text-2xs">
          <input type="checkbox" checked={onlyFlagged} onChange={(e) => setOnlyFlagged(e.target.checked)} className="accent-[var(--accent)]" />
          só ramos com detecção
        </label>
      }
    >
      <QueryState query={query} isEmpty={(d) => Object.keys(d).length === 0} empty={<Empty title="Sem eventos de processo." />}>
        {(trees) => (
          <div className="flex flex-col gap-5">
            {Object.entries(trees).map(([host, roots]) => (
              <div key={host}>
                <p className="m-0 mb-1 text-xs"><span className="text-accent">▢</span> {host}</p>
                <ProcessTree roots={roots} onlyFlagged={onlyFlagged} />
              </div>
            ))}
          </div>
        )}
      </QueryState>
    </Panel>
  );
}

function GraphTab({ id }: { id: string }) {
  const query = useQuery({ queryKey: ["incident", id, "graph"], queryFn: () => api.get<Graph>(`/incidents/${id}/graph`) });
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [group, setGroup] = useState(false);
  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_280px]">
      <Panel title="grafo de entidades" actions={
        <label className="flex items-center gap-1.5 text-2xs">
          <input type="checkbox" checked={group} onChange={(e) => setGroup(e.target.checked)} className="accent-[var(--accent)]" /> agrupar por host
        </label>
      }>
        <QueryState query={query} isEmpty={(g) => g.nodes.length === 0} empty={<Empty title="Sem entidades." />}>
          {(graph) => (
            <>
              <EntityGraph graph={graph} height={520} groupByHost={group} onSelect={setSelected} />
              <div className="mt-2"><GraphLegend /></div>
            </>
          )}
        </QueryState>
      </Panel>
      <Panel title="entidade">
        {selected ? (
          <div>
            <p className="m-0 text-2xs text-muted">{KIND_LABEL[selected.kind]}</p>
            <p className="m-0 text-sm break-all">{selected.label}</p>
            {selected.severity ? <div className="mt-2"><SeverityBadge severity={selected.severity} /></div> : null}
            <pre className="mt-3 overflow-x-auto text-2xs text-muted">{JSON.stringify(selected.data, null, 2)}</pre>
            {selected.kind === "ip" ? <Link className="link-underline text-2xs" href={`/events?ip=${encodeURIComponent(selected.label)}`}>eventos com este ip →</Link> : null}
            {selected.kind === "process" ? <Link className="link-underline text-2xs" href={`/events?process=${encodeURIComponent(selected.label)}`}>eventos deste processo →</Link> : null}
            {selected.kind === "alert" && typeof selected.data.alert_id === "string" ? <Link className="link-underline text-2xs" href={`/alerts?focus=${selected.data.alert_id}`}>abrir alerta →</Link> : null}
          </div>
        ) : <p className="text-2xs text-dim">Selecione um nó para ver detalhes e vizinhança.</p>}
      </Panel>
    </div>
  );
}

function JournalTab({ incident }: { incident: IncidentDetail }) {
  const client = useQueryClient();
  const canWrite = usePermission("incidents:write");
  const [body, setBody] = useState("");
  const [note, setNote] = useState("");
  const comment = useMutation({
    mutationFn: () => api.post(`/incidents/${incident.id}/comments`, { body }),
    onSuccess: () => {
      setBody("");
      void client.invalidateQueries({ queryKey: ["incident", incident.id] });
    },
  });
  const evidence = useMutation({
    mutationFn: () => api.post(`/incidents/${incident.id}/evidence`, { kind: "note", label: note }),
    onSuccess: () => {
      setNote("");
      void client.invalidateQueries({ queryKey: ["incident", incident.id] });
    },
  });
  const describe = (entry: JournalEntry) =>
    Object.entries(entry.changes)
      .filter(([, v]) => Array.isArray(v))
      .map(([k, v]) => `${k}: ${(v as unknown[])[0] ?? "—"} → ${(v as unknown[])[1] ?? "—"}`)
      .join(" · ");
  return (
    <div className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
      <Panel title="diário da investigação" meta={`${incident.journal.length} entrada(s)`}>
        <ol className="m-0 list-none border-l border-border p-0 pl-4">
          {incident.journal.map((j) => (
            <li key={j.id} className="relative pb-3">
              <span className={cn("absolute top-[6px] -left-[20px] block size-[7px] rounded-full border", j.entry_type === "comment" ? "border-accent bg-accent" : "border-dim bg-ground")} aria-hidden />
              <p className="m-0 text-2xs text-dim">{formatDateTime(j.created_at)} · {j.author_name} · {j.entry_type}</p>
              {j.body ? <p className="m-0 text-xs whitespace-pre-wrap">{j.body}</p> : null}
              {describe(j) ? <p className="m-0 text-2xs text-muted">{describe(j)}</p> : null}
            </li>
          ))}
        </ol>
        {canWrite ? (
          <form className="mt-2" onSubmit={(e: FormEvent) => { e.preventDefault(); comment.mutate(); }}>
            <Textarea rows={3} placeholder="Registrar observação, hipótese ou decisão…" value={body} onChange={(e) => setBody(e.target.value)} />
            <Button type="submit" size="sm" className="mt-2" disabled={!body.trim() || comment.isPending}>comentar</Button>
            {comment.error ? <ErrorState error={comment.error} className="mt-2" /> : null}
          </form>
        ) : null}
      </Panel>
      <Panel title="evidências" meta={`${incident.evidence.length}`}>
        {incident.evidence.length === 0 ? <Empty title="Nenhuma evidência registrada." hint="Adicione eventos pela tela de eventos ou registre notas aqui." /> : (
          <ul className="m-0 list-none p-0">
            {incident.evidence.map((ev) => (
              <li key={ev.id} className="border-b border-border/60 py-1.5 text-xs last:border-0">
                <span className="text-2xs text-accent">{ev.kind}</span>{" "}
                {ev.kind === "event" && ev.reference ? <Link href={`/events?focus=${ev.reference}`} className="hover:text-accent">{ev.label}</Link> : ev.label}
                <p className="m-0 text-2xs text-dim">{relative(ev.created_at)}</p>
              </li>
            ))}
          </ul>
        )}
        {canWrite ? (
          <form className="mt-3 flex gap-2" onSubmit={(e: FormEvent) => { e.preventDefault(); evidence.mutate(); }}>
            <Input placeholder="nota de evidência" value={note} onChange={(e) => setNote(e.target.value)} />
            <Button type="submit" size="md" disabled={!note.trim() || evidence.isPending}>+</Button>
          </form>
        ) : null}
      </Panel>
    </div>
  );
}

export function IncidentView({ id }: { id: string }) {
  const [tab, setTab] = useState("overview");
  const query = useQuery({ queryKey: ["incident", id], queryFn: () => api.get<IncidentDetail>(`/incidents/${id}`), refetchInterval: 20_000 });
  const exportJson = async () => {
    const data = await api.get(`/incidents/${id}/export`);
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `incident-${id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };
  const router = useRouter();
  const openEvent = (eventId: string) => router.push(`/events?focus=${eventId}`);

  if (query.isPending) return <Loading label="carregando investigação" />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => query.refetch()} />;
  const incident = query.data;
  return (
    <>
      <div className="mb-4">
        <p className="text-sm">
          <span className="text-accent">→</span> <Link href="/incidents" className="text-muted hover:text-text">~/aegis/incidentes/</Link>
          INC-{String(incident.number).padStart(4, "0")}
        </p>
        <div className="mt-1 flex flex-wrap items-center gap-2">
          <h1 className="m-0 text-[22px] leading-tight font-medium tracking-[-0.7px]">{incident.title}</h1>
          <SeverityBadge severity={incident.severity} />
          <IncidentStatusBadge status={incident.status} />
          {incident.is_synthetic ? <DemoBadge /> : null}
        </div>
        <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
          <Controls incident={incident} />
          <div className="flex gap-2">
            <Link href={`/assistant?incident=${incident.id}`} className="border border-border px-3 py-1 text-xs hover:border-accent hover:text-accent">perguntar ao assistente</Link>
            <Button onClick={exportJson}>exportar json</Button>
          </div>
        </div>
      </div>
      <Tabs
        value={tab}
        onValueChange={setTab}
        tabs={[
          { value: "overview", label: "resumo" },
          { value: "timeline", label: "linha do tempo" },
          { value: "process", label: "processos" },
          { value: "graph", label: "grafo" },
          { value: "journal", label: `diário · evidências` },
        ]}
      >
        <TabPanel value="overview"><Overview incident={incident} /></TabPanel>
        <TabPanel value="timeline"><TimelineTab incident={incident} onSelect={openEvent} /></TabPanel>
        <TabPanel value="process"><ProcessTab id={id} /></TabPanel>
        <TabPanel value="graph"><GraphTab id={id} /></TabPanel>
        <TabPanel value="journal"><JournalTab incident={incident} /></TabPanel>
      </Tabs>
    </>
  );
}
