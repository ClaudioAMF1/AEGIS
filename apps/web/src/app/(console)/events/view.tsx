"use client";

import { useInfiniteQuery, useMutation, useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { type FormEvent, useState } from "react";

import { Badge, DemoBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Drawer } from "@/components/ui/drawer";
import { Facts, Field, Input, Select } from "@/components/ui/field";
import { PageHeader, Panel } from "@/components/ui/panel";
import { Empty, ErrorState, Loading, QueryState } from "@/components/ui/states";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { api } from "@/lib/api";
import { categoryLabel, formatDateTime, formatNumber, formatTime } from "@/lib/format";
import { useScope } from "@/lib/queries";
import { usePermission } from "@/lib/session";
import type { EventDetail, EventRow, Incident, Page } from "@/lib/types";

const FILTERS = ["category", "hostname", "user", "process", "ip", "port", "q", "flagged"] as const;
type Filters = Partial<Record<(typeof FILTERS)[number], string>>;

function EventDetailPanel({ id, onClose }: { id: string; onClose: () => void }) {
  const canWrite = usePermission("incidents:write");
  const scope = useScope();
  const [incident, setIncident] = useState("");
  const query = useQuery({ queryKey: ["events", "detail", id], queryFn: () => api.get<EventDetail>(`/events/${id}`) });
  const incidents = useQuery({
    queryKey: ["incidents", scope, "open-picker"],
    queryFn: () => api.get<Page<Incident>>("/incidents", { scope, status: ["new", "investigating", "contained"], limit: 50 }),
    enabled: canWrite,
  });
  const attach = useMutation({
    mutationFn: () =>
      api.post(`/incidents/${incident}/evidence`, {
        kind: "event",
        reference: id,
        label: query.data?.summary.slice(0, 200) ?? "evento",
      }),
  });
  return (
    <Drawer open title={<span>evento <span className="text-dim">{id.slice(0, 8)}</span></span>} onClose={onClose}>
      <QueryState query={query}>
        {(e) => (
          <div className="flex flex-col gap-4">
            <div className="flex flex-wrap gap-2">
              <Badge className="text-accent">{categoryLabel[e.category] ?? e.category}.{e.action}</Badge>
              {e.is_synthetic ? <DemoBadge /> : null}
              {e.rule_ids.map((r) => <Badge key={r} className="text-warm">{r}</Badge>)}
            </div>
            <p className="m-0 text-xs break-all">{e.summary}</p>
            <Facts
              items={[
                ["ocorrência", formatDateTime(e.occurred_at)],
                ["ingestão", formatDateTime(e.ingested_at)],
                ["host", <Link key="h" className="link-underline" href={`/endpoints?focus=${e.endpoint_id}`}>{e.hostname}</Link>],
                ["usuário", e.user_name],
                ["processo", e.process_name ? `${e.process_name} (pid ${e.process_pid}, ppid ${e.process_ppid ?? "?"})` : null],
                ["seq do agente", e.seq],
                ["schema", `ACE ${e.schema_version}`],
                ["detecção", e.detection_state],
                ["alertas", e.alert_ids.length ? e.alert_ids.map((a) => <Link key={a} className="link-underline mr-2" href={`/alerts?focus=${a}`}>{a.slice(0, 8)}</Link>) : "—"],
              ]}
            />
            {Object.keys(e.enrichment).length ? (
              <div>
                <p className="eyebrow mb-1">enriquecimento</p>
                <pre className="m-0 overflow-x-auto border border-border bg-surface p-2 text-2xs text-muted">{JSON.stringify(e.enrichment, null, 2)}</pre>
                <p className="m-0 mt-1 text-2xs text-dim">Indicadores de inteligência são sinais auxiliares, não prova de comprometimento.</p>
              </div>
            ) : null}
            <div>
              <p className="eyebrow mb-1">dados brutos (ACE v1)</p>
              <pre className="m-0 max-h-[360px] overflow-auto border border-border bg-surface p-2 text-2xs">{JSON.stringify(e.payload, null, 2)}</pre>
            </div>
            {canWrite ? (
              <div className="border-t border-border pt-3">
                <Field label="adicionar como evidência a um incidente" htmlFor="incident-pick">
                  <div className="flex gap-2">
                    <Select id="incident-pick" value={incident} onChange={(ev) => setIncident(ev.target.value)}>
                      <option value="">selecione…</option>
                      {incidents.data?.items.map((i) => (
                        <option key={i.id} value={i.id}>INC-{String(i.number).padStart(4, "0")} · {i.title}</option>
                      ))}
                    </Select>
                    <Button size="md" disabled={!incident || attach.isPending} onClick={() => attach.mutate()}>adicionar</Button>
                  </div>
                </Field>
                {attach.isSuccess ? <p className="mt-1 text-2xs text-accent">evidência adicionada.</p> : null}
                {attach.error ? <ErrorState error={attach.error} className="mt-2" /> : null}
              </div>
            ) : null}
          </div>
        )}
      </QueryState>
    </Drawer>
  );
}

export function EventsView() {
  const scope = useScope();
  const params = useSearchParams();
  const router = useRouter();
  const initial: Filters = Object.fromEntries(FILTERS.map((f) => [f, params.get(f) ?? ""]));
  const [draft, setDraft] = useState<Filters>(initial);
  const [filters, setFilters] = useState<Filters>(initial);
  const focus = params.get("focus");

  const query = useInfiniteQuery({
    queryKey: ["events", scope, filters],
    initialPageParam: null as string | null,
    queryFn: ({ pageParam }) =>
      api.get<Page<EventRow>>("/events", {
        scope,
        category: filters.category || undefined,
        hostname: filters.hostname || undefined,
        user: filters.user || undefined,
        process: filters.process || undefined,
        ip: filters.ip || undefined,
        port: filters.port || undefined,
        q: filters.q || undefined,
        flagged: filters.flagged || undefined,
        cursor: pageParam ?? undefined,
        limit: 100,
      }),
    getNextPageParam: (last) => last.next_cursor,
  });

  const apply = (event: FormEvent) => {
    event.preventDefault();
    setFilters(draft);
    const next = new URLSearchParams();
    Object.entries(draft).forEach(([k, v]) => v && next.set(k, v));
    router.replace(`/events${next.size ? `?${next}` : ""}`, { scroll: false });
  };

  const setFocus = (id: string | null) => {
    const next = new URLSearchParams(params.toString());
    if (id) next.set("focus", id);
    else next.delete("focus");
    router.replace(`/events${next.size ? `?${next}` : ""}`, { scroll: false });
  };

  const rows = query.data?.pages.flatMap((p) => p.items) ?? [];
  const total = query.data?.pages[0]?.total;

  return (
    <>
      <PageHeader path="eventos" title="Exploração de eventos" description="Busca na telemetria normalizada (ACE v1). Os filtros são aplicados no servidor; a paginação usa cursor por horário de ocorrência." />
      <form onSubmit={apply} className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4 xl:grid-cols-8">
        <Field label="categoria" htmlFor="f-cat">
          <Select id="f-cat" value={draft.category} onChange={(e) => setDraft({ ...draft, category: e.target.value })}>
            <option value="">todas</option>
            {Object.entries(categoryLabel).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
          </Select>
        </Field>
        {(["hostname", "user", "process", "ip", "port"] as const).map((f) => (
          <Field key={f} label={{ hostname: "host", user: "usuário", process: "processo", ip: "ip", port: "porta" }[f]} htmlFor={`f-${f}`}>
            <Input id={`f-${f}`} value={draft[f]} onChange={(e) => setDraft({ ...draft, [f]: e.target.value })} inputMode={f === "port" ? "numeric" : undefined} />
          </Field>
        ))}
        <Field label="detecção" htmlFor="f-flag">
          <Select id="f-flag" value={draft.flagged} onChange={(e) => setDraft({ ...draft, flagged: e.target.value })}>
            <option value="">todos</option>
            <option value="true">com match de regra</option>
            <option value="false">sem match</option>
          </Select>
        </Field>
        <Field label="texto" htmlFor="f-q">
          <div className="flex gap-1">
            <Input id="f-q" placeholder="ex.: /dev/tcp" value={draft.q} onChange={(e) => setDraft({ ...draft, q: e.target.value })} />
            <Button type="submit" variant="solid">↵</Button>
          </div>
        </Field>
      </form>
      <Panel title="resultados" meta={total !== undefined && total !== null ? `${formatNumber(total)} evento(s)` : undefined}>
        {query.isPending ? <Loading /> : query.error ? <ErrorState error={query.error} onRetry={() => query.refetch()} /> : rows.length === 0 ? (
          <Empty title="Nenhum evento encontrado." hint="Ajuste os filtros ou verifique o modo (live/demo)." />
        ) : (
          <>
            <Table>
              <thead>
                <tr>
                  <Th>ocorrência</Th>
                  <Th>host</Th>
                  <Th>tipo</Th>
                  <Th>usuário</Th>
                  <Th>resumo</Th>
                  <Th>det.</Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <Tr key={e.id} className={focus === e.id ? "bg-raised" : undefined}>
                    <Td className="text-2xs whitespace-nowrap text-muted tabular" title={formatDateTime(e.occurred_at)}>{formatTime(e.occurred_at)}</Td>
                    <Td className="whitespace-nowrap">{e.hostname}</Td>
                    <Td className="text-2xs whitespace-nowrap text-accent">{categoryLabel[e.category] ?? e.category}.{e.action}</Td>
                    <Td className="text-muted">{e.user_name ?? "—"}</Td>
                    <Td className="max-w-[520px]">
                      <button onClick={() => setFocus(e.id)} className="block w-full truncate text-left hover:text-accent" title={e.summary}>
                        {e.summary}
                      </button>
                    </Td>
                    <Td className="text-2xs text-dim">{e.detection_state === "done" ? "✓" : e.detection_state}</Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
            {query.hasNextPage ? (
              <Button className="mt-3" onClick={() => query.fetchNextPage()} disabled={query.isFetchingNextPage}>
                {query.isFetchingNextPage ? "carregando…" : "carregar mais"}
              </Button>
            ) : null}
          </>
        )}
      </Panel>
      {focus ? <EventDetailPanel id={focus} onClose={() => setFocus(null)} /> : null}
    </>
  );
}
