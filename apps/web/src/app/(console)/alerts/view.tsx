"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import { EventTimeline } from "@/components/event-list";
import { AlertStatusBadge, AttackTag, DemoBadge, SeverityBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Drawer } from "@/components/ui/drawer";
import { Facts, Input, Select } from "@/components/ui/field";
import { PageHeader, Panel } from "@/components/ui/panel";
import { Empty, ErrorState, QueryState } from "@/components/ui/states";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { api } from "@/lib/api";
import { alertStatusLabel, formatDateTime, relative, SEVERITIES, severityLabel } from "@/lib/format";
import { useScope } from "@/lib/queries";
import { usePermission } from "@/lib/session";
import type { Alert, AlertDetail, Incident, Page } from "@/lib/types";

function AlertDetailPanel({ id, onClose }: { id: string; onClose: () => void }) {
  const client = useQueryClient();
  const router = useRouter();
  const canTriage = usePermission("alerts:triage");
  const canEscalate = usePermission("incidents:write");
  const [note, setNote] = useState("");
  const query = useQuery({ queryKey: ["alerts", "detail", id], queryFn: () => api.get<AlertDetail>(`/alerts/${id}`) });
  const triage = useMutation({
    mutationFn: (body: Record<string, string>) => api.patch<Alert>(`/alerts/${id}`, { ...body, note: note || undefined }),
    onSuccess: () => {
      setNote("");
      void client.invalidateQueries({ queryKey: ["alerts"] });
      void client.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
  const escalate = useMutation({
    mutationFn: () => api.post<Incident>("/alerts/escalate", { alert_ids: [id] }),
    onSuccess: (incident) => router.push(`/incidents/${incident.id}`),
  });

  return (
    <Drawer open title={query.data?.title ?? "alerta"} onClose={onClose}>
      <QueryState query={query}>
        {(a) => (
          <div className="flex flex-col gap-4">
            <div className="flex flex-wrap gap-2">
              <SeverityBadge severity={a.severity} />
              <AlertStatusBadge status={a.status} />
              {a.is_synthetic ? <DemoBadge /> : null}
              {a.attack_techniques.map((t) => <AttackTag key={t} technique={t} />)}
            </div>
            <Facts
              items={[
                ["regra", <span key="r">{a.rule_id} <span className="text-dim">v{a.rule_version}</span></span>],
                ["host", a.hostname],
                ["ocorrências", a.hit_count],
                ["primeiro evento", formatDateTime(a.first_event_at)],
                ["último evento", formatDateTime(a.last_event_at)],
                ["criado", formatDateTime(a.created_at)],
                ["triagem", a.triaged_at ? formatDateTime(a.triaged_at) : "pendente"],
                ["disposição", a.disposition],
                ["incidente", a.incident_id ? <Link key="i" className="link-underline" href={`/incidents/${a.incident_id}`}>abrir investigação</Link> : "—"],
              ]}
            />
            {a.rule ? (
              <div>
                <p className="eyebrow mb-1">por que disparou</p>
                <p className="m-0 text-xs text-muted">{a.rule.description}</p>
                {a.rule.false_positives.length ? (
                  <p className="m-0 mt-1 text-2xs text-dim">falsos positivos conhecidos: {a.rule.false_positives.join("; ")}</p>
                ) : null}
              </div>
            ) : null}
            {Object.keys(a.context).length ? (
              <div>
                <p className="eyebrow mb-1">contexto</p>
                <pre className="m-0 overflow-x-auto border border-border bg-surface p-2 text-2xs text-muted">{JSON.stringify(a.context, null, 2)}</pre>
              </div>
            ) : null}
            <div>
              <p className="eyebrow mb-2">evidências ({a.events.length})</p>
              <EventTimeline events={a.events} />
            </div>
            {canTriage ? (
              <div className="border-t border-border pt-3">
                <p className="eyebrow mb-2">triagem</p>
                <Input placeholder="nota opcional para o diário do incidente" value={note} onChange={(e) => setNote(e.target.value)} />
                <div className="mt-2 flex flex-wrap gap-2">
                  {a.status === "open" ? (
                    <Button size="sm" onClick={() => triage.mutate({ status: "acknowledged" })}>reconhecer</Button>
                  ) : null}
                  <Button size="sm" onClick={() => triage.mutate({ disposition: "true_positive" })}>verdadeiro positivo</Button>
                  <Button size="sm" onClick={() => triage.mutate({ disposition: "benign" })}>benigno</Button>
                  <Button size="sm" variant="danger" onClick={() => triage.mutate({ disposition: "false_positive" })}>falso positivo</Button>
                  {a.status !== "closed" ? (
                    <Button size="sm" variant="ghost" onClick={() => triage.mutate({ status: "closed" })}>fechar</Button>
                  ) : null}
                  {canEscalate && !a.incident_id ? (
                    <Button size="sm" variant="solid" onClick={() => escalate.mutate()}>abrir incidente</Button>
                  ) : null}
                </div>
                {triage.error ? <ErrorState error={triage.error} className="mt-2" /> : null}
                {escalate.error ? <ErrorState error={escalate.error} className="mt-2" /> : null}
              </div>
            ) : null}
          </div>
        )}
      </QueryState>
    </Drawer>
  );
}

export function AlertsView() {
  const scope = useScope();
  const params = useSearchParams();
  const router = useRouter();
  const client = useQueryClient();
  const canEscalate = usePermission("incidents:write");
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("");
  const [rule, setRule] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const focus = params.get("focus");

  const query = useQuery({
    queryKey: ["alerts", scope, status, severity, rule],
    queryFn: () =>
      api.get<Page<Alert>>("/alerts", { scope, status: status || undefined, severity: severity || undefined, rule_id: rule || undefined, limit: 200 }),
  });
  const escalate = useMutation({
    mutationFn: () => api.post<Incident>("/alerts/escalate", { alert_ids: [...selected] }),
    onSuccess: (incident) => {
      void client.invalidateQueries({ queryKey: ["alerts"] });
      router.push(`/incidents/${incident.id}`);
    },
  });

  const setFocus = (id: string | null) => {
    const next = new URLSearchParams(params.toString());
    if (id) next.set("focus", id);
    else next.delete("focus");
    router.replace(`/alerts${next.size ? `?${next}` : ""}`, { scroll: false });
  };

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  return (
    <>
      <PageHeader
        path="alertas"
        title="Alertas"
        description="Detecções agrupadas por regra e host dentro da janela de supressão. Selecione alertas relacionados para abrir uma investigação."
        actions={
          canEscalate && selected.size ? (
            <Button variant="solid" onClick={() => escalate.mutate()} disabled={escalate.isPending}>
              abrir incidente com {selected.size}
            </Button>
          ) : null
        }
      />
      <Panel
        title="fila"
        meta={query.data ? `${query.data.total ?? 0} alerta(s)` : undefined}
        actions={
          <div className="flex flex-wrap gap-2">
            <Select aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value)} className="h-6 w-auto text-2xs">
              <option value="">todos os status</option>
              {Object.entries(alertStatusLabel).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </Select>
            <Select aria-label="Severidade" value={severity} onChange={(e) => setSeverity(e.target.value)} className="h-6 w-auto text-2xs">
              <option value="">toda severidade</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{severityLabel[s]}</option>)}
            </Select>
            <Input aria-label="Regra" placeholder="id da regra" value={rule} onChange={(e) => setRule(e.target.value)} className="h-6 w-40 text-2xs" />
          </div>
        }
      >
        {escalate.error ? <ErrorState error={escalate.error} className="mb-2" /> : null}
        <QueryState
          query={query}
          isEmpty={(d) => d.items.length === 0}
          empty={<Empty title="Nenhum alerta com esses filtros." hint={scope === "demo" ? "Execute um cenário na central ou em configuração → demo." : undefined} />}
        >
          {(data) => (
            <Table>
              <thead>
                <tr>
                  {canEscalate ? <Th className="w-6"><span className="sr-only">selecionar</span></Th> : null}
                  <Th>severidade</Th>
                  <Th>alerta</Th>
                  <Th>host</Th>
                  <Th>status</Th>
                  <Th className="text-right">ocorr.</Th>
                  <Th>att&ck</Th>
                  <Th>último evento</Th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((a) => (
                  <Tr key={a.id} className={focus === a.id ? "bg-raised" : undefined}>
                    {canEscalate ? (
                      <Td>
                        <input type="checkbox" aria-label={`Selecionar ${a.title}`} checked={selected.has(a.id)} onChange={() => toggle(a.id)} className="accent-[var(--accent)]" />
                      </Td>
                    ) : null}
                    <Td><SeverityBadge severity={a.severity} /></Td>
                    <Td>
                      <button onClick={() => setFocus(a.id)} className="text-left hover:text-accent">{a.title}</button>
                      {a.incident_id ? <span className="ml-2 text-2xs text-dim">◆ incidente</span> : null}
                      {a.is_synthetic ? <span className="ml-2 text-2xs text-demo">demo</span> : null}
                    </Td>
                    <Td className="text-muted">{a.hostname}</Td>
                    <Td><AlertStatusBadge status={a.status} /></Td>
                    <Td className="text-right tabular">{a.hit_count}</Td>
                    <Td className="text-2xs text-muted">{a.attack_techniques.join(" ")}</Td>
                    <Td className="text-2xs whitespace-nowrap text-muted" title={formatDateTime(a.last_event_at)}>{relative(a.last_event_at)}</Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          )}
        </QueryState>
      </Panel>
      {focus ? <AlertDetailPanel id={focus} onClose={() => setFocus(null)} /> : null}
    </>
  );
}
