"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";

import { DemoBadge, IncidentStatusBadge, SeverityBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input, Select, Textarea } from "@/components/ui/field";
import { PageHeader, Panel } from "@/components/ui/panel";
import { Empty, ErrorState, QueryState } from "@/components/ui/states";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { api } from "@/lib/api";
import { formatDateTime, relative, SEVERITIES, severityLabel } from "@/lib/format";
import { useScope } from "@/lib/queries";
import { usePermission } from "@/lib/session";
import type { Incident, IncidentStatus, Page } from "@/lib/types";
import { cn } from "@/lib/utils";

const QUEUES: { key: string; label: string; statuses: IncidentStatus[] }[] = [
  { key: "open", label: "abertos", statuses: ["new", "investigating", "contained"] },
  { key: "closed", label: "encerrados", statuses: ["resolved", "false_positive"] },
  { key: "all", label: "todos", statuses: [] },
];

function NewIncident({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const router = useRouter();
  const scope = useScope();
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState("medium");
  const create = useMutation({
    mutationFn: () => api.post<Incident>("/incidents", { title, description, severity, is_synthetic: scope === "demo" }),
    onSuccess: (incident) => router.push(`/incidents/${incident.id}`),
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    create.mutate();
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange} title="Novo incidente" description="Abertura manual. Eventos e alertas podem ser vinculados depois.">
      <form onSubmit={submit} className="flex flex-col gap-3">
        <Field label="título" htmlFor="n-title"><Input id="n-title" required minLength={3} value={title} onChange={(e) => setTitle(e.target.value)} /></Field>
        <Field label="descrição" htmlFor="n-desc"><Textarea id="n-desc" rows={4} value={description} onChange={(e) => setDescription(e.target.value)} /></Field>
        <Field label="severidade" htmlFor="n-sev">
          <Select id="n-sev" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {SEVERITIES.map((s) => <option key={s} value={s}>{severityLabel[s]}</option>)}
          </Select>
        </Field>
        {create.error ? <ErrorState error={create.error} /> : null}
        <Button type="submit" variant="solid" disabled={create.isPending}>criar</Button>
      </form>
    </Dialog>
  );
}

export function IncidentsView() {
  const scope = useScope();
  const canWrite = usePermission("incidents:write");
  const [queue, setQueue] = useState("open");
  const [severity, setSeverity] = useState("");
  const [q, setQ] = useState("");
  const [creating, setCreating] = useState(false);
  const statuses = QUEUES.find((x) => x.key === queue)?.statuses ?? [];
  const query = useQuery({
    queryKey: ["incidents", scope, queue, severity, q],
    queryFn: () => api.get<Page<Incident>>("/incidents", { scope, status: statuses, severity: severity || undefined, q: q || undefined, limit: 100 }),
  });
  return (
    <>
      <PageHeader
        path="incidentes"
        title="Investigações"
        description="Incidentes reúnem alertas relacionados, eventos, evidências e o diário da investigação."
        actions={canWrite ? <Button variant="solid" onClick={() => setCreating(true)}>novo incidente</Button> : null}
      />
      <Panel
        title="fila de incidentes"
        meta={query.data ? `${query.data.total ?? 0}` : undefined}
        actions={
          <div className="flex flex-wrap gap-2">
            <div role="tablist" className="flex border border-border text-2xs">
              {QUEUES.map((x) => (
                <button key={x.key} role="tab" aria-selected={queue === x.key} onClick={() => setQueue(x.key)} className={cn("px-2 py-0.5", queue === x.key ? "bg-raised text-text" : "text-muted hover:text-text")}>
                  {x.label}
                </button>
              ))}
            </div>
            <Select aria-label="Severidade" value={severity} onChange={(e) => setSeverity(e.target.value)} className="h-6 w-auto text-2xs">
              <option value="">toda severidade</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{severityLabel[s]}</option>)}
            </Select>
            <Input aria-label="Buscar título" placeholder="buscar título" value={q} onChange={(e) => setQ(e.target.value)} className="h-6 w-40 text-2xs" />
          </div>
        }
      >
        <QueryState query={query} isEmpty={(d) => d.items.length === 0} empty={<Empty title="Nenhum incidente nesta fila." />}>
          {(data) => (
            <Table>
              <thead>
                <tr>
                  <Th>id</Th>
                  <Th>severidade</Th>
                  <Th>título</Th>
                  <Th>status</Th>
                  <Th>responsável</Th>
                  <Th className="text-right">alertas</Th>
                  <Th className="text-right">eventos</Th>
                  <Th>início</Th>
                  <Th>atualizado</Th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((i) => (
                  <Tr key={i.id}>
                    <Td className="text-2xs whitespace-nowrap text-dim">INC-{String(i.number).padStart(4, "0")}</Td>
                    <Td><SeverityBadge severity={i.severity} /></Td>
                    <Td>
                      <Link href={`/incidents/${i.id}`} className="hover:text-accent">{i.title}</Link>
                      {i.is_synthetic ? <DemoBadge className="ml-2" /> : null}
                      <div className="text-2xs text-dim">{i.attack_techniques.slice(0, 4).join(" · ")}</div>
                    </Td>
                    <Td><IncidentStatusBadge status={i.status} /></Td>
                    <Td className="text-muted">{i.assignee_name ?? "—"}</Td>
                    <Td className="text-right tabular">{i.alert_count}</Td>
                    <Td className="text-right tabular">{i.event_count}</Td>
                    <Td className="text-2xs whitespace-nowrap text-muted">{formatDateTime(i.started_at)}</Td>
                    <Td className="text-2xs whitespace-nowrap text-muted">{relative(i.updated_at)}</Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          )}
        </QueryState>
      </Panel>
      <NewIncident open={creating} onOpenChange={setCreating} />
    </>
  );
}
