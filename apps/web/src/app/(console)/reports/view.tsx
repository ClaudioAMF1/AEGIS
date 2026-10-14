"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/field";
import { PageHeader, Panel } from "@/components/ui/panel";
import { Empty, ErrorState, QueryState } from "@/components/ui/states";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { useScope } from "@/lib/queries";
import { usePermission } from "@/lib/session";
import type { Incident, Page } from "@/lib/types";

interface ReportRow {
  id: string;
  title: string;
  kind: string;
  period_start: string;
  period_end: string;
  incident_id: string | null;
  include_synthetic: boolean;
  created_at: string;
}

export function ReportsView() {
  const scope = useScope();
  const client = useQueryClient();
  const canCreate = usePermission("reports:create");
  const [kind, setKind] = useState("overview");
  const [days, setDays] = useState(7);
  const [incident, setIncident] = useState("");
  const [title, setTitle] = useState("");
  const reports = useQuery({ queryKey: ["reports"], queryFn: () => api.get<ReportRow[]>("/reports") });
  const incidents = useQuery({ queryKey: ["incidents", scope, "report-picker"], queryFn: () => api.get<Page<Incident>>("/incidents", { scope, limit: 100 }), enabled: kind === "incident" });
  const create = useMutation({
    mutationFn: () => {
      const end = new Date();
      const start = new Date(end.getTime() - days * 86400_000);
      return api.post<ReportRow>("/reports", kind === "incident"
        ? { kind, incident_id: incident, title: title || undefined }
        : { kind, scope, start: start.toISOString(), end: end.toISOString(), title: title || undefined });
    },
    onSuccess: () => {
      setTitle("");
      void client.invalidateQueries({ queryKey: ["reports"] });
    },
  });
  return (
    <>
      <PageHeader path="relatorios" title="Relatórios" description="Gerados a partir dos dados persistidos. O documento JSON é a fonte de verdade; o PDF é renderizado a partir dele." />
      <div className="grid gap-4 xl:grid-cols-[320px_1fr]">
        {canCreate ? (
          <Panel title="novo relatório">
            <form className="flex flex-col gap-3" onSubmit={(e: FormEvent) => { e.preventDefault(); create.mutate(); }}>
              <Field label="tipo" htmlFor="r-kind">
                <Select id="r-kind" value={kind} onChange={(e) => setKind(e.target.value)}>
                  <option value="overview">visão geral do período</option>
                  <option value="incident">incidente</option>
                </Select>
              </Field>
              {kind === "overview" ? (
                <Field label="período" htmlFor="r-days" hint={`escopo atual: ${scope}`}>
                  <Select id="r-days" value={days} onChange={(e) => setDays(Number(e.target.value))}>
                    <option value={1}>últimas 24h</option>
                    <option value={7}>últimos 7 dias</option>
                    <option value={30}>últimos 30 dias</option>
                  </Select>
                </Field>
              ) : (
                <Field label="incidente" htmlFor="r-inc">
                  <Select id="r-inc" value={incident} onChange={(e) => setIncident(e.target.value)}>
                    <option value="">selecione…</option>
                    {incidents.data?.items.map((i) => <option key={i.id} value={i.id}>INC-{String(i.number).padStart(4, "0")} · {i.title}</option>)}
                  </Select>
                </Field>
              )}
              <Field label="título (opcional)" htmlFor="r-title"><Input id="r-title" value={title} onChange={(e) => setTitle(e.target.value)} /></Field>
              <Button type="submit" variant="solid" disabled={create.isPending || (kind === "incident" && !incident)}>gerar</Button>
              {create.error ? <ErrorState error={create.error} /> : null}
            </form>
          </Panel>
        ) : null}
        <Panel title="relatórios gerados">
          <QueryState query={reports} isEmpty={(d) => d.length === 0} empty={<Empty title="Nenhum relatório." />}>
            {(rows) => (
              <Table>
                <thead><tr><Th>título</Th><Th>tipo</Th><Th>período</Th><Th>gerado</Th><Th>exportar</Th></tr></thead>
                <tbody>
                  {rows.map((r) => (
                    <Tr key={r.id}>
                      <Td>{r.title}{r.include_synthetic ? <Badge className="ml-2 border-demo/60 text-demo">demo</Badge> : null}</Td>
                      <Td className="text-2xs text-muted">{r.kind}</Td>
                      <Td className="text-2xs text-muted">{formatDateTime(r.period_start)} → {formatDateTime(r.period_end)}</Td>
                      <Td className="text-2xs text-muted">{formatDateTime(r.created_at)}</Td>
                      <Td className="text-2xs whitespace-nowrap">
                        <a className="link-underline mr-3" href={`/api/v1/reports/${r.id}.pdf`}>pdf</a>
                        <a className="link-underline" href={`/api/v1/reports/${r.id}.json`} target="_blank" rel="noopener noreferrer">json</a>
                      </Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            )}
          </QueryState>
        </Panel>
      </div>
    </>
  );
}
