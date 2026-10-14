"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter, useSearchParams } from "next/navigation";
import { type FormEvent, useState } from "react";

import { BarList } from "@/components/charts/bar-list";
import { ProcessTree } from "@/components/process-tree";
import { Badge, DemoBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Drawer } from "@/components/ui/drawer";
import { Facts, Field, Input } from "@/components/ui/field";
import { PageHeader, Panel } from "@/components/ui/panel";
import { Empty, ErrorState, QueryState } from "@/components/ui/states";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { api } from "@/lib/api";
import { categoryLabel, formatDateTime, formatNumber, relative } from "@/lib/format";
import { useScope } from "@/lib/queries";
import { usePermission } from "@/lib/session";
import type { Agent, EndpointDetail, EndpointSummary, ProcessNode } from "@/lib/types";
import { cn } from "@/lib/utils";

const STATUS_TONE: Record<EndpointSummary["status"], string> = {
  online: "text-accent",
  stale: "text-medium",
  offline: "text-critical",
  never: "text-dim",
};

function EnrollDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const client = useQueryClient();
  const [name, setName] = useState("");
  const enroll = useMutation({
    mutationFn: () => api.post<{ agent: Agent; token: string; notice: string }>("/agents", { name }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["agents"] }),
  });
  const close = (v: boolean) => {
    if (!v) {
      enroll.reset();
      setName("");
    }
    onOpenChange(v);
  };
  return (
    <Dialog open={open} onOpenChange={close} title="Cadastrar agente" description="Gera um token de ingestão. O token é exibido uma única vez e armazenado apenas como hash.">
      {enroll.data ? (
        <div className="flex flex-col gap-3 text-xs">
          <p className="m-0 text-warm">{enroll.data.notice}</p>
          <pre className="m-0 overflow-x-auto border border-border bg-surface p-2 text-2xs break-all whitespace-pre-wrap select-all">{enroll.data.token}</pre>
          <p className="m-0 text-muted">Configure o agente Linux:</p>
          <pre className="m-0 overflow-x-auto border border-border bg-surface p-2 text-2xs">{`sudo install -m 600 /dev/stdin /etc/aegis/agent.token <<< '<token>'
sudo aegis-agent --config /etc/aegis/agent.toml`}</pre>
          <Button onClick={() => close(false)}>concluir</Button>
        </div>
      ) : (
        <form onSubmit={(e: FormEvent) => { e.preventDefault(); enroll.mutate(); }} className="flex flex-col gap-3">
          <Field label="nome do agente" htmlFor="agent-name" hint="Ex.: lab-web-01. O host é vinculado no primeiro envio.">
            <Input id="agent-name" required minLength={2} value={name} onChange={(e) => setName(e.target.value)} />
          </Field>
          {enroll.error ? <ErrorState error={enroll.error} /> : null}
          <Button type="submit" variant="solid" disabled={enroll.isPending}>gerar token</Button>
        </form>
      )}
    </Dialog>
  );
}

function EndpointPanel({ id, onClose }: { id: string; onClose: () => void }) {
  const query = useQuery({ queryKey: ["endpoints", "detail", id], queryFn: () => api.get<EndpointDetail>(`/endpoints/${id}`) });
  const tree = useQuery({ queryKey: ["endpoints", "tree", id], queryFn: () => api.get<ProcessNode[]>(`/endpoints/${id}/process-tree`, { hours: 24 }) });
  return (
    <Drawer open title={query.data?.hostname ?? "endpoint"} onClose={onClose}>
      <QueryState query={query}>
        {(e) => (
          <div className="flex flex-col gap-4">
            <Facts items={[
              ["status", <span key="s" className={STATUS_TONE[e.status]}>{e.status}</span>],
              ["sistema", e.os],
              ["ips", e.ip_addresses.join(", ")],
              ["criticidade", e.criticality],
              ["primeiro visto", formatDateTime(e.first_seen_at)],
              ["último contato", formatDateTime(e.last_seen_at)],
              ["eventos 24h", formatNumber(e.events_24h)],
              ["alertas abertos", e.open_alerts],
              ["isolamento", e.isolation_state],
            ]} />
            <div>
              <p className="eyebrow mb-2">eventos por categoria</p>
              <BarList items={e.activity.map((a) => ({ key: a.category, label: categoryLabel[a.category] ?? a.category, value: a.count }))} />
            </div>
            <div>
              <p className="eyebrow mb-2">agentes</p>
              {e.agents.map((a) => (
                <Facts key={a.id} className="mb-2 border-l border-border pl-3" items={[
                  ["nome", a.name],
                  ["versão", a.version],
                  ["heartbeat", relative(a.last_heartbeat_at)],
                  ["recebidos / duplicados / rejeitados", `${a.events_received} / ${a.events_duplicated} / ${a.events_rejected}`],
                  ["buffer local", a.buffer_depth],
                  ["último seq", a.last_seq],
                ]} />
              ))}
            </div>
            <div>
              <p className="eyebrow mb-2">árvore de processos · 24h</p>
              <QueryState query={tree}>{(roots) => <ProcessTree roots={roots} onlyFlagged={roots.length > 30} />}</QueryState>
            </div>
          </div>
        )}
      </QueryState>
    </Drawer>
  );
}

export function EndpointsView() {
  const scope = useScope();
  const params = useSearchParams();
  const router = useRouter();
  const client = useQueryClient();
  const canManage = usePermission("agents:manage");
  const [enrolling, setEnrolling] = useState(false);
  const focus = params.get("focus");
  const endpoints = useQuery({ queryKey: ["endpoints", scope], queryFn: () => api.get<EndpointSummary[]>("/endpoints", { scope }), refetchInterval: 15_000 });
  const agents = useQuery({ queryKey: ["agents", scope], queryFn: () => api.get<Agent[]>("/agents", { scope }) });
  const revoke = useMutation({
    mutationFn: (id: string) => api.post(`/agents/${id}/revoke`),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["agents"] }),
  });
  const setFocus = (id: string | null) => router.replace(id ? `/endpoints?focus=${id}` : "/endpoints", { scroll: false });

  return (
    <>
      <PageHeader
        path="endpoints"
        title="Dispositivos monitorados"
        description="Hosts que enviaram telemetria e os agentes autorizados a enviar. Status: online ≤ 2 min, stale ≤ 30 min."
        actions={canManage && scope === "live" ? <Button variant="solid" onClick={() => setEnrolling(true)}>cadastrar agente</Button> : null}
      />
      <div className="flex flex-col gap-4">
        <Panel title="endpoints" meta={endpoints.data ? `${endpoints.data.length}` : undefined}>
          <QueryState query={endpoints} isEmpty={(d) => d.length === 0} empty={<Empty title="Nenhum endpoint." hint={scope === "live" ? "Cadastre um agente e inicie a coleta." : "Execute um cenário demo."} />}>
            {(rows) => (
              <Table>
                <thead><tr><Th>host</Th><Th>status</Th><Th>sistema</Th><Th>ips</Th><Th>criticidade</Th><Th className="text-right">eventos 24h</Th><Th className="text-right">alertas</Th><Th>último contato</Th></tr></thead>
                <tbody>
                  {rows.map((e) => (
                    <Tr key={e.id} className={focus === e.id ? "bg-raised" : undefined}>
                      <Td>
                        <button onClick={() => setFocus(e.id)} className="hover:text-accent">{e.hostname}</button>
                        {e.is_synthetic ? <DemoBadge className="ml-2" /> : null}
                      </Td>
                      <Td><span className={cn("flex items-center gap-1.5 text-2xs", STATUS_TONE[e.status])}><i className="block size-1.5 rounded-full bg-current" />{e.status}</span></Td>
                      <Td className="text-muted">{e.os ?? "—"}</Td>
                      <Td className="text-2xs text-muted">{e.ip_addresses.join(", ")}</Td>
                      <Td><Badge>{e.criticality}</Badge></Td>
                      <Td className="text-right tabular">{formatNumber(e.events_24h)}</Td>
                      <Td className={cn("text-right tabular", e.open_alerts ? "text-warm" : "text-dim")}>{e.open_alerts}</Td>
                      <Td className="text-2xs text-muted">{relative(e.last_seen_at)}</Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            )}
          </QueryState>
        </Panel>
        <Panel title="agentes" meta="tokens só existem como hash no servidor">
          <QueryState query={agents} isEmpty={(d) => d.length === 0} empty={<Empty title="Nenhum agente cadastrado." />}>
            {(rows) => (
              <Table>
                <thead><tr><Th>nome</Th><Th>token</Th><Th>status</Th><Th>versão</Th><Th className="text-right">recebidos</Th><Th className="text-right">dup.</Th><Th className="text-right">rejeit.</Th><Th>heartbeat</Th>{canManage ? <Th /> : null}</tr></thead>
                <tbody>
                  {rows.map((a) => (
                    <Tr key={a.id}>
                      <Td>{a.name}</Td>
                      <Td className="text-2xs text-dim">{a.token_prefix}…</Td>
                      <Td className={cn("text-2xs", a.status === "revoked" ? "text-critical" : a.status === "active" ? "text-accent" : "text-medium")}>{a.status}</Td>
                      <Td className="text-muted">{a.version ?? "—"}</Td>
                      <Td className="text-right tabular">{formatNumber(a.events_received)}</Td>
                      <Td className="text-right tabular text-muted">{formatNumber(a.events_duplicated)}</Td>
                      <Td className="text-right tabular text-muted">{formatNumber(a.events_rejected)}</Td>
                      <Td className="text-2xs text-muted">{relative(a.last_heartbeat_at)}</Td>
                      {canManage ? (
                        <Td>{a.status !== "revoked" && !a.is_synthetic ? <Button size="sm" variant="danger" onClick={() => { if (confirm(`Revogar o agente ${a.name}? Ele deixará de enviar eventos.`)) revoke.mutate(a.id); }}>revogar</Button> : null}</Td>
                      ) : null}
                    </Tr>
                  ))}
                </tbody>
              </Table>
            )}
          </QueryState>
        </Panel>
      </div>
      <EnrollDialog open={enrolling} onOpenChange={setEnrolling} />
      {focus ? <EndpointPanel id={focus} onClose={() => setFocus(null)} /> : null}
    </>
  );
}
