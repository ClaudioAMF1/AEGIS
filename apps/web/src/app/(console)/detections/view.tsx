"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { AttackTag, Badge, SeverityBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Drawer } from "@/components/ui/drawer";
import { Facts, Input, Textarea } from "@/components/ui/field";
import { PageHeader, Panel } from "@/components/ui/panel";
import { Empty, ErrorState, QueryState } from "@/components/ui/states";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { TabPanel, Tabs } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import { formatDateTime, formatNumber, formatTime, relative } from "@/lib/format";
import { useScope } from "@/lib/queries";
import { usePermission } from "@/lib/session";
import type { DetectionRun, EventRow, Rule, RuleDetail } from "@/lib/types";
import { cn } from "@/lib/utils";

interface TestResult {
  valid: boolean;
  error: string | null;
  kind: string | null;
  evaluated: number;
  matched: number;
  matches: EventRow[];
}

const TEMPLATE = `title: Minha regra
id: draft-rule-0001
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /nc
    CommandLine|contains: ' -e '
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.004
`;

function Tester({ initial }: { initial?: string }) {
  const scope = useScope();
  const [content, setContent] = useState(initial ?? TEMPLATE);
  const [hours, setHours] = useState(24);
  const test = useMutation({
    mutationFn: () => api.post<TestResult>("/detections/test", { content, scope, hours }),
  });
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <div>
        <Textarea aria-label="Regra Sigma" rows={18} className="font-mono text-2xs" spellCheck={false} value={content} onChange={(e) => setContent(e.target.value)} />
        <div className="mt-2 flex items-center gap-2 text-2xs">
          <label className="flex items-center gap-1.5">últimas <Input type="number" min={1} max={720} className="h-6 w-16 text-2xs" value={hours} onChange={(e) => setHours(Number(e.target.value))} /> horas ({scope})</label>
          <Button variant="solid" size="sm" onClick={() => test.mutate()} disabled={test.isPending}>executar dry-run</Button>
        </div>
        <p className="mt-2 text-2xs text-dim">Dry-run: nada é persistido e nenhum alerta é criado. Regras entram em produção via repositório (rules/) com casos de regressão.</p>
      </div>
      <div>
        {test.error ? <ErrorState error={test.error} /> : null}
        {test.data ? (
          test.data.valid ? (
            <div className="text-xs">
              <p className="m-0 text-accent">regra válida ({test.data.kind})</p>
              {test.data.error ? <p className="m-0 mt-1 text-muted">{test.data.error}</p> : (
                <>
                  <p className="m-0 mt-1">{formatNumber(test.data.matched)} de {formatNumber(test.data.evaluated)} eventos correspondem</p>
                  <ul className="m-0 mt-2 max-h-[340px] list-none overflow-y-auto p-0 text-2xs">
                    {test.data.matches.map((e) => (
                      <li key={e.id} className="border-b border-border/50 py-0.5"><span className="text-dim">{formatTime(e.occurred_at)} {e.hostname}</span> {e.summary}</li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          ) : <p className="text-xs text-critical">inválida: <span className="text-text">{test.data.error}</span></p>
        ) : <p className="text-2xs text-dim">Edite e execute para ver correspondências na telemetria persistida.</p>}
      </div>
    </div>
  );
}

function RulePanel({ ruleId, onClose }: { ruleId: string; onClose: () => void }) {
  const client = useQueryClient();
  const canManage = usePermission("rules:manage");
  const [reason, setReason] = useState("");
  const query = useQuery({ queryKey: ["rules", ruleId], queryFn: () => api.get<RuleDetail>(`/detections/rules/${ruleId}`) });
  const toggle = useMutation({
    mutationFn: (enabled: boolean) => api.patch<Rule>(`/detections/rules/${ruleId}`, { enabled, reason }),
    onSuccess: () => {
      setReason("");
      void client.invalidateQueries({ queryKey: ["rules"] });
    },
  });
  return (
    <Drawer open title={query.data?.title ?? ruleId} onClose={onClose}>
      <QueryState query={query}>
        {(r) => (
          <div className="flex flex-col gap-4">
            <div className="flex flex-wrap gap-2">
              <SeverityBadge severity={r.severity} />
              <Badge className={r.enabled ? "text-accent" : "text-dim"}>{r.enabled ? "ativa" : "desativada"}</Badge>
              <Badge>{r.kind}</Badge>
              {!r.generates_alerts ? <Badge className="text-muted">bloco de correlação</Badge> : null}
              {r.attack_techniques.map((t) => <AttackTag key={t} technique={t} />)}
            </div>
            <p className="m-0 text-xs whitespace-pre-wrap text-muted">{r.description}</p>
            <Facts items={[
              ["id", r.rule_id],
              ["versão", `v${r.version} · sha256 ${r.content_sha256.slice(0, 12)}`],
              ["origem", r.source],
              ["matches", formatNumber(r.match_count)],
              ["último match", formatDateTime(r.last_matched_at)],
              ["falsos positivos", r.false_positives.join("; ") || "—"],
            ]} />
            <div>
              <p className="eyebrow mb-1">histórico de versões</p>
              <ul className="m-0 list-none p-0 text-2xs">
                {r.versions.map((v) => (
                  <li key={v.version} className={cn("flex gap-3", v.is_current ? "text-text" : "text-muted")}>
                    <span>v{v.version}</span><span className="text-dim">{v.sha256.slice(0, 12)}</span><span>{formatDateTime(v.created_at)}</span>{v.is_current ? <span className="text-accent">atual</span> : null}
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <p className="eyebrow mb-1">definição</p>
              <pre className="m-0 max-h-[360px] overflow-auto border border-border bg-surface p-2 text-2xs">{r.content}</pre>
            </div>
            {canManage ? (
              <div className="border-t border-border pt-3">
                <p className="eyebrow mb-1">{r.enabled ? "desativar" : "reativar"} (registrado em auditoria)</p>
                <div className="flex gap-2">
                  <Input placeholder="justificativa (obrigatória)" value={reason} onChange={(e) => setReason(e.target.value)} />
                  <Button variant={r.enabled ? "danger" : "solid"} disabled={reason.trim().length < 3 || toggle.isPending} onClick={() => toggle.mutate(!r.enabled)}>
                    {r.enabled ? "desativar" : "ativar"}
                  </Button>
                </div>
                {toggle.error ? <ErrorState error={toggle.error} className="mt-2" /> : null}
              </div>
            ) : null}
            <div className="border-t border-border pt-3">
              <p className="eyebrow mb-2">testar esta regra</p>
              <Tester initial={r.content} />
            </div>
          </div>
        )}
      </QueryState>
    </Drawer>
  );
}

export function DetectionsView() {
  const [tab, setTab] = useState("rules");
  const [focus, setFocus] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const rules = useQuery({ queryKey: ["rules"], queryFn: () => api.get<Rule[]>("/detections/rules") });
  const errors = useQuery({ queryKey: ["rules", "errors"], queryFn: () => api.get<{ path: string; error: string }[]>("/detections/rules/errors") });
  const runs = useQuery({ queryKey: ["rules", "runs"], queryFn: () => api.get<DetectionRun[]>("/detections/runs", { limit: 100 }), enabled: tab === "runs" });
  const visible = (rules.data ?? []).filter((r) => !filter || `${r.title} ${r.rule_id} ${r.attack_techniques.join(" ")}`.toLowerCase().includes(filter.toLowerCase()));

  return (
    <>
      <PageHeader
        path="regras"
        title="Motor de detecção"
        description="Subconjunto documentado do formato Sigma e regras de correlação (event_count, value_count, temporal, temporal_ordered) avaliadas sobre matches persistidos."
      />
      {errors.data?.length ? (
        <div className="mb-4 border-l border-critical/60 pl-3 text-xs">
          <p className="m-0 text-critical">{errors.data.length} arquivo(s) de regra rejeitado(s) no carregamento:</p>
          {errors.data.map((e) => <p key={e.path} className="m-0 text-2xs text-muted">{e.path}: {e.error}</p>)}
        </div>
      ) : null}
      <Tabs value={tab} onValueChange={setTab} tabs={[{ value: "rules", label: `regras${rules.data ? ` · ${rules.data.length}` : ""}` }, { value: "test", label: "testar regra" }, { value: "runs", label: "execuções" }]}>
        <TabPanel value="rules">
          <Panel title="regras" actions={<Input aria-label="Filtrar regras" placeholder="filtrar (título, id, técnica)" value={filter} onChange={(e) => setFilter(e.target.value)} className="h-6 w-56 text-2xs" />}>
            <QueryState query={rules} isEmpty={(d) => d.length === 0} empty={<Empty title="Nenhuma regra carregada." />}>
              {() => (
                <Table>
                  <thead><tr><Th>estado</Th><Th>severidade</Th><Th>regra</Th><Th>tipo</Th><Th>att&ck</Th><Th className="text-right">matches</Th><Th>último</Th></tr></thead>
                  <tbody>
                    {visible.map((r) => (
                      <Tr key={r.id}>
                        <Td><span className={cn("text-2xs", r.enabled ? "text-accent" : "text-dim")}>{r.enabled ? "● ativa" : "○ off"}</span></Td>
                        <Td><SeverityBadge severity={r.severity} /></Td>
                        <Td>
                          <button onClick={() => setFocus(r.rule_id)} className="text-left hover:text-accent">{r.title}</button>
                          <div className="text-2xs text-dim">{r.rule_id} · v{r.version}</div>
                        </Td>
                        <Td className="text-2xs text-muted">{r.kind}{r.generates_alerts ? "" : " · bloco"}</Td>
                        <Td className="text-2xs text-muted">{r.attack_techniques.join(" ")}</Td>
                        <Td className="text-right tabular">{formatNumber(r.match_count)}</Td>
                        <Td className="text-2xs text-muted">{relative(r.last_matched_at)}</Td>
                      </Tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </QueryState>
          </Panel>
        </TabPanel>
        <TabPanel value="test"><Panel title="dry-run"><Tester /></Panel></TabPanel>
        <TabPanel value="runs">
          <Panel title="histórico de execução" meta="cada lote de eventos avaliado pelo motor">
            <QueryState query={runs} isEmpty={(d) => d.length === 0} empty={<Empty title="Nenhuma execução registrada." />}>
              {(data) => (
                <Table>
                  <thead><tr><Th>início</Th><Th>gatilho</Th><Th className="text-right">eventos</Th><Th className="text-right">regras</Th><Th className="text-right">matches</Th><Th className="text-right">alertas</Th><Th className="text-right">duração</Th><Th>erros</Th></tr></thead>
                  <tbody>
                    {data.map((r) => (
                      <Tr key={r.id}>
                        <Td className="text-2xs text-muted">{formatDateTime(r.started_at)}</Td>
                        <Td className="text-2xs">{r.trigger}</Td>
                        <Td className="text-right tabular">{r.events_evaluated}</Td>
                        <Td className="text-right tabular">{r.rules_evaluated}</Td>
                        <Td className="text-right tabular">{r.matches}</Td>
                        <Td className="text-right tabular text-warm">{r.alerts_created}</Td>
                        <Td className="text-right tabular">{r.duration_ms.toFixed(1)} ms</Td>
                        <Td className={cn("text-2xs", r.errors.length ? "text-critical" : "text-dim")}>{r.errors.length ? r.errors[0] : "—"}</Td>
                      </Tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </QueryState>
          </Panel>
        </TabPanel>
      </Tabs>
      {focus ? <RulePanel ruleId={focus} onClose={() => setFocus(null)} /> : null}
    </>
  );
}
