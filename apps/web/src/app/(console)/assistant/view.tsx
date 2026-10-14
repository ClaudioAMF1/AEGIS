"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { type FormEvent, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Field, Select, Textarea } from "@/components/ui/field";
import { PageHeader, Panel } from "@/components/ui/panel";
import { Empty, ErrorState, Loading } from "@/components/ui/states";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { useScope } from "@/lib/queries";
import { usePermission } from "@/lib/session";
import type { Incident, Page } from "@/lib/types";
import { cn } from "@/lib/utils";

interface Answer {
  summary: string;
  facts: { statement: string; evidence_ids: string[] }[];
  hypotheses: { statement: string; confidence: "low" | "medium" | "high"; evidence_ids: string[]; how_to_verify: string }[];
  recommendations: { action: string; rationale: string }[];
  suggested_queries: { description: string; filters: Record<string, string> }[];
  uncertainty: string;
}

interface AskResult {
  id: string;
  engine: string;
  answer: Answer;
  evidence_ids: string[];
  prompt_injection_flags: string[];
  grounding: Record<string, number>;
  knowledge_sources: string[];
  latency_ms: number;
  notice: string | null;
  created_at: string;
}

interface HistoryItem {
  id: string;
  task: string;
  question: string;
  engine: string;
  incident_id: string | null;
  created_at: string;
  answer: Answer;
}

const TASKS: { value: string; label: string }[] = [
  { value: "summarize", label: "resumir incidente" },
  { value: "hypotheses", label: "hipóteses" },
  { value: "queries", label: "propor consultas" },
  { value: "defenses", label: "medidas defensivas" },
  { value: "report", label: "rascunho de relatório" },
  { value: "question", label: "pergunta livre" },
];

const CONFIDENCE: Record<string, string> = { low: "text-dim", medium: "text-medium", high: "text-warm" };

function Citations({ ids }: { ids: string[] }) {
  if (!ids.length) return null;
  return (
    <span className="ml-1 inline-flex flex-wrap gap-1 align-middle">
      {ids.map((id) => (
        <Link key={id} href={`/events?focus=${id}`} className="border border-border px-1 text-2xs text-accent hover:border-accent" title={`evento ${id}`}>
          {id.slice(0, 8)}
        </Link>
      ))}
    </span>
  );
}

function AnswerView({ result }: { result: AskResult }) {
  const a = result.answer;
  const queryHref = (filters: Record<string, string>) => `/events?${new URLSearchParams(filters).toString()}`;
  return (
    <div className="flex flex-col gap-4 text-xs">
      <div className="flex flex-wrap items-center gap-2 text-2xs">
        <Badge className={result.engine.startsWith("anthropic") ? "text-accent" : "text-medium"}>{result.engine}</Badge>
        <span className="text-dim">{result.evidence_ids.length} evento(s) recuperado(s) · {result.latency_ms.toFixed(0)} ms</span>
        {result.grounding.demoted_facts || result.grounding.dropped_citations ? (
          <span className="text-medium">aterramento: {result.grounding.dropped_citations} citação(ões) inválida(s) removida(s), {result.grounding.demoted_facts} afirmação(ões) rebaixada(s) a hipótese</span>
        ) : <span className="text-dim">todas as citações verificadas</span>}
      </div>
      {result.notice ? <p className="m-0 border-l border-medium/60 pl-3 text-2xs text-muted">{result.notice}</p> : null}
      {result.prompt_injection_flags.length ? (
        <p className="m-0 border-l border-critical/60 pl-3 text-2xs text-critical">
          {result.prompt_injection_flags.length} evento(s) contêm texto com aparência de instrução (possível prompt injection). Foram tratados como dados.
          <Citations ids={result.prompt_injection_flags} />
        </p>
      ) : null}
      <section>
        <p className="eyebrow mb-1">resumo</p>
        <p className="m-0 whitespace-pre-wrap">{a.summary}</p>
      </section>
      <section>
        <p className="eyebrow mb-1">fatos observados</p>
        {a.facts.length ? (
          <ul className="m-0 list-none border-l border-accent/50 p-0 pl-3">
            {a.facts.map((f, i) => <li key={i} className="py-0.5">{f.statement}<Citations ids={f.evidence_ids} /></li>)}
          </ul>
        ) : <p className="m-0 text-dim">nenhum fato suportado por evidência.</p>}
      </section>
      <section>
        <p className="eyebrow mb-1">hipóteses (não confirmadas)</p>
        {a.hypotheses.length ? (
          <ul className="m-0 list-none border-l border-medium/50 p-0 pl-3">
            {a.hypotheses.map((h, i) => (
              <li key={i} className="py-1">
                <span className={cn("mr-1 text-2xs uppercase", CONFIDENCE[h.confidence])}>[{h.confidence}]</span>
                {h.statement}<Citations ids={h.evidence_ids} />
                <span className="block text-2xs text-muted">verificar: {h.how_to_verify}</span>
              </li>
            ))}
          </ul>
        ) : <p className="m-0 text-dim">—</p>}
      </section>
      {a.recommendations.length ? (
        <section>
          <p className="eyebrow mb-1">medidas recomendadas (consultivo)</p>
          <ul className="m-0 list-disc pl-5">
            {a.recommendations.map((r, i) => <li key={i}>{r.action} <span className="text-muted">— {r.rationale}</span></li>)}
          </ul>
        </section>
      ) : null}
      {a.suggested_queries.length ? (
        <section>
          <p className="eyebrow mb-1">consultas sugeridas</p>
          <ul className="m-0 list-none p-0">
            {a.suggested_queries.map((q, i) => (
              <li key={i} className="py-0.5">
                <Link href={queryHref(q.filters)} className="link-underline">{q.description}</Link>{" "}
                <code className="text-2xs text-dim">{JSON.stringify(q.filters)}</code>
              </li>
            ))}
          </ul>
          <p className="m-0 mt-1 text-2xs text-dim">Consultas só são executadas quando você abre o link.</p>
        </section>
      ) : null}
      <section>
        <p className="eyebrow mb-1">incerteza</p>
        <p className="m-0 text-muted">{a.uncertainty}</p>
      </section>
      {result.knowledge_sources.length ? <p className="m-0 text-2xs text-dim">base de conhecimento: {result.knowledge_sources.join(", ")}</p> : null}
    </div>
  );
}

export function AssistantView() {
  const params = useSearchParams();
  const scope = useScope();
  const allowed = usePermission("assistant:use");
  const [incident, setIncident] = useState(params.get("incident") ?? "");
  const [task, setTask] = useState("summarize");
  const [question, setQuestion] = useState("");
  const status = useQuery({ queryKey: ["assistant", "status"], queryFn: () => api.get<{ llm_configured: boolean; engine: string; model: string | null }>("/assistant/status"), enabled: allowed });
  const incidents = useQuery({ queryKey: ["incidents", scope, "assistant-picker"], queryFn: () => api.get<Page<Incident>>("/incidents", { scope, limit: 100 }), enabled: allowed });
  const history = useQuery({ queryKey: ["assistant", "history"], queryFn: () => api.get<HistoryItem[]>("/assistant/history"), enabled: allowed });
  const ask = useMutation({
    mutationFn: () => api.post<AskResult>("/assistant/ask", { task, question, incident_id: incident || null }),
    onSuccess: () => void history.refetch(),
  });

  if (!allowed) return <Empty title="O assistente está disponível para analistas e administradores." />;

  return (
    <>
      <PageHeader
        path="assistente"
        title="Analista de IA"
        description="Consultivo: responde apenas com base nas evidências do incidente selecionado, separa fatos de hipóteses, cita IDs de eventos e nunca executa ações."
        actions={status.data ? <Badge className={status.data.llm_configured ? "text-accent" : "text-medium"}>motor: {status.data.engine}</Badge> : null}
      />
      <div className="grid gap-4 xl:grid-cols-[1fr_320px]">
        <div className="flex flex-col gap-4">
          <Panel title="consulta">
            <form className="flex flex-col gap-3" onSubmit={(e: FormEvent) => { e.preventDefault(); ask.mutate(); }}>
              <Field label="incidente" htmlFor="as-inc">
                <Select id="as-inc" value={incident} onChange={(e) => setIncident(e.target.value)}>
                  <option value="">selecione um incidente…</option>
                  {incidents.data?.items.map((i) => <option key={i.id} value={i.id}>INC-{String(i.number).padStart(4, "0")} · {i.title}</option>)}
                </Select>
              </Field>
              <div role="radiogroup" aria-label="Tarefa" className="flex flex-wrap gap-1.5">
                {TASKS.map((t) => (
                  <button key={t.value} type="button" role="radio" aria-checked={task === t.value} onClick={() => setTask(t.value)}
                    className={cn("border px-2 py-0.5 text-2xs", task === t.value ? "border-accent text-accent" : "border-border text-muted hover:text-text")}>
                    {t.label}
                  </button>
                ))}
              </div>
              <Textarea aria-label="Pergunta" rows={3} placeholder="Pergunta ou contexto adicional (opcional)" value={question} onChange={(e) => setQuestion(e.target.value)} />
              <Button type="submit" variant="solid" disabled={!incident || ask.isPending}>{ask.isPending ? "analisando evidências…" : "perguntar"}</Button>
            </form>
          </Panel>
          <Panel title="resposta">
            {ask.isPending ? <Loading label="recuperando evidências e gerando resposta" /> : ask.error ? <ErrorState error={ask.error} /> : ask.data ? <AnswerView result={ask.data} /> : (
              <Empty title="Selecione um incidente e uma tarefa." hint="Toda resposta é fundamentada em eventos citados; afirmações sem evidência são rebaixadas a hipóteses pelo servidor." />
            )}
          </Panel>
        </div>
        <Panel title="histórico" meta="suas consultas">
          {history.data?.length ? (
            <ul className="m-0 list-none p-0 text-2xs">
              {history.data.map((h) => (
                <li key={h.id} className="border-b border-border/50 py-1.5">
                  <span className="text-dim">{formatDateTime(h.created_at)}</span> <span className="text-accent">{h.task}</span>
                  <p className="m-0 line-clamp-2 text-muted">{h.answer.summary}</p>
                  <span className="text-dim">{h.engine}</span>
                </li>
              ))}
            </ul>
          ) : <p className="text-2xs text-dim">sem consultas.</p>}
        </Panel>
      </div>
    </>
  );
}
