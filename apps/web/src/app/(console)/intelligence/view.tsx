"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { type FormEvent, useState } from "react";

import { BarList } from "@/components/charts/bar-list";
import { DemoBadge, SeverityBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Facts, Field, Input, Select, Textarea } from "@/components/ui/field";
import { PageHeader, Panel } from "@/components/ui/panel";
import { Empty, ErrorState, QueryState } from "@/components/ui/states";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { api } from "@/lib/api";
import { formatDateTime, relative, SEVERITIES, severityLabel } from "@/lib/format";
import { usePermission } from "@/lib/session";
import type { Page, Severity } from "@/lib/types";

interface Indicator {
  id: string;
  type: string;
  value: string;
  source: string;
  confidence: number;
  severity: Severity;
  description: string;
  tags: string[];
  license: string | null;
  first_seen_at: string;
  last_seen_at: string;
  expires_at: string | null;
  hits: number;
  is_synthetic: boolean;
}

interface Lookup {
  value: string;
  type: string | null;
  local_matches: Indicator[];
  sightings: number;
  last_seen: string | null;
  external: { provider: string; verdict: string; score: number | null; data: Record<string, unknown>; queried_at: string; cached: boolean } | null;
  note: string;
}

function LookupPanel() {
  const canLookup = usePermission("alerts:triage");
  const [value, setValue] = useState("");
  const lookup = useMutation({ mutationFn: () => api.get<Lookup>("/intel/lookup", { value: value.trim() }) });
  if (!canLookup) return null;
  return (
    <Panel title="consulta de indicador" meta="local + provedor externo opcional (cache 24h)">
      <form className="flex gap-2" onSubmit={(e: FormEvent) => { e.preventDefault(); lookup.mutate(); }}>
        <Input aria-label="Indicador" placeholder="ip, domínio, cidr ou sha256" value={value} onChange={(e) => setValue(e.target.value)} />
        <Button type="submit" variant="solid" disabled={value.trim().length < 3 || lookup.isPending}>consultar</Button>
      </form>
      {lookup.error ? <ErrorState error={lookup.error} className="mt-3" /> : null}
      {lookup.data ? (
        <div className="mt-3">
          <Facts items={[
            ["tipo", lookup.data.type ?? "não reconhecido"],
            ["ocorrências na telemetria", <Link key="s" className="link-underline" href={`/events?ip=${encodeURIComponent(lookup.data.value)}`}>{lookup.data.sightings}</Link>],
            ["última ocorrência", formatDateTime(lookup.data.last_seen)],
            ["indicadores locais", lookup.data.local_matches.map((m) => `${m.source} (${m.severity}, conf. ${m.confidence})`).join("; ") || "nenhum"],
            ["externo", lookup.data.external ? `${lookup.data.external.provider}: ${lookup.data.external.verdict}${lookup.data.external.score !== null ? ` · score ${lookup.data.external.score}` : ""}${lookup.data.external.cached ? " · cache" : ""}` : "—"],
            ["consultado em", lookup.data.external ? formatDateTime(lookup.data.external.queried_at) : "—"],
          ]} />
          <p className="m-0 mt-2 text-2xs text-dim">{lookup.data.note}</p>
        </div>
      ) : null}
    </Panel>
  );
}

function ImportPanel() {
  const client = useQueryClient();
  const [csv, setCsv] = useState("");
  const [source, setSource] = useState("lab-feed");
  const [license, setLicense] = useState("");
  const importer = useMutation({
    mutationFn: () => api.post<{ created: number; updated: number; rejected: string[] }>("/intel/indicators/import", { csv, source, license: license || null }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["intel"] }),
  });
  return (
    <Panel title="importar feed (csv)">
      <form className="flex flex-col gap-2" onSubmit={(e: FormEvent) => { e.preventDefault(); importer.mutate(); }}>
        <Textarea aria-label="CSV" rows={6} className="text-2xs" placeholder={"value,severity,confidence,description\n203.0.113.45,high,80,ssh brute force"} value={csv} onChange={(e) => setCsv(e.target.value)} />
        <div className="grid grid-cols-2 gap-2">
          <Field label="fonte" htmlFor="imp-src"><Input id="imp-src" value={source} onChange={(e) => setSource(e.target.value)} /></Field>
          <Field label="licença" htmlFor="imp-lic"><Input id="imp-lic" placeholder="ex.: CC-BY-4.0" value={license} onChange={(e) => setLicense(e.target.value)} /></Field>
        </div>
        <Button type="submit" disabled={!csv.trim() || importer.isPending}>importar</Button>
      </form>
      {importer.data ? (
        <p className="mt-2 text-2xs text-muted">criados {importer.data.created} · atualizados {importer.data.updated} · rejeitados {importer.data.rejected.length}
          {importer.data.rejected.slice(0, 3).map((r) => <span key={r} className="block text-critical">{r}</span>)}
        </p>
      ) : null}
      {importer.error ? <ErrorState error={importer.error} className="mt-2" /> : null}
      <p className="mt-2 text-2xs text-dim">Use apenas fontes públicas/autorizadas e respeite suas licenças. Indicadores são sinais auxiliares.</p>
    </Panel>
  );
}

export function IntelligenceView() {
  const client = useQueryClient();
  const canManage = usePermission("intel:manage");
  const [q, setQ] = useState("");
  const [type, setType] = useState("");
  const [value, setValue] = useState("");
  const [severity, setSeverity] = useState<Severity>("medium");
  const indicators = useQuery({ queryKey: ["intel", "indicators", q, type], queryFn: () => api.get<Page<Indicator>>("/intel/indicators", { q: q || undefined, type: type || undefined }) });
  const summary = useQuery({ queryKey: ["intel", "summary"], queryFn: () => api.get<{ by_type: Record<string, number>; by_source: Record<string, number>; top_hits: Indicator[] }>("/intel/summary") });
  const add = useMutation({
    mutationFn: () => api.post("/intel/indicators", { value, severity, source: "manual" }),
    onSuccess: () => {
      setValue("");
      void client.invalidateQueries({ queryKey: ["intel"] });
    },
  });
  const remove = useMutation({ mutationFn: (id: string) => api.delete(`/intel/indicators/${id}`), onSuccess: () => void client.invalidateQueries({ queryKey: ["intel"] }) });

  return (
    <>
      <PageHeader path="inteligencia" title="Inteligência de ameaças" description="Indicadores (IP, CIDR, domínio, SHA-256) usados para enriquecer eventos na ingestão. Cada indicador guarda fonte, confiança, licença e validade." />
      <div className="grid gap-4 xl:grid-cols-[2fr_1fr]">
        <div className="flex flex-col gap-4">
          <Panel
            title="indicadores"
            meta={indicators.data ? `${indicators.data.total ?? 0}` : undefined}
            actions={
              <div className="flex gap-2">
                <Select aria-label="Tipo" className="h-6 w-auto text-2xs" value={type} onChange={(e) => setType(e.target.value)}>
                  <option value="">todos os tipos</option>
                  {["ipv4", "ipv6", "cidr", "domain", "sha256"].map((t) => <option key={t} value={t}>{t}</option>)}
                </Select>
                <Input aria-label="Buscar" placeholder="buscar valor" className="h-6 w-40 text-2xs" value={q} onChange={(e) => setQ(e.target.value)} />
              </div>
            }
          >
            {canManage ? (
              <form className="mb-3 flex flex-wrap gap-2" onSubmit={(e: FormEvent) => { e.preventDefault(); add.mutate(); }}>
                <Input aria-label="Novo indicador" placeholder="novo indicador" className="w-56" value={value} onChange={(e) => setValue(e.target.value)} />
                <Select aria-label="Severidade" className="w-auto" value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
                  {SEVERITIES.map((s) => <option key={s} value={s}>{severityLabel[s]}</option>)}
                </Select>
                <Button type="submit" disabled={value.trim().length < 3 || add.isPending}>adicionar</Button>
                {add.error ? <ErrorState error={add.error} /> : null}
              </form>
            ) : null}
            <QueryState query={indicators} isEmpty={(d) => d.items.length === 0} empty={<Empty title="Nenhum indicador." hint="Importe um feed ou execute um cenário demo (que carrega indicadores de laboratório)." />}>
              {(data) => (
                <Table>
                  <thead><tr><Th>tipo</Th><Th>valor</Th><Th>severidade</Th><Th className="text-right">conf.</Th><Th>fonte</Th><Th className="text-right">hits</Th><Th>último</Th>{canManage ? <Th /> : null}</tr></thead>
                  <tbody>
                    {data.items.map((i) => (
                      <Tr key={i.id}>
                        <Td className="text-2xs text-muted">{i.type}</Td>
                        <Td className="break-all">{i.value}{i.is_synthetic ? <DemoBadge className="ml-2" /> : null}<div className="text-2xs text-dim">{i.description}</div></Td>
                        <Td><SeverityBadge severity={i.severity} /></Td>
                        <Td className="text-right tabular">{i.confidence}</Td>
                        <Td className="text-2xs text-muted">{i.source}{i.license ? ` · ${i.license}` : ""}</Td>
                        <Td className="text-right tabular text-warm">{i.hits}</Td>
                        <Td className="text-2xs text-muted">{relative(i.last_seen_at)}</Td>
                        {canManage ? <Td><Button size="sm" variant="ghost" onClick={() => remove.mutate(i.id)}>remover</Button></Td> : null}
                      </Tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </QueryState>
          </Panel>
        </div>
        <div className="flex flex-col gap-4">
          <LookupPanel />
          <Panel title="distribuição">
            <QueryState query={summary}>
              {(s) => (
                <>
                  <p className="eyebrow mb-2">por tipo</p>
                  <BarList items={Object.entries(s.by_type).map(([k, v]) => ({ key: k, label: k, value: v }))} />
                  <p className="eyebrow mt-4 mb-2">por fonte</p>
                  <BarList items={Object.entries(s.by_source).map(([k, v]) => ({ key: k, label: k, value: v }))} />
                </>
              )}
            </QueryState>
          </Panel>
          {canManage ? <ImportPanel /> : null}
        </div>
      </div>
    </>
  );
}
