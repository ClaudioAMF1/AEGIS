"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import QRCode from "qrcode";
import { type FormEvent, useEffect, useState } from "react";

import { DemoLauncher } from "@/components/demo-launcher";
import { ActionList } from "@/components/response-actions";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Facts, Field, Input, Select } from "@/components/ui/field";
import { PageHeader, Panel } from "@/components/ui/panel";
import { ErrorState, QueryState } from "@/components/ui/states";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { TabPanel, Tabs } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import { formatDateTime, relative } from "@/lib/format";
import { useMe, usePermission } from "@/lib/session";
import type { AuditEntry, Page, UserRow } from "@/lib/types";
import { cn } from "@/lib/utils";

interface SessionRow {
  id: string;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  ip_address: string | null;
  user_agent: string | null;
  current: boolean;
}

function MfaSetup() {
  const client = useQueryClient();
  const me = useMe();
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [qr, setQr] = useState<string | null>(null);
  const setup = useMutation({ mutationFn: () => api.post<{ secret: string; otpauth_uri: string }>("/auth/mfa/setup") });
  const enable = useMutation({ mutationFn: () => api.post("/auth/mfa/enable", { code }), onSuccess: () => void client.invalidateQueries({ queryKey: ["me"] }) });
  const disable = useMutation({ mutationFn: () => api.post("/auth/mfa/disable", { code, password }), onSuccess: () => void client.invalidateQueries({ queryKey: ["me"] }) });
  useEffect(() => {
    if (!setup.data) return;
    let cancelled = false;
    void QRCode.toDataURL(setup.data.otpauth_uri, { margin: 1, width: 168, color: { dark: "#0b0c0b", light: "#d2d0b9" } }).then((url) => {
      if (!cancelled) setQr(url);
    });
    return () => {
      cancelled = true;
    };
  }, [setup.data]);
  if (me.data?.mfa_enabled) {
    return (
      <form className="flex flex-col gap-2" onSubmit={(e: FormEvent) => { e.preventDefault(); disable.mutate(); }}>
        <p className="m-0 text-xs text-accent">MFA ativo (TOTP).</p>
        <div className="grid grid-cols-2 gap-2">
          <Input type="password" aria-label="Senha" placeholder="senha" value={password} onChange={(e) => setPassword(e.target.value)} />
          <Input aria-label="Código" placeholder="código" inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} />
        </div>
        <Button type="submit" variant="danger" disabled={!password || code.length < 6}>desativar MFA</Button>
        {disable.error ? <ErrorState error={disable.error} /> : null}
      </form>
    );
  }
  return (
    <div className="flex flex-col gap-2 text-xs">
      <p className="m-0 text-muted">Proteja sua conta com um aplicativo autenticador (TOTP, RFC 6238).</p>
      {!setup.data ? <Button onClick={() => setup.mutate()} disabled={setup.isPending}>iniciar configuração</Button> : (
        <form className="flex flex-col gap-2" onSubmit={(e: FormEvent) => { e.preventDefault(); enable.mutate(); }}>
          {/* eslint-disable-next-line @next/next/no-img-element -- local data: URL, no optimisation applicable */}
          {qr ? <img src={qr} alt="QR code para o aplicativo autenticador" width={168} height={168} className="border border-border" /> : null}
          <p className="m-0 text-2xs text-muted">ou digite a chave: <code className="select-all break-all text-text">{setup.data.secret}</code></p>
          <Input aria-label="Código de verificação" placeholder="código de 6 dígitos" inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} maxLength={6} />
          <Button type="submit" variant="solid" disabled={code.length !== 6 || enable.isPending}>ativar</Button>
          <p className="m-0 text-2xs text-dim">Ao ativar, suas outras sessões são encerradas.</p>
        </form>
      )}
      {setup.error ? <ErrorState error={setup.error} /> : null}
      {enable.error ? <ErrorState error={enable.error} /> : null}
    </div>
  );
}

function AccountTab() {
  const client = useQueryClient();
  const me = useMe();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const sessions = useQuery({ queryKey: ["sessions"], queryFn: () => api.get<SessionRow[]>("/auth/sessions") });
  const change = useMutation({ mutationFn: () => api.post("/auth/password", { current_password: current, new_password: next }), onSuccess: () => { setCurrent(""); setNext(""); void client.invalidateQueries({ queryKey: ["sessions"] }); } });
  const revoke = useMutation({ mutationFn: (id: string) => api.delete(`/auth/sessions/${id}`), onSuccess: () => void client.invalidateQueries({ queryKey: ["sessions"] }) });
  return (
    <div className="grid gap-4 xl:grid-cols-3">
      <Panel title="perfil">
        {me.data ? <Facts items={[["nome", me.data.display_name], ["e-mail", me.data.email], ["perfil", me.data.role], ["permissões", me.data.permissions.join(", ")], ["sessão expira", formatDateTime(me.data.session_expires_at)]]} /> : null}
      </Panel>
      <Panel title="autenticação multifator"><MfaSetup /></Panel>
      <Panel title="alterar senha">
        <form className="flex flex-col gap-2" onSubmit={(e: FormEvent) => { e.preventDefault(); change.mutate(); }}>
          <Field label="senha atual" htmlFor="pw-cur"><Input id="pw-cur" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} /></Field>
          <Field label="nova senha" htmlFor="pw-new" hint="Mínimo 12 caracteres; frases longas são bem-vindas."><Input id="pw-new" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} /></Field>
          <Button type="submit" disabled={!current || next.length < 12 || change.isPending}>alterar</Button>
          {change.isSuccess ? <p className="m-0 text-2xs text-accent">senha alterada; outras sessões encerradas.</p> : null}
          {change.error ? <ErrorState error={change.error} /> : null}
        </form>
      </Panel>
      <Panel title="sessões ativas" className="xl:col-span-3">
        <QueryState query={sessions}>
          {(rows) => (
            <Table>
              <thead><tr><Th>criada</Th><Th>último uso</Th><Th>expira</Th><Th>ip</Th><Th>agente</Th><Th /></tr></thead>
              <tbody>
                {rows.map((s) => (
                  <Tr key={s.id}>
                    <Td className="text-2xs">{formatDateTime(s.created_at)}</Td>
                    <Td className="text-2xs">{relative(s.last_seen_at)}</Td>
                    <Td className="text-2xs">{formatDateTime(s.expires_at)}</Td>
                    <Td className="text-2xs text-muted">{s.ip_address}</Td>
                    <Td className="max-w-[320px] truncate text-2xs text-muted">{s.user_agent}</Td>
                    <Td>{s.current ? <Badge className="text-accent">atual</Badge> : <Button size="sm" variant="ghost" onClick={() => revoke.mutate(s.id)}>revogar</Button>}</Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          )}
        </QueryState>
      </Panel>
    </div>
  );
}

function UsersTab() {
  const client = useQueryClient();
  const canManage = usePermission("users:manage");
  const users = useQuery({ queryKey: ["users"], queryFn: () => api.get<UserRow[]>("/users") });
  const [form, setForm] = useState({ email: "", display_name: "", role: "analyst", password: "" });
  const create = useMutation({ mutationFn: () => api.post("/users", form), onSuccess: () => { setForm({ email: "", display_name: "", role: "analyst", password: "" }); void client.invalidateQueries({ queryKey: ["users"] }); } });
  const update = useMutation({ mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) => api.patch(`/users/${id}`, body), onSuccess: () => void client.invalidateQueries({ queryKey: ["users"] }) });
  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_320px]">
      <Panel title="usuários">
        <QueryState query={users}>
          {(rows) => (
            <Table>
              <thead><tr><Th>usuário</Th><Th>perfil</Th><Th>mfa</Th><Th>status</Th><Th>último login</Th></tr></thead>
              <tbody>
                {rows.map((u) => (
                  <Tr key={u.id}>
                    <Td>{u.display_name}<div className="text-2xs text-dim">{u.email}</div></Td>
                    <Td>
                      {canManage ? (
                        <Select aria-label={`Perfil de ${u.email}`} className="h-6 w-auto text-2xs" value={u.role} onChange={(e) => update.mutate({ id: u.id, body: { role: e.target.value } })}>
                          {["administrator", "analyst", "viewer"].map((r) => <option key={r} value={r}>{r}</option>)}
                        </Select>
                      ) : u.role}
                    </Td>
                    <Td className={cn("text-2xs", u.mfa_enabled ? "text-accent" : "text-dim")}>{u.mfa_enabled ? "ativo" : "—"}</Td>
                    <Td>
                      {canManage ? (
                        <button className={cn("text-2xs", u.is_active ? "text-accent" : "text-critical")} onClick={() => update.mutate({ id: u.id, body: { is_active: !u.is_active } })}>{u.is_active ? "ativo" : "desativado"}</button>
                      ) : u.is_active ? "ativo" : "desativado"}
                    </Td>
                    <Td className="text-2xs text-muted">{relative(u.last_login_at)}</Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          )}
        </QueryState>
        {update.error ? <ErrorState error={update.error} className="mt-2" /> : null}
        <p className="mt-2 text-2xs text-dim">Mudanças de perfil ou desativação encerram as sessões do usuário imediatamente.</p>
      </Panel>
      {canManage ? (
        <Panel title="novo usuário">
          <form className="flex flex-col gap-2" onSubmit={(e: FormEvent) => { e.preventDefault(); create.mutate(); }}>
            <Field label="e-mail" htmlFor="nu-email"><Input id="nu-email" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></Field>
            <Field label="nome" htmlFor="nu-name"><Input id="nu-name" value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} /></Field>
            <Field label="perfil" htmlFor="nu-role">
              <Select id="nu-role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
                <option value="viewer">viewer</option><option value="analyst">analyst</option><option value="administrator">administrator</option>
              </Select>
            </Field>
            <Field label="senha inicial" htmlFor="nu-pw" hint="Compartilhe por canal seguro; o usuário deve trocá-la."><Input id="nu-pw" type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></Field>
            <Button type="submit" variant="solid" disabled={create.isPending}>criar</Button>
            {create.error ? <ErrorState error={create.error} /> : null}
          </form>
        </Panel>
      ) : null}
    </div>
  );
}

function AuditTab() {
  const [action, setAction] = useState("");
  const [outcome, setOutcome] = useState("");
  const audit = useQuery({ queryKey: ["audit", action, outcome], queryFn: () => api.get<Page<AuditEntry>>("/audit", { action: action || undefined, outcome: outcome || undefined, limit: 200 }) });
  return (
    <Panel title="trilha de auditoria" meta="somente inserção; segredos são redigidos" actions={
      <div className="flex gap-2">
        <Input aria-label="Ação" placeholder="prefixo da ação (ex.: auth.)" className="h-6 w-48 text-2xs" value={action} onChange={(e) => setAction(e.target.value)} />
        <Select aria-label="Resultado" className="h-6 w-auto text-2xs" value={outcome} onChange={(e) => setOutcome(e.target.value)}>
          <option value="">todos</option>{["success", "failure", "throttled", "locked", "rejected", "executed", "failed"].map((o) => <option key={o} value={o}>{o}</option>)}
        </Select>
      </div>
    }>
      <QueryState query={audit}>
        {(data) => (
          <Table>
            <thead><tr><Th>quando</Th><Th>ator</Th><Th>ação</Th><Th>recurso</Th><Th>resultado</Th><Th>ip</Th><Th>detalhes</Th></tr></thead>
            <tbody>
              {data.items.map((e) => (
                <Tr key={e.id}>
                  <Td className="text-2xs whitespace-nowrap text-muted">{formatDateTime(e.created_at)}</Td>
                  <Td className="text-2xs">{e.actor_email ?? "sistema"}</Td>
                  <Td className="text-2xs text-accent">{e.action}</Td>
                  <Td className="text-2xs text-muted">{e.resource_type}{e.resource_id ? ` · ${e.resource_id.slice(0, 8)}` : ""}</Td>
                  <Td className={cn("text-2xs", e.outcome === "success" || e.outcome === "executed" ? "text-muted" : "text-warm")}>{e.outcome}</Td>
                  <Td className="text-2xs text-dim">{e.ip_address}</Td>
                  <Td className="max-w-[360px] truncate text-2xs text-dim" title={JSON.stringify(e.details)}>{JSON.stringify(e.details)}</Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        )}
      </QueryState>
    </Panel>
  );
}

function SystemTab() {
  const health = useQuery({ queryKey: ["health"], queryFn: () => api.get<{ status: string; version: string; checks: Record<string, string>; pipeline_mode: string; environment: string }>("/health") });
  const assistant = useQuery({ queryKey: ["assistant", "status"], queryFn: () => api.get<{ engine: string; llm_configured: boolean }>("/assistant/status"), retry: false });
  const errors = useQuery({ queryKey: ["rules", "errors"], queryFn: () => api.get<{ path: string; error: string }[]>("/detections/rules/errors") });
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Panel title="saúde">
        <QueryState query={health}>
          {(h) => <Facts items={[["status", <span key="s" className={h.status === "ok" ? "text-accent" : "text-critical"}>{h.status}</span>], ["versão", h.version], ["ambiente", h.environment], ["pipeline", h.pipeline_mode], ...Object.entries(h.checks).map(([k, v]) => [k, v] as [string, string])]} />}
        </QueryState>
      </Panel>
      <Panel title="componentes">
        <Facts items={[
          ["assistente de IA", assistant.data ? `${assistant.data.engine}${assistant.data.llm_configured ? "" : " (sem chave de API)"}` : "sem permissão"],
          ["regras rejeitadas", errors.data ? String(errors.data.length) : "—"],
          ["métricas prometheus", "/metrics (rede interna)"],
        ]} />
        <p className="mt-2 text-2xs text-dim">Configuração sensível (segredos, chaves de API) é feita por variáveis de ambiente, nunca pela interface.</p>
      </Panel>
    </div>
  );
}

export function SettingsView() {
  const [tab, setTab] = useState("account");
  const canUsers = usePermission("incidents:write");
  const canAudit = usePermission("audit:read");
  const canRequest = usePermission("response:request");
  const canApprove = usePermission("response:approve");
  const canRespond = canRequest || canApprove;
  const tabs = [
    { value: "account", label: "conta" },
    ...(canUsers ? [{ value: "users", label: "usuários" }] : []),
    ...(canRespond ? [{ value: "response", label: "aprovações de resposta" }] : []),
    { value: "demo", label: "modo demo" },
    ...(canAudit ? [{ value: "audit", label: "auditoria" }] : []),
    { value: "system", label: "sistema" },
  ];
  return (
    <>
      <PageHeader path="configuracao" title="Configuração e administração" description="Conta, usuários e perfis (RBAC), aprovações de resposta, cenários demo, auditoria e estado do sistema. Todas as permissões são verificadas pela API." />
      <Tabs value={tab} onValueChange={setTab} tabs={tabs}>
        <TabPanel value="account"><AccountTab /></TabPanel>
        <TabPanel value="users"><UsersTab /></TabPanel>
        <TabPanel value="response"><Panel title="fila de ações de resposta" meta="toda decisão exige confirmação digitada e é auditada"><ActionList /></Panel></TabPanel>
        <TabPanel value="demo"><Panel title="cenários sintéticos" meta="passam pelo pipeline real; isolados dos dados live"><DemoLauncher /></Panel></TabPanel>
        <TabPanel value="audit"><AuditTab /></TabPanel>
        <TabPanel value="system"><SystemTab /></TabPanel>
      </Tabs>
    </>
  );
}
