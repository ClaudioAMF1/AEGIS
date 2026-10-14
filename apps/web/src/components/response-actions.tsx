"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input, Select, Textarea } from "@/components/ui/field";
import { Empty, ErrorState } from "@/components/ui/states";
import { api } from "@/lib/api";
import { formatDateTime, SEVERITIES, severityLabel } from "@/lib/format";
import { useMe, usePermission } from "@/lib/session";
import { cn } from "@/lib/utils";

export interface ResponseActionRow {
  id: string;
  action_type: string;
  target_type: string;
  target_id: string;
  incident_id: string | null;
  status: string;
  justification: string;
  impact_preview: { target_label?: string; description?: string; effects?: string[]; confirmation_text?: string; reversible?: boolean; parameters?: Record<string, string> };
  result: Record<string, unknown>;
  reversible: boolean;
  requested_by: string;
  approved_by: string | null;
  requested_at: string;
  decided_at: string | null;
  executed_at: string | null;
  reverted_at: string | null;
}

export const ACTION_LABEL: Record<string, string> = {
  request_investigation: "solicitar investigação",
  raise_incident_severity: "elevar severidade",
  disable_rule: "desativar regra",
  revoke_user_sessions: "revogar sessões de usuário",
  isolate_host_lab: "isolar host (laboratório)",
};

const STATUS_TONE: Record<string, string> = {
  proposed: "text-medium",
  approved: "text-warm",
  executed: "text-accent",
  rejected: "text-dim",
  failed: "text-critical",
  reverted: "text-muted",
};

export interface TargetOption {
  action_type: string;
  target_id: string;
  label: string;
}

/** Propose an action: preview first, then submit with a justification. */
export function ProposeAction({ options, incidentId }: { options: TargetOption[]; incidentId?: string }) {
  const client = useQueryClient();
  const [choice, setChoice] = useState(0);
  const [severity, setSeverity] = useState("critical");
  const [justification, setJustification] = useState("");
  const option = options[choice];
  const parameters = option?.action_type === "raise_incident_severity" ? { severity } : {};
  const preview = useQuery({
    queryKey: ["response", "preview", option?.action_type, option?.target_id, severity],
    queryFn: () => api.post<{ target_label: string; description: string; effects?: string[]; reversible: boolean }>("/response/preview", { action_type: option.action_type, target_id: option.target_id, parameters }),
    enabled: Boolean(option),
    retry: false,
  });
  const propose = useMutation({
    mutationFn: () => api.post<ResponseActionRow>("/response/actions", { action_type: option.action_type, target_id: option.target_id, parameters, justification, incident_id: incidentId ?? null }),
    onSuccess: () => {
      setJustification("");
      void client.invalidateQueries({ queryKey: ["response"] });
    },
  });
  if (!options.length) return <Empty title="Nenhuma ação aplicável." />;
  return (
    <form className="flex flex-col gap-3" onSubmit={(e: FormEvent) => { e.preventDefault(); propose.mutate(); }}>
      <Field label="ação" htmlFor="ra-choice">
        <Select id="ra-choice" value={choice} onChange={(e) => setChoice(Number(e.target.value))}>
          {options.map((o, i) => <option key={`${o.action_type}-${o.target_id}`} value={i}>{ACTION_LABEL[o.action_type] ?? o.action_type} · {o.label}</option>)}
        </Select>
      </Field>
      {option?.action_type === "raise_incident_severity" ? (
        <Field label="nova severidade" htmlFor="ra-sev">
          <Select id="ra-sev" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {SEVERITIES.map((s) => <option key={s} value={s}>{severityLabel[s]}</option>)}
          </Select>
        </Field>
      ) : null}
      <div className="border border-border bg-surface p-2 text-2xs">
        <p className="eyebrow m-0 mb-1">prévia de impacto</p>
        {preview.isPending ? <span className="text-muted">calculando…</span> : preview.error ? <ErrorState error={preview.error} /> : preview.data ? (
          <>
            <p className="m-0 text-muted">{preview.data.description}</p>
            <ul className="m-0 mt-1 list-disc pl-4">{preview.data.effects?.map((e) => <li key={e}>{e}</li>)}</ul>
            <p className="m-0 mt-1 text-dim">{preview.data.reversible ? "reversível" : "irreversível"} · alvo: {preview.data.target_label}</p>
          </>
        ) : null}
      </div>
      <Field label="justificativa" htmlFor="ra-just" hint="Registrada em auditoria. Mínimo 10 caracteres.">
        <Textarea id="ra-just" rows={3} value={justification} onChange={(e) => setJustification(e.target.value)} />
      </Field>
      <Button type="submit" variant="solid" disabled={justification.trim().length < 10 || !preview.data || propose.isPending}>solicitar aprovação</Button>
      {propose.error ? <ErrorState error={propose.error} /> : null}
      {propose.isSuccess ? <p className="m-0 text-2xs text-accent">solicitação registrada; aguarda aprovação de um administrador.</p> : null}
    </form>
  );
}

function DecisionDialog({ action, onClose }: { action: ResponseActionRow; onClose: () => void }) {
  const client = useQueryClient();
  const [confirmation, setConfirmation] = useState("");
  const [comment, setComment] = useState("");
  const decide = useMutation({
    mutationFn: (approve: boolean) => api.post<ResponseActionRow>(`/response/actions/${action.id}/decision`, { approve, confirmation, comment }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["response"] });
      void client.invalidateQueries({ queryKey: ["incident"] });
      onClose();
    },
  });
  const expected = action.impact_preview.confirmation_text ?? "";
  return (
    <Dialog open onOpenChange={(v) => !v && onClose()} title={`Aprovar: ${ACTION_LABEL[action.action_type] ?? action.action_type}`} description={action.impact_preview.description}>
      <div className="flex flex-col gap-3 text-xs">
        <p className="m-0 text-muted">justificativa: {action.justification}</p>
        <ul className="m-0 list-disc pl-4 text-2xs">{action.impact_preview.effects?.map((e) => <li key={e}>{e}</li>)}</ul>
        <Field label={`digite "${expected}" para confirmar`} htmlFor="dd-confirm">
          <Input id="dd-confirm" value={confirmation} onChange={(e) => setConfirmation(e.target.value)} autoComplete="off" />
        </Field>
        <Field label="comentário" htmlFor="dd-comment"><Input id="dd-comment" value={comment} onChange={(e) => setComment(e.target.value)} /></Field>
        {decide.error ? <ErrorState error={decide.error} /> : null}
        <div className="flex gap-2">
          <Button variant="solid" disabled={confirmation !== expected || decide.isPending} onClick={() => decide.mutate(true)}>aprovar e executar</Button>
          <Button variant="danger" disabled={decide.isPending} onClick={() => decide.mutate(false)}>rejeitar</Button>
        </div>
      </div>
    </Dialog>
  );
}

export function ActionList({ incidentId }: { incidentId?: string }) {
  const client = useQueryClient();
  const me = useMe();
  const canApprove = usePermission("response:approve");
  const [deciding, setDeciding] = useState<ResponseActionRow | null>(null);
  const actions = useQuery({ queryKey: ["response", "actions", incidentId ?? "all"], queryFn: () => api.get<ResponseActionRow[]>("/response/actions", { incident_id: incidentId }), refetchInterval: 10_000 });
  const revert = useMutation({ mutationFn: (id: string) => api.post(`/response/actions/${id}/revert`), onSuccess: () => void client.invalidateQueries({ queryKey: ["response"] }) });
  if (!actions.data?.length) return <Empty title="Nenhuma ação de resposta registrada." />;
  return (
    <>
      <ul className="m-0 list-none p-0">
        {actions.data.map((a) => (
          <li key={a.id} className="border-b border-border/60 py-2 text-xs last:border-0">
            <div className="flex flex-wrap items-center gap-2">
              <Badge className={cn(STATUS_TONE[a.status])}>{a.status}</Badge>
              <span>{ACTION_LABEL[a.action_type] ?? a.action_type}</span>
              <span className="text-muted">→ {a.impact_preview.target_label ?? a.target_id}</span>
              <span className="ml-auto text-2xs text-dim">{formatDateTime(a.requested_at)}</span>
            </div>
            <p className="m-0 mt-0.5 text-2xs text-muted">{a.justification}</p>
            {Object.keys(a.result).length ? <pre className="m-0 mt-1 overflow-x-auto text-2xs text-dim">{JSON.stringify(a.result)}</pre> : null}
            <div className="mt-1 flex gap-2">
              {canApprove && a.status === "proposed" ? (
                <Button size="sm" variant="solid" onClick={() => setDeciding(a)}>{a.requested_by === me.data?.id ? "decidir (própria solicitação)" : "decidir"}</Button>
              ) : null}
              {canApprove && a.status === "executed" && a.reversible ? (
                <Button size="sm" onClick={() => revert.mutate(a.id)}>reverter</Button>
              ) : null}
            </div>
          </li>
        ))}
      </ul>
      {revert.error ? <ErrorState error={revert.error} /> : null}
      {deciding ? <DecisionDialog action={deciding} onClose={() => setDeciding(null)} /> : null}
    </>
  );
}
