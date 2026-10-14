import type { AlertStatus, IncidentStatus, Severity } from "./types";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"];

export const severityLabel: Record<Severity, string> = {
  critical: "crítica",
  high: "alta",
  medium: "média",
  low: "baixa",
  informational: "info",
};

export const incidentStatusLabel: Record<IncidentStatus, string> = {
  new: "novo",
  investigating: "investigando",
  contained: "contido",
  resolved: "resolvido",
  false_positive: "falso positivo",
};

export const alertStatusLabel: Record<AlertStatus, string> = {
  open: "aberto",
  acknowledged: "reconhecido",
  closed: "fechado",
};

export const categoryLabel: Record<string, string> = {
  process: "processo",
  network: "rede",
  file: "arquivo",
  authentication: "autenticação",
  system: "sistema",
};

const pad = (n: number) => String(n).padStart(2, "0");

export function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  const d = new Date(value);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return "—";
  const d = new Date(value);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${formatTime(value)}`;
}

export function relative(value: string | null | undefined, now: number = Date.now()): string {
  if (!value) return "nunca";
  const seconds = Math.round((now - new Date(value).getTime()) / 1000);
  if (seconds < 5) return "agora";
  if (seconds < 60) return `há ${seconds}s`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `há ${minutes}min`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `há ${hours}h`;
  return `há ${Math.round(hours / 24)}d`;
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 60) return `${seconds.toFixed(0)}s`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)}min`;
  return `${(seconds / 3600).toFixed(1)}h`;
}

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return new Intl.NumberFormat("pt-BR").format(value);
}

export function shortId(id: string): string {
  return id.slice(0, 8);
}

/** pt-BR text for metrics computed by the API (keys are stable; English is the API fallback). */
export const metricText: Record<string, { label: string; definition: string }> = {
  endpoints: { label: "endpoints monitorados", definition: "Hosts distintos que já enviaram telemetria." },
  endpoints_online: { label: "endpoints online", definition: "Hosts que reportaram nos últimos 2 minutos." },
  events_per_second: { label: "eventos / segundo", definition: "Eventos ingeridos nos últimos 60 s divididos por 60." },
  events_period: { label: "eventos no período", definition: "Eventos cujo horário de ocorrência está no período selecionado." },
  open_alerts: { label: "alertas abertos", definition: "Alertas que não estão fechados (qualquer data)." },
  rules_enabled: { label: "regras ativas", definition: "Versões atuais de regras habilitadas no motor de detecção." },
};
