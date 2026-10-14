"use client";

import { useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { type FormEvent, useState } from "react";

import { AegisMark } from "@/components/brand";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/field";
import { api, ApiError, setCsrfToken } from "@/lib/api";
import type { LoginResult } from "@/lib/types";

function safeNext(value: string | null): string {
  // Only same-site relative paths: prevents open redirects through ?next=.
  if (!value || !value.startsWith("/") || value.startsWith("//")) return "/dashboard";
  return value;
}

export function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const client = useQueryClient();
  const [stage, setStage] = useState<"password" | "mfa">("password");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const done = (result: LoginResult) => {
    setCsrfToken(result.csrf_token);
    if (result.user) client.setQueryData(["me"], result.user);
    router.replace(safeNext(params.get("next")));
  };

  const describe = (err: unknown) => {
    if (err instanceof ApiError) {
      if (err.status === 429) return "Muitas tentativas. Aguarde alguns minutos.";
      if (err.status === 401) return stage === "mfa" ? "Código inválido." : "Credenciais inválidas.";
      return err.message;
    }
    return "Não foi possível contatar a API.";
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (stage === "password") {
        const result = await api.post<LoginResult>("/auth/login", { email, password });
        setPassword("");
        if (result.mfa_required) {
          setCsrfToken(result.csrf_token);
          setStage("mfa");
        } else {
          done(result);
        }
      } else {
        done(await api.post<LoginResult>("/auth/mfa/verify", { code }));
      }
    } catch (err) {
      setError(describe(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="grid min-h-svh place-items-center px-4">
      <div className="w-[min(360px,100%)]">
        <Link href="/" className="mb-8 flex items-center gap-3">
          <AegisMark className="size-8" />
          <span>
            <span className="block text-sm">aegis</span>
            <span className="block text-2xs text-muted">autonomous cyber defense platform</span>
          </span>
        </Link>
        <form onSubmit={submit} className="border border-border bg-surface p-5" noValidate>
          <p className="text-sm">
            <span className="text-accent">→</span>{" "}
            {stage === "password" ? "autenticação" : "verificação em duas etapas"}
          </p>
          <div className="mt-4 flex flex-col gap-3">
            {stage === "password" ? (
              <>
                <Field label="e-mail" htmlFor="email">
                  <Input
                    id="email"
                    type="email"
                    autoComplete="username"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    autoFocus
                  />
                </Field>
                <Field label="senha" htmlFor="password">
                  <Input
                    id="password"
                    type="password"
                    autoComplete="current-password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </Field>
              </>
            ) : (
              <Field label="código do autenticador" htmlFor="code" hint="6 dígitos, válido por 30 s.">
                <Input
                  id="code"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  required
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                  autoFocus
                />
              </Field>
            )}
          </div>
          {error ? (
            <p role="alert" className="mt-3 text-xs text-critical">
              {error}
            </p>
          ) : null}
          <Button type="submit" variant="solid" className="mt-4 w-full" disabled={busy}>
            {busy ? "verificando…" : stage === "password" ? "entrar" : "confirmar"}
          </Button>
        </form>
        <p className="mt-4 text-2xs leading-relaxed text-dim">
          Contas são criadas por um administrador (CLI <code>aegis create-user</code>). Não há
          credenciais padrão.
        </p>
      </div>
    </main>
  );
}
