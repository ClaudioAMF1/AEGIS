"use client";

import { motion } from "motion/react";
import Link from "next/link";
import { useState, useSyncExternalStore } from "react";

import { BootSequence } from "@/components/boot/boot-sequence";
import { AegisMark, Wordmark } from "@/components/brand";
import { useUi } from "@/lib/store";

const FLOW = [
  ["agente rust", "procfs · auth.log · inotify"],
  ["ingestão", "validação ACE v1 · dedup · origem"],
  ["enriquecimento", "intel · processo pai"],
  ["persistência", "postgresql"],
  ["detecção", "sigma · correlação"],
  ["alertas", "agrupamento · incidentes"],
  ["console", "tempo real · investigação"],
] as const;

const MODULES = [
  ["autenticação", "sessões no servidor, MFA TOTP, RBAC administrator/analyst/viewer, auditoria."],
  ["telemetria", "agente Linux em Rust: processos, conexões, arquivos e logins, com buffer local."],
  ["pipeline", "eventos validados, deduplicados, enriquecidos e entregues ao motor por broker."],
  ["detecção", "subconjunto documentado de Sigma + regras de correlação por janela temporal."],
  ["investigação", "linha do tempo, árvore de processos, grafo de entidades, evidências e diário."],
  ["modo demo", "cenários sintéticos reproduzíveis que passam pelo pipeline real, isolados do live."],
] as const;

export function Landing() {
  const introSeen = useUi((s) => s.introSeen);
  const setIntroSeen = useUi((s) => s.setIntroSeen);
  // true only in the browser: the intro depends on persisted client state.
  const mounted = useSyncExternalStore(
    () => () => {},
    () => true,
    () => false,
  );
  const [replay, setReplay] = useState(false);
  const showBoot = mounted && (!introSeen || replay);

  return (
    <div className="min-h-svh">
      {showBoot ? (
        <BootSequence
          onDone={() => {
            setIntroSeen();
            setReplay(false);
          }}
        />
      ) : null}
      <header className="mx-auto flex h-[78px] w-[min(1130px,calc(100%-32px))] items-center justify-between">
        <Wordmark />
        <nav className="flex items-center gap-6 text-sm text-muted">
          <button onClick={() => setReplay(true)} className="hover:text-text">
            intro
          </button>
          <a
            href="https://github.com/ClaudioAMF1/AEGIS"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-text"
          >
            github <span className="text-dim">↗</span>
          </a>
          <Link href="/login" className="text-text hover:text-accent">
            entrar →
          </Link>
        </nav>
      </header>

      <main className="mx-auto w-[min(1130px,calc(100%-32px))] pb-16">
        <section className="grid items-center gap-10 border-b border-border py-14 md:grid-cols-[1.2fr_1fr]">
          <div>
            <p className="text-sm">
              <span className="text-accent">→</span> <span className="text-muted">~/aegis</span>{" "}
              <span className="text-dim"># security operations</span>
            </p>
            <h1 className="mt-3 text-[clamp(32px,5vw,54px)] leading-[1.05] font-medium tracking-[-2px]">
              Defesa cibernética
              <br />
              <span className="text-accent">observável</span>, explicável.
            </h1>
            <p className="mt-5 max-w-xl text-sm text-muted">
              AEGIS coleta telemetria de máquinas Linux autorizadas, detecta comportamentos suspeitos
              com regras Sigma e correlações temporais, agrupa alertas em incidentes e oferece uma
              bancada de investigação com linha do tempo, árvore de processos e grafo de entidades.
              Toda métrica exibida tem definição e fonte; todo dado sintético é marcado como tal.
            </p>
            <div className="mt-7 flex flex-wrap gap-3">
              <Link
                href="/login"
                className="bg-text px-4 py-2 text-xs text-ground transition-colors hover:bg-accent"
              >
                abrir console
              </Link>
              <a
                href="https://github.com/ClaudioAMF1/AEGIS#readme"
                className="border border-border px-4 py-2 text-xs hover:border-accent hover:text-accent"
              >
                documentação
              </a>
            </div>
          </div>
          <motion.div
            className="scanlines relative border border-dim bg-surface p-5"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <div className="flex justify-between border-b border-border pb-2 text-[8px] tracking-[0.4px] text-muted">
              <span>AEGIS / ESTADO</span>
              <span>RFC 5737 · LAB</span>
            </div>
            <div className="flex items-center justify-between gap-4 py-6">
              <div>
                <p className="m-0 text-xs text-accent">autonomous cyber defense</p>
                <p className="m-0 mt-2 text-[40px] leading-none font-medium tracking-[-2px]">AEGIS</p>
                <p className="m-0 mt-2 text-2xs text-muted">edr · siem · detecção · investigação</p>
              </div>
              <AegisMark className="size-24 text-text" />
            </div>
            <div className="flex justify-between border-t border-border pt-2 text-[8px] text-muted">
              <span>somente ambientes autorizados</span>
              <span>contenção requer aprovação</span>
            </div>
          </motion.div>
        </section>

        <section className="border-b border-border py-10">
          <p className="eyebrow">fluxo de eventos</p>
          <ol className="mt-4 grid list-none gap-px border border-border bg-border p-0 sm:grid-cols-2 lg:grid-cols-7">
            {FLOW.map(([title, detail], i) => (
              <li key={title} className="bg-ground p-3">
                <span className="text-2xs text-dim tabular">0{i + 1}</span>
                <p className="m-0 mt-1 text-sm">{title}</p>
                <p className="m-0 mt-1 text-2xs text-muted">{detail}</p>
              </li>
            ))}
          </ol>
        </section>

        <section className="py-10">
          <p className="eyebrow">módulos</p>
          <dl className="mt-4 grid gap-x-10 gap-y-5 md:grid-cols-2">
            {MODULES.map(([name, text]) => (
              <div key={name} className="grid grid-cols-[120px_minmax(0,1fr)] gap-3 border-b border-border pb-3">
                <dt className="text-sm text-accent">{name}</dt>
                <dd className="m-0 text-sm text-muted">{text}</dd>
              </div>
            ))}
          </dl>
          <p className="mt-8 max-w-3xl text-2xs leading-relaxed text-dim">
            AEGIS é um projeto de portfólio. Não alega equivalência com soluções EDR/SIEM comerciais.
            Coleta, simulação e resposta operam apenas em ambientes próprios, autorizados ou isolados;
            nenhuma ação de contenção é executada sem aprovação explícita registrada em auditoria.
          </p>
        </section>
      </main>
    </div>
  );
}
