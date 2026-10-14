# ADR 0008 — Agente com polling de /proc antes de eBPF

**Estado:** aceita

## Contexto

eBPF dá visibilidade completa de `exec`/`connect` com baixo custo, mas exige kernel recente,
privilégios, toolchain específica e mais superfície de falha. O pipeline, o contrato e a
detecção precisavam ser validados ponta a ponta primeiro.

## Decisão

- Coletores em espaço de usuário: snapshots de `/proc` (processos, 250 ms; TCP, 1 s), inotify e
  leitura de `auth.log`/`secure`.
- Robustez antes de cobertura: detecção de reuso de PID (`start_ticks`), redação de segredos,
  rate limit, fila limitada, spool em disco, `Retry-After`, heartbeats com contadores de perda.
- eBPF como próximo coletor, mantendo o polling como *fallback*.

## Consequências

- Funciona em qualquer Linux com `/proc`, sem dependências de kernel; ~10 MB RSS e ~1,8 % de CPU
  medidos.
- Processos e conexões mais curtos que o intervalo podem ser perdidos — documentado em
  limitações e no README do agente.
