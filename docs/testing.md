# Testes e métricas

Todos os números abaixo foram obtidos executando as suítes neste repositório. Nada aqui é
estimado; quando um número depende do ambiente, o ambiente está descrito.

## Suítes

| Suíte | Onde | Como rodar | Resultado |
|---|---|---|---|
| API (unidade + integração HTTP) | `apps/api/tests` | `uv run pytest` | SQLite: 106 ✓, 5 ignorados · PostgreSQL 16 + Redis 7 + binário do agente: **111 ✓** |
| Regras (regressão) | `rules/tests/*.yml` via `test_rules_regression.py` | idem | 14 arquivos de casos, toda regra base coberta |
| Agente | `agents/linux-agent` | `cargo test` | **19 ✓**, `clippy -D warnings` limpo |
| Contrato agente ↔ schema | `test_contracts.py` + `AEGIS_AGENT_BIN` | ver [desenvolvimento](development.md) | ✓ |
| Web (unidade) | `apps/web/src/lib/*.test.ts` | `npx vitest run` | **8 ✓** |
| Web (E2E) | `apps/web/e2e` | `npx playwright test` | **10 ✓** contra o build de produção (com CSP) |

### O que os testes da API cobrem

| Arquivo | Cobertura |
|---|---|
| `test_vertical_slice.py` | ingestão → detecção → alerta → incidente; idempotência; rejeição parcial; vínculo agente↔host; limites de lote/corpo; retenção preservando evidências; **lotes concorrentes do mesmo host** (regressão de *deadlock*) |
| `test_auth.py` | cookie HttpOnly, erro genérico auditado, bloqueio por tentativas, CSRF, logout, listar/revogar sessões, MFA (cadastro, login, código reutilizado recusado), política e rotação na troca de senha, token *bearer* |
| `test_rbac.py` | matriz papel × permissão, requisições sem sessão, leitor sem triagem, troca de papel revoga sessões, admin não rebaixa a si mesmo |
| `test_sigma.py` | modificadores, curingas, condições, `1 of`/`all of`, erros explícitos para recursos não suportados, mapeamento de campos |
| `test_correlation.py` | `event_count` (limiar, fora de ordem, fora da janela, grupos independentes), `value_count` (*password spray*), `temporal_ordered` exige ordem, agregação de disparos repetidos |
| `test_incidents.py` | ciclo de vida, diário, evidências, contexto da linha do tempo, árvore de processos, grafo, escalonar alertas, falso positivo, desativar regra, *dry-run* de regra |
| `test_broker.py` | modo Redis Streams: publicação/consumo, *backpressure* 503, reprocessamento de mensagens pendentes |
| `test_demo.py` | detecções esperadas por cenário, zero falsos positivos no *baseline*, reprodutibilidade, reset só de sintéticos |
| `test_response_intel.py` | indicadores e enriquecimento, ciclo de ações de resposta (*four-eyes*, confirmação, reversão, isolamento só em `lab`), relatórios JSON/PDF |
| `test_assistant.py` | grounding, injeção de prompt sinalizada, RBAC, caminho LLM com cliente simulado e *fallback* |
| `test_contracts.py` | JSON Schemas e OpenAPI commitados iguais aos gerados; exemplos válidos; saída real do agente válida |

### E2E (Playwright)

- credenciais erradas → mensagem genérica; rotas do console redirecionam sem sessão;
- login, navegação por atalhos de teclado, logout;
- introdução pulável e reduzida com `prefers-reduced-motion`;
- **fluxo completo:** cenário demo → alertas → investigação do incidente → analista;
- explorador de eventos filtrando no servidor;
- leitor vê dados, não vê controles de gestão, e a API recusa escritas;
- ausência de rolagem horizontal em 3 *viewports* (móvel, tablet, desktop).

## Medições

### Ingestão

`tests/perf/ingest_load.py` envia eventos sintéticos (2 % deles disparam regras) com vários
remetentes concorrentes e mede vazão e latência por lote.

| Configuração | Resultado |
|---|---|
| 20 000 eventos, lotes de 200, 4 remetentes, 1 processo uvicorn, PostgreSQL 16 local, modo *inline* (detecção no request), container de desenvolvimento com 4 vCPUs / 16 GB | **~1 100 eventos/s**, p95 por lote **1,2 s**, **0 erros** |

O teste de carga encontrou dois defeitos reais antes desse resultado — corrida na criação do
endpoint (HTTP 500 por violação de unicidade) e *deadlock*/atualizações perdidas nos contadores —
corrigidos com `INSERT … ON CONFLICT` e `UPDATE` atômicos em ordem fixa (ver histórico do commit
`Fix ingestion race and deadlock under concurrency`).

Não foi medido: múltiplas réplicas da API, vários workers, volumes acima de 20 mil eventos por
execução. O modo broker foi validado funcionalmente (ponta a ponta), não em carga.

### Agente

| Configuração | Resultado |
|---|---|
| build *release*, host com ~120 processos, configuração padrão (processos a cada 250 ms, rede a cada 1 s), amostra de 30 s | **~10 MB RSS**, **~1,8 % de um núcleo**, 6 threads |
| API indisponível | lotes vão para o spool em disco e são entregues em ordem quando a API volta (verificado manualmente parando a API) |

### Stack Docker ponta a ponta

`docker compose up` (modo broker) + cenário `ssh-intrusion`: **88 eventos → 14 alertas → 1
incidente**, com notificação chegando ao navegador via WebSocket através do gateway Caddy.
Telemetria real do agente no próprio container de desenvolvimento gerou 5 alertas a partir de
atividade benigna provocada.

## Auditorias

| Ferramenta | Resultado na última execução |
|---|---|
| ruff (lint + format), mypy `--strict` | limpos |
| ESLint, `tsc --noEmit` | limpos |
| `pip-audit --strict` (dependências de produção) | sem vulnerabilidades conhecidas |
| `npm audit --omit=dev --audit-level=high` | sem achados *high*/*critical* |
| `cargo audit` | sem vulnerabilidades conhecidas |
| CodeQL | configurado em CI (Python, JS/TS, Rust); não executado localmente |
