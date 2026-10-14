# Guia de desenvolvimento

## Pré-requisitos

| Ferramenta | Versão usada |
|---|---|
| Python | 3.13 (gerenciado com [uv](https://docs.astral.sh/uv/)) |
| Node.js | 22 |
| Rust | estável (edição 2024) |
| PostgreSQL / Redis | 16 / 7 — opcionais; SQLite e modo *inline* bastam para desenvolver |

## API (`apps/api`)

```bash
cd apps/api
uv sync                                   # cria .venv com dependências de dev
cat > .env <<EOF
AEGIS_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')
AEGIS_COOKIE_SECURE=false
AEGIS_RESPONSE_ALLOW_SELF_APPROVAL=true
# AEGIS_DATABASE_URL=postgresql://aegis:aegis@localhost:5432/aegis
# AEGIS_REDIS_URL=redis://localhost:6379/0
# AEGIS_PIPELINE_MODE=broker              # exige Redis e `uv run aegis worker`
EOF
uv run aegis migrate
uv run aegis create-user --email admin@aegis.lab --generate-password
uv run uvicorn aegis.main:create_app --factory --reload --port 8000
```

Documentação interativa: <http://localhost:8000/api/v1/docs>.

### CLI `aegis`

| Comando | Uso |
|---|---|
| `aegis migrate` | aplica migrações e cria os papéis |
| `aegis create-user --email … [--role …] [--password-stdin \| --generate-password]` | cria usuário |
| `aegis rules [--dir …]` | valida todas as regras (`ok`/`FAIL` com motivo) |
| `aegis demo [cenário…] [--reset]` | roda cenários sintéticos pelo pipeline |
| `aegis worker` | consumidor de detecção (modo broker) + retenção horária |
| `aegis retention [--days N]` | purga manual |
| `aegis export-schemas` / `aegis export-openapi` | regenera os contratos em `packages/` |

### Qualidade

```bash
uv run ruff format src tests && uv run ruff check src tests
uv run mypy src                           # strict
uv run pytest                             # SQLite
AEGIS_TEST_DATABASE_URL=postgresql://aegis:aegis@localhost:5432/aegis_test \
AEGIS_TEST_REDIS_URL=redis://localhost:6379/0 uv run pytest   # PostgreSQL + broker
```

### Migrações

Os modelos ficam em `src/aegis/models.py`; as migrações Alembic em `src/aegis/migrations`
(empacotadas, sem `alembic.ini`, para rodar dentro da imagem). Nova migração:

```bash
uv run python -c "from alembic import command; from aegis.migrations import alembic_config; \
command.revision(alembic_config(), message='descrição', autogenerate=True)"
```

Revise o arquivo gerado (tipos JSON/JSONB e `UTCDateTime`) antes de commitar.

### Contratos

Alterou `events/contract.py` ou alguma rota? Rode `uv run aegis export-schemas` e
`uv run aegis export-openapi`; `tests/test_contracts.py` falha se os arquivos commitados
divergirem.

### Adicionando um módulo

1. Modelo(s) em `models.py` + migração.
2. Regra de negócio em `services/<módulo>.py` (sem dependência de FastAPI).
3. Rotas em `routers/<módulo>.py` com `require(Permission.X)` em cada rota; registre em
   `main.py`. Nova permissão → `security/rbac.py` e `tests/test_rbac.py`.
4. Eventos de auditoria via `services.audit.record(...)` para toda mutação.
5. Testes em `tests/`.

## Web (`apps/web`)

```bash
cd apps/web
npm ci
npm run dev            # http://localhost:3000; /api é encaminhado a AEGIS_API_ORIGIN (padrão :8000)
npx eslint src && npx tsc --noEmit
npx vitest run
npm run build          # saída standalone em .next/standalone
```

Convenções:

- Leia `apps/web/AGENTS.md`: Next.js 16 tem APIs diferentes das versões anteriores (`proxy.ts`
  no lugar de `middleware.ts`, `params` assíncronos, *cache components*).
- Cada rota do console tem `page.tsx` (servidor, com `export const instant = false`, porque o
  shell só renderiza o conteúdo após confirmar a sessão) e `view.tsx` (cliente).
- Requisições passam por `src/lib/api.ts` (CSRF automático, erros tipados); chaves de query em
  `src/lib/queries.ts`; tipos de resposta em `src/lib/types.ts`.
- Cores e tipografia vêm dos *tokens* em `src/app/globals.css` (`@theme inline`); os temas
  *noite*, *fósforo* e *papel* trocam apenas variáveis CSS.
- Componentes base em `src/components/ui` (Radix por baixo). Sem bibliotecas de UI adicionais.
- Movimento: use `motion` e respeite a preferência de movimento do usuário (`motion` no store
  `useUi`, que também segue `prefers-reduced-motion`).

### E2E

Com API e web rodando e um administrador criado:

```bash
E2E_ADMIN_EMAIL=admin@aegis.lab E2E_ADMIN_PASSWORD='…' npx playwright test
# PW_CHROMIUM_PATH=/caminho/chromium  para usar um Chromium já instalado
```

O *global setup* cria, a cada execução, um usuário leitor com senha aleatória para os testes de
RBAC.

## Agente (`agents/linux-agent`)

```bash
cd agents/linux-agent
cargo fmt --check && cargo clippy --all-targets -- -D warnings
cargo test
cargo run -- snapshot                     # eventos ACE do host atual, sem rede
cargo run -- run --config dev.toml        # envio real (cadastre um agente no console antes)
```

Teste de contrato entre linguagens:

```bash
cargo build --release
cd ../../apps/api && AEGIS_AGENT_BIN=../../agents/linux-agent/target/release/aegis-agent \
  uv run pytest tests/test_contracts.py
```

## Regras e cenários

- Regras: veja [detection.md](detection.md#escrevendo-e-testando-uma-regra).
- Cenários de demonstração: YAML em `simulations/scenarios/`, com *templates* determinísticos
  (`{{cycle:a|b}}`, `{{choice:a|b}}`, `{{int:1-9}}`, `{{hex:8}}`), offsets como `1m30s` e
  referências a processos pais. A mesma semente gera os mesmos eventos;
  `tests/test_demo.py` valida cada cenário.

## CI

`.github/workflows/ci.yml` executa os mesmos passos acima em jobs separados (API com SQLite e
PostgreSQL+Redis, agente, contrato agente↔schema, web, E2E contra a stack, build das imagens) e
`codeql.yml` faz análise estática de Python, JavaScript/TypeScript e Rust. O Dependabot
acompanha pip/uv, npm, cargo, GitHub Actions e Docker.
