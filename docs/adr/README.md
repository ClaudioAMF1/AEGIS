# Decisões arquiteturais (ADRs)

Formato: contexto → decisão → consequências. Uma decisão substituída ganha um novo ADR em vez de
ser reescrita.

| # | Decisão | Estado |
|---|---|---|
| [0001](0001-modular-monolith.md) | Monólito modular em FastAPI + worker do mesmo pacote | aceita |
| [0002](0002-postgresql-first.md) | PostgreSQL (SQLite em dev/testes) antes de ClickHouse | aceita |
| [0003](0003-event-broker.md) | Redis Streams como broker, com modo *inline* | aceita |
| [0004](0004-sigma-subset.md) | Subconjunto explícito do Sigma + correlação sobre matches persistidos | aceita |
| [0005](0005-sessions-csrf.md) | Sessões server-side com cookie HttpOnly + CSRF em vez de JWT | aceita |
| [0006](0006-ai-analyst-grounding.md) | Analista de IA consultivo, sem ferramentas, com grounding no servidor | aceita |
| [0007](0007-response-actions.md) | Catálogo fechado de ações com aprovação *four-eyes* | aceita |
| [0008](0008-agent-polling-first.md) | Agente com polling de `/proc` antes de eBPF | aceita |
