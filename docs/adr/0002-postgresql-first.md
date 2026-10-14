# ADR 0002 — PostgreSQL primeiro, ClickHouse adiado

**Estado:** aceita

## Contexto

Eventos de telemetria são *append-heavy* e consultados por tempo, host e campos. Um banco
colunar (ClickHouse) é o padrão para isso em escala. O restante do domínio (usuários, sessões,
alertas, incidentes, ações) é transacional e relacional.

## Decisão

- PostgreSQL 16 para tudo nesta versão, com colunas extraídas e índices para os filtros mais
  usados e `JSONB` para o payload completo.
- SQLite suportado para desenvolvimento e testes sem infraestrutura (`UTCDateTime` e tipos JSON
  portáveis; a suíte roda nos dois bancos em CI).
- ClickHouse fica no roadmap, como armazenamento de eventos brutos, mantendo PostgreSQL para o
  estado transacional.

## Consequências

- Um só banco para operar, backup simples, transações que cobrem evento + detecção.
- Medido ~1,1 mil eventos/s com uma réplica; consultas analíticas em dezenas de milhões de
  eventos não foram testadas e são o gatilho para adotar ClickHouse.
- A retenção (30 dias padrão) limita o crescimento da tabela de eventos.
