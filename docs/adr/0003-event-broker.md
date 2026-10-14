# ADR 0003 — Redis Streams como broker de eventos

**Estado:** aceita

## Contexto

A ingestão precisa responder rápido ao agente e desacoplar a detecção, com reentrega em caso
de falha do consumidor e *backpressure*. Kafka/Redpanda foram sugeridos no escopo.

## Decisão

- Redis Streams (`aegis.events`) com grupo de consumidores `detection`: uma mensagem por evento
  novo, `XACK` só depois do commit da detecção, `XAUTOCLAIM` para reprocessar mensagens de
  consumidores que caíram.
- **Persistir antes de publicar:** o evento é gravado no PostgreSQL e só depois publicado; a
  idempotência vem do `event_id` único e do registro único (regra, evento) em `rule_matches`.
- *Backpressure*: se o backlog passar de `AEGIS_STREAM_MAX_PENDING`, a ingestão responde 503 com
  `Retry-After`; o agente guarda em spool.
- Modo `inline` (sem Redis) para desenvolvimento, testes e instalações mínimas.
- O mesmo Redis faz o pub/sub de tempo real para as réplicas da API.

## Consequências

- Uma dependência leve que já seria usada para tempo real; operação muito mais simples que um
  cluster Kafka.
- Sem particionamento por chave, sem retenção longa nem *replay* histórico pelo broker (o
  histórico está no PostgreSQL).
- Se o volume exigir, o publicador e o consumidor estão isolados em `events/broker.py` e podem
  ser trocados por Kafka/Redpanda sem mudar o pipeline.
