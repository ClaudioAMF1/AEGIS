# ADR 0001 — Monólito modular

**Estado:** aceita

## Contexto

O escopo pedia vários módulos (auth, ingestão, detecção, investigação, intel, IA, resposta,
relatórios). Microsserviços trariam rede, versionamento e deploy entre cada fronteira, para um
volume de laboratório e um único mantenedor. Ao mesmo tempo, a detecção precisa escalar
separadamente da API.

## Decisão

- Um pacote Python (`aegis`) com módulos por domínio (`routers/`, `services/`, `detection/`,
  `events/`, `security/`). Serviços não dependem de FastAPI.
- Dois processos a partir do mesmo código: a API (`uvicorn aegis.main:create_app`) e o worker de
  detecção (`aegis worker`), ligados por Redis Streams (ADR 0003).
- Contratos explícitos nas bordas: ACE v1 (JSON Schema) e OpenAPI gerados e testados.

## Consequências

- Uma única base de código, um schema, transações locais (persistir evento + contadores no mesmo
  commit) e testes de integração simples.
- A detecção escala adicionando workers; a API escala com réplicas (tempo real via pub/sub).
- Separar um módulo em serviço no futuro exige trocar chamadas internas por rede; os limites de
  pacote e os contratos reduzem esse custo.
