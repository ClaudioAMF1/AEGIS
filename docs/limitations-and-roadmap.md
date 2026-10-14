# Limitações conhecidas e roadmap

O AEGIS é um projeto de portfólio funcional, pensado para laboratórios. Ele **não** substitui um
EDR/SIEM comercial. Abaixo, o que não existe ou tem restrições — sem eufemismos.

## Limitações conhecidas

### Coleta (agente)

- **Polling, não rastreamento:** processos são lidos de `/proc` a cada 250 ms; processos mais
  curtos podem passar despercebidos e o pai de processos efêmeros pode ficar desconhecido. Não
  há eBPF/auditd.
- Rede: apenas TCP (`/proc/net/tcp*`), sem UDP/DNS; conexões mais curtas que o intervalo de
  1 s podem ser perdidas; sem captura de pacotes.
- Arquivos: inotify não recursivo (cada diretório é listado explicitamente); sem hash de
  arquivos alterados.
- Autenticação: só `auth.log`/`secure`; sistemas apenas com journald não são suportados.
- Somente Linux. Sem Windows/macOS.
- Ação de isolamento é **simulada**: o agente confirma como `simulated` e não altera firewall.

### Plataforma

- **Armazenamento:** PostgreSQL para tudo. ClickHouse (sugerido no escopo) não foi implementado;
  consultas analíticas sobre volumes grandes (dezenas de milhões de eventos) não foram testadas.
- **Mensageria:** Redis Streams no lugar de Kafka/Redpanda ([ADR 0003](adr/0003-event-broker.md)).
  Sem particionamento por chave nem retenção longa no broker.
- **OpenTelemetry não implementado:** há métricas Prometheus e logs JSON, mas não *traces*
  distribuídos.
- **Escala:** medido com 1 processo da API (~1,1 mil eventos/s). Várias réplicas e vários
  workers são suportados pelo desenho (grupo de consumidores, pub/sub para tempo real), mas não
  foram testados em carga.
- **Rate limit por agente** no servidor não existe (há limites de lote/corpo e *backpressure*
  global no modo broker).
- Atrás do gateway, o limite de tentativas de login por IP enxerga o IP do proxy (o limite por
  usuário continua funcionando). Falta configurar *trusted proxies*.
- Sem SSO/OIDC/SAML; usuários locais apenas. Sem multi-tenant.
- Auditoria é *append-only* por convenção da aplicação, não por garantia do banco (sem
  encadeamento por hash nem WORM).
- CSP ainda permite `'unsafe-inline'` em `script-src`.

### Detecção

- **Subconjunto do Sigma** ([detection.md](detection.md)): sem `base64offset`, `windash`,
  referências de campo, pipelines pySigma, agregações legadas. Regras fora do subconjunto falham
  ao carregar.
- 20 regras, focadas nos cenários de laboratório; não é uma cobertura ampla de ATT&CK.
- Sem detecção por anomalia/linha de base estatística.
- Sem *threat hunting* com linguagem de consulta; o explorador usa filtros estruturados e busca
  textual.

### Analista de IA

- RAG lexical (BM25) sobre regras e playbooks; sem embeddings/pgvector.
- Filtro de *prompt injection* é heurístico (a defesa principal é estrutural).
- O caminho com LLM real não roda em CI.

### Interface

- Grafos grandes (milhares de nós) não foram otimizados; o grafo 3D é carregado sob demanda e
  limitado.
- Interface somente em pt-BR.

## Roadmap

Ordem aproximada de prioridade:

1. **Coletor eBPF** (`sched_process_exec`, `tcp_connect`, `inet_sock_set_state`) no agente,
   mantendo o polling como *fallback*; DNS e UDP.
2. **OpenTelemetry**: *traces* da ingestão até o alerta (API → Redis → worker), exportados via
   OTLP.
3. **ClickHouse** para eventos brutos com PostgreSQL mantendo o estado transacional (alertas,
   incidentes, usuários); retenção por camadas.
4. **Rate limit por agente** e *trusted proxies*; mTLS opcional entre agente e gateway.
5. **Auditoria à prova de adulteração** (encadeamento por hash + exportação periódica).
6. **pgvector** para recuperação semântica no analista, mantendo o grounding atual.
7. CSP com *nonces*; OIDC para login corporativo.
8. Mais regras (escalonamento de privilégio, *container escape*, *rootkit* em espaço de
   usuário) e testes de regressão a partir de *datasets* públicos de laboratório.
9. Teste de carga do modo broker com múltiplos workers e réplicas da API.
