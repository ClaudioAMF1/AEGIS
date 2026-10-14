# ADR 0006 — Analista de IA consultivo com grounding no servidor

**Estado:** aceita

## Contexto

Um LLM ajuda a resumir e levantar hipóteses, mas pode inventar fatos, e a telemetria contém
texto controlado por atacantes (*prompt injection*). O escopo exigia citar eventos, separar
fatos de hipóteses e nunca executar ações automaticamente.

## Decisão

- O modelo **não recebe ferramentas**. Recomendações são texto; consultas sugeridas são filtros
  estruturados que o analista decide rodar.
- Evidência restrita a um incidente/alerta, serializada como JSON num bloco delimitado,
  declarada como dado; padrões de injeção sinalizados.
- Saída estruturada (`AnalystAnswer`) validada por Pydantic.
- `ground()` no servidor, independente do modelo: remove citações a eventos não recuperados,
  rebaixa fatos sem citação para hipóteses, restringe filtros a uma allow-list; estatísticas
  salvas.
- Motor determinístico (`local-rules`) com a mesma estrutura quando não há chave de API ou o
  provedor falha — rotulado como “sem LLM”.

## Consequências

- O valor do analista não depende de um provedor externo; testes rodam sem rede.
- Mesmo uma resposta manipulada não consegue citar eventos inexistentes nem executar nada.
- RAG lexical é limitado; embeddings ficam no roadmap.
