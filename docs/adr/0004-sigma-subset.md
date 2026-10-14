# ADR 0004 — Subconjunto explícito do Sigma

**Estado:** aceita

## Contexto

Sigma é o formato aberto mais usado para regras de detecção, mas a especificação completa
(modificadores, pipelines pySigma, backends) é grande. Uma implementação parcial que ignora
silenciosamente o que não entende cria regras que nunca disparam — pior que não ter a regra.

## Decisão

- Compilador próprio para um subconjunto documentado (`detection/sigma.py`, `docs/detection.md`).
- Qualquer recurso, campo ou `logsource` fora do subconjunto gera `RuleError` ao carregar; o
  erro aparece no console e em `aegis rules`.
- Campos Sysmon/Sigma traduzidos para o modelo ACE por um mapa explícito; campos sem fonte no
  Linux não são mapeados.
- Correlação conforme a especificação de correlação do Sigma (`event_count`, `value_count`,
  `temporal`, `temporal_ordered`), avaliada sobre `rule_matches` persistidos — e não em memória —
  para tolerar eventos fora de ordem e reinícios.
- Regras como código: YAML versionado no Git, versão no banco por hash de conteúdo, casos de
  regressão obrigatórios em `rules/tests`.

## Consequências

- Comportamento previsível e testável; nenhuma regra “morta” silenciosa.
- Regras upstream que usam recursos não suportados precisam de adaptação.
- A documentação nunca afirma compatibilidade total com Sigma.
