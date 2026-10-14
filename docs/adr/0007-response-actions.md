# ADR 0007 — Catálogo fechado de ações de resposta

**Estado:** aceita

## Contexto

Ações de resposta têm impacto real. O escopo proibia execução remota arbitrária e contenção sem
autorização explícita.

## Decisão

- Catálogo fixo no servidor: `request_investigation`, `raise_incident_severity`, `disable_rule`,
  `revoke_user_sessions`, `isolate_host_lab`. Não existe ação “executar comando”.
- Fluxo: *preview* (alvo, impacto, reversibilidade) → proposta com justificativa → aprovação por
  **outro** administrador (`AEGIS_RESPONSE_ALLOW_SELF_APPROVAL=false` por padrão) com confirmação
  digitada do alvo → execução → resultado → reversão quando possível. Cada passo auditado.
- `isolate_host_lab` só para endpoints com tag `lab` (ou sintéticos); entregue ao agente no
  heartbeat; o agente incluído apenas confirma como `simulated`.

## Consequências

- Nenhum caminho de código transforma entrada do usuário em comando no host.
- Contenção real exigiria um agente que aplique regras de firewall — fora do escopo desta versão
  por segurança, e documentado como limitação.
