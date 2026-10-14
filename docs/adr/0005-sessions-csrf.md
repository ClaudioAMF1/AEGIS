# ADR 0005 — Sessões server-side em vez de JWT

**Estado:** aceita

## Contexto

O console é uma aplicação de mesma origem. Requisitos: revogar sessões imediatamente (troca de
senha, mudança de papel, ação de resposta `revoke_user_sessions`), expiração ociosa e absoluta, MFA
em duas etapas, e não expor tokens a JavaScript.

## Decisão

- Token aleatório opaco; no banco só o HMAC-SHA256 (chave derivada de `AEGIS_SECRET_KEY`).
- Cookie `HttpOnly`, `SameSite=Lax`, `Secure` configurável; token CSRF por sessão em
  `X-CSRF-Token` para métodos de escrita.
- Sessão em estágio `mfa_pending` até o TOTP ser verificado; ao concluir, um token novo é emitido
  (rotação) e o pendente é revogado.
- Alternativa *bearer* (mesmo token no header `Authorization`) para automação, sem CSRF.
- Agentes usam tokens próprios (`aga_…`), separados de usuários.

## Consequências

- Revogação imediata e auditável; nenhuma chave de assinatura para vazar ou rotacionar.
- Uma consulta ao banco por requisição autenticada (aceitável no volume-alvo).
- O WebSocket autentica pelo mesmo cookie e valida `Origin`.
