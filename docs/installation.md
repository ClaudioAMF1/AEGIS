# Guia de instalação

> Instale o AEGIS e o agente apenas em ambientes que você controla ou para os quais tem
> autorização explícita.

## 1. Stack com Docker Compose

Requisitos: Docker 24+ e Compose v2, ~2 GB de RAM livres.

```bash
git clone https://github.com/ClaudioAMF1/AEGIS.git && cd AEGIS
cp .env.example .env
```

Edite `.env`:

| Variável | Obrigatória | Descrição |
|---|---|---|
| `AEGIS_SECRET_KEY` | sim | ≥32 caracteres aleatórios. Deriva o HMAC dos tokens e a chave de criptografia dos segredos MFA — trocar invalida sessões, tokens de agente e MFA |
| `POSTGRES_PASSWORD` | sim | senha do banco |
| `AEGIS_ANTHROPIC_API_KEY` | não | habilita o analista de IA com LLM |
| `AEGIS_ASSISTANT_MODEL` | não | modelo usado pelo analista (padrão do compose: `claude-opus-5-5`) |
| `AEGIS_INTEL_EXTERNAL_ENABLED`, `AEGIS_ABUSEIPDB_API_KEY` | não | reputação de IPs públicos (cache de 24 h) |
| `AEGIS_RESPONSE_ALLOW_SELF_APPROVAL` | não | `true` só em laboratório de uma pessoa; com mais de um admin, mantenha `false` |
| `AEGIS_HTTP_PORT` | não | porta do gateway (padrão 8080, ligada a 127.0.0.1) |

Gere segredos com `python3 -c 'import secrets; print(secrets.token_urlsafe(48))'`.

```bash
docker compose up -d --build          # postgres, redis, migrate, api, worker, web, gateway
docker compose ps                     # migrate deve terminar com "exited (0)"
docker compose run --rm api aegis create-user --email voce@lab.local --generate-password
```

A senha gerada aparece uma única vez no terminal. Acesse <http://localhost:8080>.
Para criar outros papéis: `--role analyst` ou `--role viewer` (ou pela tela **Configuração**).

Verificação rápida:

```bash
curl -s localhost:8080/api/v1/health    # {"status":"ok", "checks": {"database":"ok","redis":"ok"}, "pipeline_mode":"broker", ...}
```

### Observabilidade

```bash
docker compose --profile observability up -d
```

Prometheus em <http://127.0.0.1:9090> (raspa `api:8000/metrics`), Grafana em
<http://127.0.0.1:3001> com o dashboard *AEGIS pipeline* provisionado (ingestão, duplicados,
rejeições, latência de lote e de detecção, alertas, backlog do broker, requisições HTTP,
clientes WebSocket).

### TLS e exposição

O gateway serve HTTP em `127.0.0.1`. Para expor na rede do laboratório, termine TLS no Caddy
(edite `infrastructure/docker/Caddyfile` com o nome do host), publique a porta na interface
desejada e defina `AEGIS_COOKIE_SECURE=true` no bloco `x-api-env` do compose.

### Proxy corporativo com inspeção TLS

O build da API aceita um bundle de CA opcional como *secret* do BuildKit:

```bash
docker build --secret id=extra_ca,src=/caminho/ca-bundle.crt -f apps/api/Dockerfile -t aegis-api:local .
```

## 2. Agente Linux

Requisitos: Linux com `/proc`, root (para ler `exe`/`cwd`/sockets de todos os processos), Rust
estável para compilar.

1. No console, **Endpoints → cadastrar agente**; copie o token `aga_…` (exibido uma vez).
2. Compile e instale:

   ```bash
   cd agents/linux-agent
   cargo build --release
   sudo install -m 0755 target/release/aegis-agent /usr/local/bin/
   sudo install -d -m 0700 /etc/aegis /var/lib/aegis-agent
   sudo install -m 0600 packaging/agent.example.toml /etc/aegis/agent.toml
   sudo sh -c 'umask 077; cat > /etc/aegis/agent.token'   # cole o token, Ctrl-D
   ```

3. Em `/etc/aegis/agent.toml`, ajuste `api_url` (ex.: `http://localhost:8080` no mesmo host;
   `http://` só é aceito para localhost, redes RFC 1918 e domínios `.local`/`.lab`).
4. `sudo aegis-agent check --config /etc/aegis/agent.toml` valida a configuração, a leitura do
   arquivo de token e a conectividade com `/api/v1/health` (o token em si é validado no primeiro
   envio).
5. Serviço:

   ```bash
   sudo install -m 0644 packaging/aegis-agent.service /etc/systemd/system/
   sudo systemctl enable --now aegis-agent
   journalctl -u aegis-agent -f
   ```

O endpoint aparece em **Endpoints** após o primeiro heartbeat (padrão 30 s). Para permitir a
ação de isolamento simulado, adicione a tag `lab` ao endpoint.

## 3. Instalação sem Docker

Veja o [guia de desenvolvimento](development.md): a API roda com SQLite ou PostgreSQL e o modo
*inline* dispensa Redis.

## Atualização e backup

- `docker compose pull && docker compose up -d --build` — o serviço `migrate` aplica migrações
  Alembic antes da API subir.
- Backup: `docker compose exec postgres pg_dump -U aegis aegis > backup.sql`.
- Retenção: eventos com mais de `AEGIS_EVENT_RETENTION_DAYS` (30) são apagados de hora em hora
  pelo worker, preservando os ligados a alertas/incidentes. Manual:
  `docker compose run --rm api aegis retention --days 30`.
