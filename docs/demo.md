# Guia de demonstração

O modo demonstração gera telemetria **sintética e determinística** de hosts fictícios e a envia
pelo **mesmo pipeline** usado pelo agente real (validação, enriquecimento, detecção,
correlação, alertas, incidentes). Nada é executado em máquina alguma, e os IPs “atacantes”
estão em faixas de documentação (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).

Todo dado gerado tem `is_synthetic = true`, aparece só quando o seletor **live/demo** do topo
está em `demo` (faixa e selos na cor de demonstração) e pode ser apagado sem tocar nos dados
reais.

🎬 Vídeo: [`assets/aegis-walkthrough.mp4`](assets/aegis-walkthrough.mp4)

## Cenários

| Cenário | Duração simulada | O que acontece | Resultado esperado (testado) |
|---|---|---|---|
| `ssh-intrusion` | 30 min | *brute force* SSH a partir de `203.0.113.0/24`, login como `deploy`, descoberta, download, persistência por cron e `authorized_keys`, reverse shell, movimento para o host de banco | ≥8 alertas, incidente de alta severidade aberto |
| `webshell-miner` | 20 min | aplicação PHP vulnerável gera shells, minerador em `/tmp` conecta a um pool em `192.0.2.0/24` | ≥5 alertas, incluindo shell gerado por servidor web e rajada de descoberta |
| `baseline-benign` | 60 min | atualizações de pacote, *restarts*, *deploys* e logins por chave a partir da rede de gestão | **0 alertas** (checagem de falsos positivos) |

As expectativas ficam no próprio YAML (`expected:`) e são verificadas por
`apps/api/tests/test_demo.py`. A mesma semente reproduz exatamente os mesmos eventos.

## Roteiro sugerido (≈5 minutos)

1. **Entrar.** Primeira visita mostra a sequência de inicialização (pode ser pulada; respeita
   movimento reduzido).
2. **Central → Modo demonstração → `ssh-intrusion` → executar.** Use *reprodução instantânea*,
   ou ×30/×120 para ver os eventos chegando em tempo real pelo WebSocket. O seletor muda para
   `demo` automaticamente.
3. **Alertas.** Filtre por severidade; abra *SSH Brute Force*: regra e versão, técnicas
   ATT&CK, eventos que dispararam, contagem de ocorrências agregadas pela supressão.
4. **Incidentes → #N.** Mostre:
   - **Linha do tempo** com *brush* para recortar o período;
   - **Árvore de processos** (sshd → bash → curl/crontab…);
   - **Grafo** de entidades (host, usuário, processo, IP, arquivo) — no menu **Rede** há a versão 3D;
   - **Evidências e diário**: registre uma nota;
   - **Analista**: “resumir” e “hipóteses” — note os IDs de eventos citados e a separação entre
     fatos e hipóteses. Sem chave de API, a resposta vem do motor determinístico e diz isso.
5. **Resposta.** Proponha `raise_incident_severity` ou `isolate_host_lab`: veja o *preview*,
   escreva a justificativa, aprove com a confirmação digitada (outro administrador, ou
   auto-aprovação habilitada em laboratório) e depois **reverta**. Tudo aparece em
   **Configuração → auditoria**.
6. **Regras → testar regra.** Cole uma variação de regra e avalie contra a telemetria demo.
7. **Relatórios.** Gere o relatório do incidente em PDF e JSON.
8. **Central → reiniciar dados demo.** Mostre que só os dados sintéticos sumiram.
9. **`baseline-benign`.** Rode e mostre que nenhum alerta é criado.

## Pela linha de comando

```bash
cd apps/api
uv run aegis demo ssh-intrusion webshell-miner
uv run aegis demo --reset
# Docker:
docker compose run --rm api aegis demo ssh-intrusion
```

## Telemetria real em laboratório

Para ver dados *live*, instale o agente numa VM sua ([instalação](installation.md#2-agente-linux))
e gere atividade benigna que dispara regras, por exemplo:

```bash
cp /bin/sleep /tmp/demo-sleep && /tmp/demo-sleep 3   # execução a partir de /tmp (regra medium)
```

O coletor de processos faz *polling* a cada 250 ms: comandos que terminam antes disso (como
`id` ou `whoami`) podem não ser vistos. Por isso o exemplo usa um processo que dura alguns
segundos.

Faça isso **apenas** em máquinas suas. Não gere tráfego contra infraestrutura de terceiros.
