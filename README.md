# ThreatForge

**Open Source Cyber Threat Intelligence Platform**

Plataforma open source de CTI para ingestão, enriquecimento, scoring explicável e geração de inteligência acionável a partir de fontes públicas. Foco no cenário brasileiro: monitoramento de marca, phishing e abuso de domínios.

## Funcionalidades

**CTI / IOC (v0.1)**

- **IOC Intake** — cadastre IP, domínio, URL, hash, e-mail ou CVE via API
- **Conectores públicos** — CISA KEV, URLhaus (abuse.ch), MITRE ATT&CK, EPSS (FIRST)
- **Enriquecimento** — consulta automática das fontes relevantes para cada tipo de IOC
- **Scoring explicável** — score 0–100 com fatores e justificativas, não uma "nota mágica"
- **Relatórios** — relatório técnico em Markdown por observável

**Monitoramento de marca / DRP (v0.2)**

- **Brand intake** — cadastre a marca, domínios oficiais (allowlist) e keywords
- **Detecção de typosquatting** — gera centenas de variações (homóglifos, teclas adjacentes, omissão, termos-isca BR como `seguro`, `pix`, `2via`, `boleto`) em TLDs abusados
- **Descoberta via Certificate Transparency** — encontra domínios reais que mencionam a marca em CT logs (crt.sh)
- **Enriquecimento do finding** — resolução DNS, registro MX, idade do domínio (RDAP), idade do certificado (CT), cruzamento com URLhaus
- **Scoring de abuso explicável** — prioriza domínios ativos, recém-registrados e similares
- **Alertas nos principais canais** — Telegram, webhook (Slack/Discord/Teams/SIEM) e e-mail SMTP, disparados automaticamente para findings suspeitos/maliciosos

**Interface web e usuários (v0.3)**

- **Login web** — interface servida pela própria API em `http://localhost:8000/`
- **Autenticação real** — senhas com PBKDF2-HMAC-SHA256 (salt único, 240k iterações), sessão em JWT HS256 dentro de cookie `httpOnly`/`SameSite=Strict` (token inacessível a JavaScript — XSS não rouba sessão). Sem dependências externas de auth.
- **RBAC em 3 papéis** — `admin` (gerencia usuários e tudo), `analyst` (cadastra IOC, roda scan, edita findings), `viewer` (só leitura). Enforcement no servidor em toda rota.
- **Gestão de usuários** — criar, ativar/desativar, trocar papel e senha (admin). Proteções contra lockout (não remove o último admin, não rebaixa a própria conta).
- **Hardening** — CSP restritiva, headers de segurança, rate-limit de login, mensagem de erro genérica (anti-enumeração de usuário).

**Comum**

- **API REST** — FastAPI; autenticação por sessão (cookie) na UI ou por API key de serviço (header `X-API-Key`, papel admin) para automação. Docs em `/docs`.

## Subindo com Docker Compose

```bash
cp .env.example .env
# Edite .env: defina API_KEY com um valor forte (ex.: openssl rand -hex 32)
docker compose up -d --build
```

A API e a interface web sobem em `http://localhost:8000`. Documentação interativa da API: `http://localhost:8000/docs`.

### Primeiro acesso à interface web

Abra `http://localhost:8000/` no navegador. No primeiro start, um **admin inicial** é criado:

- Se você definiu `BOOTSTRAP_ADMIN_EMAIL` e `BOOTSTRAP_ADMIN_PASSWORD` no `.env`, use essas credenciais.
- Se deixou a senha em branco, uma senha aleatória é **gerada e impressa no log** do container. Veja com:

  ```bash
  docker compose logs api | grep -A4 "ADMIN INICIAL"
  ```

Faça login, vá em **Usuários** e crie as contas da equipe (analista/leitor). Troque a senha do admin no primeiro acesso.

## Uso rápido

```bash
export API_KEY="sua-chave-do-.env"

# 1. Sincronizar feeds locais (KEV + ATT&CK)
curl -X POST -H "X-API-Key: $API_KEY" http://localhost:8000/sync/kev
curl -X POST -H "X-API-Key: $API_KEY" http://localhost:8000/sync/mitre

# 2. Cadastrar um IOC
curl -X POST -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"type": "cve", "value": "CVE-2024-3400"}' \
  http://localhost:8000/observables

# 3. Enriquecer e pontuar
curl -X POST -H "X-API-Key: $API_KEY" http://localhost:8000/observables/1/enrich

# 4. Gerar relatório Markdown
curl -H "X-API-Key: $API_KEY" http://localhost:8000/reports/observable/1
```

Observáveis aceitam valores "defanged" (`hxxp://`, `[.]`) — são normalizados automaticamente.

## Monitoramento de marca

```bash
# 1. Cadastrar a marca com domínios oficiais (allowlist)
curl -X POST -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"name": "Banco Exemplo", "official_domains": ["bancoexemplo.com.br"], "keywords": ["bexemplo"]}' \
  http://localhost:8000/brands

# 2. Rodar a varredura (gera typosquats, consulta CT, DNS, RDAP, URLhaus e alerta)
curl -X POST -H "X-API-Key: $API_KEY" http://localhost:8000/brands/1/scan

# 3. Listar findings priorizados (maior score primeiro)
curl -H "X-API-Key: $API_KEY" "http://localhost:8000/brands/1/findings?min_score=45"

# 4. Atualizar status de um finding no workflow de investigação
curl -X PATCH -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"status": "takedown_requested"}' \
  http://localhost:8000/brands/findings/10
```

Use `?deep=false` no scan para uma varredura rápida (só DNS + descoberta CT, sem RDAP/cert por candidato). Para varredura recorrente, agende `POST /brands/{id}/scan` (ex.: cron a cada 6h). Os alertas só disparam para findings com veredito ≥ `ALERT_MIN_VERDICT` (default `suspicious`) e nunca repetem para o mesmo finding.

**Takedown é workflow defensivo, não automático:** o sistema gera a evidência e o finding; a ação de takedown é registrada via status e deve ser executada por canal autorizado, com revisão humana.

## Tipos de observável suportados

| Tipo | Exemplo | Fontes de enriquecimento |
|------|---------|--------------------------|
| `ip` | `203.0.113.10` | URLhaus host |
| `domain` | `example[.]com` | URLhaus host |
| `url` | `hxxp://evil.example/x` | URLhaus URL |
| `hash` | MD5/SHA1/SHA256 | URLhaus payload |
| `cve` | `CVE-2024-3400` | CISA KEV + EPSS |
| `email` | `a@b.com` | (intake apenas no MVP) |

## Scoring

O score é a soma de fatores explicáveis, limitado a 0–100:

| Fator | Pontos | Fonte |
|-------|--------|-------|
| Listado no CISA KEV | +50 | CISA |
| Uso conhecido em ransomware (KEV) | +10 | CISA |
| EPSS (probabilidade de exploração) | até +30 | FIRST |
| URL ativa no URLhaus | +45 (+10 se online) | abuse.ch |
| Host com URLs maliciosas no URLhaus | +35 | abuse.ch |
| Payload conhecido no URLhaus | +45 | abuse.ch |

Veredito: `malicious` (≥70), `suspicious` (≥40), `low` (1–39), `no_known_threat` (0).

## Configuração

| Variável | Obrigatória | Descrição |
|----------|-------------|-----------|
| `API_KEY` | sim | Chave de autenticação da API (header `X-API-Key`) |
| `DATABASE_URL` | não | Default: PostgreSQL do compose. Aceita SQLite p/ dev |
| `ABUSECH_API_KEY` | não | Auth-Key do abuse.ch (necessária para a API do URLhaus — gratuita em https://auth.abuse.ch) |
| `CORS_ORIGINS` | não | Origens permitidas, separadas por vírgula. Default: nenhuma |

## Configuração de alertas

| Variável | Descrição |
|----------|-----------|
| `ALERT_MIN_VERDICT` | Veredito mínimo p/ alertar: `low`, `suspicious` (default) ou `malicious` |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | Bot do Telegram (crie via @BotFather) |
| `ALERT_WEBHOOK_URL` | Webhook que recebe o JSON do alerta (Slack/Discord/Teams/SIEM) |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_FROM` / `SMTP_TO` | E-mail via SMTP |

Cada canal é independente e best-effort: só os configurados disparam, e a falha de um não bloqueia os demais nem a varredura.

## Roadmap

- **v0.3** — Dashboard web, casos investigativos, timeline, export JSON/CSV/PDF
- **v0.4** — Grafo de relacionamento (Neo4j), STIX parcial, integração MISP/OpenCTI
- **v0.5** — Multi-tenant, API keys por organização, auditoria, SLA por cliente

## Licença

Apache-2.0
