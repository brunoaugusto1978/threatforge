# ThreatForge

**Open Source Cyber Threat Intelligence Platform**

Plataforma open source de CTI para ingestão, enriquecimento, scoring explicável e geração de inteligência acionável a partir de fontes públicas. O objetivo é apoiar analistas de segurança, SOC, times antifraude e pesquisadores na organização de indicadores, monitoramento de marca, abuso de domínios, phishing e investigação de risco digital.

## Funcionalidades

### CTI / IOC

* **IOC Intake** — cadastro de IP, domínio, URL, hash, e-mail ou CVE via API.
* **Conectores públicos** — CISA KEV, URLhaus/abuse.ch, MITRE ATT&CK e EPSS/FIRST.
* **Enriquecimento** — consulta automática das fontes relevantes para cada tipo de observável.
* **Scoring explicável** — score de 0 a 100 com fatores e justificativas.
* **Relatórios** — geração de relatório técnico em Markdown por observável.

### Monitoramento de marca / DRP

* **Brand intake** — cadastro de marca, domínios oficiais e keywords.
* **Detecção de typosquatting** — geração de variações usando homóglifos, teclas adjacentes, omissões e termos-isca como `seguro`, `pix`, `2via` e `boleto`.
* **Descoberta via Certificate Transparency** — busca de domínios reais que mencionam a marca em CT logs.
* **Enriquecimento de findings** — DNS, MX, RDAP, idade de domínio, idade de certificado e cruzamento com URLhaus.
* **Scoring de abuso explicável** — priorização de domínios ativos, recentes e similares à marca.
* **Alertas** — Telegram, webhook e SMTP para findings suspeitos ou maliciosos.

### Interface web, usuários e RBAC

* **Login web** — interface servida pela própria API em `http://localhost:8000/`.
* **Autenticação** — sessão em JWT dentro de cookie `httpOnly`/`SameSite=Strict`.
* **Senhas seguras** — Argon2id quando disponível, com fallback para PBKDF2-HMAC-SHA256.
* **Papéis de tenant** — `admin`, `analyst` e `viewer`.
* **Papéis de plataforma** — `platform_admin`, `support_operator` e `support_viewer`.
* **Auditoria** — ações sensíveis registradas com usuário, operador, tenant, IP e user-agent.
* **Hardening web** — CSP, headers de segurança, rate-limit de login e mensagens genéricas de erro.

### Multi-tenant

A plataforma é multi-tenant. Cada cliente é um **tenant** isolado. As tabelas sensíveis possuem `tenant_id` e as consultas são filtradas pelo tenant, impedindo que um cliente acesse dados de outro.

Existem duas visões principais:

* **Operador de plataforma** — cria e gerencia tenants, operadores, convites e API keys. Para atuar em um tenant específico via API, usa o header `X-Tenant-Id`.
* **Usuário de tenant** — fica preso ao próprio `tenant_id` e visualiza apenas os dados do seu cliente.

API keys são por tenant. A chave definida em `API_KEY` no `.env` funciona como chave de plataforma para automação administrativa.

## Subindo com Docker Compose

Copie o arquivo de exemplo:

```bash
cp .env.example .env
```

Gere valores fortes para as variáveis sensíveis:

```bash
openssl rand -hex 32
openssl rand -hex 32
openssl rand -hex 32
```

Edite o arquivo `.env`:

```bash
vi .env
```

Configure pelo menos as variáveis abaixo:

```env
API_KEY=<valor_gerado>
POSTGRES_PASSWORD=<valor_gerado>
JWT_SECRET=<valor_gerado>
COOKIE_SECURE=false
APP_BASE_URL=http://localhost:8000
```

Observações:

* use valores diferentes para `API_KEY`, `POSTGRES_PASSWORD` e `JWT_SECRET`;
* não versionar o arquivo `.env`;
* em ambiente local com HTTP, mantenha `COOKIE_SECURE=false`;
* em produção com HTTPS, use `COOKIE_SECURE=true`;
* `APP_BASE_URL` é usado para montar links de convite.

Suba a aplicação:

```bash
docker compose up -d --build
```

Valide a instalação:

```bash
curl http://localhost:8000/health
```

Resultado esperado:

```json
{"status":"ok","service":"threatforge","version":"0.6.0"}
```

A API e a interface web ficam disponíveis em:

```text
http://localhost:8000
```

A documentação interativa da API fica em:

```text
http://localhost:8000/docs
```

## Teste automatizado de isolamento

Execute o selftest principal:

```bash
docker compose exec api python -m app.selftest_isolation
```

Resultado esperado:

```text
ISOLAMENTO + CONVITES + PAPÉIS DE OPERADOR: TODOS OS TESTES PASSARAM ✅
```

Esse teste valida:

* criação do primeiro operador de plataforma;
* criação de tenants;
* autenticação de admins de clientes;
* isolamento de marcas e observáveis por tenant;
* bloqueio de acesso cruzado por ID;
* API key presa ao tenant correto;
* convite por e-mail com token hasheado, uso único e expiração;
* suporte sem tenant atribuído bloqueado;
* suporte acessando apenas tenant permitido;
* suporte bloqueado em ações administrativas/destrutivas;
* bloqueio/ativação de tenant por platform admin;
* auditoria;
* revogação imediata de acesso do suporte.

## Primeiro acesso pela interface

Abra:

```text
http://localhost:8000/
```

Em uma instalação limpa, o primeiro passo é criar o **operador de plataforma**.

Esse primeiro usuário será o `platform_admin` e poderá:

* criar tenants/clientes;
* criar operadores de suporte;
* criar convites de acesso;
* criar API keys por tenant;
* acessar a visão operacional da plataforma;
* consultar auditoria.

## Fluxo recomendado de validação manual

### 1. Platform admin

Crie o primeiro operador pela interface.

Depois crie dois tenants, por exemplo:

```text
Cliente A
Cliente B
```

Crie um admin para cada tenant.

Resultado esperado:

* platform admin visualiza operação da plataforma;
* tenants são criados corretamente;
* usuários de cliente ficam vinculados ao tenant correto.

### 2. Cliente / tenant admin

Entre como admin do Cliente A e crie dados, como marca e observáveis.

Depois entre como admin do Cliente B e crie outros dados.

Resultado esperado:

* Cliente A vê apenas dados do Cliente A;
* Cliente B vê apenas dados do Cliente B;
* acesso cruzado por ID não deve revelar dados de outro tenant.

### 3. Suporte

Crie um operador de suporte.

Conceda acesso apenas ao Cliente A.

Resultado esperado:

* suporte visualiza apenas o Cliente A;
* suporte não visualiza o Cliente B;
* suporte não cria tenant;
* suporte não cria operador;
* suporte não cria API key;
* suporte não executa ações destrutivas;
* ao revogar o acesso, o suporte perde acesso imediatamente.

## Convites de acesso

Ao criar um tenant sem senha para o admin, o sistema gera um convite por e-mail.

O convite usa:

* token aleatório;
* hash do token no banco;
* expiração;
* uso único;
* vínculo fixo ao tenant;
* ativação apenas após aceite.

O link é montado usando `APP_BASE_URL`.

Em ambiente de desenvolvimento sem SMTP configurado, o convite aparece no log da API.

Para acompanhar os logs:

```bash
docker compose logs -f api
```

Também é possível subir o MailHog para capturar e-mails localmente:

```bash
docker compose -f docker-compose.yml -f docker-compose.mailhog.yml up -d --build
```

A interface do MailHog fica em:

```text
http://localhost:8025
```

## Provisionamento headless

O fluxo padrão é criar o primeiro operador pela interface.

Para ambientes automatizados, é possível criar o operador inicial no primeiro start definindo:

```env
BOOTSTRAP_OPERATOR_EMAIL=admin.platform@threatforge.local
BOOTSTRAP_OPERATOR_PASSWORD=<senha_forte>
```

Use esse modo apenas quando fizer sentido para automação. Em ambiente local, o onboarding pela interface é mais simples.

As variáveis abaixo são legadas do fluxo single-tenant e não devem ser usadas no fluxo multi-tenant atual:

```env
BOOTSTRAP_ADMIN_EMAIL=
BOOTSTRAP_ADMIN_PASSWORD=
```

## Uso rápido via API

Defina a chave de plataforma:

```bash
export API_KEY="valor-definido-no-.env"
```

Para chamadas de plataforma que atuam em um tenant específico, informe também `X-Tenant-Id`.

Exemplo:

```bash
export TENANT_ID=1
```

Sincronizar feeds locais:

```bash
curl -X POST -H "X-API-Key: $API_KEY" http://localhost:8000/sync/kev
curl -X POST -H "X-API-Key: $API_KEY" http://localhost:8000/sync/mitre
```

Cadastrar um observável em um tenant:

```bash
curl -X POST \
  -H "X-API-Key: $API_KEY" \
  -H "X-Tenant-Id: $TENANT_ID" \
  -H "Content-Type: application/json" \
  -d '{"type": "cve", "value": "CVE-2024-3400"}' \
  http://localhost:8000/observables
```

Enriquecer e pontuar:

```bash
curl -X POST \
  -H "X-API-Key: $API_KEY" \
  -H "X-Tenant-Id: $TENANT_ID" \
  http://localhost:8000/observables/1/enrich
```

Gerar relatório Markdown:

```bash
curl \
  -H "X-API-Key: $API_KEY" \
  -H "X-Tenant-Id: $TENANT_ID" \
  http://localhost:8000/reports/observable/1
```

Observáveis aceitam valores defanged, como:

```text
hxxp://example[.]com
```

Esses valores são normalizados automaticamente.

## Monitoramento de marca

Cadastrar marca com domínios oficiais:

```bash
curl -X POST \
  -H "X-API-Key: $API_KEY" \
  -H "X-Tenant-Id: $TENANT_ID" \
  -H "Content-Type: application/json" \
  -d '{"name": "Banco Exemplo", "official_domains": ["bancoexemplo.com.br"], "keywords": ["bexemplo"]}' \
  http://localhost:8000/brands
```

Rodar varredura:

```bash
curl -X POST \
  -H "X-API-Key: $API_KEY" \
  -H "X-Tenant-Id: $TENANT_ID" \
  http://localhost:8000/brands/1/scan
```

Listar findings priorizados:

```bash
curl \
  -H "X-API-Key: $API_KEY" \
  -H "X-Tenant-Id: $TENANT_ID" \
  "http://localhost:8000/brands/1/findings?min_score=45"
```

Atualizar status de um finding:

```bash
curl -X PATCH \
  -H "X-API-Key: $API_KEY" \
  -H "X-Tenant-Id: $TENANT_ID" \
  -H "Content-Type: application/json" \
  -d '{"status": "takedown_requested"}' \
  http://localhost:8000/brands/findings/10
```

Use `?deep=false` no scan para uma varredura rápida.

Para varredura recorrente, agende:

```text
POST /brands/{id}/scan
```

Os alertas disparam apenas para findings com veredito igual ou superior ao valor de `ALERT_MIN_VERDICT`.

## Takedown

O ThreatForge não executa takedown automático.

O sistema apoia o fluxo defensivo:

* identifica o finding;
* registra evidências;
* calcula risco;
* organiza status;
* permite acompanhamento.

A ação de takedown deve ser executada por canal autorizado e com revisão humana.

## Tipos de observável suportados

| Tipo     | Exemplo                 | Fontes de enriquecimento |
| -------- | ----------------------- | ------------------------ |
| `ip`     | `203.0.113.10`          | URLhaus host             |
| `domain` | `example[.]com`         | URLhaus host             |
| `url`    | `hxxp://evil.example/x` | URLhaus URL              |
| `hash`   | MD5/SHA1/SHA256         | URLhaus payload          |
| `cve`    | `CVE-2024-3400`         | CISA KEV + EPSS          |
| `email`  | `a@b.com`               | Intake apenas no MVP     |

## Scoring

O score é a soma de fatores explicáveis, limitado a 0–100.

| Fator                               |                   Pontos | Fonte    |
| ----------------------------------- | -----------------------: | -------- |
| Listado no CISA KEV                 |                      +50 | CISA     |
| Uso conhecido em ransomware no KEV  |                      +10 | CISA     |
| EPSS                                |                  até +30 | FIRST    |
| URL ativa no URLhaus                | +45, com bônus se online | abuse.ch |
| Host com URLs maliciosas no URLhaus |                      +35 | abuse.ch |
| Payload conhecido no URLhaus        |                      +45 | abuse.ch |

Vereditos:

|  Score | Veredito          |
| -----: | ----------------- |
| 70–100 | `malicious`       |
|  40–69 | `suspicious`      |
|   1–39 | `low`             |
|      0 | `no_known_threat` |

## Configuração

| Variável            | Obrigatória           | Descrição                                                 |
| ------------------- | --------------------- | --------------------------------------------------------- |
| `API_KEY`           | sim                   | Chave de plataforma para automação via header `X-API-Key` |
| `POSTGRES_PASSWORD` | sim no Docker Compose | Senha do PostgreSQL usada pelo compose                    |
| `JWT_SECRET`        | recomendado           | Segredo para assinar sessões JWT                          |
| `DATABASE_URL`      | não                   | Default: PostgreSQL do compose. Aceita SQLite para dev    |
| `COOKIE_SECURE`     | sim                   | `false` em localhost HTTP; `true` em produção HTTPS       |
| `APP_BASE_URL`      | sim                   | URL base usada em links de convite                        |
| `INVITE_TTL_HOURS`  | não                   | Validade do convite em horas. Default: 168                |
| `CORS_ORIGINS`      | não                   | Origens permitidas, separadas por vírgula                 |
| `ABUSECH_API_KEY`   | não                   | Auth-Key do abuse.ch para URLhaus                         |

## Configuração de alertas

| Variável             | Descrição                                                        |
| -------------------- | ---------------------------------------------------------------- |
| `ALERT_MIN_VERDICT`  | Veredito mínimo para alertar: `low`, `suspicious` ou `malicious` |
| `TELEGRAM_BOT_TOKEN` | Token do bot Telegram                                            |
| `TELEGRAM_CHAT_ID`   | Chat ID de destino                                               |
| `ALERT_WEBHOOK_URL`  | Webhook para Slack, Discord, Teams, SIEM ou SOAR                 |
| `SMTP_HOST`          | Servidor SMTP                                                    |
| `SMTP_PORT`          | Porta SMTP                                                       |
| `SMTP_USER`          | Usuário SMTP                                                     |
| `SMTP_PASSWORD`      | Senha SMTP                                                       |
| `SMTP_FROM`          | Remetente                                                        |
| `SMTP_TO`            | Destinatário                                                     |
| `SMTP_STARTTLS`      | Ativa STARTTLS                                                   |

Cada canal é independente e best-effort. Falha em um canal não bloqueia a varredura nem os demais alertas.

## Comandos úteis

Ver containers:

```bash
docker compose ps
```

Ver logs da API:

```bash
docker compose logs -f api
```

Reiniciar:

```bash
docker compose restart
```

Parar:

```bash
docker compose down
```

Parar e apagar volumes locais:

```bash
docker compose down -v
```

Use `docker compose down -v` somente quando quiser apagar o banco local e começar do zero.

## Roadmap

* **v0.7** — melhoria da experiência da UI, mensagens de erro, onboarding e documentação.
* **v0.8** — casos investigativos, timeline e exportações.
* **v0.9** — grafo de relacionamento com Neo4j.
* **v1.0** — modelo STIX parcial, integrações MISP/OpenCTI, hardening de produção e empacotamento estável.

## Licença

Apache-2.0

