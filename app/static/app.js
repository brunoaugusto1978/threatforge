"use strict";

// ---------- helpers ----------
const $ = (sel) => document.querySelector(sel);
let ME = null;

async function api(method, path, body) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (res.status === 204) return null;
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) {
    const msg = (data && data.detail) ? data.detail : `Erro ${res.status}`;
    throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
  }
  return data;
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "html") node.innerHTML = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) node.setAttribute(k, v);
  }
  for (const c of children) {
    if (c == null) continue;
    node.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return node;
}

// escapa texto que vai pra innerHTML (defesa contra XSS vindo de dados externos)
function esc(s) {
  return String(s == null ? "" : s)
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}
function defang(s) { return String(s || "").replace(/\./g, "[.]").replace(/^http/, "hxxp"); }

let toastTimer;
function toast(msg, isErr = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast show" + (isErr ? " err" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = "toast"; }, 3500);
}

function can(role) {
  const rank = { viewer: 1, analyst: 2, admin: 3 };
  return ME && rank[ME.role] >= rank[role];
}
function verdictCell(v) {
  return `<span class="v v-${esc(v)}">${esc((v || "").toUpperCase())}</span>`;
}
function scoreBar(score) {
  const color = score >= 70 ? "var(--red)" : score >= 40 ? "var(--orange)"
    : score >= 20 ? "var(--yellow)" : "var(--gray)";
  return `<div class="score-bar"><i style="width:${Math.min(100, score)}%;background:${color}"></i></div>`;
}
// botão como string com data-action (delegação trata o clique — compatível com CSP)
function actBtn(action, id, label, cls = "ghost") {
  return `<button class="sm ${cls}" data-action="${action}" data-id="${esc(id)}">${esc(label)}</button>`;
}

// ---------- auth ----------
async function doLogin(e) {
  e.preventDefault();
  $("#loginErr").textContent = "";
  try {
    await api("POST", "/auth/login", { email: $("#email").value, password: $("#password").value });
    await boot();
  } catch (err) {
    $("#loginErr").textContent = err.message;
  }
}

async function logout() {
  try { await api("POST", "/auth/logout"); } catch {}
  ME = null;
  showOnly("login");
  $("#password").value = "";
}

function showOnly(id) {
  ["login", "createAdmin", "invite", "wizard", "operator", "app"].forEach(s =>
    $("#" + s).classList.toggle("hidden", s !== id));
}

function inviteTokenFromUrl() {
  const u = new URL(window.location.href);
  if (u.pathname === "/invite/accept" || u.searchParams.has("token")) {
    return u.searchParams.get("token");
  }
  return null;
}

let INVITE_TOKEN = null;

async function showInviteAccept(token) {
  INVITE_TOKEN = token;
  showOnly("invite");
  $("#inviteErr").textContent = "";
  try {
    const v = await api("GET", `/invites/validate?token=${encodeURIComponent(token)}`);
    if (!v.valid) {
      $("#inviteSub").textContent = v.reason || "Convite inválido.";
      $("#inviteForm").classList.add("hidden");
      return;
    }
    $("#inviteForm").classList.remove("hidden");
    $("#inviteSub").textContent = `Convite para ${v.tenant_name || "seu tenant"}`;
    $("#invEmail").value = v.email || "";
  } catch (e) {
    $("#inviteSub").textContent = "Não foi possível validar o convite.";
    $("#inviteForm").classList.add("hidden");
  }
}

async function doInviteAccept(e) {
  e.preventDefault();
  $("#inviteErr").textContent = "";
  if ($("#invPass").value !== $("#invPass2").value) {
    $("#inviteErr").textContent = "As senhas não conferem."; return;
  }
  try {
    await api("POST", "/invites/accept", { token: INVITE_TOKEN, password: $("#invPass").value });
    toast("Acesso ativado");
    // limpa o token da URL e entra normalmente
    window.history.replaceState({}, "", "/");
    INVITE_TOKEN = null;
    await boot();
  } catch (err) { $("#inviteErr").textContent = err.message; }
}

async function boot() {
  // 0) fluxo de aceite de convite (link de e-mail)
  const inviteToken = inviteTokenFromUrl();
  if (inviteToken && !ME) { await showInviteAccept(inviteToken); return; }

  let st = null;
  try { st = await api("GET", "/setup/status"); } catch { /* segue */ }

  // 1) nenhum usuário -> criar operador de plataforma
  if (st && st.needs_operator) { showOnly("createAdmin"); return; }

  // 2) sessão
  try { ME = await api("GET", "/auth/me"); }
  catch { showOnly("login"); return; }

  // 3) operador -> console da operação
  if (ME.is_operator) { showOnly("operator"); renderOperator(); return; }

  // 4) usuário de tenant -> gate de setup do próprio tenant
  let ts = null;
  try { ts = await api("GET", "/tenant/setup-status"); } catch { /* segue */ }
  if (ts && !ts.setup_completed) {
    showOnly("wizard");
    if (can("admin")) { startWizard(); }
    else {
      $("#wizSteps").style.display = "none";
      $("#wizBody").innerHTML = '<p class="hint">A plataforma está em configuração inicial. Aguarde um administrador concluir o setup.</p>';
      $("#wizBack").style.display = $("#wizNext").style.display = "none";
    }
    return;
  }

  // 5) app do tenant liberado
  showOnly("app");
  $("#who").innerHTML = `${esc(ME.subject)} &nbsp;<span class="badge role-${esc(ME.role)}">${esc(ME.role)}</span>`;
  $("#navUsers").style.display = can("admin") ? "" : "none";
  $("#navAudit").style.display = can("admin") ? "" : "none";
  navigate("dashboard");
}

async function doCreateAdmin(e) {
  e.preventDefault();
  $("#adminErr").textContent = "";
  try {
    await api("POST", "/setup/operator", { email: $("#caEmail").value, password: $("#caPass").value });
    toast("Operador criado");
    await boot();
  } catch (err) { $("#adminErr").textContent = err.message; }
}

// ===================== CONSOLE DO OPERADOR =====================
async function renderOperator() {
  $("#opWho").innerHTML = `${esc(ME.subject)} &nbsp;<span class="badge role-admin">operador</span>`;
  const m = $("#opMain");
  m.innerHTML = `<h2 class="title">Tenants (clientes)</h2>
    <p class="muted" style="margin:-8px 0 16px">Cada tenant é isolado: usuários, marcas, IOCs, watchlist, findings e auditoria são exclusivos do cliente.</p>`;
  const p = el("div", { class: "panel" });
  p.append(el("div", { class: "row" },
    field("Nome do tenant", inputEl("tName", "ex.: Cliente X")),
    field("E-mail do admin", inputEl("tEmail", "admin@cliente.com")),
    field("Senha (vazio = enviar convite)", inputEl("tPass", "", "password")),
    el("button", { onclick: createTenant }, "Criar tenant")));
  m.append(p);
  m.append(el("div", { class: "panel", id: "tList" }, "carregando…"));
  await loadTenants();
}
async function loadTenants() {
  try {
    const items = await api("GET", "/tenants");
    const box = $("#tList");
    if (!items.length) { box.innerHTML = '<span class="muted">Nenhum tenant ainda.</span>'; return; }
    const rows = items.map(t => `
      <tr>
        <td>${esc(t.id)}</td>
        <td><b>${esc(t.name)}</b></td>
        <td><code>${esc(t.slug)}</code></td>
        <td class="muted">${esc(t.status)}</td>
        <td>${actBtn("tenantKey", t.id, "Gerar API key")}</td>
      </tr>`).join("");
    box.innerHTML = `<table><thead><tr><th>ID</th><th>Nome</th><th>Slug</th><th>Status</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
  } catch (e) { $("#tList").textContent = e.message; }
}
async function createTenant() {
  const name = $("#tName").value.trim(), email = $("#tEmail").value.trim(), pass = $("#tPass").value;
  if (!name || !email) { toast("Informe nome e e-mail do admin.", true); return; }
  const body = { name, admin_email: email };
  if (pass) body.admin_password = pass;
  try {
    const r = await api("POST", "/tenants", body);
    if (r.invite_link) {
      const sent = r.invite_email_sent ? "E-mail de convite enviado." : "SMTP não configurado — use o link abaixo (dev).";
      prompt(`Tenant "${r.name}" criado.\n${sent}\n\nLink de convite (uso único) para ${r.admin_email}:`, r.invite_link);
    } else {
      toast("Tenant criado");
    }
    $("#tName").value = $("#tEmail").value = $("#tPass").value = "";
    await loadTenants();
  } catch (e) { toast(e.message, true); }
}
async function genTenantKey(id) {
  if (!confirm("Gerar uma API key (papel analyst) para este tenant?")) return;
  try {
    const r = await api("POST", `/tenants/${id}/api-keys`, { label: "ui", role: "analyst" });
    alert(`API key do tenant ${id} (guarde agora, não será exibida de novo):\n\n${r.api_key}`);
  } catch (e) { toast(e.message, true); }
}

// ===================== SETUP WIZARD =====================
const WIZ = { step: 1, max: 5 };
const SCOPE_SOURCES = [
  ["iocs", "IOCs"], ["dominios", "Domínios"], ["typosquatting", "Typosquatting"],
  ["certificate_transparency", "Certificate Transparency"], ["urlhaus", "URLhaus"],
  ["cisa_kev", "CISA KEV"], ["epss", "EPSS"], ["mitre", "MITRE ATT&CK"],
  ["github", "GitHub"], ["paste_sites", "Paste sites"], ["foruns", "Fóruns"],
  ["deep_web", "Deep web"], ["dark_web", "Dark web"],
  ["telegram_publico", "Telegram público/autorizado"],
  ["whatsapp_intake", "WhatsApp (intake manual/autorizado)"],
];
const ORG_WIZ_FIELDS = [
  ["name", "Nome *"], ["trade_name", "Nome fantasia"], ["legal_name", "Razão social"],
  ["tax_id", "CNPJ"], ["subsector", "Subsetor"], ["country", "País"],
  ["state", "Estado"], ["city", "Cidade"], ["website", "Website"],
  ["security_email", "E-mail de segurança"], ["legal_email", "E-mail jurídico"],
  ["phone", "Telefone"], ["timezone", "Timezone"], ["language", "Idioma"],
];

function startWizard() {
  $("#wizSteps").style.display = "";
  $("#wizBack").style.display = $("#wizNext").style.display = "";
  WIZ.step = 1;
  renderWizard();
}

function renderWizard() {
  document.querySelectorAll("#wizSteps li").forEach(li => {
    const n = Number(li.dataset.step);
    li.classList.toggle("active", n === WIZ.step);
    li.classList.toggle("done", n < WIZ.step);
  });
  $("#wizErr").textContent = "";
  $("#wizBack").style.visibility = WIZ.step === 1 ? "hidden" : "visible";
  $("#wizNext").textContent = WIZ.step === WIZ.max ? "Concluir configuração" : "Continuar";
  $("#wizNext").disabled = false;  // reabilita; a etapa de revisão pode desabilitar
  WIZ_RENDER[WIZ.step]();
}

async function wizNext() {
  $("#wizErr").textContent = "";
  try {
    const ok = await WIZ_SAVE[WIZ.step]();
    if (ok === false) return;
    if (WIZ.step < WIZ.max) { WIZ.step++; renderWizard(); }
    else { await api("POST", "/setup/complete"); toast("Configuração concluída"); await boot(); }
  } catch (err) { $("#wizErr").textContent = err.message; }
}
function wizBack() { if (WIZ.step > 1) { WIZ.step--; renderWizard(); } }

// ---- Passo 1: Organização ----
const WIZ_RENDER = {};
const WIZ_SAVE = {};
WIZ_RENDER[1] = async () => {
  let org = {};
  try { org = (await api("GET", "/organization")) || {}; } catch {}
  const grid = el("div", { class: "srow2" });
  // setor + criticidade primeiro (dirigem o threat profile)
  const sectorSel = selectEl("wz_sector",
    ["", "Telecom", "Financeiro", "Varejo", "Saúde", "Governo", "Indústria", "Tecnologia", "Energia", "Outro"]);
  sectorSel.value = org.sector || "";
  const critSel = selectEl("wz_criticality", ["baixo", "medio", "alto", "critico"]);
  critSel.value = org.criticality || "medio";
  grid.append(field("Setor *", sectorSel), field("Criticidade", critSel));
  ORG_WIZ_FIELDS.forEach(([k, label]) => {
    const inp = inputEl("wz_org_" + k, "");
    inp.value = org[k] || "";
    grid.append(field(label, inp));
  });
  $("#wizBody").innerHTML = "<h3>Organização</h3><p class='hint'>Dados da sua organização. O setor define o Threat Profile sugerido.</p>";
  $("#wizBody").append(grid);
};
WIZ_SAVE[1] = async () => {
  const name = $("#wz_org_name").value.trim();
  const sector = $("#wz_sector").value;
  if (!name) { $("#wizErr").textContent = "Informe o nome da organização."; return false; }
  if (!sector) { $("#wizErr").textContent = "Selecione o setor."; return false; }
  const body = { name, sector, criticality: $("#wz_criticality").value };
  ORG_WIZ_FIELDS.forEach(([k]) => { if (k !== "name") body[k] = $("#wz_org_" + k).value || null; });
  await api("PUT", "/organization", body);
  return true;
};

// ---- Passo 2: Marca e ativos ----
const BRAND_LIST_FIELDS = [
  ["variations", "Variações do nome"], ["aliases", "Siglas"], ["products", "Produtos"],
  ["subdomains", "Subdomínios oficiais"], ["social_profiles", "Perfis oficiais"],
  ["keywords", "Palavras-chave"], ["sensitive_terms", "Termos sensíveis de fraude"],
];
WIZ_RENDER[2] = async () => {
  let brands = [];
  try { brands = await api("GET", "/brands"); } catch {}
  const existing = brands.length
    ? `<p class="hint">Marcas já cadastradas: ${brands.map(b => esc(b.name)).join(", ")}. Você pode adicionar outra ou seguir.</p>` : "";
  $("#wizBody").innerHTML = `<h3>Marca e ativos oficiais</h3>
    <p class="hint">Cadastre ao menos uma marca. Listas aceitam itens separados por vírgula.</p>${existing}`;
  const grid = el("div", { class: "srow2" });
  grid.append(field("Nome da marca", inputEl("wz_b_name", "ex.: Banco Exemplo")));
  grid.append(field("Domínios oficiais (vírgula)", inputEl("wz_b_domains", "exemplo.com.br")));
  BRAND_LIST_FIELDS.forEach(([k, label]) => grid.append(field(label, inputEl("wz_b_" + k, ""))));
  grid.append(field("Logotipo (URL)", inputEl("wz_b_logo", "https://...")));
  $("#wizBody").append(grid);
  $("#wizBody").dataset.hasBrands = brands.length ? "1" : "";
};
WIZ_SAVE[2] = async () => {
  const name = $("#wz_b_name").value.trim();
  const hadBrands = $("#wizBody").dataset.hasBrands === "1";
  if (!name) {
    if (hadBrands) return true;  // já existe marca; pode seguir sem adicionar
    $("#wizErr").textContent = "Cadastre ao menos uma marca."; return false;
  }
  const csv = (id) => $("#" + id).value.split(",").map(s => s.trim()).filter(Boolean);
  const domains = csv("wz_b_domains");
  if (!domains.length) { $("#wizErr").textContent = "Informe ao menos um domínio oficial."; return false; }
  const body = { name, official_domains: domains, logo_url: $("#wz_b_logo").value || null };
  BRAND_LIST_FIELDS.forEach(([k]) => { body[k] = csv("wz_b_" + k); });
  try { await api("POST", "/brands", body); }
  catch (e) { if (!/já cadastrada/i.test(e.message)) throw e; }
  return true;
};

// ---- Passo 3: Escopo ----
WIZ_RENDER[3] = async () => {
  let org = {};
  try { org = (await api("GET", "/organization")) || {}; } catch {}
  const sel = new Set(org.monitoring_scope || [
    "iocs", "dominios", "typosquatting", "certificate_transparency", "urlhaus", "cisa_kev", "epss", "mitre"]);
  $("#wizBody").innerHTML = "<h3>Escopo de monitoramento</h3><p class='hint'>Selecione o que a plataforma deve vigiar. WhatsApp é apenas intake manual/autorizado.</p>";
  const grid = el("div", { class: "scope-grid" });
  SCOPE_SOURCES.forEach(([k, label]) => {
    const cb = el("input", { type: "checkbox", id: "sc_" + k });
    if (sel.has(k)) cb.setAttribute("checked", "true");
    grid.append(el("label", {}, cb, label));
  });
  $("#wizBody").append(grid);
};
WIZ_SAVE[3] = async () => {
  const scope = SCOPE_SOURCES.filter(([k]) => $("#sc_" + k).checked).map(([k]) => k);
  if (!scope.length) { $("#wizErr").textContent = "Selecione ao menos uma fonte de monitoramento."; return false; }
  await api("PUT", "/setup/scope", { monitoring_scope: scope });
  return true;
};

// ---- Passo 4: Threat Profile ----
WIZ_RENDER[4] = async () => {
  let org = {};
  try { org = (await api("GET", "/organization")) || {}; } catch {}
  const sector = org.sector || "";
  $("#wizBody").innerHTML = `<h3>Threat Profile — ${esc(sector || "setor")}</h3>
    <p class="hint">Sugestões típicas do setor. Geram <b>seeds de monitoramento</b> (watchlist), não findings confirmados.</p>
    <div id="tpBody">carregando…</div>`;
  try {
    const p = await api("GET", `/sectors/${encodeURIComponent(sector)}/profile`);
    const chips = (arr) => `<div class="chips">${(arr || []).map(x => `<span class="chip">${esc(x)}</span>`).join("") || '<span class="muted">—</span>'}</div>`;
    $("#tpBody").innerHTML = `
      <div style="margin-bottom:10px"><b>Keywords</b>${chips(p.keywords)}</div>
      <div style="margin-bottom:10px"><b>Ameaças comuns</b>${chips(p.threats)}</div>
      <div style="margin-bottom:10px"><b>Categorias de IOC</b>${chips(p.ioc_categories)}</div>
      <div style="margin-bottom:10px"><b>Fontes recomendadas</b>${chips(p.sources)}</div>
      <button id="genSeeds" style="margin-top:8px">Gerar seeds de monitoramento</button>
      <span id="seedMsg" class="muted" style="margin-left:10px"></span>`;
    $("#genSeeds").addEventListener("click", async () => {
      try {
        const r = await api("POST", "/setup/threat-profile");
        $("#seedMsg").textContent = `${r.seeds_created} seeds criadas (watchlist).`;
        toast(`${r.seeds_created} seeds geradas`);
      } catch (e) { toast(e.message, true); }
    });
  } catch (e) { $("#tpBody").textContent = e.message; }
};
WIZ_SAVE[4] = async () => true;  // geração de seeds é opcional

// ---- Passo 5: Revisão ----
WIZ_RENDER[5] = async () => {
  let org = {}, brands = [], seeds = [];
  try { org = (await api("GET", "/organization")) || {}; } catch {}
  try { brands = await api("GET", "/brands"); } catch {}
  try { seeds = await api("GET", "/seeds?status=candidate"); } catch {}
  const scope = (org.monitoring_scope || []).map(k =>
    (SCOPE_SOURCES.find(s => s[0] === k) || [k, k])[1]);
  const hasDomain = brands.some(b => (b.official_domains || "").trim());

  // checklist de pendências que bloqueiam a conclusão
  const checks = [
    [!!(org.name && org.sector), "Organização (nome + setor)"],
    [brands.length > 0, "Pelo menos uma marca"],
    [hasDomain, "Pelo menos um domínio oficial"],
    [scope.length > 0, "Escopo de monitoramento"],
  ];
  const pending = checks.filter(([ok]) => !ok);
  const checklist = checks.map(([ok, label]) =>
    `<div class="factor">${ok ? "✅" : "⛔"} ${esc(label)}</div>`).join("");

  $("#wizBody").innerHTML = `<h3>Revisão</h3>
    <p class="hint">Confira e finalize. Você poderá ajustar tudo depois nas abas da plataforma.</p>
    <table>
      <tr><th>Organização</th><td>${esc(org.name || "—")} ${org.sector ? "· " + esc(org.sector) : ""}</td></tr>
      <tr><th>Marcas</th><td>${brands.map(b => esc(b.name)).join(", ") || "—"}</td></tr>
      <tr><th>Domínios oficiais</th><td><code>${brands.map(b => esc(b.official_domains)).filter(Boolean).join("; ") || "—"}</code></td></tr>
      <tr><th>Escopo</th><td>${scope.map(esc).join(", ") || "—"}</td></tr>
      <tr><th>Seeds (watchlist)</th><td>${seeds.length} candidatas</td></tr>
    </table>
    <div style="margin-top:16px"><b>Requisitos para concluir</b>${checklist}</div>
    <p class="hint" style="margin-top:12px">${pending.length
      ? "Resolva os itens marcados com ⛔ antes de concluir (volte às etapas anteriores)."
      : "Tudo pronto. Ao concluir, as abas da plataforma serão liberadas."}</p>`;

  // bloqueia o botão Concluir enquanto houver pendência
  $("#wizNext").disabled = pending.length > 0;
};
WIZ_SAVE[5] = async () => true;

// ---------- views ----------
function navigate(view) {
  document.querySelectorAll("#nav button").forEach(b =>
    b.classList.toggle("active", b.dataset.view === view));
  ({ dashboard: viewDashboard, iocs: viewIocs, brands: viewBrands, watchlist: viewWatchlist,
     org: viewOrg, users: viewUsers, audit: viewAudit }[view] || viewDashboard)();
}

async function viewDashboard() {
  const m = $("#main");
  m.innerHTML = `<h2 class="title">Visão geral</h2><div class="cards" id="cards">carregando…</div>`;
  try {
    const s = await api("GET", "/stats");
    $("#cards").innerHTML = `
      ${cardHtml(s.observables, "IOCs cadastrados")}
      ${cardHtml(s.observables_malicious, "IOCs maliciosos", true)}
      ${cardHtml(s.brands, "Marcas monitoradas")}
      ${cardHtml(s.findings, "Findings de marca")}
      ${cardHtml(s.findings_priority, "Findings prioritários", true)}
      ${cardHtml(s.users, "Usuários")}`;
  } catch (e) { $("#cards").textContent = e.message; }
}
function cardHtml(n, label, alert = false) {
  return `<div class="card ${alert ? "alert" : ""}"><div class="n">${esc(n)}</div><div class="l">${esc(label)}</div></div>`;
}

// ---- IOCs ----
async function viewIocs() {
  const m = $("#main");
  m.innerHTML = `<h2 class="title">Indicadores (IOCs)</h2>`;
  if (can("analyst")) {
    const p = el("div", { class: "panel" });
    p.append(el("div", { class: "row" },
      field("Tipo", selectEl("iocType", ["cve", "ip", "domain", "url", "hash", "email"])),
      field("Valor", inputEl("iocValue", "ex.: CVE-2024-3400 ou evil[.]com")),
      el("button", { onclick: addIoc }, "Adicionar"),
      el("button", { class: "ghost", onclick: syncFeeds }, "Sincronizar feeds (KEV/MITRE)")
    ));
    m.append(p);
  }
  m.append(el("div", { class: "panel", id: "iocList" }, "carregando…"));
  await loadIocs();
}

async function loadIocs() {
  try {
    const items = await api("GET", "/observables?limit=200");
    const box = $("#iocList");
    if (!items.length) { box.innerHTML = '<span class="muted">Nenhum IOC ainda.</span>'; return; }
    const rows = items.map(o => `
      <tr>
        <td><code>${esc(o.type)}</code></td>
        <td><code>${esc(o.value)}</code></td>
        <td>${scoreBar(o.score)} <span class="muted">${o.score}</span></td>
        <td>${verdictCell(o.verdict)}</td>
        <td>${can("analyst") ? actBtn("enrich", o.id, "Enriquecer") : ""}
            ${actBtn("iocDetail", o.id, "Detalhes")}</td>
      </tr>`).join("");
    box.innerHTML = `<table><thead><tr><th>Tipo</th><th>Valor</th><th>Score</th><th>Veredito</th><th></th></tr></thead><tbody>${rows}</tbody></table><div id="iocDetail"></div>`;
  } catch (e) { $("#iocList").textContent = e.message; }
}

async function addIoc() {
  try {
    await api("POST", "/observables", { type: $("#iocType").value, value: $("#iocValue").value });
    $("#iocValue").value = "";
    toast("IOC adicionado");
    await loadIocs();
  } catch (e) { toast(e.message, true); }
}
async function enrich(id) {
  toast("Enriquecendo…");
  try { await api("POST", `/observables/${id}/enrich`); toast("Enriquecido"); await loadIocs(); }
  catch (e) { toast(e.message, true); }
}
async function iocDetail(id) {
  try {
    const o = await api("GET", `/observables/${id}`);
    const factors = (o.score_factors || []).map(f =>
      `<div class="factor"><b>+${esc(f.points)}</b> ${esc(f.reason)} <span class="muted">(${esc(f.source)})</span></div>`).join("") || '<span class="muted">Sem fatores. Enriqueça o IOC.</span>';
    $("#iocDetail").innerHTML = `<div class="panel" style="margin-top:14px">
      <b>${esc(o.value)}</b> — ${verdictCell(o.verdict)} score ${o.score}/100
      <div style="margin-top:8px">${factors}</div></div>`;
  } catch (e) { toast(e.message, true); }
}
async function syncFeeds() {
  toast("Sincronizando KEV…");
  try {
    const k = await api("POST", "/sync/kev");
    toast(`KEV: ${k.items} CVEs. Sincronizando MITRE…`);
    const mi = await api("POST", "/sync/mitre");
    toast(`Feeds OK — KEV ${k.items}, MITRE ${mi.items}`);
  } catch (e) { toast(e.message, true); }
}

// ---- Marcas ----
async function viewBrands() {
  const m = $("#main");
  m.innerHTML = `<h2 class="title">Monitoramento de marca</h2>`;
  if (can("analyst")) {
    const p = el("div", { class: "panel" });
    p.append(el("div", { class: "row" },
      field("Nome da marca", inputEl("brName", "ex.: Banco Exemplo")),
      field("Domínios oficiais (vírgula)", inputEl("brDomains", "bancoexemplo.com.br")),
      el("button", { onclick: addBrand }, "Cadastrar marca")));
    m.append(p);
  }
  m.append(el("div", { class: "panel", id: "brList" }, "carregando…"));
  await loadBrands();
}
async function loadBrands() {
  try {
    const items = await api("GET", "/brands");
    const box = $("#brList");
    if (!items.length) { box.innerHTML = '<span class="muted">Nenhuma marca cadastrada.</span>'; return; }
    const rows = items.map(b => `
      <tr>
        <td><b>${esc(b.name)}</b></td>
        <td><code>${esc(b.official_domains)}</code></td>
        <td class="muted">${b.last_scan_at ? esc(b.last_scan_at.slice(0, 16).replace("T", " ")) : "nunca"}</td>
        <td>
          ${can("analyst") ? actBtn("scanFast", b.id, "Scan rápido") + " " + actBtn("scanDeep", b.id, "Scan profundo") : ""}
          ${actBtn("findings", b.id, "Findings")}
        </td>
      </tr>`).join("");
    box.innerHTML = `<table><thead><tr><th>Marca</th><th>Domínios oficiais</th><th>Último scan</th><th></th></tr></thead><tbody>${rows}</tbody></table><div id="findings"></div>`;
  } catch (e) { $("#brList").textContent = e.message; }
}
async function addBrand() {
  try {
    const domains = $("#brDomains").value.split(",").map(s => s.trim()).filter(Boolean);
    await api("POST", "/brands", { name: $("#brName").value, official_domains: domains });
    $("#brName").value = ""; $("#brDomains").value = "";
    toast("Marca cadastrada"); await loadBrands();
  } catch (e) { toast(e.message, true); }
}
async function scan(id, deep) {
  toast(deep ? "Scan profundo em andamento (pode levar minutos)…" : "Scan rápido…");
  try {
    const r = await api("POST", `/brands/${id}/scan?deep=${deep}`);
    toast(`Scan: ${r.new_findings} novos findings, ${r.alerts_sent} alertas`);
    await loadBrands(); await findings(id);
  } catch (e) { toast(e.message, true); }
}
async function findings(id) {
  try {
    const items = await api("GET", `/brands/${id}/findings?min_score=20`);
    const box = $("#findings");
    if (!items.length) { box.innerHTML = '<div class="panel" style="margin-top:14px"><span class="muted">Nenhum finding com score ≥ 20. Rode um scan profundo.</span></div>'; return; }
    const rows = items.map(f => `
      <tr>
        <td><code>${esc(defang(f.domain))}</code></td>
        <td>${scoreBar(f.score)} <span class="muted">${f.score}</span></td>
        <td>${verdictCell(f.verdict)}</td>
        <td class="muted">${esc(f.similarity)}%</td>
        <td><code>${esc(f.source)}</code></td>
        <td class="muted">${esc(f.status)}</td>
      </tr>`).join("");
    box.innerHTML = `<div class="panel" style="margin-top:14px">
      <b>Findings priorizados</b>
      <table style="margin-top:8px"><thead><tr><th>Domínio</th><th>Score</th><th>Veredito</th><th>Sim.</th><th>Origem</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  } catch (e) { toast(e.message, true); }
}

// ---- Usuários ----
async function viewUsers() {
  const m = $("#main");
  if (!can("admin")) { m.innerHTML = '<span class="muted">Acesso restrito a administradores.</span>'; return; }
  m.innerHTML = `<h2 class="title">Usuários</h2>`;
  const p = el("div", { class: "panel" });
  p.append(el("div", { class: "row" },
    field("E-mail", inputEl("uEmail", "usuario@empresa.com")),
    field("Senha (mín. 8)", inputEl("uPass", "", "password")),
    field("Papel", selectEl("uRole", ["viewer", "analyst", "admin"])),
    el("button", { onclick: addUser }, "Criar usuário")));
  m.append(p);
  m.append(el("div", { class: "panel", id: "uList" }, "carregando…"));
  await loadUsers();
}
async function loadUsers() {
  try {
    const items = await api("GET", "/users");
    const rows = items.map(u => `
      <tr>
        <td>${esc(u.email)}</td>
        <td><span class="badge role-${esc(u.role)}">${esc(u.role)}</span></td>
        <td>${u.is_active ? '<span style="color:var(--green)">ativo</span>' : '<span class="muted">inativo</span>'}</td>
        <td class="muted">${u.last_login_at ? esc(u.last_login_at.slice(0, 16).replace("T", " ")) : "—"}</td>
        <td>
          ${actBtn(u.is_active ? "userOff" : "userOn", u.id, u.is_active ? "Desativar" : "Ativar")}
          ${actBtn("userReset", u.id, "Resetar senha")}
          ${actBtn("userDel", u.id, "Excluir", "danger")}
        </td>
      </tr>`).join("");
    $("#uList").innerHTML = `<table><thead><tr><th>E-mail</th><th>Papel</th><th>Status</th><th>Último login</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
  } catch (e) { $("#uList").textContent = e.message; }
}
async function addUser() {
  try {
    await api("POST", "/users", { email: $("#uEmail").value, password: $("#uPass").value, role: $("#uRole").value });
    $("#uEmail").value = ""; $("#uPass").value = "";
    toast("Usuário criado"); await loadUsers();
  } catch (e) { toast(e.message, true); }
}
async function toggleUser(id, active) {
  try { await api("PATCH", `/users/${id}`, { is_active: active }); toast("Atualizado"); await loadUsers(); }
  catch (e) { toast(e.message, true); }
}
async function delUser(id) {
  if (!confirm("Excluir este usuário?")) return;
  try { await api("DELETE", `/users/${id}`); toast("Excluído"); await loadUsers(); }
  catch (e) { toast(e.message, true); }
}
async function resetUser(id) {
  if (!confirm("Gerar uma senha temporária para este usuário? A sessão atual dele será encerrada.")) return;
  try {
    const r = await api("POST", `/users/${id}/reset-password`, {});
    alert(`Senha temporária de ${r.email}:\n\n${r.temporary_password}\n\nRepasse por canal seguro. Não será exibida de novo.`);
    await loadUsers();
  } catch (e) { toast(e.message, true); }
}

// ---- Watchlist (seeds por escopo) ----
const SCOPE_LABEL = {
  global: "Watchlist Global",
  sector: "Watchlist Setorial (Threat Profile)",
  organization: "Watchlist Organizacional",
};
const SCOPE_HINT = {
  organization: "Itens derivados da marca: domínio, slug e combinações marca + termo de risco.",
  sector: "Itens derivados do setor selecionado: ameaças típicas e categorias de CVE.",
  global: "Indicadores relevantes para qualquer organização.",
};
const PRIO_COLOR = { high: "var(--red)", medium: "var(--orange)", low: "var(--gray)" };
const TYPE_DESC = {
  domain: "Domínio oficial ou domínio-base monitorado",
  slug: "Nome simplificado da marca (termo de busca, não é domínio)",
  keyword_combo: "Combinação de marca + termo de risco",
  threat: "Ameaça típica do setor",
  cve_tech: "Categoria tecnológica para watchlist de CVEs",
};
const PRIO_TOOLTIP = "Prioridade indica a relevância/urgência da seed para monitoramento. Não representa severidade confirmada nem um IOC validado.";

async function viewWatchlist() {
  const m = $("#main");
  m.innerHTML = `<h2 class="title">Watchlist</h2>
    <div class="panel" style="border-left:3px solid var(--accent);margin-bottom:16px">
      <span class="muted">Os itens desta tela são <b>seeds de monitoramento</b>. Não representam
      ameaça confirmada, incidente ou IOC validado. Um <b>finding</b> só será criado quando houver
      evidência real coletada em uma fonte monitorada. Os findings relacionados à marca ficarão
      disponíveis na aba <b>Marcas</b>.</span>
    </div>
    <div id="wl">carregando…</div>`;
  try {
    const seeds = await api("GET", "/seeds");
    if (!seeds.length) {
      $("#wl").innerHTML = '<span class="muted">Nenhuma seed ainda. Gere no wizard (Threat Profile) ou reabra a configuração.</span>';
      return;
    }
    const groups = {};
    seeds.forEach(s => (groups[s.scope] || (groups[s.scope] = [])).push(s));
    let html = "";
    ["organization", "sector", "global"].forEach(scope => {
      const arr = groups[scope] || [];
      if (!arr.length) return;
      const rows = arr.map(s => `
        <tr>
          <td><code>${esc(s.seed)}</code></td>
          <td class="muted" title="${esc(TYPE_DESC[s.seed_type] || "")}"><code>${esc(s.seed_type)}</code></td>
          <td title="${esc(PRIO_TOOLTIP)}"><span style="color:${PRIO_COLOR[s.confidence] || "var(--muted)"}">${esc(s.confidence)}</span></td>
          <td class="muted">${esc(s.status)}</td>
          <td class="muted"><code>${esc(s.source_type)}</code></td>
        </tr>`).join("");
      html += `<div class="panel">
        <b>${esc(SCOPE_LABEL[scope] || scope)}</b> <span class="muted">· ${arr.length}</span>
        <div class="muted" style="font-size:12px;margin-top:2px">${esc(SCOPE_HINT[scope] || "")}</div>
        <table style="margin-top:10px"><thead><tr>
          <th>Seed</th>
          <th>Tipo</th>
          <th title="${esc(PRIO_TOOLTIP)}">Prioridade ⓘ</th>
          <th>Status</th>
          <th>Fonte</th>
        </tr></thead><tbody>${rows}</tbody></table></div>`;
    });
    // legenda dos tipos
    html += `<div class="panel"><b>Legenda de tipos</b>
      <div class="chips" style="margin-top:8px">${Object.entries(TYPE_DESC).map(([k, v]) =>
        `<span class="chip" title="${esc(v)}"><code>${esc(k)}</code> — ${esc(v)}</span>`).join("")}</div></div>`;
    $("#wl").innerHTML = html;
  } catch (e) { $("#wl").textContent = e.message; }
}

// ---- Organização ----
const ORG_FIELDS = [
  ["name", "Nome *"], ["trade_name", "Nome fantasia"], ["legal_name", "Razão social"],
  ["tax_id", "CNPJ"], ["sector", "Setor"], ["subsector", "Subsetor"],
  ["country", "País"], ["state", "Estado"], ["city", "Cidade"],
  ["website", "Website"], ["security_email", "E-mail de segurança"],
  ["legal_email", "E-mail jurídico"], ["phone", "Telefone"],
  ["timezone", "Timezone"], ["language", "Idioma"],
];
async function viewOrg() {
  const m = $("#main");
  m.innerHTML = `<h2 class="title">Organização</h2>`;
  let org = {};
  try { org = (await api("GET", "/organization")) || {}; } catch (e) { /* sem org ainda */ }
  const editable = can("admin");
  const p = el("div", { class: "panel" });
  p.style.maxWidth = "640px";
  const grid = el("div", { class: "srow2" });
  ORG_FIELDS.forEach(([k, label]) => {
    const inp = inputEl("org_" + k, "");
    inp.value = org[k] || "";
    if (!editable) inp.setAttribute("disabled", "true");
    grid.append(field(label, inp));
  });
  // criticidade como select
  const crit = selectEl("org_criticality", ["baixo", "medio", "alto", "critico"]);
  crit.value = org.criticality || "medio";
  if (!editable) crit.setAttribute("disabled", "true");
  grid.append(field("Criticidade", crit));
  p.append(grid);
  if (editable) p.append(el("div", { style: "margin-top:14px;display:flex;gap:10px" },
    el("button", { onclick: saveOrg }, org.id ? "Salvar alterações" : "Criar organização"),
    org.id ? el("button", { class: "ghost", onclick: reopenSetup }, "Reabrir configuração (wizard)") : null));
  else p.append(el("div", { class: "muted", style: "margin-top:10px" },
    "Somente administradores podem editar."));
  if (editable && org.monitoring_scope) {
    const labels = org.monitoring_scope.map(k => (SCOPE_SOURCES.find(s => s[0] === k) || [k, k])[1]);
    p.append(el("div", { class: "muted", style: "margin-top:12px", html:
      "<b>Escopo de monitoramento:</b> " + labels.map(esc).join(", ") }));
  }
  m.append(p);
}
async function saveOrg() {
  const body = { criticality: $("#org_criticality").value };
  ORG_FIELDS.forEach(([k]) => { body[k] = $("#org_" + k).value || null; });
  try { await api("PUT", "/organization", body); toast("Organização salva"); }
  catch (e) { toast(e.message, true); }
}
async function reopenSetup() {
  if (!confirm("Reabrir o wizard de configuração? As abas ficarão travadas até você concluir de novo. Nenhum dado é apagado.")) return;
  try { await api("POST", "/setup/reopen"); toast("Configuração reaberta"); await boot(); }
  catch (e) { toast(e.message, true); }
}

// ---- Auditoria ----
async function viewAudit() {
  const m = $("#main");
  if (!can("admin")) { m.innerHTML = '<span class="muted">Acesso restrito a administradores.</span>'; return; }
  m.innerHTML = `<h2 class="title">Trilha de auditoria</h2><div class="panel" id="auditList">carregando…</div>`;
  try {
    const items = await api("GET", "/audit?limit=300");
    if (!items.length) { $("#auditList").innerHTML = '<span class="muted">Nenhum evento ainda.</span>'; return; }
    const rows = items.map(a => `
      <tr>
        <td class="muted">${esc((a.ts || "").slice(0, 19).replace("T", " "))}</td>
        <td>${esc(a.actor)}</td>
        <td><code>${esc(a.action)}</code></td>
        <td class="muted">${esc(a.target_type || "")}${a.target_id ? " #" + esc(a.target_id) : ""}</td>
        <td class="muted">${esc(a.ip || "")}</td>
      </tr>`).join("");
    $("#auditList").innerHTML = `<table><thead><tr><th>Quando (UTC)</th><th>Ator</th><th>Ação</th><th>Alvo</th><th>IP</th></tr></thead><tbody>${rows}</tbody></table>`;
  } catch (e) { $("#auditList").textContent = e.message; }
}

// ---- Conta (trocar a própria senha) ----
function viewAccount() {
  document.querySelectorAll("#nav button").forEach(b => b.classList.remove("active"));
  const m = $("#main");
  m.innerHTML = `<h2 class="title">Minha conta</h2>`;
  const p = el("div", { class: "panel" });
  p.style.maxWidth = "420px";
  p.append(
    field("Senha atual", inputEl("cpCurrent", "", "password")),
    field("Nova senha (mín. 8)", inputEl("cpNew", "", "password")),
    field("Confirmar nova senha", inputEl("cpConfirm", "", "password")),
    el("div", { style: "margin-top:14px" }, el("button", { onclick: doChangePassword }, "Trocar senha"))
  );
  m.append(p);
}
async function doChangePassword() {
  const cur = $("#cpCurrent").value, nw = $("#cpNew").value, cf = $("#cpConfirm").value;
  if (nw !== cf) { toast("A confirmação não confere.", true); return; }
  try {
    await api("POST", "/auth/change-password", { current_password: cur, new_password: nw });
    toast("Senha alterada com sucesso");
    navigate("dashboard");
  } catch (e) { toast(e.message, true); }
}

// ---------- delegação de cliques (compatível com CSP, sem onclick inline) ----------
const ACTIONS = {
  enrich: (id) => enrich(id),
  iocDetail: (id) => iocDetail(id),
  scanFast: (id) => scan(id, false),
  scanDeep: (id) => scan(id, true),
  findings: (id) => findings(id),
  userOn: (id) => toggleUser(id, true),
  userOff: (id) => toggleUser(id, false),
  userReset: (id) => resetUser(id),
  userDel: (id) => delUser(id),
  tenantKey: (id) => genTenantKey(id),
};
document.addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-action]");
  if (!btn) return;
  const fn = ACTIONS[btn.dataset.action];
  if (fn) fn(Number(btn.dataset.id));
});

// ---------- form helpers ----------
function field(label, control) { return el("div", {}, el("label", {}, label), control); }
function inputEl(id, ph, type = "text") { return el("input", { id, placeholder: ph || "", type }); }
function selectEl(id, opts) {
  const s = el("select", { id });
  opts.forEach(o => s.append(el("option", { value: o }, o)));
  return s;
}

// ---------- init ----------
$("#loginForm").addEventListener("submit", doLogin);
$("#adminForm").addEventListener("submit", doCreateAdmin);
$("#inviteForm").addEventListener("submit", doInviteAccept);
$("#wizNext").addEventListener("click", wizNext);
$("#wizBack").addEventListener("click", wizBack);
$("#wizLogout").addEventListener("click", logout);
$("#opLogout").addEventListener("click", logout);
$("#logout").addEventListener("click", logout);
$("#changePw").addEventListener("click", viewAccount);
document.querySelectorAll("#nav button").forEach(b =>
  b.addEventListener("click", () => navigate(b.dataset.view)));
boot();
