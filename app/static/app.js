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
  $("#app").classList.add("hidden");
  $("#login").classList.remove("hidden");
  $("#password").value = "";
}

async function boot() {
  try {
    ME = await api("GET", "/auth/me");
  } catch {
    $("#app").classList.add("hidden");
    $("#login").classList.remove("hidden");
    return;
  }
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  $("#who").innerHTML = `${esc(ME.subject)} &nbsp;<span class="badge role-${esc(ME.role)}">${esc(ME.role)}</span>`;
  $("#navUsers").style.display = can("admin") ? "" : "none";
  navigate("dashboard");
}

// ---------- views ----------
function navigate(view) {
  document.querySelectorAll("#nav button").forEach(b =>
    b.classList.toggle("active", b.dataset.view === view));
  ({ dashboard: viewDashboard, iocs: viewIocs, brands: viewBrands, users: viewUsers }[view] || viewDashboard)();
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
$("#logout").addEventListener("click", logout);
$("#changePw").addEventListener("click", viewAccount);
document.querySelectorAll("#nav button").forEach(b =>
  b.addEventListener("click", () => navigate(b.dataset.view)));
boot();
