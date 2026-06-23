"use strict";

// ---------- helpers ----------
const $ = (sel) => document.querySelector(sel);
let ME = null;

let SUPPORT_TENANT = null;  // operator in support mode inside a tenant

async function api(method, path, body) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (SUPPORT_TENANT) opts.headers["X-Tenant-Id"] = String(SUPPORT_TENANT.id);
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
    const msg = (data && data.detail) ? data.detail : `Error ${res.status}`;
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

// escape text before inserting into innerHTML (XSS defense for external data)
function esc(s) {
  const div = document.createElement("div");
  div.textContent = String(s == null ? "" : s);
  return div.innerHTML;
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
  // in support mode, use the operator effective role inside the tenant
  const myRole = (SUPPORT_TENANT && ME && ME._effRole) ? ME._effRole : (ME && ME.role);
  return ME && rank[myRole] >= rank[role];
}
function verdictCell(v) {
  return `<span class="v v-${esc(v)}">${esc((v || "").toUpperCase())}</span>`;
}
function scoreBar(score) {
  const color = score >= 70 ? "var(--red)" : score >= 40 ? "var(--orange)"
    : score >= 20 ? "var(--yellow)" : "var(--gray)";
  return `<div class="score-bar"><i style="width:${Math.min(100, score)}%;background:${color}"></i></div>`;
}
// button as string with data-action; delegated click handler, CSP-compatible
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
  SUPPORT_TENANT = null;
  $("#supportBanner").classList.add("hidden");
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
      $("#inviteSub").textContent = v.reason || "Invalid invitation.";
      $("#inviteForm").classList.add("hidden");
      return;
    }
    $("#inviteForm").classList.remove("hidden");
    $("#inviteSub").textContent = `Invitation for ${v.tenant_name || "your tenant"}`;
    $("#invEmail").value = v.email || "";
  } catch (e) {
    $("#inviteSub").textContent = "Could not validate the invitation.";
    $("#inviteForm").classList.add("hidden");
  }
}

async function doInviteAccept(e) {
  e.preventDefault();
  $("#inviteErr").textContent = "";
  if ($("#invPass").value !== $("#invPass2").value) {
    $("#inviteErr").textContent = "Passwords do not match."; return;
  }
  try {
    await api("POST", "/invites/accept", { token: INVITE_TOKEN, password: $("#invPass").value });
    toast("Access activated");
    // remove the token from the URL and continue normally
    window.history.replaceState({}, "", "/");
    INVITE_TOKEN = null;
    await boot();
  } catch (err) { $("#inviteErr").textContent = err.message; }
}

async function boot() {
  // 0) invitation acceptance flow from e-mail link
  const inviteToken = inviteTokenFromUrl();
  if (inviteToken && !ME) { await showInviteAccept(inviteToken); return; }

  let st = null;
  try { st = await api("GET", "/setup/status"); } catch { /* segue */ }

  // 1) no users -> create platform operator
  if (st && st.needs_operator) { showOnly("createAdmin"); return; }

  // 2) session
  try { ME = await api("GET", "/auth/me"); }
  catch { showOnly("login"); return; }

  // 3) operator -> operations console
  if (ME.is_operator) { showOnly("operator"); renderOperator(); return; }

  // 4) tenant user -> own tenant setup gate
  let ts = null;
  try { ts = await api("GET", "/tenant/setup-status"); } catch { /* segue */ }
  if (ts && !ts.setup_completed) {
    showOnly("wizard");
    if (can("admin")) { startWizard(); }
    else {
      $("#wizSteps").style.display = "none";
      $("#wizBody").innerHTML = '<p class="hint">The platform is in initial setup. Wait for an administrator to complete the setup.</p>';
      $("#wizBack").style.display = $("#wizNext").style.display = "none";
    }
    return;
  }

  // 5) tenant app enabled
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
    toast("Operator created");
    await boot();
  } catch (err) { $("#adminErr").textContent = err.message; }
}

// ===================== OPERATOR CONSOLE =====================
let OP_TAB = "tenants";
function isPlatformAdmin() { return ME && ME.operator_role === "platform_admin"; }

async function renderOperator() {
  const roleLabel = ME.operator_role === "platform_admin" ? "platform admin"
    : ME.operator_role === "support_operator" ? "support" : "support (read-only)";
  $("#opWho").innerHTML = `${esc(ME.subject)} &nbsp;<span class="badge role-admin">${esc(roleLabel)}</span>`;
  const m = $("#opMain");
  const tabs = el("div", { class: "optabs" });
  const tb = (id, label) => el("button", {
    class: OP_TAB === id ? "active" : "", onclick: () => { OP_TAB = id; renderOperator(); }
  }, label);
  tabs.append(tb("tenants", "Tenants"));
  if (isPlatformAdmin()) tabs.append(tb("operators", "Operators"));
  m.innerHTML = "";
  m.append(tabs);
  const body = el("div", { id: "opBody" });
  m.append(body);
  if (OP_TAB === "operators" && isPlatformAdmin()) await viewOpOperators(body);
  else await viewOpTenants(body);
}

// ---- Tenants ----
async function viewOpTenants(box) {
  box.innerHTML = `<h2 class="title">Tenants (customers)</h2>
    <p class="muted" style="margin:-8px 0 16px">Each tenant is isolated. Enter support mode to validate the customer environment.</p>`;
  if (isPlatformAdmin()) {
    const p = el("div", { class: "panel" });
    p.append(el("div", { class: "row" },
      field("Tenant name", inputEl("tName", "e.g. Customer X")),
      field("Admin e-mail", inputEl("tEmail", "admin@customer.com")),
      field("Password (empty = send invitation)", inputEl("tPass", "", "password")),
      el("button", { onclick: createTenant }, "Create tenant")));
    box.append(p);
  }
  const list = el("div", { class: "panel", id: "tList" }, "loading…");
  box.append(list);
  try {
    const items = await api("GET", "/tenants");
    if (!items.length) { list.innerHTML = '<span class="muted">No tenant assigned.</span>'; return; }
    const rows = items.map(t => `
      <tr>
        <td>${esc(t.id)}</td>
        <td><b>${esc(t.name)}</b></td>
        <td><code>${esc(t.slug)}</code></td>
        <td class="muted">${esc(t.status)}</td>
        <td>
          ${actBtn("enterTenant", t.id, "Enter tenant")}
          ${isPlatformAdmin() ? actBtn("tenantKey", t.id, "API key") : ""}
          ${isPlatformAdmin() ? actBtn(t.status === "active" ? "tenantSuspend" : "tenantActivate", t.id, t.status === "active" ? "Suspend" : "Activate") : ""}
        </td>
      </tr>`).join("");
    list.innerHTML = `<table><thead><tr><th>ID</th><th>Name</th><th>Slug</th><th>Status</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
    list.dataset.names = JSON.stringify(Object.fromEntries(items.map(t => [t.id, t.name])));
  } catch (e) { list.textContent = e.message; }
}
async function createTenant() {
  const name = $("#tName").value.trim(), email = $("#tEmail").value.trim(), pass = $("#tPass").value;
  if (!name || !email) { toast("Provide tenant name and admin e-mail.", true); return; }
  const body = { name, admin_email: email };
  if (pass) body.admin_password = pass;
  try {
    const r = await api("POST", "/tenants", body);
    if (r.invite_link) {
      const sent = r.invite_email_sent ? "Invitation e-mail sent." : "SMTP is not configured — use the link below in development.";
      prompt(`Tenant "${r.name}" created.\n${sent}\n\nSingle-use invitation link for ${r.admin_email}:`, r.invite_link);
    } else { toast("Tenant created"); }
    renderOperator();
  } catch (e) { toast(e.message, true); }
}
async function genTenantKey(id) {
  if (!confirm("Generate an API key with analyst role for this tenant?")) return;
  try {
    const r = await api("POST", `/tenants/${id}/api-keys`, { label: "ui", role: "analyst" });
    alert(`Tenant API key ${id} — store it now; it will not be displayed again:\n\n${r.api_key}`);
  } catch (e) { toast(e.message, true); }
}
async function setTenantStatus(id, status) {
  try { await api("PATCH", `/tenants/${id}?status=${status}`); toast("Status updated"); renderOperator(); }
  catch (e) { toast(e.message, true); }
}

// ---- Modo support: entrar/sair do tenant ----
function tenantNameFromList(id) {
  try { return JSON.parse($("#tList").dataset.names || "{}")[id] || ("tenant " + id); }
  catch { return "tenant " + id; }
}
function enterTenant(id) {
  SUPPORT_TENANT = { id, name: tenantNameFromList(id) };
  $("#supportTenantName").textContent = SUPPORT_TENANT.name;
  $("#supportBanner").classList.remove("hidden");
  showOnly("app");
  $("#who").innerHTML = `${esc(ME.subject)} &nbsp;<span class="badge role-admin">${esc(ME.operator_role || "operador")}</span>`;
  // operador em support: mostra abas conforme papel efetivo
  const eff = ME.operator_role === "platform_admin" ? "admin"
    : ME.operator_role === "support_operator" ? "analyst" : "viewer";
  $("#navUsers").style.display = eff === "admin" ? "" : "none";
  $("#navAudit").style.display = eff === "admin" ? "" : "none";
  ME._effRole = eff;
  navigate("dashboard");
}
function exitTenant() {
  SUPPORT_TENANT = null;
  ME._effRole = null;
  $("#supportBanner").classList.add("hidden");
  showOnly("operator");
  renderOperator();
}

// ---- Operators (platform_admin) ----
async function viewOpOperators(box) {
  box.innerHTML = `<h2 class="title">Operators</h2>
    <p class="muted" style="margin:-8px 0 16px">Platform Admin manages the platform. Support Operator can access only assigned tenants.</p>`;
  const p = el("div", { class: "panel" });
  p.append(el("div", { class: "row" },
    field("E-mail", inputEl("opEmail", "operador@empresa.com")),
    field("Password (empty = generate)", inputEl("opPass", "", "password")),
    field("Role", selectEl("opRole", ["support_operator", "support_viewer", "platform_admin"])),
    el("button", { onclick: createOperator }, "Create operator")));
  box.append(p);
  const list = el("div", { class: "panel", id: "opList" }, "loading…");
  box.append(list);
  try {
    const ops = await api("GET", "/operators");
    const rows = ops.map(o => `
      <tr>
        <td>${esc(o.email)}</td>
        <td><span class="badge role-${o.operator_role === "platform_admin" ? "admin" : "analyst"}">${esc(o.operator_role || "")}</span></td>
        <td>${o.is_active ? '<span style="color:var(--green)">active</span>' : '<span class="muted">inactive</span>'}</td>
        <td>
          ${o.operator_role !== "platform_admin" ? actBtn("opAccess", o.id, "Allowed tenants") : '<span class="muted">full access</span>'}
          ${actBtn(o.is_active ? "opOff" : "opOn", o.id, o.is_active ? "Deactivate" : "Activate")}
        </td>
      </tr>`).join("");
    list.innerHTML = `<table><thead><tr><th>E-mail</th><th>Role</th><th>Status</th><th></th></tr></thead><tbody>${rows}</tbody></table><div id="opAccessBox"></div>`;
  } catch (e) { list.textContent = e.message; }
}
async function createOperator() {
  const email = $("#opEmail").value.trim(), pass = $("#opPass").value, role = $("#opRole").value;
  if (!email) { toast("Informe o e-mail.", true); return; }
  const body = { email, operator_role: role };
  if (pass) body.password = pass;
  try {
    await api("POST", "/operators", body);
    if (!pass) toast("Operator created — set the password through reset or provide a password.");
    else toast("Operator created");
    renderOperator();
  } catch (e) { toast(e.message, true); }
}
async function toggleOperator(id, active) {
  try { await api("PATCH", `/operators/${id}`, { is_active: active }); toast("Atualizado"); renderOperator(); }
  catch (e) { toast(e.message, true); }
}
async function manageOpAccess(id) {
  const box = $("#opAccessBox");
  try {
    const [access, tenants] = await Promise.all([
      api("GET", `/operators/${id}/tenant-access`), api("GET", "/tenants")]);
    const granted = new Set(access.filter(a => a.is_active).map(a => a.tenant_id));
    const rows = tenants.map(t => `
      <tr><td>${esc(t.name)}</td>
        <td>${granted.has(t.id) ? '<span style="color:var(--green)">permitido</span>' : '<span class="muted">—</span>'}</td>
        <td>${granted.has(t.id)
          ? `<button class="sm ghost" data-action="opRevoke" data-id="${id}" data-tid="${t.id}">Revogar</button>`
          : `<button class="sm ghost" data-action="opGrant" data-id="${id}" data-tid="${t.id}">Conceder</button>`}</td>
      </tr>`).join("");
    box.innerHTML = `<div class="panel" style="margin-top:14px"><b>Allowed tenants — operador #${id}</b>
      <table style="margin-top:8px"><thead><tr><th>Tenant</th><th>Access</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
  } catch (e) { toast(e.message, true); }
}
async function grantAccess(opId, tid) {
  try { await api("POST", `/operators/${opId}/tenant-access`, { tenant_id: tid, access_role: "support_operator" }); toast("Access granted"); manageOpAccess(opId); }
  catch (e) { toast(e.message, true); }
}
async function revokeAccess(opId, tid) {
  try { await api("DELETE", `/operators/${opId}/tenant-access/${tid}`); toast("Access revoked"); manageOpAccess(opId); }
  catch (e) { toast(e.message, true); }
}

// ===================== SETUP WIZARD =====================
const WIZ = { step: 1, max: 5 };
const SCOPE_SOURCES = [
  ["iocs", "IOCs"], ["dominios", "Domains"], ["typosquatting", "Typosquatting"],
  ["certificate_transparency", "Certificate Transparency"], ["urlhaus", "URLhaus"],
  ["cisa_kev", "CISA KEV"], ["epss", "EPSS"], ["mitre", "MITRE ATT&CK"],
  ["github", "GitHub"], ["paste_sites", "Paste sites"], ["foruns", "Forums"],
  ["deep_web", "Deep web"], ["dark_web", "Dark web"],
  ["telegram_publico", "Public/authorized Telegram"],
  ["whatsapp_intake", "WhatsApp (intake manual/autorizado)"],
];
const ORG_WIZ_FIELDS = [
  ["name", "Name *"], ["trade_name", "Trade name"], ["legal_name", "Legal name"],
  ["tax_id", "CNPJ"], ["subsector", "Subsector"], ["country", "Country"],
  ["state", "State"], ["city", "City"], ["website", "Website"],
  ["security_email", "Security e-mail"], ["legal_email", "Legal e-mail"],
  ["phone", "Phone"], ["timezone", "Timezone"], ["language", "Language"],
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
  $("#wizNext").textContent = WIZ.step === WIZ.max ? "Complete setup" : "Continuar";
  $("#wizNext").disabled = false;  // reabilita; a etapa de revisão pode desabilitar
  WIZ_RENDER[WIZ.step]();
}

async function wizNext() {
  $("#wizErr").textContent = "";
  try {
    const ok = await WIZ_SAVE[WIZ.step]();
    if (ok === false) return;
    if (WIZ.step < WIZ.max) { WIZ.step++; renderWizard(); }
    else { await api("POST", "/setup/complete"); toast("Setup completed"); await boot(); }
  } catch (err) { $("#wizErr").textContent = err.message; }
}
function wizBack() { if (WIZ.step > 1) { WIZ.step--; renderWizard(); } }

// ---- Step 1: Organization ----
const WIZ_RENDER = {};
const WIZ_SAVE = {};
WIZ_RENDER[1] = async () => {
  let org = {};
  try { org = (await api("GET", "/organization")) || {}; } catch {}
  const grid = el("div", { class: "srow2" });
  // setor + criticidade primeiro (dirigem o threat profile)
  const sectorSel = selectEl("wz_sector",
    [["", ""], ["Telecom", "Telecom"], ["Financeiro", "Finance"], ["Varejo", "Retail"], ["Saúde", "Healthcare"], ["Governo", "Government"], ["Indústria", "Industry"], ["Tecnologia", "Technology"], ["Energia", "Energy"], ["Outro", "Other"]]);
  sectorSel.value = org.sector || "";
  const critSel = selectEl("wz_criticality", [["baixo", "low"], ["medio", "medium"], ["alto", "high"], ["critico", "critical"]]);
  critSel.value = org.criticality || "medio";
  grid.append(field("Sector *", sectorSel), field("Criticality", critSel));
  ORG_WIZ_FIELDS.forEach(([k, label]) => {
    const inp = inputEl("wz_org_" + k, "");
    inp.value = org[k] || "";
    grid.append(field(label, inp));
  });
  $("#wizBody").innerHTML = "<h3>Organization</h3><p class='hint'>Information about your organization. The sector defines the suggested Threat Profile.</p>";
  $("#wizBody").append(grid);
};
WIZ_SAVE[1] = async () => {
  const name = $("#wz_org_name").value.trim();
  const sector = $("#wz_sector").value;
  if (!name) { $("#wizErr").textContent = "Provide the organization name."; return false; }
  if (!sector) { $("#wizErr").textContent = "Selecione o setor."; return false; }
  const body = { name, sector, criticality: $("#wz_criticality").value };
  ORG_WIZ_FIELDS.forEach(([k]) => { if (k !== "name") body[k] = $("#wz_org_" + k).value || null; });
  await api("PUT", "/organization", body);
  return true;
};

// ---- Step 2: Brand and assets ----
const BRAND_LIST_FIELDS = [
  ["variations", "Name variations"], ["aliases", "Acronyms"], ["products", "Products"],
  ["subdomains", "Official subdomains"], ["social_profiles", "Official profiles"],
  ["keywords", "Keywords"], ["sensitive_terms", "Sensitive fraud terms"],
];
WIZ_RENDER[2] = async () => {
  let brands = [];
  try { brands = await api("GET", "/brands"); } catch {}
  const existing = brands.length
    ? `<p class="hint">Brands already registered: ${brands.map(b => esc(b.name)).join(", ")}. You can add another one or continue.</p>` : "";
  $("#wizBody").innerHTML = `<h3>Brand and official assets</h3>
    <p class="hint">Register at least one brand. Lists accept comma-separated items.</p>${existing}`;
  const grid = el("div", { class: "srow2" });
  grid.append(field("Brand name", inputEl("wz_b_name", "e.g. Example Bank")));
  grid.append(field("Official domains (comma-separated)", inputEl("wz_b_domains", "exemplo.com.br")));
  BRAND_LIST_FIELDS.forEach(([k, label]) => grid.append(field(label, inputEl("wz_b_" + k, ""))));
  grid.append(field("Logotipo (URL)", inputEl("wz_b_logo", "https://...")));
  $("#wizBody").append(grid);
  $("#wizBody").dataset.hasBrands = brands.length ? "1" : "";
};
WIZ_SAVE[2] = async () => {
  const name = $("#wz_b_name").value.trim();
  const hadBrands = $("#wizBody").dataset.hasBrands === "1";
  if (!name) {
    if (hadBrands) return true;  // a brand already exists; continue without adding another
    $("#wizErr").textContent = "Add at least one brand."; return false;
  }
  const csv = (id) => $("#" + id).value.split(",").map(s => s.trim()).filter(Boolean);
  const domains = csv("wz_b_domains");
  if (!domains.length) { $("#wizErr").textContent = "Provide at least one official domain."; return false; }
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
  $("#wizBody").innerHTML = "<h3>Monitoring scope</h3><p class='hint'>Select what the platform should monitor. WhatsApp is manual/authorized intake only.</p>";
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
    <p class="hint">Typical sector suggestions. They generate <b>monitoring seeds</b> (watchlist), not confirmed findings.</p>
    <div id="tpBody">loading…</div>`;
  try {
    const p = await api("GET", `/sectors/${encodeURIComponent(sector)}/profile`);
    const chips = (arr) => `<div class="chips">${(arr || []).map(x => `<span class="chip">${esc(x)}</span>`).join("") || '<span class="muted">—</span>'}</div>`;
    $("#tpBody").innerHTML = `
      <div style="margin-bottom:10px"><b>Keywords</b>${chips(p.keywords)}</div>
      <div style="margin-bottom:10px"><b>Common threats</b>${chips(p.threats)}</div>
      <div style="margin-bottom:10px"><b>Categorias de IOC</b>${chips(p.ioc_categories)}</div>
      <div style="margin-bottom:10px"><b>Recommended sources</b>${chips(p.sources)}</div>
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
WIZ_SAVE[4] = async () => true;  // seed generation is optional

// ---- Step 5: Review ----
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
    [!!(org.name && org.sector), "Organization (name + sector)"],
    [brands.length > 0, "At least one brand"],
    [hasDomain, "At least one official domain"],
    [scope.length > 0, "Escopo de monitoramento"],
  ];
  const pending = checks.filter(([ok]) => !ok);
  const checklist = checks.map(([ok, label]) =>
    `<div class="factor">${ok ? "✅" : "⛔"} ${esc(label)}</div>`).join("");

  $("#wizBody").innerHTML = `<h3>Review</h3>
    <p class="hint">Review and finish. You can adjust everything later in the platform tabs.</p>
    <table>
      <tr><th>Organization</th><td>${esc(org.name || "—")} ${org.sector ? "· " + esc(org.sector) : ""}</td></tr>
      <tr><th>Brands</th><td>${brands.map(b => esc(b.name)).join(", ") || "—"}</td></tr>
      <tr><th>Official domains</th><td><code>${brands.map(b => esc(b.official_domains)).filter(Boolean).join("; ") || "—"}</code></td></tr>
      <tr><th>Escopo</th><td>${scope.map(esc).join(", ") || "—"}</td></tr>
      <tr><th>Seeds (watchlist)</th><td>${seeds.length} candidatas</td></tr>
    </table>
    <div style="margin-top:16px"><b>Requirements to complete</b>${checklist}</div>
    <p class="hint" style="margin-top:12px">${pending.length
      ? "Resolve the items marked with ⛔ before finishing. Go back to the previous steps."
      : "Everything is ready. After completion, platform tabs will be enabled."}</p>`;

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
  m.innerHTML = `<h2 class="title">Overview</h2><div class="cards" id="cards">loading…</div>`;
  try {
    const s = await api("GET", "/stats");
    $("#cards").innerHTML = `
      ${cardHtml(s.observables, "Registered IOCs")}
      ${cardHtml(s.observables_malicious, "Malicious IOCs", true)}
      ${cardHtml(s.brands, "Monitored brands")}
      ${cardHtml(s.findings, "Brand findings")}
      ${cardHtml(s.findings_priority, "Priority findings", true)}
      ${cardHtml(s.users, "Users")}`;
  } catch (e) { $("#cards").textContent = e.message; }
}
function cardHtml(n, label, alert = false) {
  return `<div class="card ${alert ? "alert" : ""}"><div class="n">${esc(n)}</div><div class="l">${esc(label)}</div></div>`;
}

// ---- IOCs ----
async function viewIocs() {
  const m = $("#main");
  m.innerHTML = `<h2 class="title">Indicators (IOCs)</h2>`;
  if (can("analyst")) {
    const p = el("div", { class: "panel" });
    p.append(el("div", { class: "row" },
      field("Type", selectEl("iocType", ["cve", "ip", "domain", "url", "hash", "email"])),
      field("Value", inputEl("iocValue", "e.g. CVE-2024-3400 or evil.examplel[.]com")),
      el("button", { onclick: addIoc }, "Add"),
      el("button", { class: "ghost", onclick: syncFeeds }, "Sync feeds (KEV/MITRE)")
    ));
    m.append(p);
  }
  m.append(el("div", { class: "panel", id: "iocList" }, "loading…"));
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
        <td>${can("analyst") ? actBtn("enrich", o.id, "Enrich") : ""}
            ${actBtn("iocDetail", o.id, "Details")}</td>
      </tr>`).join("");
    box.innerHTML = `<table><thead><tr><th>Type</th><th>Value</th><th>Score</th><th>Verdict</th><th></th></tr></thead><tbody>${rows}</tbody></table><div id="iocDetail"></div>`;
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

// ---- Brands ----
async function viewBrands() {
  const m = $("#main");
  m.innerHTML = `<h2 class="title">Brand monitoring</h2>`;
  if (can("analyst")) {
    const p = el("div", { class: "panel" });
    p.append(el("div", { class: "row" },
      field("Brand name", inputEl("brName", "e.g. Example Bank")),
      field("Official domains (comma-separated)", inputEl("brDomains", "example-bank.example")),
      el("button", { onclick: addBrand }, "Add brand")));
    m.append(p);
  }
  m.append(el("div", { class: "panel", id: "brList" }, "loading…"));
  await loadBrands();
}
async function loadBrands() {
  try {
    const items = await api("GET", "/brands");
    const box = $("#brList");
    if (!items.length) { box.innerHTML = '<span class="muted">No brands registered.</span>'; return; }
    const rows = items.map(b => `
      <tr>
        <td><b>${esc(b.name)}</b></td>
        <td><code>${esc(b.official_domains)}</code></td>
        <td class="muted">${b.last_scan_at ? esc(b.last_scan_at.slice(0, 16).replace("T", " ")) : "never"}</td>
        <td>
          ${can("analyst") ? actBtn("scanFast", b.id, "Quick scan") + " " + actBtn("scanDeep", b.id, "Deep scan") : ""}
          ${actBtn("findings", b.id, "Findings")}
          ${can("admin") ? actBtn("editBrand", b.id, "Edit") : ""}
        </td>
      </tr>`).join("");
    box.innerHTML = `<table><thead><tr><th>Brand</th><th>Official domains</th><th>Last scan</th><th></th></tr></thead><tbody>${rows}</tbody></table><div id="brandEdit"></div><div id="findings"></div>`;
  } catch (e) { $("#brList").textContent = e.message; }
}
async function addBrand() {
  try {
    const domains = $("#brDomains").value.split(",").map(s => s.trim()).filter(Boolean);
    await api("POST", "/brands", { name: $("#brName").value, official_domains: domains });
    $("#brName").value = ""; $("#brDomains").value = "";
    toast("Brand registered"); await loadBrands();
  } catch (e) { toast(e.message, true); }
}
async function scan(id, deep) {
  toast(deep ? "Deep scan em andamento (pode levar minutos)…" : "Quick scan…");
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
      <table style="margin-top:8px"><thead><tr><th>Domain</th><th>Score</th><th>Verdict</th><th>Sim.</th><th>Source</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  } catch (e) { toast(e.message, true); }
}

async function editBrand(id) {
  try {
    const b = await api("GET", `/brands/${id}`);
    const doms = (b.official_domains || "").split(",").map(s => s.trim()).filter(Boolean).join(", ");
    $("#brandEdit").innerHTML = `<div class="panel" style="margin-top:14px;border-left:3px solid var(--accent)">
      <b>Edit brand #${esc(b.id)}</b>
      <label>Name</label><input id="eb_name" style="width:100%">
      <label>Official domains (comma-separated)</label><input id="eb_domains" style="width:100%">
      <label style="display:flex;gap:8px;align-items:center;margin-top:10px">
        <input type="checkbox" id="eb_clear"> Clear existing findings (reprocess after scope change)</label>
      <div style="margin-top:12px;display:flex;gap:10px">
        <button data-action="brandSave" data-id="${esc(b.id)}">Save</button>
        <button class="ghost" data-action="brandCancel" data-id="${esc(b.id)}">Cancel</button>
      </div>
      <div class="err" id="eb_err"></div></div>`;
    $("#eb_name").value = b.name || "";
    $("#eb_domains").value = doms;
  } catch (e) { toast(e.message, true); }
}
async function saveBrand(id) {
  const name = $("#eb_name").value.trim();
  const domains = $("#eb_domains").value.split(",").map(s => s.trim()).filter(Boolean);
  const clear = $("#eb_clear").checked;
  if (!domains.length) { $("#eb_err").textContent = "Provide at least one official domain."; return; }
  try {
    await api("PATCH", `/brands/${id}?clear_findings=${clear}`, { name, official_domains: domains });
    toast("Brand updated");
    $("#brandEdit").innerHTML = "";
    await loadBrands();
  } catch (e) { $("#eb_err").textContent = e.message; }
}
function cancelBrandEdit() { $("#brandEdit").innerHTML = ""; }

// ---- Users ----
async function viewUsers() {
  const m = $("#main");
  if (!can("admin")) { m.innerHTML = '<span class="muted">Access restricted to administrators.</span>'; return; }
  m.innerHTML = `<h2 class="title">Users</h2>`;
  const p = el("div", { class: "panel" });
  p.append(el("div", { class: "row" },
    field("E-mail", inputEl("uEmail", "user@example.com")),
    field("Password (min. 8)", inputEl("uPass", "", "password")),
    field("Role", selectEl("uRole", ["viewer", "analyst", "admin"])),
    el("button", { onclick: addUser }, "Create user")));
  m.append(p);
  m.append(el("div", { class: "panel", id: "uList" }, "loading…"));
  await loadUsers();
}
async function loadUsers() {
  try {
    const items = await api("GET", "/users");
    const rows = items.map(u => `
      <tr>
        <td>${esc(u.email)}</td>
        <td><span class="badge role-${esc(u.role)}">${esc(u.role)}</span></td>
        <td>${u.is_active ? '<span style="color:var(--green)">active</span>' : '<span class="muted">inactive</span>'}</td>
        <td class="muted">${u.last_login_at ? esc(u.last_login_at.slice(0, 16).replace("T", " ")) : "—"}</td>
        <td>
          ${actBtn(u.is_active ? "userOff" : "userOn", u.id, u.is_active ? "Deactivate" : "Activate")}
          ${actBtn("userReset", u.id, "Reset password")}
          ${actBtn("userDel", u.id, "Delete", "danger")}
        </td>
      </tr>`).join("");
    $("#uList").innerHTML = `<table><thead><tr><th>E-mail</th><th>Role</th><th>Status</th><th>Last login</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
  } catch (e) { $("#uList").textContent = e.message; }
}
async function addUser() {
  try {
    await api("POST", "/users", { email: $("#uEmail").value, password: $("#uPass").value, role: $("#uRole").value });
    $("#uEmail").value = ""; $("#uPass").value = "";
    toast("User created"); await loadUsers();
  } catch (e) { toast(e.message, true); }
}
async function toggleUser(id, active) {
  try { await api("PATCH", `/users/${id}`, { is_active: active }); toast("Atualizado"); await loadUsers(); }
  catch (e) { toast(e.message, true); }
}
async function delUser(id) {
  if (!confirm("Delete this user?")) return;
  try { await api("DELETE", `/users/${id}`); toast("Deleted"); await loadUsers(); }
  catch (e) { toast(e.message, true); }
}
async function resetUser(id) {
  if (!confirm("Generate a temporary password for this user? Their current session will be terminated.")) return;
  try {
    const r = await api("POST", `/users/${id}/reset-password`, {});
    alert(`Temporary password for ${r.email}:\n\n${r.temporary_password}\n\nShare it through a secure channel. It will not be displayed again.`);
    await loadUsers();
  } catch (e) { toast(e.message, true); }
}

// ---- Watchlist (seeds por escopo) ----
const SCOPE_LABEL = {
  global: "Watchlist Global",
  sector: "Watchlist Sectorial (Threat Profile)",
  organization: "Watchlist Organizacional",
};
const SCOPE_HINT = {
  organization: "Items derived from the brand: domain, slug and brand + risk term combinations.",
  sector: "Items derived from the selected sector: typical threats and CVE categories.",
  global: "Indicators relevant to any organization.",
};
const PRIO_COLOR = { high: "var(--red)", medium: "var(--orange)", low: "var(--gray)" };
const TYPE_DESC = {
  domain: "Official domain or monitored base domain",
  slug: "Simplified brand name (search term, not a domain)",
  keyword_combo: "Brand + risk term combination",
  threat: "Typical sector threat",
  cve_tech: "Technology category for CVE watchlist",
};
const PRIO_TOOLTIP = "Priority indicates the seed relevance/urgency for monitoring. It does not represent confirmed severity or a validated IOC.";

async function viewWatchlist() {
  const m = $("#main");
  m.innerHTML = `<h2 class="title">Watchlist</h2>
    <div class="panel" style="border-left:3px solid var(--accent);margin-bottom:16px">
      <span class="muted">The items on this screen are <b>monitoring seeds</b>. They do not represent
      a confirmed threat, incident or validated IOC. A <b>finding</b> is only created when
      real evidence is collected from a monitored source. Brand-related findings will be
      available in the <b>Brands</b> tab.</span>
    </div>
    <div id="wl">loading…</div>`;
  try {
    const seeds = await api("GET", "/seeds");
    if (!seeds.length) {
      $("#wl").innerHTML = '<span class="muted">No seeds yet. Generate them in the wizard (Threat Profile) or reopen setup.</span>';
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
          <th>Type</th>
          <th title="${esc(PRIO_TOOLTIP)}">Priority ⓘ</th>
          <th>Status</th>
          <th>Source</th>
        </tr></thead><tbody>${rows}</tbody></table></div>`;
    });
    // legenda dos tipos
    html += `<div class="panel"><b>Type legend</b>
      <div class="chips" style="margin-top:8px">${Object.entries(TYPE_DESC).map(([k, v]) =>
        `<span class="chip" title="${esc(v)}"><code>${esc(k)}</code> — ${esc(v)}</span>`).join("")}</div></div>`;
    $("#wl").innerHTML = html;
  } catch (e) { $("#wl").textContent = e.message; }
}

// ---- Organization ----
const ORG_FIELDS = [
  ["name", "Name *"], ["trade_name", "Trade name"], ["legal_name", "Legal name"],
  ["tax_id", "CNPJ"], ["sector", "Sector"], ["subsector", "Subsector"],
  ["country", "Country"], ["state", "State"], ["city", "City"],
  ["website", "Website"], ["security_email", "Security e-mail"],
  ["legal_email", "Legal e-mail"], ["phone", "Phone"],
  ["timezone", "Timezone"], ["language", "Language"],
];
async function viewOrg() {
  const m = $("#main");
  m.innerHTML = `<h2 class="title">Organization</h2>`;
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
  const crit = selectEl("org_criticality", [["baixo", "low"], ["medio", "medium"], ["alto", "high"], ["critico", "critical"]]);
  crit.value = org.criticality || "medio";
  if (!editable) crit.setAttribute("disabled", "true");
  grid.append(field("Criticality", crit));
  p.append(grid);
  if (editable) p.append(el("div", { style: "margin-top:14px;display:flex;gap:10px" },
    el("button", { onclick: saveOrg }, org.id ? "Save changes" : "Create organization"),
    org.id ? el("button", { class: "ghost", onclick: reopenSetup }, "Reopen setup wizard") : null));
  else p.append(el("div", { class: "muted", style: "margin-top:10px" },
    "Only administrators can edit."));
  if (editable && org.monitoring_scope) {
    const labels = org.monitoring_scope.map(k => (SCOPE_SOURCES.find(s => s[0] === k) || [k, k])[1]);
    p.append(el("div", { class: "muted", style: "margin-top:12px", html:
      "<b>Monitoring scope:</b> " + labels.map(esc).join(", ") }));
  }
  m.append(p);
}
async function saveOrg() {
  const body = { criticality: $("#org_criticality").value };
  ORG_FIELDS.forEach(([k]) => { body[k] = $("#org_" + k).value || null; });
  try { await api("PUT", "/organization", body); toast("Organization saved"); }
  catch (e) { toast(e.message, true); }
}
async function reopenSetup() {
  if (!confirm("Reopen the setup wizard? Tabs will remain locked until you complete it again. No data will be deleted.")) return;
  try { await api("POST", "/setup/reopen"); toast("Setup reopened"); await boot(); }
  catch (e) { toast(e.message, true); }
}

// ---- Audit ----
async function viewAudit() {
  const m = $("#main");
  if (!can("admin")) { m.innerHTML = '<span class="muted">Access restricted to administrators.</span>'; return; }
  m.innerHTML = `<h2 class="title">Audit trail</h2><div class="panel" id="auditList">loading…</div>`;
  try {
    const items = await api("GET", "/audit?limit=300");
    if (!items.length) { $("#auditList").innerHTML = '<span class="muted">No events yet.</span>'; return; }
    const rows = items.map(a => `
      <tr>
        <td class="muted">${esc((a.ts || "").slice(0, 19).replace("T", " "))}</td>
        <td>${esc(a.actor)}</td>
        <td><code>${esc(a.action)}</code></td>
        <td class="muted">${esc(a.target_type || "")}${a.target_id ? " #" + esc(a.target_id) : ""}</td>
        <td class="muted">${esc(a.ip || "")}</td>
      </tr>`).join("");
    $("#auditList").innerHTML = `<table><thead><tr><th>When (UTC)</th><th>Actor</th><th>Action</th><th>Target</th><th>IP</th></tr></thead><tbody>${rows}</tbody></table>`;
  } catch (e) { $("#auditList").textContent = e.message; }
}

// ---- Account (change own password) ----
function viewAccount() {
  document.querySelectorAll("#nav button").forEach(b => b.classList.remove("active"));
  const m = $("#main");
  m.innerHTML = `<h2 class="title">My account</h2>`;
  const p = el("div", { class: "panel" });
  p.style.maxWidth = "420px";
  p.append(
    field("Current password", inputEl("cpCurrent", "", "password")),
    field("New password (min. 8)", inputEl("cpNew", "", "password")),
    field("Confirm new password", inputEl("cpConfirm", "", "password")),
    el("div", { style: "margin-top:14px" }, el("button", { onclick: doChangePassword }, "Change password"))
  );
  m.append(p);
}
async function doChangePassword() {
  const cur = $("#cpCurrent").value, nw = $("#cpNew").value, cf = $("#cpConfirm").value;
  if (nw !== cf) { toast("Password confirmation does not match.", true); return; }
  try {
    await api("POST", "/auth/change-password", { current_password: cur, new_password: nw });
    toast("Password changed successfully");
    navigate("dashboard");
  } catch (e) { toast(e.message, true); }
}

// ---------- click delegation (CSP-compatible, no inline onclick) ----------
const ACTIONS = {
  enrich: (id) => enrich(id),
  iocDetail: (id) => iocDetail(id),
  scanFast: (id) => scan(id, false),
  scanDeep: (id) => scan(id, true),
  findings: (id) => findings(id),
  editBrand: (id) => editBrand(id),
  brandSave: (id) => saveBrand(id),
  brandCancel: () => cancelBrandEdit(),
  userOn: (id) => toggleUser(id, true),
  userOff: (id) => toggleUser(id, false),
  userReset: (id) => resetUser(id),
  userDel: (id) => delUser(id),
  tenantKey: (id) => genTenantKey(id),
  enterTenant: (id) => enterTenant(id),
  tenantSuspend: (id) => setTenantStatus(id, "suspended"),
  tenantActivate: (id) => setTenantStatus(id, "active"),
  opAccess: (id) => manageOpAccess(id),
  opOn: (id) => toggleOperator(id, true),
  opOff: (id) => toggleOperator(id, false),
  opGrant: (id, btn) => grantAccess(id, Number(btn.dataset.tid)),
  opRevoke: (id, btn) => revokeAccess(id, Number(btn.dataset.tid)),
};
document.addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-action]");
  if (!btn) return;
  const fn = ACTIONS[btn.dataset.action];
  if (fn) fn(Number(btn.dataset.id), btn);
});

// ---------- form helpers ----------
function field(label, control) { return el("div", {}, el("label", {}, label), control); }
function inputEl(id, ph, type = "text") { return el("input", { id, placeholder: ph || "", type }); }
function selectEl(id, opts) {
  const s = el("select", { id });
  opts.forEach(o => {
    const value = Array.isArray(o) ? o[0] : o;
    const label = Array.isArray(o) ? o[1] : o;
    s.append(el("option", { value }, label));
  });
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
$("#exitTenant").addEventListener("click", exitTenant);
$("#logout").addEventListener("click", logout);
$("#changePw").addEventListener("click", viewAccount);
document.querySelectorAll("#nav button").forEach(b =>
  b.addEventListener("click", () => navigate(b.dataset.view)));
boot();
