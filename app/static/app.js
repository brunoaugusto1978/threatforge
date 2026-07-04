"use strict";

// ---------- helpers ----------
const $ = (sel) => document.querySelector(sel);
let ME = null;

let SUPPORT_TENANT = null;  // operator in support mode inside a tenant

async function api(method, path, body) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (SUPPORT_TENANT) opts.headers["X-Tenant-Id"] = String(SUPPORT_TENANT.id);
  if (body !== undefined) {
    if (typeof FormData !== "undefined" && body instanceof FormData) {
      // multipart: deixar o browser definir o Content-Type (boundary)
      opts.body = body;
    } else {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
  }
  const res = await fetch(path, opts);
  if (res.status === 204) return null;
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) {
    const detail = (data && data.detail !== undefined) ? data.detail : null;
    const msg = (typeof detail === "string" && detail) ? detail
      : (detail && detail.message) ? detail.message : `Error ${res.status}`;
    const err = new Error(msg);
    err.status = res.status;
    err.detail = detail;
    throw err;
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
     org: viewOrg, users: viewUsers, audit: viewAudit, cases: viewCases,
     integrations: viewIntegrations, exposure: viewExposure,
     credentials: viewCredentials }[view] || viewDashboard)();
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
        <td><b>${esc(b.name)}</b>${b.status === "archived" ? ' <span class="muted">(archived)</span>' : ""}</td>
        <td><code>${esc(b.official_domains)}</code></td>
        <td class="muted">${b.last_scan_at ? esc(b.last_scan_at.slice(0, 16).replace("T", " ")) : "never"}</td>
        <td>
          ${can("analyst") && b.status !== "archived" ? actBtn("scanFast", b.id, "Quick scan") + " " + actBtn("scanDeep", b.id, "Deep scan") : ""}
          ${actBtn("findings", b.id, "Findings")}
          ${can("admin") ? actBtn("editBrand", b.id, "Edit") : ""}
          ${can("admin") ? actBtn(b.status === "archived" ? "brandUnarchive" : "brandArchive", b.id, b.status === "archived" ? "Unarchive" : "Archive") : ""}
          ${can("admin") ? actBtn("brandDelete", b.id, "Delete", "danger") : ""}
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
        <td>${can("analyst") ? `<button class="sm ghost" data-action="openCase" data-id="${f.id}" data-bid="${id}">Open case</button>` : ""}</td>
      </tr>`).join("");
    box.innerHTML = `<div class="panel" style="margin-top:14px">
      <b>Findings priorizados</b>
      <table style="margin-top:8px"><thead><tr><th>Domain</th><th>Score</th><th>Verdict</th><th>Sim.</th><th>Source</th><th>Status</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
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

async function archiveBrand(id, archive) {
  try {
    await api("POST", `/brands/${id}/${archive ? "archive" : "unarchive"}`);
    toast(archive ? "Brand archived" : "Brand unarchived");
    await loadBrands();
  } catch (e) { toast(e.message, true); }
}
async function deleteBrand(id) {
  let b;
  try { b = await api("GET", `/brands/${id}`); } catch (e) { toast(e.message, true); return; }
  const typed = prompt(`Type the brand name to confirm permanent deletion:\n\n${b.name}`);
  if (typed === null) return;
  if (typed !== b.name) { toast("Name does not match — deletion cancelled.", true); return; }
  const q = `confirm_name=${encodeURIComponent(b.name)}`;
  try {
    await api("DELETE", `/brands/${id}?${q}`);
  } catch (e) {
    if (/findings/i.test(e.message)) {
      if (!confirm(`${e.message}\n\nDelete the brand AND its findings?`)) return;
      try { await api("DELETE", `/brands/${id}?${q}&force=true`); }
      catch (e2) { toast(e2.message, true); return; }
    } else { toast(e.message, true); return; }
  }
  toast("Brand deleted");
  await loadBrands();
}

// ---- Users ----

// ---- Investigation Cases ----
const CASE_STATUSES = ["open", "triage", "investigating", "contained", "closed", "false_positive"];
const CASE_ACTIVE = ["open", "triage", "investigating", "contained"];
const SEV_COLOR = { critico: "var(--red)", alto: "var(--orange)", medio: "var(--yellow)", baixo: "var(--gray)" };
const SEV_LABEL = { critico: "critical", alto: "high", medio: "medium", baixo: "low" };

function severityLabel(value) {
  return SEV_LABEL[value] || value || "";
}

function selectHtml(id, opts, current, disabled) {
  const o = opts.map((opt) => {
    const value = Array.isArray(opt) ? opt[0] : opt;
    const label = Array.isArray(opt) ? opt[1] : (opt || "(any)");
    return `<option value="${esc(value)}" ${String(value) === String(current || "") ? "selected" : ""}>${esc(label)}</option>`;
  }).join("");
  return `<select id="${esc(id)}" style="width:100%" ${disabled ? "disabled" : ""}>${o}</select>`;
}
function selectKV(id, pairs, anyLabel) {
  const sel = el("select", { id });
  if (anyLabel !== undefined) sel.append(el("option", { value: "" }, anyLabel));
  pairs.forEach(([v, label]) => sel.append(el("option", { value: String(v) }, label)));
  return sel;
}

async function viewCases() {
  const m = $("#main");
  m.innerHTML = `<h2 class="title">Investigation cases</h2>`;
  let brands = [], users = [];
  try { brands = await api("GET", "/brands"); } catch {}
  if (can("admin")) { try { users = await api("GET", "/users"); } catch {} }
  const brandPairs = brands.map(b => [b.id, b.name]);
  const userPairs = users.map(u => [u.id, u.email]);

  if (can("analyst")) {
    const p = el("div", { class: "panel" });
    const grid = el("div", { class: "srow2" });
    grid.append(field("Title", inputEl("cs_title", "Investigation title")));
    grid.append(field("Severity", selectEl("cs_sev", [["baixo", "low"], ["medio", "medium"], ["alto", "high"], ["critico", "critical"]])));
    grid.append(field("Brand (optional)", selectKV("cs_brand", brandPairs, "(none)")));
    if (can("admin")) grid.append(field("Assignee (optional)", selectKV("cs_assignee", userPairs, "(unassigned)")));
    p.append(grid);
    p.append(field("Description", inputEl("cs_desc", "")));
    p.append(el("div", { style: "margin-top:10px" }, el("button", { onclick: createCaseManual }, "Create case")));
    m.append(p);
  }

  const fp = el("div", { class: "panel" });
  const frow = el("div", { class: "row" });
  frow.append(field("Status", selectEl("cs_fstatus", ["", ...CASE_STATUSES])));
  frow.append(field("Severity", selectEl("cs_fsev", [["", ""], ["baixo", "low"], ["medio", "medium"], ["alto", "high"], ["critico", "critical"]])));
  frow.append(field("Brand", selectKV("cs_fbrand", brandPairs, "(any brand)")));
  if (can("admin")) frow.append(field("Assignee", selectKV("cs_fassignee", userPairs, "(any assignee)")));
  else frow.append(field("Assignee id", inputEl("cs_fassignee_num", "")));
  frow.append(field("Search title", inputEl("cs_q", "")));
  frow.append(el("button", { class: "ghost", onclick: loadCases }, "Filter"));
  fp.append(frow);
  m.append(fp);
  m.append(el("div", { class: "panel", id: "caseList" }, "loading…"));
  m.append(el("div", { id: "caseDetail" }));
  await loadCases();
}

async function loadCases() {
  const qp = new URLSearchParams();
  const v = (id) => { const e = $("#" + id); return e ? e.value : ""; };
  if (v("cs_fstatus")) qp.set("status", v("cs_fstatus"));
  if (v("cs_fsev")) qp.set("severity", v("cs_fsev"));
  if (v("cs_fbrand")) qp.set("brand_id", v("cs_fbrand"));
  const asg = v("cs_fassignee") || v("cs_fassignee_num");
  if (asg) qp.set("assignee_user_id", asg);
  const q = (v("cs_q") || "").trim(); if (q) qp.set("q", q);
  try {
    const items = await api("GET", `/cases?${qp.toString()}`);
    const box = $("#caseList");
    if (!items.length) { box.innerHTML = '<span class="muted">No cases.</span>'; return; }
    const rows = items.map(c => `
      <tr>
        <td>#${esc(c.id)}</td>
        <td><b>${esc(c.title)}</b></td>
        <td><span style="color:${SEV_COLOR[c.severity] || "var(--muted)"}">${esc(severityLabel(c.severity))}</span></td>
        <td class="muted">${esc(c.status)}</td>
        <td class="muted">${c.brand_id ?? "—"}</td>
        <td class="muted">${c.assignee_user_id ?? "—"}</td>
        <td class="muted">${esc((c.created_at || "").slice(0, 16).replace("T", " "))}</td>
        <td>${actBtn("caseView", c.id, "View")}</td>
      </tr>`).join("");
    box.innerHTML = `<table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Brand</th><th>Assignee</th><th>Created</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
  } catch (e) { $("#caseList").textContent = e.message; }
}

async function createCaseManual() {
  const title = $("#cs_title").value.trim();
  if (!title) { toast("Title is required", true); return; }
  const body = { title, severity: $("#cs_sev").value };
  const desc = $("#cs_desc").value.trim(); if (desc) body.description = desc;
  const brand = $("#cs_brand") && $("#cs_brand").value; if (brand) body.brand_id = Number(brand);
  const asg = $("#cs_assignee") && $("#cs_assignee").value; if (asg) body.assignee_user_id = Number(asg);
  try {
    await api("POST", "/cases", body);
    $("#cs_title").value = ""; $("#cs_desc").value = "";
    toast("Case created");
    await loadCases();
  } catch (e) { toast(e.message, true); }
}

async function openCaseFromFinding(brandId, findingId) {
  try {
    const c = await api("POST", `/brands/${brandId}/findings/${findingId}/case`);
    toast(`Case #${c.id} opened`);
    navigate("cases");
  } catch (e) {
    const ex = e.detail && e.detail.existing_case_id;
    if (ex) {
      if (confirm(`An active investigation already exists for this finding (case #${ex}). Open it?`)) {
        navigate("cases");
        setTimeout(() => caseDetail(ex), 50);
      }
    } else { toast(e.message, true); }
  }
}

async function caseDetail(id) {
  let c;
  try { c = await api("GET", `/cases/${id}`); } catch (e) { toast(e.message, true); return; }
  const admin = can("admin");
  const editable = can("analyst");
  const terminal = !CASE_ACTIVE.includes(c.status);

  // status: admin vê todos; analyst ativo vê ativos; analyst terminal -> read-only
  let statusOpts, statusDisabled;
  if (admin) { statusOpts = CASE_STATUSES; statusDisabled = false; }
  else if (!terminal) { statusOpts = CASE_ACTIVE; statusDisabled = !editable; }
  else { statusOpts = [c.status]; statusDisabled = true; }

  let assigneeControl = "";
  if (admin) {
    let users = [];
    try { users = await api("GET", "/users"); } catch {}
    const opts = ['<option value="">(unassigned)</option>'].concat(
      users.map(u => `<option value="${u.id}" ${c.assignee_user_id === u.id ? "selected" : ""}>${esc(u.email)}</option>`)).join("");
    assigneeControl = `<label>Assignee</label><select id="cd_assignee" style="width:100%">${opts}</select>`;
  }

  // botões explícitos de ciclo de vida (admin)
  let lifecycle = "";
  if (admin) {
    if (terminal) {
      lifecycle = `<button class="ghost" data-action="caseReopen" data-id="${esc(c.id)}">Reopen</button>`;
    } else {
      lifecycle = `<button class="ghost" data-action="caseClose" data-id="${esc(c.id)}">Close</button>
                   <button class="ghost" data-action="caseFP" data-id="${esc(c.id)}">Mark false positive</button>`;
    }
  }

  const snap = c.finding_snapshot
    ? `<div class="muted" style="margin-top:8px">Finding snapshot: <code>${esc(defang(c.finding_snapshot.domain || ""))}</code> · score ${esc(c.finding_snapshot.score)} · ${esc(c.finding_snapshot.verdict)} ${c.finding_id == null ? "· <i>(finding removido — contexto preservado)</i>" : ""}</div>`
    : "";

  $("#caseDetail").innerHTML = `<div class="panel" style="margin-top:14px;border-left:3px solid var(--accent)">
    <b>Case #${esc(c.id)}</b> <span class="muted">created ${esc((c.created_at || "").slice(0, 16).replace("T", " "))}${c.closed_at ? " · closed " + esc(c.closed_at.slice(0, 16).replace("T", " ")) : ""} · current status: <b>${esc(c.status)}</b></span>
    ${snap}
    <label>Title</label><input id="cd_title" style="width:100%" ${editable ? "" : "disabled"}>
    <label>Description</label><textarea id="cd_desc" style="width:100%;min-height:70px" ${editable ? "" : "disabled"}></textarea>
    <div class="srow2">
      <div><label>Severity</label>${selectHtml("cd_sev", [["baixo", "low"], ["medio", "medium"], ["alto", "high"], ["critico", "critical"]], c.severity, !editable)}</div>
      <div><label>Status</label>${selectHtml("cd_status", statusOpts, c.status, statusDisabled)}</div>
    </div>
    ${assigneeControl}
    <div style="margin-top:12px;display:flex;gap:10px;flex-wrap:wrap">
      ${editable ? `<button data-action="caseSave" data-id="${esc(c.id)}">Save</button>` : '<span class="muted">Read-only.</span>'}
      ${lifecycle}
      <button class="ghost" data-action="caseExportMd" data-id="${esc(c.id)}">Export Markdown</button>
      <button class="ghost" data-action="caseExportStix" data-id="${esc(c.id)}" title="STIX 2.1 bundle">Export STIX</button>
      <button class="ghost" data-action="caseExportPdf" data-id="${esc(c.id)}" title="ThreatForge Enterprise">Export PDF 🔒</button>
    </div>
    <div class="err" id="cd_err"></div></div>
    <div id="caseNotes"></div>
    <div id="caseEvidence"></div>`;
  $("#cd_title").value = c.title || "";
  $("#cd_desc").value = c.description || "";
  loadNotes(c.id);
  loadEvidence(c.id);
}

async function saveCaseDetail(id) {
  const body = {
    title: $("#cd_title").value.trim(),
    description: $("#cd_desc").value,
    severity: $("#cd_sev").value,
  };
  const stEl = $("#cd_status");
  if (stEl && !stEl.disabled) body.status = stEl.value;
  const asg = $("#cd_assignee");
  if (asg) body.assignee_user_id = asg.value ? Number(asg.value) : null;
  try {
    await api("PATCH", `/cases/${id}`, body);
    toast("Case updated");
    await loadCases();
    await caseDetail(id);
  } catch (e) { $("#cd_err").textContent = e.message; }
}

async function loadNotes(id) {
  const box = $("#caseNotes");
  if (!box) return;
  let notes = [];
  try { notes = await api("GET", `/cases/${id}/notes`); }
  catch (e) { box.innerHTML = `<div class="panel" style="margin-top:14px"><span class="muted">Notes unavailable: ${esc(e.message)}</span></div>`; return; }
  const items = notes.length ? notes.map(n => `
    <div style="background:var(--panel2);border:1px solid var(--line);border-radius:6px;padding:8px 10px">
      <div class="muted" style="font-size:12px">user #${esc(n.author_user_id ?? "—")} · ${esc((n.created_at || "").slice(0, 16).replace("T", " "))}${n.is_internal ? " · internal" : ""}</div>
      <div style="white-space:pre-wrap">${esc(n.body)}</div>
    </div>`).join("") : '<span class="muted">No notes yet.</span>';
  const adder = can("analyst") ? `
    <div style="margin-top:10px">
      <textarea id="note_body" style="width:100%;min-height:60px" placeholder="Add an internal note…"></textarea>
      <div style="margin-top:8px"><button data-action="noteAdd" data-id="${esc(id)}">Add note</button></div>
      <div class="err" id="note_err"></div>
    </div>` : "";
  box.innerHTML = `<div class="panel" style="margin-top:14px"><b>Notes</b>
    <div style="margin-top:8px;display:flex;flex-direction:column;gap:8px">${items}</div>${adder}</div>`;
}

async function addNote(id) {
  const t = $("#note_body");
  const body = t ? t.value.trim() : "";
  if (!body) { const e = $("#note_err"); if (e) e.textContent = "Note cannot be empty."; return; }
  try {
    await api("POST", `/cases/${id}/notes`, { body });
    toast("Note added");
    await loadNotes(id);
  } catch (e) { const el = $("#note_err"); if (el) el.textContent = e.message; }
}

// ---------- evidence (chain of custody) ----------
const EVIDENCE_ORIGINS = [
  ["manual_upload", "Manual upload"],
  ["authorized_export", "Authorized export"],
  ["whatsapp_intake", "WhatsApp intake"],
  ["telegram_public", "Telegram (public)"],
  ["email", "E-mail"],
  ["other", "Other"],
];

function humanBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n < 10 ? 1 : 0) + " " + u[i];
}

async function loadEvidence(id) {
  const box = $("#caseEvidence");
  if (!box) return;
  let rows = [];
  try { rows = await api("GET", `/cases/${id}/evidence`); }
  catch (e) { box.innerHTML = `<div class="panel" style="margin-top:14px"><span class="muted">Evidence unavailable: ${esc(e.message)}</span></div>`; return; }
  const items = rows.length ? rows.map(ev => {
    const when = (ev.created_at || "").slice(0, 16).replace("T", " ");
    const dl = ev.stored
      ? `<button class="sm ghost" data-action="evidenceDownload" data-id="${esc(ev.id)}" data-cid="${esc(id)}" data-fn="${esc(ev.filename)}">Download</button>`
      : `<span class="muted" title="metadata-only (binary not retained)">metadata-only</span>`;
    return `<div style="background:var(--panel2);border:1px solid var(--line);border-radius:6px;padding:8px 10px">
      <div style="display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap">
        <b>${esc(ev.filename)}</b> ${dl}
      </div>
      <div class="muted" style="font-size:12px">${esc(ev.mime_type)} · ${esc(humanBytes(ev.size_bytes))} · origin: ${esc(ev.origin)} · user #${esc(ev.uploaded_by_user_id ?? "—")} · ${esc(when)}</div>
      ${ev.description ? `<div style="white-space:pre-wrap;margin-top:4px">${esc(ev.description)}</div>` : ""}
      <div class="muted" style="font-size:11px;font-family:monospace;margin-top:4px;word-break:break-all">sha256: ${esc(ev.sha256)}</div>
    </div>`;
  }).join("") : '<span class="muted">No evidence attached yet.</span>';
  const originOpts = EVIDENCE_ORIGINS.map(o => `<option value="${o[0]}">${esc(o[1])}</option>`).join("");
  const adder = can("analyst") ? `
    <div style="margin-top:10px;border-top:1px solid var(--line);padding-top:10px">
      <input type="file" id="ev_file" style="width:100%">
      <div class="srow2" style="margin-top:8px">
        <div><label>Origin</label><select id="ev_origin" style="width:100%">${originOpts}</select></div>
        <div><label>Description (optional)</label><input id="ev_desc" style="width:100%" placeholder="context/label"></div>
      </div>
      <div style="margin-top:8px"><button data-action="evidenceAdd" data-id="${esc(id)}">Attach evidence</button></div>
      <div class="err" id="ev_err"></div>
    </div>` : "";
  box.innerHTML = `<div class="panel" style="margin-top:14px"><b>Evidence</b>
    <div class="muted" style="font-size:12px">Append-only · SHA-256 computed server-side · chain of custody</div>
    <div style="margin-top:8px;display:flex;flex-direction:column;gap:8px">${items}</div>${adder}</div>`;
}

async function addEvidence(id) {
  const errEl = $("#ev_err");
  if (errEl) errEl.textContent = "";
  const fileEl = $("#ev_file");
  const f = fileEl && fileEl.files && fileEl.files[0];
  if (!f) { if (errEl) errEl.textContent = "Select a file."; return; }
  const fd = new FormData();
  fd.append("file", f);
  fd.append("origin", $("#ev_origin").value);
  const desc = $("#ev_desc").value.trim();
  if (desc) fd.append("description", desc);
  try {
    await api("POST", `/cases/${id}/evidence`, fd);
    toast("Evidence attached");
    await loadEvidence(id);
  } catch (e) { if (errEl) errEl.textContent = e.message; else toast(e.message, true); }
}

async function downloadEvidence(evId, btn) {
  const caseId = Number(btn.dataset.cid);
  const filename = btn.dataset.fn || "evidence.bin";
  try {
    const headers = SUPPORT_TENANT ? { "X-Tenant-Id": String(SUPPORT_TENANT.id) } : {};
    const res = await fetch(`/cases/${caseId}/evidence/${evId}/download`,
      { method: "GET", credentials: "same-origin", headers });
    if (!res.ok) {
      let msg = `Error ${res.status}`;
      try { const j = await res.json(); if (j && j.detail) msg = typeof j.detail === "string" ? j.detail : msg; } catch {}
      throw new Error(msg);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  } catch (e) { toast(e.message, true); }
}

async function exportCaseMarkdown(id) {
  try {
    const headers = SUPPORT_TENANT ? { "X-Tenant-Id": String(SUPPORT_TENANT.id) } : {};
    const res = await fetch(`/cases/${id}/export.md`, { method: "GET", credentials: "same-origin", headers });
    if (!res.ok) {
      let msg = `Error ${res.status}`;
      try { const j = await res.json(); if (j && typeof j.detail === "string") msg = j.detail; } catch {}
      throw new Error(msg);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `case-${id}.md`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
    toast("Markdown exported");
  } catch (e) { toast(e.message, true); }
}

async function exportCaseStix(id) {
  try {
    const headers = SUPPORT_TENANT ? { "X-Tenant-Id": String(SUPPORT_TENANT.id) } : {};
    const res = await fetch(`/cases/${id}/export.stix.json`, { method: "GET", credentials: "same-origin", headers });
    if (!res.ok) {
      let msg = `Error ${res.status}`;
      try { const j = await res.json(); if (j && typeof j.detail === "string") msg = j.detail; } catch {}
      throw new Error(msg);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `case-${id}.stix.json`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
    toast("STIX bundle exported");
  } catch (e) { toast(e.message, true); }
}


function enterpriseUpgradeMessage(payload, fallback) {
  const lines = [];

  if (payload && payload.detail) {
    lines.push(payload.detail);
  } else if (fallback) {
    lines.push(fallback);
  } else {
    lines.push("Premium feature requires a ThreatForge Enterprise license.");
  }

  const upgrade = payload && payload.upgrade ? payload.upgrade : {};

  if (upgrade.message) lines.push(upgrade.message);
  if (upgrade.email) lines.push(`Contact: ${upgrade.email}`);
  if (upgrade.url) lines.push(`More information: ${upgrade.url}`);

  return lines.filter(Boolean).join("\n");
}

async function exportCasePdf(id) {
  try {
    const headers = {};
    const supportTenant = (typeof SUPPORT_TENANT !== "undefined") ? SUPPORT_TENANT : null;

    if (supportTenant && supportTenant.id) {
      headers["X-Tenant-Id"] = String(supportTenant.id);
    }

    const fallback = "Premium PDF export requires a ThreatForge Enterprise license.";
    const res = await fetch(`/cases/${id}/export.pdf`, {
      method: "GET",
      credentials: "same-origin",
      headers,
    });

    if (!res.ok) {
      let data = {};
      try {
        data = await res.json();
      } catch (_) {
        data = {};
      }

      toast(enterpriseUpgradeMessage(data, fallback), true);
      return;
    }

    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `case-${id}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  } catch (e) {
    toast(e.message || "PDF export failed", true);
  }
}

async function setCaseStatus(id, status) {
  try {
    await api("PATCH", `/cases/${id}`, { status });
    toast(`Case → ${status}`);
    await loadCases();
    await caseDetail(id);
  } catch (e) { toast(e.message, true); }
}

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
  openCase: (id, btn) => openCaseFromFinding(Number(btn.dataset.bid), id),
  caseView: (id) => caseDetail(id),
  caseSave: (id) => saveCaseDetail(id),
  caseClose: (id) => setCaseStatus(id, 'closed'),
  caseFP: (id) => setCaseStatus(id, 'false_positive'),
  caseReopen: (id) => setCaseStatus(id, 'open'),
  noteAdd: (id) => addNote(id),
  editBrand: (id) => editBrand(id),
  brandSave: (id) => saveBrand(id),
  brandCancel: () => cancelBrandEdit(),
  brandArchive: (id) => archiveBrand(id, true),
  brandUnarchive: (id) => archiveBrand(id, false),
  brandDelete: (id) => deleteBrand(id),
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
  evidenceAdd: (id) => addEvidence(id),
  evidenceDownload: (id, btn) => downloadEvidence(id, btn),
  caseExportMd: (id) => exportCaseMarkdown(id),
  caseExportStix: (id) => exportCaseStix(id),
  caseExportPdf: (id) => exportCasePdf(id),
  integrationConfigure: (_id, btn) => configureIntegration(btn.dataset.name),
  expTab: (_id, btn) => exposureTab(btn.dataset.name),
  expApplyFilters: () => applyExposureFilters(),
  expTriage: (id) => triageExposure(id),
  expOpenCase: (id) => openCaseFromExposure(id),
  expAssetAdd: () => addExposureAsset(),
  expImport: () => importExposure(),
  expRollback: (id) => rollbackIngest(id),
  expRisk: (id) => toggleRiskBreakdown(id),
  expTimeline: (id) => toggleFindingTimeline(id),
  expCorrelate: (id) => toggleCorrelate(id),
  corList: (id) => renderCorList(id),
  corGraph: (id) => renderCorGraph(id),
  tlFilter: (_id, btn) => tlSourceFilter(btn.dataset.name),
  credDossier: (_id, btn) => credDossier(btn.dataset.hash),
  credCase: (_id, btn) => credCase(btn.dataset.hash),
};
document.addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-action]");
  if (!btn) return;
  const fn = ACTIONS[btn.dataset.action];
  if (fn) fn(Number(btn.dataset.id), btn);
});

// ---------- integrations (premium catalog; configure is Enterprise-gated) ----------
async function viewIntegrations() {
  const m = $("#main");
  m.innerHTML = `<h2 class="title">Integrations</h2>
    <p class="muted" style="margin-top:-6px">Connect ThreatForge to external threat-intel platforms. Premium connectors require a ThreatForge Enterprise license.</p>
    <div id="intgList">loading…</div>`;
  let items = [];
  try { items = await api("GET", "/integrations"); }
  catch (e) { $("#intgList").textContent = e.message; return; }
  if (!items.length) { $("#intgList").innerHTML = '<span class="muted">No integrations available.</span>'; return; }
  const canConfig = can("admin");
  $("#intgList").innerHTML = `<div class="cards" style="grid-template-columns:repeat(auto-fill,minmax(260px,1fr))">${
    items.map(it => {
      const locked = it.premium && !it.enabled;
      const badge = locked
        ? '<span class="muted" title="ThreatForge Enterprise" style="border:1px solid var(--line);border-radius:10px;padding:1px 8px;font-size:12px">Enterprise 🔒</span>'
        : '<span class="muted" style="border:1px solid var(--line);border-radius:10px;padding:1px 8px;font-size:12px">Available</span>';
      const caps = (it.capabilities || []).map(c => `<code style="font-size:11px;background:var(--panel2);border:1px solid var(--line);border-radius:4px;padding:1px 5px;margin:0 4px 4px 0;display:inline-block">${esc(c)}</code>`).join("");
      const btn = canConfig
        ? `<button class="sm ghost" data-action="integrationConfigure" data-name="${esc(it.name)}">${locked ? "Configure (Enterprise)" : "Configure"}</button>`
        : '<span class="muted" style="font-size:12px">Admin only</span>';
      return `<div class="panel" style="display:flex;flex-direction:column;gap:8px">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px">
          <b>${esc(it.title)}</b>${badge}
        </div>
        <div class="muted" style="font-size:13px">${esc(it.description || "")}</div>
        <div>${caps}</div>
        <div style="margin-top:auto">${btn}</div>
      </div>`;
    }).join("")
  }</div>`;
}

async function configureIntegration(name) {
  try {
    const headers = SUPPORT_TENANT ? { "X-Tenant-Id": String(SUPPORT_TENANT.id) } : {};
    const fallback = "This premium integration requires a ThreatForge Enterprise license.";
    const res = await fetch(`/integrations/${encodeURIComponent(name)}/connections`, {
      method: "POST", credentials: "same-origin",
      headers: { ...headers, "Content-Type": "application/json" }, body: "{}",
    });
    if (res.ok) { toast("Integration configured"); return; }
    let data = {};
    try { data = await res.json(); } catch (_) { data = {}; }
    // 402 -> mesmo CTA de upgrade do PDF; outros erros -> mensagem simples
    toast(enterpriseUpgradeMessage(data, fallback), true);
  } catch (e) { toast(e.message || "Configuration failed", true); }
}

// ---------- exposure monitoring (DRP) ----------
let EXPOSURE_TAB = "dashboard";
const EXPF = { type: "", status: "" };
let LAST_IMPORT = null;
const ASSET_TYPES_UI = ["identity", "email", "domain", "keyword", "secret_pattern", "repo", "ip_range"];
const CRIT_UI = ["low", "medium", "high", "critical"];
const EXP_TYPES_UI = [["identity_exposure", "Identity"], ["credential_exposure", "Credential"]];
const EXP_STATUS_UI = ["new", "triaging", "confirmed", "mitigated", "closed", "false_positive", "duplicate"];
const PARSERS_UI = [["combolist", "Combolist (email:password)"], ["csv_generic", "Generic CSV"], ["json_findings", "JSON findings"]];

function _svgBars(rows) {
  const w = 280, h = 24, gap = 9, labelW = 66;
  const barW = w - labelW - 44;
  const max = Math.max(1, ...rows.map(r => r[1]));
  const height = rows.length * (h + gap);
  const bars = rows.map((r, i) => {
    const y = i * (h + gap);
    const bw = Math.round(barW * r[1] / max);
    return `<text x="0" y="${y + h / 2 + 4}" font-size="12" fill="#888">${esc(r[0])}</text>`
      + `<rect x="${labelW}" y="${y}" width="${bw}" height="${h}" rx="4" fill="${r[2]}"></rect>`
      + `<text x="${labelW + bw + 6}" y="${y + h / 2 + 4}" font-size="12" fill="currentColor">${esc(r[1])}</text>`;
  }).join("");
  return `<svg viewBox="0 0 ${w} ${height}" width="100%" style="margin-top:8px;max-width:${w}px">${bars}</svg>`;
}

function _riskBandOf(f) {
  const b = f.detail && f.detail.risk_breakdown && f.detail.risk_breakdown.band;
  if (b) return b;
  const s = f.risk_score || 0;
  return s >= 90 ? "critical" : s >= 70 ? "high" : s >= 40 ? "medium" : "low";
}

async function loadExposureDashboard() {
  const box = $("#expBody");
  if (!box) return;
  box.innerHTML = '<span class="muted">loading…</span>';
  let findings = [], assets = [], cases = [];
  try {
    [findings, assets, cases] = await Promise.all([
      api("GET", "/exposure/findings"),
      api("GET", "/exposure/assets"),
      api("GET", "/cases").catch(() => []),
    ]);
  } catch (e) { box.innerHTML = `<span class="muted">${esc(e.message)}</span>`; return; }

  const today = new Date().toISOString().slice(0, 10);
  const total = findings.length;
  const highRisk = findings.filter(f => ["high", "critical"].includes(_riskBandOf(f))).length;
  const creds = findings.filter(f => f.exposure_type === "credential_exposure").length;
  const newToday = findings.filter(f => (f.created_at || "").slice(0, 10) === today).length;
  const openCases = cases.filter(c => !["closed", "false_positive"].includes(c.status)).length;

  const byAsset = {};
  findings.forEach(f => {
    if (!f.asset_id) return;
    const a = byAsset[f.asset_id] || { count: 0, max: 0 };
    a.count++; a.max = Math.max(a.max, f.risk_score || 0);
    byAsset[f.asset_id] = a;
  });
  const label = {}; assets.forEach(a => { label[a.id] = a.label; });
  const topAssets = Object.entries(byAsset)
    .map(([id, v]) => ({ id, label: label[id] || ("asset #" + id), count: v.count, max: v.max }))
    .sort((a, b) => b.count - a.count || b.max - a.max).slice(0, 5);

  const bands = { low: 0, medium: 0, high: 0, critical: 0 };
  findings.forEach(f => { bands[_riskBandOf(f)]++; });

  const card = (n, lbl, color) => `<div class="panel" style="text-align:center;min-width:130px;flex:1">
    <div style="font-size:30px;font-weight:800;color:${color || "var(--txt)"}">${esc(n)}</div>
    <div class="muted" style="font-size:12px">${esc(lbl)}</div></div>`;
  const bars = _svgBars([
    ["low", bands.low, "#2e7d32"], ["medium", bands.medium, "#b8860b"],
    ["high", bands.high, "#d9772e"], ["critical", bands.critical, "#c0392b"],
  ]);
  const topHtml = topAssets.length ? topAssets.map(a =>
    `<div style="display:flex;justify-content:space-between;gap:10px;padding:5px 0;border-bottom:1px solid var(--line)">
      <span>${esc(a.label)}</span>
      <span class="muted" style="font-size:12px">${esc(a.count)} findings · max risk ${esc(a.max)}</span></div>`).join("")
    : '<span class="muted">No asset-linked findings yet.</span>';

  box.innerHTML = `
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px">
      ${card(total, "Total Findings")}
      ${card(highRisk, "Critical / High Risk", "#c0392b")}
      ${card(creds, "Credential Leaks", "#d9772e")}
      ${card(newToday, "New Today", "#2f6fb0")}
      ${card(openCases, "Open Cases", "#b8860b")}
    </div>
    <div style="display:flex;gap:14px;flex-wrap:wrap">
      <div class="panel" style="flex:1;min-width:280px"><b>Findings by risk band</b>${bars}</div>
      <div class="panel" style="flex:1;min-width:280px"><b>Top Exposed Assets</b>
        <div style="margin-top:8px">${topHtml}</div></div>
    </div>`;
}

function viewExposure() {
  const m = $("#main");
  const tab = (t, label) => `<button class="sm ${EXPOSURE_TAB === t ? "" : "ghost"}" data-action="expTab" data-name="${t}">${esc(label)}</button>`;
  m.innerHTML = `<h2 class="title">Exposure Monitoring</h2>
    <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px">
      ${tab("dashboard", "Dashboard")}${tab("findings", "Findings")}${tab("assets", "Monitored Assets")}${tab("imports", "Imports")}${tab("timeline", "Timeline")}
    </div>
    <div id="expBody">loading…</div>`;
  renderExposureTab();
}

function renderExposureTab() {
  if (EXPOSURE_TAB === "dashboard") return loadExposureDashboard();
  if (EXPOSURE_TAB === "assets") return loadExposureAssets();
  if (EXPOSURE_TAB === "imports") return loadExposureImports();
  if (EXPOSURE_TAB === "timeline") return loadTenantTimeline();
  return loadExposureFindings();
}

function exposureTab(name) { EXPOSURE_TAB = name; viewExposure(); }

function _pill(text, bg, fg, title) {
  return `<span${title ? ` title="${esc(title)}"` : ""} style="display:inline-block;background:${bg};color:${fg};border-radius:10px;padding:1px 8px;font-size:12px;font-weight:600;line-height:1.5">${esc(text)}</span>`;
}

const _SEV_COLOR = { low: "#2e7d32", medium: "#b8860b", high: "#d9772e", critical: "#c0392b" };
const _STATUS_COLOR = {
  new: "#2f6fb0", triaging: "#b8860b", confirmed: "#c0392b", mitigated: "#2e7d32",
  closed: "#555", false_positive: "#555", duplicate: "#555",
};

function sevBadge(sev) { return _pill(sev, _SEV_COLOR[sev] || "#555", "#fff", "Severity"); }
function statusBadge(st) { return _pill(st, _STATUS_COLOR[st] || "#555", "#fff", "Status"); }

// ----- risk score (explainable) -----
const _RISK_COLOR = { low: "#2e7d32", medium: "#b8860b", high: "#d9772e", critical: "#c0392b" };

function _hasBreakdown(f) {
  return !!(f.detail && f.detail.risk_breakdown && f.detail.risk_breakdown.factors);
}

function riskBadgeMarkup(id, score, band) {
  const c = _RISK_COLOR[band] || "#555";
  return `<button id="riskbadge_${esc(id)}" data-action="expRisk" data-id="${esc(id)}" title="Risk score — click for breakdown"
      style="border:none;cursor:pointer;background:${c};color:#fff;border-radius:8px;padding:5px 12px;text-align:center;min-width:66px">
      <div style="font-size:22px;font-weight:800;line-height:1">${esc(score)}</div>
      <div style="font-size:10px;letter-spacing:.5px">${esc((band || "").toUpperCase())}</div></button>`;
}

function riskBadge(f) {
  if (_hasBreakdown(f)) {
    const bd = f.detail.risk_breakdown;
    return riskBadgeMarkup(f.id, bd.score != null ? bd.score : f.risk_score, bd.band || "");
  }
  // sem breakdown embutido (finding antigo): placeholder; hidratado via /risk
  return riskBadgeMarkup(f.id, "\u2026", "");
}

async function hydrateRisk(id) {
  try {
    const bd = await api("GET", `/exposure/findings/${id}/risk`);
    const badge = $("#riskbadge_" + id);
    if (badge) {
      badge.style.background = _RISK_COLOR[bd.band] || "#555";
      badge.innerHTML = `<div style="font-size:22px;font-weight:800;line-height:1">${esc(bd.score)}</div>`
        + `<div style="font-size:10px;letter-spacing:.5px">${esc((bd.band || "").toUpperCase())}</div>`;
    }
    const el = $("#riskbd_" + id);
    if (el) el.innerHTML = riskBreakdownHtml(bd);
  } catch (_) { /* silencioso */ }
}

function riskBreakdownHtml(bd) {
  if (!bd || !bd.factors) return '<span class="muted">No breakdown.</span>';
  const rows = bd.factors.map(x => `<div style="display:flex;justify-content:space-between;gap:12px;font-size:13px">
      <span><b>+${esc(x.points)}</b> ${esc(x.value || x.label)}${x.reason ? ` <span class="muted">(${esc(x.reason)})</span>` : ""}</span>
      <span class="muted" style="font-size:11px">${esc(x.label)}</span></div>`).join("");
  return `<div style="margin-top:8px;border-top:1px solid var(--line);padding-top:6px">
    <b>Risk breakdown</b><div style="margin-top:4px;display:flex;flex-direction:column;gap:2px">${rows}</div>
    <div style="border-top:1px solid var(--line);margin-top:6px;padding-top:4px;text-align:right;font-size:15px"><b>${esc(bd.score)}</b> <span class="muted" style="font-size:12px">${esc((bd.band || "").toUpperCase())}</span></div></div>`;
}

function toggleRiskBreakdown(id) {
  const el = $("#riskbd_" + id);
  if (el) el.style.display = el.style.display === "none" ? "block" : "none";
}

// ----- timeline -----
const _TL_ICON = { exposure: "\ud83d\udd11", case: "\ud83d\udcc1", brand: "\ud83d\udee1\ufe0f", integration: "\ud83d\udd0c", audit: "\u2022" };
let TL_SOURCE = "";

function renderTimeline(evs) {
  if (!evs || !evs.length) return '<span class="muted">No events.</span>';
  return `<div style="display:flex;flex-direction:column;gap:5px;margin-top:6px">` + evs.map(e => {
    const ts = e.ts || "";
    const when = ts.slice(0, 10) + " " + ts.slice(11, 16);
    const sev = e.severity ? " " + sevBadge(e.severity) : "";
    return `<div style="display:flex;gap:8px;align-items:baseline">
      <span class="muted" style="font-size:11px;min-width:104px">${esc(when)}</span>
      <span>${_TL_ICON[e.source] || "\u2022"}</span>
      <span style="font-size:13px">${esc(e.title)}</span>${sev}
      <span class="muted" style="font-size:11px">${esc(e.actor)}</span></div>`;
  }).join("") + `</div>`;
}

async function toggleFindingTimeline(id) {
  const box = $("#tl_" + id);
  if (!box) return;
  if (box.style.display === "block") { box.style.display = "none"; return; }
  box.style.display = "block";
  box.innerHTML = '<span class="muted">loading…</span>';
  try { box.innerHTML = renderTimeline(await api("GET", `/timeline?scope=finding:${id}`)); }
  catch (e) { box.innerHTML = `<span class="muted">${esc(e.message)}</span>`; }
}

async function loadTenantTimeline() {
  const box = $("#expBody");
  if (!box) return;
  let evs = [], srcs = [];
  try { evs = await api("GET", "/timeline?scope=tenant&limit=200"); }
  catch (e) { box.innerHTML = `<span class="muted">${esc(e.message)}</span>`; return; }
  try { srcs = await api("GET", "/timeline/sources"); } catch (_) { srcs = []; }
  const chips = [""].concat(srcs).map(sn =>
    `<button class="sm ${TL_SOURCE === sn ? "" : "ghost"}" data-action="tlFilter" data-name="${esc(sn)}">${sn ? esc(sn) : "all"}</button>`).join(" ");
  const filtered = TL_SOURCE ? evs.filter(e => e.source === TL_SOURCE) : evs;
  box.innerHTML = `<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px">${chips}</div>
    <div class="panel">${renderTimeline(filtered)}</div>`;
}

function tlSourceFilter(name) { TL_SOURCE = name; loadTenantTimeline(); }

function admiraltyBadge(f) {
  const relRank = "ABCDEF".indexOf(f.source_reliability) + 1 || 6;
  const credRank = Number(f.info_credibility) || 6;
  let bg = "#8a4b4b";  // weak (E/F, 5/6)
  if (relRank <= 2 && credRank <= 2) bg = "#2e7d32";        // strong
  else if (relRank <= 4 && credRank <= 4) bg = "#b8860b";   // medium
  return _pill(`${f.source_reliability}${f.info_credibility}`, bg, "#fff",
    "Admiralty Code — source reliability (A–F) / info credibility (1–6)");
}

// rótulos amigáveis + ícones para os campos do detail
const _FIELD_META = {
  email: ["\u2709\ufe0f", "Email"], domain: ["\ud83c\udf10", "Domain"],
  url: ["\ud83d\udd17", "URL"], url_defanged: ["\ud83d\udd17", "URL"],
  person_label: ["\ud83d\udc64", "Person"], platform: ["\ud83d\udccd", "Platform"],
  exposure_kind: ["\ud83c\udff7\ufe0f", "Kind"],
  password_masked: ["\ud83d\udd11", "Password (masked)"],
  password_sha256: ["#\ufe0f\u20e3", "Password hash"],
  secret_masked: ["\ud83d\udd11", "Secret (masked)"],
  fingerprint: ["#\ufe0f\u20e3", "Secret fingerprint"],
  stealer_family: ["\ud83e\udda0", "Stealer"], breach_name: ["\ud83d\udca5", "Breach"],
  line_source: ["\ud83d\udcc4", "Source line"], sightings: ["\ud83d\udc41\ufe0f", "Sightings"],
};
const _FIELD_ORDER = ["person_label", "email", "domain", "url", "url_defanged", "platform",
  "exposure_kind", "password_masked", "password_sha256", "secret_masked", "fingerprint",
  "stealer_family", "breach_name", "line_source", "sightings"];

function prettyDetail(detail) {
  const d = detail || {};
  const keys = Object.keys(d);
  const ordered = _FIELD_ORDER.filter(k => k in d).concat(keys.filter(k => !_FIELD_ORDER.includes(k)));
  if (!ordered.length) return '<span class="muted">no detail</span>';
  const items = ordered.map(k => {
    const meta = _FIELD_META[k] || ["\u2022", k];
    const mono = (k.includes("hash") || k.includes("sha") || k === "fingerprint")
      ? "font-family:monospace;font-size:11px" : "";
    return `<div style="display:flex;gap:6px;align-items:baseline;min-width:210px">
      <span>${meta[0]}</span>
      <span class="muted" style="font-size:12px">${esc(meta[1])}</span>
      <span style="${mono}">${esc(String(d[k]))}</span></div>`;
  }).join("");
  return `<div style="display:flex;flex-wrap:wrap;gap:6px 18px;margin-top:4px">${items}</div>`;
}

async function loadExposureFindings() {
  const box = $("#expBody");
  if (!box) return;
  const qs = [];
  if (EXPF.type) qs.push(`exposure_type=${encodeURIComponent(EXPF.type)}`);
  if (EXPF.status) qs.push(`status=${encodeURIComponent(EXPF.status)}`);
  let rows = [];
  try { rows = await api("GET", `/exposure/findings${qs.length ? "?" + qs.join("&") : ""}`); }
  catch (e) { box.innerHTML = `<span class="muted">${esc(e.message)}</span>`; return; }
  const typeOpts = ['<option value="">all types</option>']
    .concat(EXP_TYPES_UI.map(t => `<option value="${t[0]}" ${EXPF.type === t[0] ? "selected" : ""}>${esc(t[1])}</option>`)).join("");
  const statusOpts = ['<option value="">all status</option>']
    .concat(EXP_STATUS_UI.map(st => `<option value="${st}" ${EXPF.status === st ? "selected" : ""}>${esc(st)}</option>`)).join("");
  const filters = `<div style="display:flex;gap:8px;align-items:end;flex-wrap:wrap;margin-bottom:10px">
    <div><label>Type</label><select id="expf_type" style="min-width:150px">${typeOpts}</select></div>
    <div><label>Status</label><select id="expf_status" style="min-width:140px">${statusOpts}</select></div>
    <button class="sm" data-action="expApplyFilters">Apply</button>
  </div>`;
  const canTri = can("analyst");
  rows.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
  const cards = rows.length ? rows.map(f => {
    const triage = canTri && !["closed", "false_positive", "duplicate"].includes(f.status) ? `
      <div style="display:flex;gap:6px;align-items:end;flex-wrap:wrap;margin-top:8px">
        <div><label>Status</label>${selectHtml("tri_status_" + f.id, EXP_STATUS_UI, f.status, false)}</div>
        <div><label>Severity</label>${selectHtml("tri_sev_" + f.id, CRIT_UI, f.severity, false)}</div>
        <button class="sm" data-action="expTriage" data-id="${esc(f.id)}">Save</button>
        <button class="sm ghost" data-action="expOpenCase" data-id="${esc(f.id)}">Open case</button>
      </div>` : (canTri ? `<div style="margin-top:8px"><button class="sm ghost" data-action="expOpenCase" data-id="${esc(f.id)}">Open case</button></div>` : "");
    const bd = (f.detail && f.detail.risk_breakdown) || null;
    return `<div class="panel" style="margin-bottom:8px">
      <div style="display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap">
        <div style="flex:1;min-width:200px">
          <b>${esc(f.title)}</b>
          <div style="display:flex;gap:6px;align-items:center;margin-top:4px;flex-wrap:wrap">${admiraltyBadge(f)} ${sevBadge(f.severity)} ${statusBadge(f.status)} <span class="muted" style="font-size:12px">${esc(f.exposure_type)}</span></div>
        </div>
        ${riskBadge(f)}
      </div>
      <div id="riskbd_${esc(f.id)}" style="display:none">${riskBreakdownHtml(bd)}</div>
      <div style="margin-top:6px">${prettyDetail(f.detail)}</div>
      <div class="muted" style="font-size:11px;margin-top:4px">source: ${esc(f.source)} · ${esc((f.created_at || "").slice(0, 16).replace("T", " "))}${f.ingest_id ? " · ingest #" + esc(f.ingest_id) : ""}</div>
      <div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap">
        <button class="sm ghost" data-action="expTimeline" data-id="${esc(f.id)}">Timeline</button>
        <button class="sm ghost" data-action="expCorrelate" data-id="${esc(f.id)}">Correlate</button>
      </div>
      <div id="tl_${esc(f.id)}" style="display:none"></div>
      <div id="cor_${esc(f.id)}" style="display:none"></div>
      ${triage}
    </div>`;
  }).join("") : '<span class="muted">No exposure findings.</span>';
  box.innerHTML = filters + cards;
  rows.forEach(f => { if (!_hasBreakdown(f)) hydrateRisk(f.id); });
}

function applyExposureFilters() {
  const t = $("#expf_type"); const st = $("#expf_status");
  EXPF.type = t ? t.value : ""; EXPF.status = st ? st.value : "";
  loadExposureFindings();
}

async function triageExposure(id) {
  const st = $("#tri_status_" + id); const sv = $("#tri_sev_" + id);
  const body = {};
  if (st) body.status = st.value;
  if (sv) body.severity = sv.value;
  try { await api("PATCH", `/exposure/findings/${id}`, body); toast("Finding updated"); loadExposureFindings(); }
  catch (e) { toast(e.message, true); }
}

async function openCaseFromExposure(id) {
  try {
    const r = await api("POST", `/exposure/findings/${id}/case`);
    toast(`Case #${r.case_id} opened`);
    navigate("cases");
  } catch (e) { toast(e.message, true); }
}

async function loadExposureAssets() {
  const box = $("#expBody");
  if (!box) return;
  let rows = [];
  try { rows = await api("GET", "/exposure/assets"); }
  catch (e) { box.innerHTML = `<span class="muted">${esc(e.message)}</span>`; return; }
  const cards = rows.length ? rows.map(a => `<div class="panel" style="margin-bottom:8px">
      <div style="display:flex;justify-content:space-between;gap:8px;align-items:center;flex-wrap:wrap">
        <b>${esc(a.label)}</b>
        <span class="muted" style="font-size:12px">${esc(a.asset_type)} · ${esc(a.criticality)}${a.active ? "" : " · inactive"}</span>
      </div>
      <div style="margin-top:4px">${esc(a.value)} <span class="muted" style="font-size:11px">(hash ${esc((a.value_hash || "").slice(0, 12))}…)</span></div>
      ${a.consent_ref ? `<div class="muted" style="font-size:11px;margin-top:2px">consent: ${esc(a.consent_ref)}</div>` : ""}
    </div>`).join("") : '<span class="muted">No monitored assets yet.</span>';
  const form = can("admin") ? `<div class="panel" style="margin-bottom:12px">
      <b>Add monitored asset</b>
      <div class="srow2" style="margin-top:8px">
        <div><label>Type</label>${selectHtml("ma_type", ASSET_TYPES_UI, "identity", false)}</div>
        <div><label>Criticality</label>${selectHtml("ma_crit", CRIT_UI, "medium", false)}</div>
      </div>
      <label>Label</label><input id="ma_label" style="width:100%" placeholder="e.g. CEO – Jane Doe">
      <label>Value</label><input id="ma_value" style="width:100%" placeholder="email / domain / handle">
      <label>Consent reference (LGPD/GDPR, for identities)</label><input id="ma_consent" style="width:100%" placeholder="e.g. DPA-2026-001">
      <div style="margin-top:8px"><button data-action="expAssetAdd">Add asset</button></div>
      <div class="err" id="ma_err"></div>
    </div>` : "";
  box.innerHTML = form + cards;
}

async function addExposureAsset() {
  const errEl = $("#ma_err");
  if (errEl) errEl.textContent = "";
  const body = {
    asset_type: $("#ma_type").value, criticality: $("#ma_crit").value,
    label: $("#ma_label").value.trim(), value: $("#ma_value").value.trim(),
    consent_ref: ($("#ma_consent").value.trim() || null),
  };
  if (!body.label || !body.value) { if (errEl) errEl.textContent = "Label and value are required."; return; }
  try { await api("POST", "/exposure/assets", body); toast("Asset added"); loadExposureAssets(); }
  catch (e) { if (errEl) errEl.textContent = e.message; }
}

function importSummaryPanel() {
  const b = LAST_IMPORT;
  if (!b) return "";
  const stat = (n, label, color) => `<div style="text-align:center;min-width:74px">
    <div style="font-size:22px;font-weight:700;color:${color}">${esc(n)}</div>
    <div class="muted" style="font-size:11px">${esc(label)}</div></div>`;
  return `<div class="panel" style="margin-bottom:12px;border-left:3px solid var(--accent)">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
      <b>Last import — batch #${esc(b.id)} (${esc(b.parser)} v${esc(b.parser_version)})</b>
      <span class="muted" style="font-size:11px">sha256 ${esc((b.source_file_hash || "").slice(0, 16))}…</span>
    </div>
    <div style="display:flex;gap:18px;margin-top:8px;flex-wrap:wrap">
      ${stat(b.created_count, "created", "#2e7d32")}
      ${stat(b.deduped_count, "deduped", "#b8860b")}
      ${stat(b.error_count, "errors", b.error_count ? "#c0392b" : "#888")}
      ${stat(b.record_count, "records", "#888")}
    </div></div>`;
}

async function loadExposureImports() {
  const box = $("#expBody");
  if (!box) return;
  let rows = [];
  try { rows = await api("GET", "/exposure/ingests"); }
  catch (e) { box.innerHTML = `<span class="muted">${esc(e.message)}</span>`; return; }
  const isAdmin = can("admin");
  const th = (t) => `<th style="text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);font-size:12px;color:var(--muted)">${t}</th>`;
  const td = (v, extra) => `<td style="padding:6px 10px;border-bottom:1px solid var(--line);${extra || ""}">${v}</td>`;
  const statusChip = (st) => _pill(st, st === "rolled_back" ? "#8a4b4b" : "#2e7d32", "#fff");
  const body = rows.length ? rows.map(b => {
    const rb = (isAdmin && b.status !== "rolled_back")
      ? `<button class="sm ghost" data-action="expRollback" data-id="${esc(b.id)}">Rollback</button>`
      : (b.status === "rolled_back" ? '<span class="muted" style="font-size:11px">—</span>' : "");
    return `<tr>
      ${td("#" + esc(b.id))}
      ${td(esc(b.original_filename || b.source))}
      ${td(esc(b.parser) + " <span class='muted' style='font-size:11px'>v" + esc(b.parser_version) + "</span>")}
      ${td("<b style='color:#2e7d32'>" + esc(b.created_count) + "</b>")}
      ${td("<span style='color:#b8860b'>" + esc(b.deduped_count) + "</span>")}
      ${td((b.error_count ? "<span style='color:#c0392b'>" : "<span class='muted'>") + esc(b.error_count) + "</span>")}
      ${td(statusChip(b.status))}
      ${td("<span class='muted' style='font-size:11px'>" + esc((b.created_at || "").slice(0, 16).replace("T", " ")) + "</span>")}
      ${td(rb)}
    </tr>`;
  }).join("") : `<tr><td colspan="9" class="muted" style="padding:10px">No imports yet.</td></tr>`;
  const table = `<div class="panel" style="overflow-x:auto">
    <table style="width:100%;border-collapse:collapse">
      <thead><tr>${["#", "File", "Parser", "Created", "Deduped", "Errors", "Status", "Date", ""].map(th).join("")}</tr></thead>
      <tbody>${body}</tbody>
    </table></div>`;
  const parserOpts = PARSERS_UI.map(p2 => `<option value="${p2[0]}">${esc(p2[1])}</option>`).join("");
  const form = can("analyst") ? `<div class="panel" style="margin-bottom:12px">
      <b>Import file</b> <span class="muted" style="font-size:12px">authorized/manual intake only · secrets redacted server-side</span>
      <input type="file" id="imp_file" style="width:100%;margin-top:8px">
      <div style="margin-top:8px"><label>Parser</label><select id="imp_parser" style="min-width:220px">${parserOpts}</select></div>
      <div style="margin-top:8px"><button data-action="expImport">Import</button></div>
      <div class="err" id="imp_err"></div>
    </div>` : "";
  box.innerHTML = form + importSummaryPanel() + table;
}

async function importExposure() {
  const errEl = $("#imp_err");
  if (errEl) errEl.textContent = "";
  const fileEl = $("#imp_file");
  const f = fileEl && fileEl.files && fileEl.files[0];
  if (!f) { if (errEl) errEl.textContent = "Select a file."; return; }
  const fd = new FormData();
  fd.append("file", f);
  fd.append("parser", $("#imp_parser").value);
  try {
    const r = await api("POST", "/exposure/import", fd);
    LAST_IMPORT = r;
    toast(`Imported: ${r.created_count} created, ${r.deduped_count} deduped, ${r.error_count} errors`);
    loadExposureImports();
  } catch (e) { if (errEl) errEl.textContent = e.message; else toast(e.message, true); }
}

async function rollbackIngest(id) {
  if (!window.confirm(`Rollback import #${id}? This permanently deletes its findings.`)) return;
  try {
    const r = await api("DELETE", `/exposure/ingests/${id}`);
    toast(`Rolled back: ${r.removed} findings removed`);
    loadExposureImports();
  } catch (e) { toast(e.message, true); }
}

// ----- correlation engine -----
const _COR_META = {
  exposure_finding: ["\ud83d\udd11", "Exposure finding"],
  monitored_asset: ["\ud83c\udfaf", "Monitored asset"],
  observable: ["\ud83e\uddec", "IOC"],
  brand: ["\ud83d\udee1\ufe0f", "Brand"],
  brand_finding: ["\ud83c\udf10", "Brand finding"],
  case: ["\ud83d\udcc1", "Case"],
  identifier: ["\ud83d\udd17", "Identifier"],
};

function _corGroup(kind, nodes) {
  const meta = _COR_META[kind] || ["\u2022", kind];
  const items = nodes.map(n => {
    const via = (n._via ? ` <span class="muted" style="font-size:11px">via ${esc(n._via)}</span>` : "");
    const risk = (n.risk != null ? ` <span class="muted" style="font-size:11px">risk ${esc(n.risk)}</span>` : "");
    return `<div style="padding:3px 0;border-bottom:1px solid var(--line)">${esc(n.label)}${risk}${via}</div>`;
  }).join("");
  return `<div style="min-width:220px;flex:1">
    <div class="muted" style="font-size:12px;margin-bottom:4px">${meta[0]} ${esc(meta[1])} (${nodes.length})</div>${items}</div>`;
}

const COR_CACHE = {};
const COR_EXPAND = {};
const _COR_COLOR = {
  exposure_finding: "#c0392b", monitored_asset: "#2f6fb0", observable: "#2e7d32",
  brand: "#8e44ad", brand_finding: "#b8860b", case: "#16a085", identifier: "#888",
};
const _COR_CAP = 3;  // agrupa quando um tipo tem mais que isso

function _viaColor(via) {
  const p = String(via || "").split(":")[0];
  return { email: "#2f6fb0", domain: "#2e7d32", hash: "#8e44ad",
    "case-of-finding": "#d4a017", case: "#d4a017" }[p] || "#5a6b80";
}

async function toggleCorrelate(id) {
  const box = $("#cor_" + id);
  if (!box) return;
  if (box.style.display === "block") { box.style.display = "none"; return; }
  box.style.display = "block";
  box.innerHTML = '<span class="muted">correlating…</span>';
  let g;
  try { g = await api("GET", `/correlation?entity=finding:${id}`); }
  catch (e) { box.innerHTML = `<span class="muted">${esc(e.message)}</span>`; return; }
  COR_CACHE[id] = g; COR_EXPAND[id] = new Set();
  if ((g.nodes || []).length) renderCorGraph(id); else renderCorList(id);
}

function _corHeader(id, title, otherBtn) {
  return `<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
    <b>${esc(title)}</b>
    <span style="display:flex;gap:6px">${otherBtn}
      ${can("analyst") ? `<button class="sm" data-action="expOpenCase" data-id="${esc(id)}">Open investigation</button>` : ""}
    </span></div>`;
}

function renderCorList(id) {
  const box = $("#cor_" + id); const g = COR_CACHE[id];
  if (!box || !g) return;
  const viaOf = {}; (g.edges || []).forEach(e => { viaOf[e.target] = e.via; });
  const nodes = (g.nodes || []).map(n => ({ ...n, _via: viaOf[n.id] }));
  if (!nodes.length) { box.innerHTML = '<div class="panel" style="margin-top:6px"><span class="muted">No related entities found.</span></div>'; return; }
  const groups = {};
  nodes.forEach(n => { (groups[n.kind] = groups[n.kind] || []).push(n); });
  const order = ["monitored_asset", "brand", "brand_finding", "observable", "exposure_finding", "case", "identifier"];
  const cols = order.filter(k => groups[k]).map(k => _corGroup(k, groups[k])).join("");
  const idents = g.identifiers ? Object.entries(g.identifiers).map(([k, vs]) =>
    `<span class="muted" style="font-size:11px;margin-right:8px"><b>${esc(k)}</b>: ${esc(vs.join(", "))}</span>`).join("") : "";
  box.innerHTML = `<div class="panel" style="margin-top:6px;border-left:3px solid var(--accent)">
    ${_corHeader(id, `Correlated entities (${nodes.length})`, `<button class="sm ghost" data-action="corGraph" data-id="${esc(id)}">Graph view</button>`)}
    <div style="margin-top:4px">${idents}</div>
    <div style="display:flex;gap:18px;flex-wrap:wrap;margin-top:8px">${cols}</div>
  </div>`;
}

function _corLegend(kinds) {
  return `<div style="display:flex;gap:12px;flex-wrap:wrap;margin:6px 0">` + kinds.map(k => {
    const meta = _COR_META[k] || ["\u2022", k];
    return `<span class="muted" style="font-size:11px;display:inline-flex;align-items:center;gap:4px">
      <span style="width:10px;height:10px;border-radius:50%;background:${_COR_COLOR[k] || "#555"};display:inline-block"></span>${esc(meta[1])}</span>`;
  }).join("") + `</div>`;
}

function renderCorGraph(id) {
  const box = $("#cor_" + id); const g = COR_CACHE[id];
  if (!box || !g) return;
  const nodes = g.nodes || [];
  if (!nodes.length) return renderCorList(id);
  const viaOf = {}; (g.edges || []).forEach(e => { viaOf[e.target] = e.via; });
  const meta = (k) => _COR_META[k] || ["\u2022", k];
  const trunc = (t, n) => { t = String(t || ""); return t.length > n ? esc(t.slice(0, n - 1)) + "\u2026" : esc(t); };
  const expanded = COR_EXPAND[id] || new Set();

  // agrupa por tipo; tipos volumosos viram um nó agregado "+N"
  const byKind = {};
  nodes.forEach(n => { (byKind[n.kind] = byKind[n.kind] || []).push(n); });
  const kindsPresent = Object.keys(byKind);
  const items = [];
  kindsPresent.forEach(k => {
    const arr = byKind[k];
    if (arr.length > _COR_CAP && !expanded.has(k)) {
      items.push({ agg: true, kind: k, count: arr.length, via: viaOf[arr[0].id] });
    } else {
      arr.forEach(n => items.push({ agg: false, node: n, via: viaOf[n.id] }));
    }
  });

  const W = 760, H = 540, cx = W / 2, cy = H / 2;
  const R = Math.min(230, Math.max(175, 130 + items.length * 8));
  let edges = "", gnodes = "";
  items.forEach((it, i) => {
    const ang = (i / items.length) * 2 * Math.PI - Math.PI / 2;
    const x = cx + R * Math.cos(ang), y = cy + R * Math.sin(ang);
    const via = it.via || "";
    const mx = cx + (x - cx) * 0.55, my = cy + (y - cy) * 0.55;
    edges += `<line x1="${cx}" y1="${cy}" x2="${x.toFixed(0)}" y2="${y.toFixed(0)}" stroke="${_viaColor(via)}" stroke-width="2"/>`;
    if (via) edges += `<text x="${mx.toFixed(0)}" y="${my.toFixed(0)}" font-size="10" fill="${_viaColor(via)}" text-anchor="middle">${esc(via)}</text>`;
    if (it.agg) {
      gnodes += `<g data-agg="1" data-kind="${esc(it.kind)}" style="cursor:pointer">
        <title>Click to expand ${esc(it.count)} ${esc(meta(it.kind)[1])}</title>
        <circle cx="${x.toFixed(0)}" cy="${y.toFixed(0)}" r="30" fill="${_COR_COLOR[it.kind] || "#555"}" stroke="#fff" stroke-width="1.5" stroke-dasharray="4 3"/>
        <text x="${x.toFixed(0)}" y="${(y + 6).toFixed(0)}" font-size="17" text-anchor="middle" fill="#fff" font-weight="700">+${esc(it.count)}</text>
        <text x="${x.toFixed(0)}" y="${(y + 48).toFixed(0)}" font-size="11" text-anchor="middle" fill="currentColor">${esc(meta(it.kind)[1])}s</text>
      </g>`;
    } else {
      const n = it.node;
      const risk = (n.risk != null ? ` \u00b7 risk ${n.risk}` : "");
      gnodes += `<g data-node="1" data-kind="${esc(n.kind)}" data-refid="${esc(n.ref && n.ref.id)}" style="cursor:pointer">
        <title>${esc(meta(n.kind)[1])}: ${esc(n.label)}${via ? " \u00b7 via " + esc(via) : ""}${esc(risk)}</title>
        <circle cx="${x.toFixed(0)}" cy="${y.toFixed(0)}" r="30" fill="${_COR_COLOR[n.kind] || "#555"}"/>
        <text x="${x.toFixed(0)}" y="${(y + 6).toFixed(0)}" font-size="18" text-anchor="middle">${meta(n.kind)[0]}</text>
        <text x="${x.toFixed(0)}" y="${(y + 48).toFixed(0)}" font-size="11" text-anchor="middle" fill="currentColor">${trunc(n.label, 24)}</text>
      </g>`;
    }
  });
  const seed = `<g><title>${esc(g.seed.label)}</title>
    <circle cx="${cx}" cy="${cy}" r="38" fill="#c0392b" stroke="#fff" stroke-width="2"/>
    <text x="${cx}" y="${cy + 6}" font-size="20" text-anchor="middle">\ud83d\udd11</text>
    <text x="${cx}" y="${cy + 58}" font-size="12" text-anchor="middle" fill="currentColor" font-weight="700">${trunc(g.seed.label, 28)}</text></g>`;
  const svg = `<svg viewBox="0 0 ${W} ${H}" width="100%" style="max-width:${W}px;color:var(--txt)">${edges}${seed}${gnodes}</svg>`;
  box.innerHTML = `<div class="panel" style="margin-top:6px;border-left:3px solid var(--accent)">
    ${_corHeader(id, `Correlation graph (${nodes.length})`, `<button class="sm ghost" data-action="corList" data-id="${esc(id)}">List view</button>`)}
    ${_corLegend(kindsPresent)}
    <div style="overflow-x:auto">${svg}</div>
    <div class="muted" style="font-size:11px">Hover a node for details \u00b7 click to open the module \u00b7 click "+N" to expand.</div>
  </div>`;
  const svgEl = box.querySelector("svg");
  if (svgEl) svgEl.addEventListener("click", (e) => {
    const ag = e.target.closest("[data-agg]");
    if (ag) { (COR_EXPAND[id] = COR_EXPAND[id] || new Set()).add(ag.dataset.kind); renderCorGraph(id); return; }
    const gg = e.target.closest("[data-node]");
    if (gg) corNodeClick(gg.dataset.kind, gg.dataset.refid);
  });
}

function corNodeClick(kind, refid) {
  if (kind === "observable") navigate("iocs");
  else if (kind === "brand" || kind === "brand_finding") navigate("brands");
  else if (kind === "case") navigate("cases");
  else if (kind === "monitored_asset") { EXPOSURE_TAB = "assets"; navigate("exposure"); }
  else if (kind === "exposure_finding") { EXPOSURE_TAB = "findings"; navigate("exposure"); }
  else toast(`${kind}: ${refid}`);
}

// ---------- credential intelligence ----------
function _credBand(score) { score = score || 0; return score >= 90 ? "critical" : score >= 70 ? "high" : score >= 40 ? "medium" : "low"; }

async function viewCredentials() {
  const m = $("#main");
  m.innerHTML = `<h2 class="title">Credential Intelligence</h2>
    <p class="muted" style="margin-top:-6px">Identity dossiers from credential leaks. Passwords are never stored — only hashes/masks.</p>
    <div id="credList">loading…</div><div id="credDetail"></div>`;
  let rows = [];
  try { rows = await api("GET", "/credentials/identities"); }
  catch (e) { $("#credList").textContent = e.message; return; }
  if (!rows.length) { $("#credList").innerHTML = '<span class="muted">No credential identities yet.</span>'; return; }
  const th = (t) => `<th style="text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);font-size:12px;color:var(--muted)">${t}</th>`;
  const td = (v) => `<td style="padding:6px 10px;border-bottom:1px solid var(--line)">${v}</td>`;
  const body = rows.map(r => {
    const band = _credBand(r.max_risk);
    const vip = r.vip_asset_id ? _pill("VIP", "#c0392b", "#fff", "VIP identity") : "";
    const reuse = (r.reuse_count > 0) ? _pill("reuse " + r.reuse_count, "#8e44ad", "#fff", "Password reuse") : "";
    const risk = _pill(String(r.max_risk || 0), _RISK_COLOR[band], "#fff", "Max risk");
    return `<tr>
      ${td("<b>" + esc(r.email) + "</b>")}
      ${td('<span class="muted" style="font-size:12px">' + esc(r.domain || "") + "</span>")}
      ${td(risk + " " + vip + " " + reuse)}
      ${td('<span class="muted" style="font-size:12px">leaks ' + esc(r.leak_count) + " · uniq " + esc(r.unique_passwords) + "</span>")}
      ${td('<button class="sm ghost" data-action="credDossier" data-hash="' + esc(r.identity_hash) + '">Dossier</button>')}
    </tr>`;
  }).join("");
  $("#credList").innerHTML = `<div class="panel" style="overflow-x:auto"><table style="width:100%;border-collapse:collapse">
    <thead><tr>${["Email", "Domain", "Risk / flags", "Leaks", ""].map(th).join("")}</tr></thead>
    <tbody>${body}</tbody></table></div>`;
}

function _credReuseGraph(ident, related) {
  const W = 320, H = Math.max(190, 90 + related.length * 26), cx = W / 2, cy = H / 2;
  const R = Math.min(125, 55 + related.length * 12);
  let edges = "", nodes = "";
  related.forEach((r, i) => {
    const ang = (i / related.length) * 2 * Math.PI - Math.PI / 2;
    const x = cx + R * Math.cos(ang), y = cy + R * Math.sin(ang);
    edges += `<line x1="${cx}" y1="${cy}" x2="${x.toFixed(0)}" y2="${y.toFixed(0)}" stroke="#8e44ad" stroke-width="1.6"/>`;
    const lbl = (r.email || "").split("@")[0];
    nodes += `<g data-hash="${esc(r.identity_hash)}" style="cursor:pointer"><title>${esc(r.email)}</title>
      <circle cx="${x.toFixed(0)}" cy="${y.toFixed(0)}" r="16" fill="#2f6fb0"></circle>
      <text x="${x.toFixed(0)}" y="${(y + 30).toFixed(0)}" font-size="10" text-anchor="middle" fill="currentColor">${esc(lbl.slice(0, 12))}</text></g>`;
  });
  const seed = `<g><title>${esc(ident.email)}</title>
    <circle cx="${cx}" cy="${cy}" r="20" fill="#c0392b" stroke="#fff" stroke-width="2"></circle>
    <text x="${cx}" y="${cy + 5}" font-size="13" text-anchor="middle">🔑</text></g>`;
  return `<svg data-credgraph="1" viewBox="0 0 ${W} ${H}" width="100%" style="max-width:${W}px;color:var(--txt);margin-top:6px">${edges}${seed}${nodes}</svg>`;
}

async function credDossier(hash) {
  const box = $("#credDetail");
  if (!box) return;
  box.innerHTML = '<div class="panel" style="margin-top:12px"><span class="muted">loading dossier…</span></div>';
  let ident, findings, related, tl;
  try {
    [ident, findings, related, tl] = await Promise.all([
      api("GET", `/credentials/identities/${hash}`),
      api("GET", `/credentials/identities/${hash}/findings`).catch(() => []),
      api("GET", `/credentials/identities/${hash}/related`).catch(() => []),
      api("GET", `/timeline?scope=identity:${hash}`).catch(() => []),
    ]);
  } catch (e) { box.innerHTML = `<div class="panel" style="margin-top:12px"><span class="muted">${esc(e.message)}</span></div>`; return; }
  const band = _credBand(ident.max_risk);
  const vip = ident.vip_asset_id ? _pill("VIP", "#c0392b", "#fff") : "";
  const reuse = (ident.reuse_count > 0) ? _pill("reuse " + ident.reuse_count + " (+" + ident.reuse_risk + ")", "#8e44ad", "#fff") : "";
  const risk = _pill("risk " + (ident.max_risk || 0), _RISK_COLOR[band], "#fff");
  const fHtml = findings.length ? findings.map(f => {
    const det = Object.entries(f.detail || {}).filter(([k]) => k !== "risk_breakdown")
      .map(([k, v]) => `<span class="muted" style="font-size:12px;margin-right:10px"><b>${esc(k)}</b>: ${esc(String(v))}</span>`).join("");
    return `<div style="padding:5px 0;border-bottom:1px solid var(--line)">
      <span class="muted" style="font-size:11px">${esc((f.created_at || "").slice(0, 16).replace("T", " "))} · ${esc(f.source)} · risk ${esc(f.risk_score)}</span>
      <div style="margin-top:2px">${det}</div></div>`;
  }).join("") : '<span class="muted">No leaks.</span>';
  const rHtml = related.length ? related.map(r =>
    `<div style="display:flex;justify-content:space-between;gap:10px;padding:4px 0;border-bottom:1px solid var(--line)">
      <span>${esc(r.email)}</span>
      <button class="sm ghost" data-action="credDossier" data-hash="${esc(r.identity_hash)}">open</button></div>`).join("")
    : '<span class="muted">No related identities.</span>';
  box.innerHTML = `<div class="panel" style="margin-top:12px;border-left:3px solid var(--accent)">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
      <div><b>${esc(ident.email)}</b> <span class="muted" style="font-size:12px">${esc(ident.domain || "")}</span></div>
      <span style="display:flex;gap:6px;align-items:center">${risk} ${vip} ${reuse}
        ${can("analyst") ? `<button class="sm" data-action="credCase" data-hash="${esc(hash)}">Open investigation</button>` : ""}</span>
    </div>
    <div class="muted" style="font-size:12px;margin-top:6px">leaks ${esc(ident.leak_count)} · unique passwords ${esc(ident.unique_passwords)} · sources: ${esc((ident.sources || []).join(", ") || "—")}${(ident.stealer_families || []).length ? " · stealers: " + esc(ident.stealer_families.join(", ")) : ""}</div>
    <div style="display:flex;gap:16px;flex-wrap:wrap;margin-top:10px">
      <div style="flex:1;min-width:280px"><b>Leaks (${findings.length})</b><div style="margin-top:6px">${fHtml}</div></div>
      <div style="flex:1;min-width:240px"><b>Related by password reuse (${related.length})</b><div style="margin-top:6px">${rHtml}</div>
        ${related.length ? `<div style="margin-top:8px"><b>Reuse graph</b>${_credReuseGraph(ident, related)}</div>` : ""}</div>
    </div>
    <div style="margin-top:12px"><b>Timeline</b>${renderTimeline(tl)}</div>
  </div>`;
  const svg = box.querySelector("svg[data-credgraph]");
  if (svg) svg.addEventListener("click", (e) => {
    const g = e.target.closest("[data-hash]");
    if (g) credDossier(g.dataset.hash);
  });
}

async function credCase(hash) {
  try {
    const r = await api("POST", `/credentials/identities/${hash}/case`);
    toast(`Case #${r.case_id} opened`);
    navigate("cases");
  } catch (e) { toast(e.message, true); }
}

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
