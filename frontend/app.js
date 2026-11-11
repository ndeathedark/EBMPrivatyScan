'use strict';
/* EBMPrivatyScan: lógica de la interfaz. Sin manejadores en línea ni innerHTML con
   datos externos: todo el contenido dinámico se inserta con textContent (evita XSS). */

const API = '/api/v1';
const STATUS_LABELS = {
  CUMPLE: 'Sin brechas observadas', BRECHA: 'Posible brecha', ALERTA: 'Revisar',
  NO_CONCLUYENTE: 'No concluyente', NO_APLICA: 'No aplica', INFORMATIVO: 'Informativo',
};
const state = { user: null, audit: null, tokens: new Map(), authMode: 'login' };
const $ = (id) => document.getElementById(id);

// ------------------------------------------------------------------ API
async function api(path, { method = 'GET', body, token, raw = false } = {}) {
  const headers = {};
  if (method !== 'GET') headers['X-Requested-With'] = 'EBMPrivatyScan';   // protección CSRF
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers['X-Audit-Token'] = token;
  let response;
  try {
    response = await fetch(API + path, {
      method, headers, credentials: 'same-origin', cache: 'no-store',
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (err) {
    throw new Error('No se pudo conectar con el servidor. Revisa tu conexión e inténtalo de nuevo.');
  }
  if (!response.ok) {
    let message = `La solicitud no se completó (HTTP ${response.status}).`;
    try {
      const data = await response.json();
      if (typeof data.detail === 'string') message = data.detail;
    } catch (_) { /* respuesta sin JSON */ }
    if (response.status === 429) message += ' (límite de uso alcanzado)';
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return raw ? response : response.json();
}

function show(el, visible = true) { el.hidden = !visible; }
function message(el, text, kind = '') {
  el.textContent = text;
  el.className = 'notice' + (kind ? ` notice-${kind}` : '');
  show(el, Boolean(text));
}
function formatDate(value) {
  try {
    return new Date(value).toLocaleString('es-CL', { timeZone: 'America/Santiago', dateStyle: 'medium', timeStyle: 'short' });
  } catch (_) { return String(value); }
}
function riskColor(risk) {
  if (risk > 50) return 'var(--gap)';
  if (risk > 20) return 'var(--warn)';
  return 'var(--ok)';
}

// ------------------------------------------------------------------ Vistas
function setView(view) {
  show($('viewEvaluator'), view === 'evaluator');
  show($('viewHistory'), view === 'history');
  document.querySelectorAll('.nav-link').forEach((b) => {
    if (b.dataset.view === view) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
  });
  if (view === 'history') void loadHistory();
}

function renderSession() {
  const logged = Boolean(state.user);
  show($('btnLogin'), !logged);
  show($('btnLogout'), logged);
  show($('navHistory'), logged);
  show($('whoami'), logged);
  show($('scopeWrap'), logged && state.user.role === 'admin');
  $('whoami').textContent = logged ? state.user.email : '';
  if (!logged && !$('viewHistory').hidden) setView('evaluator');
}

async function refreshSession() {
  try {
    const data = await api('/auth/me');
    state.user = data.authenticated ? data.user : null;
  } catch (err) {
    // Sin sesión válida o API no disponible: la interfaz sigue funcionando en modo invitado.
    console.info('Sesión no disponible:', err.message);
    state.user = null;
  }
  renderSession();
}

// ------------------------------------------------------------------ Auditoría
function normaliseUrl(value) {
  const trimmed = value.trim();
  if (!trimmed) return '';
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

async function runAudit(event) {
  event.preventDefault();
  const errorBox = $('formError');
  message(errorBox, '');
  const url = normaliseUrl($('urlInput').value);
  if (!url) { message(errorBox, 'Escribe la dirección del sitio, por ejemplo https://tudominio.cl', 'error'); $('urlInput').focus(); return; }
  if (!$('authorized').checked) { message(errorBox, 'Marca la declaración de autorización para continuar.', 'error'); $('authorized').focus(); return; }

  $('btnAudit').disabled = true;
  show($('loading'));
  show($('results'), false);
  try {
    const data = await api('/audit/quick', { method: 'POST', body: { url, authorized: true } });
    if (data.access_token) state.tokens.set(data.id, data.access_token);
    renderResult(data);
  } catch (err) {
    message(errorBox, 'No se pudo completar el análisis: ' + err.message, 'error');
  } finally {
    show($('loading'), false);
    $('btnAudit').disabled = false;
  }
}

function formatEvidenceValue(value) {
  if (typeof value === 'boolean') return value ? 'sí' : 'no';
  if (Array.isArray(value)) return value.join(', ');
  return String(value);
}

function isEmptyEvidence(value) {
  return value === null || value === '' || (Array.isArray(value) && value.length === 0);
}

function buildEvidenceList(evidence) {
  const dl = document.createElement('dl');
  dl.className = 'evidence';
  for (const [key, value] of Object.entries(evidence || {})) {
    if (isEmptyEvidence(value)) continue;
    const dt = document.createElement('dt');
    dt.textContent = key.replaceAll('_', ' ');
    const dd = document.createElement('dd');
    dd.textContent = formatEvidenceValue(value);
    dl.append(dt, dd);
  }
  return dl;
}

function buildFinding(f) {
  const li = document.createElement('li');
  li.className = `finding st-${f.status}`;

  const top = document.createElement('div');
  top.className = 'finding-top';
  const h3 = document.createElement('h3');
  h3.textContent = f.category;
  const badge = document.createElement('span');
  badge.className = 'status';
  badge.textContent = STATUS_LABELS[f.status] || f.status;
  top.append(h3, badge);

  const p = document.createElement('p');
  p.textContent = f.explanation;

  const details = document.createElement('details');
  const summary = document.createElement('summary');
  summary.textContent = 'Ver evidencia y limitaciones';
  details.append(summary, buildEvidenceList(f.evidence));
  if (f.limitation) {
    const lim = document.createElement('p');
    lim.className = 'limitation';
    lim.textContent = 'Limitación: ' + f.limitation;
    details.append(lim);
  }
  li.append(top, p, details);
  return li;
}

function renderGauge(risk) {
  $('resRisk').textContent = String(risk);
  $('gauge').style.setProperty('--risk-color', riskColor(risk));
  $('scaleMarker').style.left = '0%';
  requestAnimationFrame(() => { $('scaleMarker').style.left = `${Math.min(100, Math.max(0, risk))}%`; });
}

function resultTitle(data) {
  if (data.final_url && data.final_url !== data.url) return `${data.url} → ${data.final_url}`;
  return data.url;
}

function renderResult(data) {
  state.audit = data;
  $('resTitle').textContent = resultTitle(data);
  $('resMeta').textContent = `Analizado el ${formatDate(data.created_at)}. Disponible hasta el ${formatDate(data.expires_at)}.`;
  renderGauge(Number(data.risk_percentage) || 0);
  show($('guestNotice'), !data.owned);
  $('findingsList').replaceChildren(...(data.findings || []).map(buildFinding));

  show($('emailForm'), false);
  $('btnShowEmail').setAttribute('aria-expanded', 'false');
  message($('actionMsg'), '');
  show($('results'));
  $('resTitle').focus({ preventScroll: true });
  const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
  $('results').scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
}

async function downloadPdf(auditId) {
  const response = await api(`/audit/${encodeURIComponent(auditId)}/pdf`, { raw: true, token: state.tokens.get(auditId) });
  const blob = await response.blob();
  if (blob.type !== 'application/pdf') throw new Error('El servidor no devolvió un PDF.');
  const href = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = href;
  link.download = `informe_ley21719_${auditId}.pdf`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(href), 10_000);
}

async function onPdf() {
  const btn = $('btnPdf');
  btn.disabled = true;
  try { await downloadPdf(state.audit.id); message($('actionMsg'), 'Informe descargado.', 'ok'); }
  catch (err) { message($('actionMsg'), 'No se pudo descargar el PDF: ' + err.message, 'error'); }
  finally { btn.disabled = false; }
}

async function onSendEmail(event) {
  event.preventDefault();
  const email = $('emailInput').value.trim();
  if (!$('emailInput').checkValidity() || !email) { message($('actionMsg'), 'Escribe un correo válido.', 'error'); return; }
  const btn = $('btnSendEmail');
  btn.disabled = true;
  message($('actionMsg'), 'Enviando…');
  try {
    // La confirmación solo se muestra si el servidor responde con éxito (RF13).
    const data = await api(`/audit/${state.audit.id}/email`, { method: 'POST', body: { email }, token: state.tokens.get(state.audit.id) });
    message($('actionMsg'), data.message, 'ok');
    $('emailInput').value = '';
  } catch (err) {
    message($('actionMsg'), 'El informe no se envió: ' + err.message, 'error');
  } finally { btn.disabled = false; }
}

async function deleteAudit(auditId) {
  if (!confirm('¿Eliminar este análisis de forma permanente?')) return false;
  await api(`/audit/${encodeURIComponent(auditId)}`, { method: 'DELETE', token: state.tokens.get(auditId) });
  state.tokens.delete(auditId);
  return true;
}

async function onDeleteCurrent() {
  try {
    if (await deleteAudit(state.audit.id)) {
      show($('results'), false);
      state.audit = null;
      message($('formError'), 'El análisis fue eliminado.', 'ok');
    }
  } catch (err) { message($('actionMsg'), 'No se pudo eliminar: ' + err.message, 'error'); }
}

// ------------------------------------------------------------------ Historial
function historyMessageRow(text, isError = false) {
  const tr = document.createElement('tr');
  const td = document.createElement('td');
  td.colSpan = 4;
  td.className = 'help';
  if (isError) td.style.color = 'var(--gap)';
  td.textContent = text;
  tr.append(td);
  return tr;
}

async function loadHistory() {
  const body = $('historyBody');
  body.replaceChildren(historyMessageRow('Cargando…'));
  const scope = $('scopeAll').checked ? 'all' : 'mine';
  try {
    const data = await api(`/history?limit=50&scope=${scope}`);
    body.replaceChildren();
    if (!data.items.length) { body.append(historyMessageRow('Aún no tienes análisis. Ve a “Analizar” para crear el primero.')); return; }
    for (const item of data.items) {
      const tr = document.createElement('tr');
      const urlTd = document.createElement('td'); urlTd.className = 'url-cell'; urlTd.textContent = item.url;
      const riskTd = document.createElement('td');
      const pill = document.createElement('span'); pill.className = 'risk-pill'; pill.style.color = riskColor(item.risk_percentage);
      pill.textContent = `${item.risk_percentage}%`; riskTd.append(pill);
      const dateTd = document.createElement('td'); dateTd.textContent = formatDate(item.created_at);
      const actTd = document.createElement('td'); actTd.className = 'actions-cell';
      const actions = document.createElement('div'); actions.className = 'row-actions';
      const viewBtn = document.createElement('button'); viewBtn.type = 'button'; viewBtn.className = 'btn'; viewBtn.textContent = 'Ver';
      viewBtn.addEventListener('click', async () => {
        try { const detail = await api(`/audit/${item.id}`); setView('evaluator'); renderResult(detail); }
        catch (err) { alert(err.message); }
      });
      const pdfBtn = document.createElement('button'); pdfBtn.type = 'button'; pdfBtn.className = 'btn'; pdfBtn.textContent = 'PDF';
      pdfBtn.addEventListener('click', () => downloadPdf(item.id).catch((err) => alert(err.message)));
      const delBtn = document.createElement('button'); delBtn.type = 'button'; delBtn.className = 'btn btn-danger-quiet'; delBtn.textContent = 'Eliminar';
      delBtn.addEventListener('click', async () => {
        try { if (await deleteAudit(item.id)) await loadHistory(); } catch (err) { alert(err.message); }
      });
      actions.append(viewBtn, pdfBtn, delBtn);
      actTd.append(actions);
      tr.append(urlTd, riskTd, dateTd, actTd);
      body.append(tr);
    }
  } catch (err) {
    body.replaceChildren(historyMessageRow('No se pudo cargar el historial: ' + err.message, true));
  }
}

async function onDeleteAccount(event) {
  event.preventDefault();
  const password = $('deletePassword').value;
  if (!password) return;
  if (!confirm('Esta acción elimina tu cuenta y todos tus análisis. ¿Continuar?')) return;
  try {
    await api('/auth/me', { method: 'DELETE', body: { password } });
    state.user = null;
    renderSession();
    setView('evaluator');
    message($('formError'), 'Tu cuenta y tus análisis fueron eliminados.', 'ok');
  } catch (err) { alert('No se pudo eliminar la cuenta: ' + err.message); }
}

// ------------------------------------------------------------------ Acceso
function setAuthMode(mode) {
  state.authMode = mode;
  const register = mode === 'register';
  $('authTitle').textContent = register ? 'Crear cuenta' : 'Ingresar';
  $('authSubmit').textContent = register ? 'Crear cuenta' : 'Ingresar';
  $('authSwitch').textContent = register ? 'Ya tengo cuenta' : 'Crear una cuenta';
  $('authPassword').autocomplete = register ? 'new-password' : 'current-password';
  show($('pwHelp'), register);
  show($('privacyWrap'), register);
  message($('authError'), '');
}

function openAuth() {
  setAuthMode('login');
  $('authForm').reset();
  $('authDialog').showModal();
  $('authEmail').focus();
}

async function onAuthSubmit(event) {
  event.preventDefault();
  const email = $('authEmail').value.trim();
  const password = $('authPassword').value;
  if (!email || !password) { message($('authError'), 'Completa el correo y la contraseña.', 'error'); return; }
  const register = state.authMode === 'register';
  if (register && !$('acceptPrivacy').checked) { message($('authError'), 'Debes aceptar la política de privacidad.', 'error'); return; }
  $('authSubmit').disabled = true;
  try {
    const path = register ? '/auth/register' : '/auth/login';
    const body = register ? { email, password, accept_privacy: true } : { email, password };
    state.user = await api(path, { method: 'POST', body });
    $('authDialog').close();
    renderSession();
  } catch (err) {
    message($('authError'), err.message, 'error');
  } finally {
    $('authSubmit').disabled = false;
    $('authPassword').value = '';
  }
}

async function onLogout() {
  try { await api('/auth/logout', { method: 'POST' }); } catch (_) { /* se limpia igual */ }
  state.user = null;
  renderSession();
}

// ------------------------------------------------------------------ Inicio
document.addEventListener('DOMContentLoaded', () => {
  $('auditForm').addEventListener('submit', runAudit);
  $('btnPdf').addEventListener('click', onPdf);
  $('btnShowEmail').addEventListener('click', () => {
    const open = $('emailForm').hidden;
    show($('emailForm'), open);
    $('btnShowEmail').setAttribute('aria-expanded', String(open));
    if (open) $('emailInput').focus();
  });
  $('emailForm').addEventListener('submit', onSendEmail);
  $('btnDeleteAudit').addEventListener('click', onDeleteCurrent);
  document.querySelectorAll('.nav-link').forEach((b) => b.addEventListener('click', () => setView(b.dataset.view)));
  $('btnRefresh').addEventListener('click', loadHistory);
  $('scopeAll').addEventListener('change', loadHistory);
  $('deleteAccountForm').addEventListener('submit', onDeleteAccount);
  $('btnLogin').addEventListener('click', openAuth);
  $('btnLogout').addEventListener('click', onLogout);
  $('authSwitch').addEventListener('click', () => setAuthMode(state.authMode === 'login' ? 'register' : 'login'));
  $('authCancel').addEventListener('click', () => $('authDialog').close());
  $('authForm').addEventListener('submit', onAuthSubmit);
  void refreshSession();
});
