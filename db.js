'use strict';
/* Portier de la base de données : le navigateur n'a plus aucun accès direct.
   Chaque requête est contrôlée selon l'identité (visiteur / membre / administrateur). */
const C = (function () {
  const module = { exports: {} };
/* Outils communs : sessions signées, mots de passe, accès base de données, e-mails.
   Aucune dépendance externe. Tous les secrets viennent des variables d'environnement Netlify. */
const crypto = require('crypto');

const ADMIN_EMAIL = () => String(process.env.ADMIN_EMAIL || 'wilfridengassa@gmail.com').trim().toLowerCase();
const SUPA_URL = () => String(process.env.SUPABASE_URL || 'https://vsvqcuympzywprintwdc.supabase.co').replace(/\/+$/, '');
const SITE_URL = () => String(process.env.SITE_URL || 'https://arrivercanada.com').replace(/\/+$/, '');
const PBKDF2_ITER = 600000;
const SESSION_TTL = 30 * 24 * 3600;

/* ── réponses HTTP ── */
function json(status, obj, headers) {
  return {
    statusCode: status,
    headers: Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }, headers || {}),
    body: JSON.stringify(obj)
  };
}
function rawBody(event) {
  let b = event.body || '';
  if (event.isBase64Encoded) b = Buffer.from(b, 'base64').toString('utf8');
  return b;
}
function parseJSON(event) {
  try { const o = JSON.parse(rawBody(event) || '{}'); return (o && typeof o === 'object' && !Array.isArray(o)) ? o : null; } catch (e) { return null; }
}
function header(event, name) {
  const h = event.headers || {}; const n = name.toLowerCase();
  for (const k of Object.keys(h)) if (k.toLowerCase() === n) return h[k];
  return undefined;
}
function clientIp(event) {
  return String(header(event, 'x-nf-client-connection-ip') || header(event, 'x-forwarded-for') || 'inconnu').split(',')[0].trim();
}
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const isEmail = e => typeof e === 'string' && e.length <= 120 && /^[^\s@<>"']+@[^\s@<>"']+\.[^\s@<>"']{2,}$/.test(e);

/* ── limitation des tentatives (par instance : meilleur effort) ── */
const _hits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now();
  const arr = (_hits.get(key) || []).filter(t => now - t < windowMs);
  arr.push(now); _hits.set(key, arr);
  if (_hits.size > 5000) for (const [k, v] of _hits) if (!v.length || now - v[v.length - 1] > windowMs) _hits.delete(k);
  return arr.length > max;
}
function _resetLimits() { _hits.clear(); }

/* ── sessions : jeton signé HS256 ── */
const sessionSecret = () => { const s = process.env.SESSION_SECRET; return (s && s.length >= 32) ? s : null; };
function signToken(payload, ttlSec) {
  const secret = sessionSecret(); if (!secret) throw Object.assign(new Error('SESSION_SECRET manquant ou trop court (32 caractères minimum)'), { status: 500 });
  const now = Math.floor(Date.now() / 1000);
  const body = Object.assign({ iat: now, exp: now + (ttlSec || SESSION_TTL) }, payload);
  const data = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url') + '.' + Buffer.from(JSON.stringify(body)).toString('base64url');
  return data + '.' + crypto.createHmac('sha256', secret).update(data).digest('base64url');
}
function verifyToken(token) {
  const secret = sessionSecret(); if (!secret || typeof token !== 'string') return null;
  const p = token.split('.'); if (p.length !== 3) return null;
  let h; try { h = JSON.parse(Buffer.from(p[0], 'base64url').toString()); } catch (e) { return null; }
  if (!h || h.alg !== 'HS256') return null;                    /* refuse "none" et tout autre algorithme */
  const expected = crypto.createHmac('sha256', secret).update(p[0] + '.' + p[1]).digest();
  let got; try { got = Buffer.from(p[2], 'base64url'); } catch (e) { return null; }
  if (got.length !== expected.length || !crypto.timingSafeEqual(got, expected)) return null;
  let pl; try { pl = JSON.parse(Buffer.from(p[1], 'base64url').toString()); } catch (e) { return null; }
  if (!pl || typeof pl.exp !== 'number' || pl.exp < Math.floor(Date.now() / 1000)) return null;
  return pl;
}
/* Qui appelle ? { email, admin } ou null. « admin » = uniquement l'adresse ADMIN_EMAIL, jamais une valeur de la base. */
function principal(event) {
  const a = String(header(event, 'authorization') || '');
  if (!/^Bearer\s+/i.test(a)) return null;
  const pl = verifyToken(a.replace(/^Bearer\s+/i, '').trim());
  if (!pl || pl.purpose !== 'session' || !isEmail(pl.sub)) return null;
  const email = pl.sub.toLowerCase();
  return { email, admin: email === ADMIN_EMAIL() };
}

/* ── mots de passe ── */
function pbkdf2Hash(pw, iter) {
  const it = iter || PBKDF2_ITER, salt = crypto.randomBytes(16);
  const h = crypto.pbkdf2Sync(String(pw), salt, it, 32, 'sha256');
  return ['pbkdf2', it, salt.toString('base64url'), h.toString('base64url')].join('$');
}
function pbkdf2Verify(pw, stored) {
  const p = String(stored || '').split('$');
  if (p.length !== 4 || p[0] !== 'pbkdf2') return false;
  const it = parseInt(p[1], 10); if (!(it >= 100000 && it <= 2000000)) return false;
  let salt, exp; try { salt = Buffer.from(p[2], 'base64url'); exp = Buffer.from(p[3], 'base64url'); } catch (e) { return false; }
  if (!salt.length || !exp.length) return false;
  const got = crypto.pbkdf2Sync(String(pw), salt, it, exp.length, 'sha256');
  return got.length === exp.length && crypto.timingSafeEqual(got, exp);
}
/* Ancienne empreinte 32 bits utilisée jusqu'ici par le site (conservée uniquement pour laisser les anciens membres se connecter une dernière fois). */
function legacyHash(pwd, email) {
  let hash = 0; const str = pwd + email + 'arrivercanada2025';
  for (let i = 0; i < str.length; i++) { const c = str.charCodeAt(i); hash = ((hash << 5) - hash) + c; hash = hash & hash; }
  return Math.abs(hash).toString(36).padStart(10, '0');
}
function verifyPassword(pw, email, stored) {
  if (!stored || typeof stored !== 'string') return { ok: false };             /* compte sans mot de passe : jamais accepté */
  if (stored.startsWith('pbkdf2$')) return { ok: pbkdf2Verify(pw, stored) };
  if (process.env.ALLOW_LEGACY_LOGIN === 'false') return { ok: false };
  const ok = legacyHash(pw, email) === stored;
  return { ok, upgrade: ok };
}

/* ── base de données (clé secrète = variable d'environnement, jamais dans la page) ── */
async function sb(method, pathQuery, body) {
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!key) throw Object.assign(new Error('SUPABASE_SECRET_KEY manquante'), { status: 500 });
  const headers = { apikey: key, 'Content-Type': 'application/json' };
  if (key.startsWith('eyJ')) headers.Authorization = 'Bearer ' + key;          /* anciennes clés JWT ; les clés sb_secret_ passent par « apikey » seul */
  if (method !== 'GET') headers.Prefer = 'return=representation';
  const res = await fetch(SUPA_URL() + pathQuery, { method, headers, body: (body === undefined || body === null) ? undefined : JSON.stringify(body) });
  const text = await res.text(); let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
  return { status: res.status, ok: res.ok, data };
}
const q = encodeURIComponent;
async function getUser(email) {
  const r = await sb('GET', '/rest/v1/users?email=eq.' + q(email) + '&select=*&limit=1');
  return (r.ok && Array.isArray(r.data) && r.data[0]) || null;
}
/* Version envoyée au navigateur : jamais de mot de passe ; « admin » vient de l'adresse, pas de la base. */
function publicUser(row) {
  if (!row) return null;
  const u = Object.assign({}, row); delete u.password; delete u.password_hash; delete u.stripe_customer_id;
  const admin = String(u.email || '').toLowerCase() === ADMIN_EMAIL();
  u.is_admin = admin; u.role = admin ? 'admin' : 'user';
  if (admin) u.plan = 'admin'; else if (u.plan === 'admin') u.plan = 'gratuit';
  return u;
}
async function activatePendingPro(email) {
  try {
    const r = await sb('GET', '/rest/v1/pending_pro?email=eq.' + q(email) + '&select=email');
    if (r.ok && Array.isArray(r.data) && r.data.length) { await sb('DELETE', '/rest/v1/pending_pro?email=eq.' + q(email)); return true; }
  } catch (e) { /* table absente : ignoré */ }
  return false;
}

/* ── e-mails (Resend, clé côté serveur uniquement) ── */
async function sendMail(to, subject, html) {
  const key = process.env.RESEND_API_KEY; if (!key || !isEmail(to)) return false;
  try {
    const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: process.env.MAIL_FROM || 'ArriverCanada <info@arrivercanada.com>', to: [to], subject, html }) });
    return r.ok;
  } catch (e) { return false; }
}

module.exports = { ADMIN_EMAIL, SUPA_URL, SITE_URL, json, rawBody, parseJSON, header, clientIp, esc, isEmail, limited, _resetLimits,
  signToken, verifyToken, principal, pbkdf2Hash, pbkdf2Verify, legacyHash, verifyPassword, sb, q, getUser, publicUser, activatePendingPro, sendMail, PBKDF2_ITER };
  return module.exports;
})();

const TABLES = new Set(['users', 'payments', 'feedback', 'visits', 'jobs', 'housing', 'site_stats', 'update_logs']);
const COL = /^[a-z_][a-z0-9_]{0,40}$/;
const OP = /^(eq|neq|gt|gte|lt|lte|like|ilike|is|in)\./;
const MEMBER_EDITABLE = new Set(['fname', 'lname', 'country', 'province', 'status', 'checks', 'username']);
const deny = (m) => ({ error: m || 'Accès refusé.', status: 403 });

function parsePath(p) {
  if (typeof p !== 'string' || p.length > 2000 || !p.startsWith('/rest/v1/')) return null;
  let u; try { u = new URL('http://x' + p); } catch (e) { return null; }
  const seg = u.pathname.split('/').filter(Boolean);                       /* rest, v1, table */
  if (seg.length !== 3 || !TABLES.has(seg[2])) return null;
  const params = [];
  for (const [k, v] of u.searchParams) params.push([k, v]);
  return { table: seg[2], params };
}
/* Reconstruit une chaîne de requête sûre. Retourne null si un paramètre est suspect. */
function cleanQuery(params, who, maxLimit) {
  const out = []; let hasLimit = false;
  for (const [k, v] of params) {
    if (k === 'select') {
      if (!who.admin && !/^[a-z_*,]{1,200}$/.test(v)) return null;           /* pas de jointures pour les non-admins */
      if (who.admin && v.length > 400) return null;
      out.push(['select', v]);
    } else if (k === 'order') { if (!/^[a-z_.,]+$/.test(v) || v.length > 80) return null; out.push([k, v]); }
    else if (k === 'limit') { const n = parseInt(v, 10); if (!(n >= 0)) return null; out.push([k, String(Math.min(n, maxLimit))]); hasLimit = true; }
    else if (k === 'offset') { const n = parseInt(v, 10); if (!(n >= 0 && n < 1e6)) return null; out.push([k, String(n)]); }
    else if (COL.test(k)) { if (!OP.test(v) || v.length > 300) return null; out.push([k, v]); }
    else if ((k === 'or' || k === 'and') && who.admin && v.length < 400) out.push([k, v]);
    else return null;
  }
  if (!hasLimit) out.push(['limit', String(maxLimit)]);
  return out;
}
const qs = (arr) => arr.map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v)).join('&');
const filterValue = (arr, col) => { const f = arr.find(([k]) => k === col); return f ? f[1] : null; };
const emailFilter = (arr) => { const v = filterValue(arr, 'email'); return (v && /^eq\./.test(v)) ? v.slice(3).toLowerCase() : null; };
const tooBig = (b) => b != null && JSON.stringify(b).length > 20000;
function badStrings(b) {
  const rows = Array.isArray(b) ? b : [b];
  return rows.some(r => !r || typeof r !== 'object' || Object.values(r).some(v => typeof v === 'string' && v.length > 5000));
}

exports.handler = async (event) => {
  try {
    if (event.httpMethod !== 'POST') return C.json(405, { error: 'Méthode non autorisée.' });
    const req = C.parseJSON(event); if (!req) return C.json(400, { error: 'Requête invalide.' });
    const method = String(req.m || 'GET').toUpperCase();
    if (!['GET', 'POST', 'PATCH', 'DELETE'].includes(method)) return C.json(405, { error: 'Méthode refusée.' });
    const parsed = parsePath(req.p); if (!parsed) return C.json(400, { error: 'Chemin refusé.' });
    const { table } = parsed;
    const principal = C.principal(event);
    if (C.header(event, 'authorization') && !principal) return C.json(401, { error: 'Session expirée. Reconnectez-vous.' });
    const who = principal || { email: null, admin: false };
    const member = !!principal;
    let body = req.b == null ? null : req.b;
    if (tooBig(body)) return C.json(413, { error: 'Requête trop volumineuse.' });

    const maxLimit = who.admin ? 5000 : 1000;
    const query = cleanQuery(parsed.params, who, maxLimit);
    if (!query) return C.json(400, { error: 'Paramètres refusés.' });
    let verdict = null;

    /* ───────── règles par table ───────── */
    if (table === 'users') {
      if (who.admin) {
        if (method === 'POST') { body = Array.isArray(body) ? null : Object.assign({}, body); if (!body) return C.json(400, { error: 'Un seul compte à la fois.' }); delete body.password; delete body.password_hash; body.is_admin = false; if (body.plan === 'admin') body.plan = 'gratuit'; if (String(body.email || '').toLowerCase() === C.ADMIN_EMAIL()) verdict = deny('Adresse réservée.'); }
        if (method === 'PATCH' || method === 'DELETE') {
          if (!query.some(([k]) => COL.test(k) && k !== 'select' && k !== 'order' && k !== 'limit' && k !== 'offset')) verdict = deny('Un filtre est obligatoire.');
          else {
            const targets = await C.sb('GET', '/rest/v1/users?' + qs(query.filter(([k]) => !['select', 'order', 'limit', 'offset'].includes(k))) + '&select=email&limit=200');
            const hitsAdmin = Array.isArray(targets.data) && targets.data.some(r => String(r.email).toLowerCase() === C.ADMIN_EMAIL());
            if (method === 'DELETE' && hitsAdmin) verdict = deny('Le compte administrateur ne peut pas être supprimé.');
            if (method === 'PATCH') {
              body = Object.assign({}, body); delete body.password; delete body.password_hash; delete body.id;
              const grants = body.is_admin === true || body.plan === 'admin';
              if (grants && !(Array.isArray(targets.data) && targets.data.length && targets.data.every(r => String(r.email).toLowerCase() === C.ADMIN_EMAIL()))) verdict = deny('Un seul administrateur est autorisé.');
              if ('email' in body && hitsAdmin) verdict = deny('Adresse de l\'administrateur non modifiable.');
            }
          }
        }
      } else if (member) {
        const target = emailFilter(query);
        if (!target || target !== who.email) verdict = deny();
        else if (method === 'GET') { /* lecture de son propre profil */ }
        else if (method === 'PATCH') {
          if (!body || Array.isArray(body) || Object.keys(body).some(k => !MEMBER_EDITABLE.has(k))) verdict = deny('Modification non autorisée.');
        } else verdict = deny();
      } else {
        const sel = filterValue(query, 'select'), un = filterValue(query, 'username');
        if (!(method === 'GET' && sel === 'username' && un && /^eq\./.test(un))) verdict = deny('Connexion requise.');
      }
    } else if (table === 'payments' || table === 'site_stats' || table === 'update_logs') {
      if (!who.admin) verdict = deny('Réservé à l\'administrateur.');
    } else if (table === 'feedback') {
      if (method === 'POST') {
        if (!body || badStrings(body) || (Array.isArray(body) && body.length > 1)) verdict = deny('Message refusé.');
        else if (C.limited('fb:' + C.clientIp(event), 12, 3600e3) && !who.admin) verdict = { error: 'Trop de messages. Réessayez plus tard.', status: 429 };
        else if (!who.admin) { body = Object.assign({}, Array.isArray(body) ? body[0] : body); for (const k of Object.keys(body)) if (/^(id|admin_.*|replied.*|reply.*)$/i.test(k)) delete body[k]; }
      } else if (method === 'GET') {
        if (!who.admin) { const ue = filterValue(query, 'user_email'); if (!member || !ue || !/^eq\./.test(ue) || ue.slice(3).toLowerCase() !== who.email) verdict = deny(); }
      } else if (!who.admin) verdict = deny('Réservé à l\'administrateur.');
    } else if (table === 'visits') {
      if (method === 'POST') {
        if (!body || badStrings(body) || Array.isArray(body)) verdict = deny('Refusé.');
        else if (C.limited('vis:' + C.clientIp(event), 240, 3600e3) && !who.admin) return C.json(200, { data: [] });   /* silencieux */
        else { body = Object.assign({}, body); delete body.id; }
      } else if (!who.admin) verdict = deny('Réservé à l\'administrateur.');
    } else if (table === 'jobs' || table === 'housing') {
      if (method !== 'GET' && !who.admin) verdict = deny('Réservé à l\'administrateur.');
    }
    if (verdict) return C.json(verdict.status, { error: verdict.error });

    /* ───────── exécution ───────── */
    const path = '/rest/v1/' + table + (query.length ? '?' + qs(query) : '');
    const r = await C.sb(method, path, (method === 'GET' || method === 'DELETE') ? undefined : body);
    if (!r.ok) {
      const msg = (r.data && (r.data.message || r.data.hint)) || ('Erreur ' + r.status);
      return C.json(r.status >= 400 && r.status < 500 ? r.status : 502, { error: String(msg).slice(0, 200) });
    }
    let data = r.data;
    if (table === 'feedback' && method === 'POST' && !who.admin && body) {          /* prévient l'administrateur par courriel (côté serveur) */
      const f = body;
      await C.sendMail(C.ADMIN_EMAIL(), 'Nouveau message : ' + String(f.service || f.type || 'contact').slice(0, 80),
        '<p><b>De :</b> ' + C.esc(f.user_name) + ' (' + C.esc(f.user_email) + ')</p><p>' + C.esc(f.message).replace(/\n/g, '<br>') + '</p>').catch(() => {});
    }
    if (table === 'users') {
      if (Array.isArray(data)) data = data.map(row => (!who.admin && !member) ? { username: row.username } : C.publicUser(row));
    }
    return C.json(200, { data });
  } catch (e) {
    console.error('db error:', e && e.message);
    return C.json(e && e.status ? e.status : 500, { error: 'Erreur serveur.' });
  }
};
