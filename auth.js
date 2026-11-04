'use strict';
const crypto = require('crypto');
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

const ok = (o) => C.json(200, Object.assign({ ok: true }, o || {}));
const fail = (s, m) => C.json(s, { ok: false, error: m });

function newSession(email) { return C.signToken({ sub: email, purpose: 'session' }, 30 * 24 * 3600); }
const clip = (v, n) => String(v == null ? '' : v).trim().slice(0, n);

async function register(event, b) {
  const ip = C.clientIp(event);
  if (C.limited('reg:' + ip, 10, 3600e3)) return fail(429, 'Trop de tentatives. Réessayez plus tard.');
  const email = clip(b.email, 120).toLowerCase(), fname = clip(b.fname, 60), lname = clip(b.lname, 60), pw = String(b.password || '');
  if (!fname || !lname) return fail(400, 'Prénom et nom requis.');
  if (!C.isEmail(email)) return fail(400, 'Adresse courriel invalide.');
  if (pw.length < 8 || pw.length > 128) return fail(400, 'Mot de passe : 8 caractères minimum.');
  if (email === C.ADMIN_EMAIL()) return fail(403, 'Cette adresse est réservée.');
  const existing = await C.getUser(email);
  if (existing) return fail(409, 'Cette adresse est déjà utilisée. Connectez-vous.');
  const plan = (await C.activatePendingPro(email)) ? 'pro' : 'gratuit';          /* paiement reçu avant l'inscription */
  const row = {
    email, fname, lname,
    username: fname.toLowerCase().replace(/[^a-z0-9]/g, '') + (1000 + crypto.randomInt(9000)),
    password: C.pbkdf2Hash(pw),
    country: clip(b.country, 60) || 'Autre', province: clip(b.province, 10) || 'QC', status: clip(b.status, 60) || 'Autre',
    plan, is_admin: false,
    promo_code: (fname.slice(0, 3) + lname.slice(0, 3)).toUpperCase().replace(/[^A-Z]/g, '') + (100 + crypto.randomInt(900)),
    promo_used: false, promo_discount: 20, checks: [false, false, false, false, false, false, false]
  };
  const r = await C.sb('POST', '/rest/v1/users', row);
  if (!r.ok) {
    if (r.status === 409 || /duplicate|unique/i.test(JSON.stringify(r.data))) return fail(409, 'Cette adresse est déjà utilisée. Connectez-vous.');
    return fail(502, 'Création du compte impossible pour le moment. Réessayez dans un instant.');
  }
  const saved = (Array.isArray(r.data) && r.data[0]) || row;
  /* courriels : meilleur effort, sans bloquer l'inscription */
  await Promise.allSettled([
    C.sendMail(email, 'Bienvenue sur ArriverCanada, ' + fname + ' !', '<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:24px"><h2 style="color:#0C2340">Bienvenue ' + C.esc(fname) + ' !</h2><p>Votre compte ArriverCanada est créé. Il ne vous reste qu\'à explorer les services de votre province.</p><p><a href="' + C.SITE_URL() + '" style="color:#D52B1E">Ouvrir ArriverCanada</a></p></div>'),
    C.sendMail(C.ADMIN_EMAIL(), 'Nouvel inscrit : ' + fname + ' ' + lname, '<p>' + C.esc(fname) + ' ' + C.esc(lname) + ' (' + C.esc(email) + ') — province ' + C.esc(row.province) + ' — plan ' + C.esc(plan) + '</p>')
  ]);
  return ok({ token: newSession(email), user: C.publicUser(saved) });
}

async function login(event, b) {
  const ip = C.clientIp(event), email = clip(b.email, 120).toLowerCase(), pw = String(b.password || '');
  if (!C.isEmail(email) || !pw || pw.length > 256) return fail(400, 'Adresse courriel et mot de passe requis.');
  if (C.limited('login-ip:' + ip, 30, 15 * 60e3) || C.limited('login:' + email, 8, 15 * 60e3)) return fail(429, 'Trop de tentatives. Patientez 15 minutes.');
  const generic = 'Adresse courriel ou mot de passe incorrect.';

  if (email === C.ADMIN_EMAIL()) {
    /* L'administrateur se connecte UNIQUEMENT avec le mot de passe défini dans Netlify (ADMIN_PASSWORD_HASH), pas avec la base de données. */
    const stored = process.env.ADMIN_PASSWORD_HASH;
    if (!stored) return fail(503, 'Accès administrateur non configuré (ADMIN_PASSWORD_HASH manquant).');
    if (!C.pbkdf2Verify(pw, stored)) return fail(401, generic);
    const row = (await C.getUser(email)) || { email, fname: 'Admin', lname: '' };
    return ok({ token: newSession(email), user: C.publicUser(row) });
  }

  const row = await C.getUser(email);
  if (!row) { C.pbkdf2Hash('x', 100000); return fail(401, generic); }             /* temps de réponse comparable */
  if (!row.password) return fail(401, 'Ce compte doit être réactivé. Utilisez « Mot de passe oublié » ou écrivez-nous.');
  const v = C.verifyPassword(pw, email, row.password);
  if (!v.ok) return fail(401, generic);
  if (v.upgrade) { try { await C.sb('PATCH', '/rest/v1/users?email=eq.' + C.q(email), { password: C.pbkdf2Hash(pw) }); } catch (e) { /* non bloquant */ } }
  await C.activatePendingPro(email).then(async (hit) => { if (hit && row.plan !== 'pro') { await C.sb('PATCH', '/rest/v1/users?email=eq.' + C.q(email), { plan: 'pro' }); row.plan = 'pro'; } }).catch(() => {});
  return ok({ token: newSession(email), user: C.publicUser(row) });
}

async function me(event) {
  const who = C.principal(event); if (!who) return fail(401, 'Session expirée. Reconnectez-vous.');
  const row = (await C.getUser(who.email)) || (who.admin ? { email: who.email, fname: 'Admin', lname: '' } : null);
  if (!row) return fail(401, 'Compte introuvable.');
  if (!who.admin && row.plan !== 'pro' && row.plan !== 'annuel') {
    if (await C.activatePendingPro(who.email)) { await C.sb('PATCH', '/rest/v1/users?email=eq.' + C.q(who.email), { plan: 'pro' }); row.plan = 'pro'; }
  }
  return ok({ user: C.publicUser(row) });
}

async function forgot(event, b) {
  const email = clip(b.email, 120).toLowerCase();
  if (!C.isEmail(email)) return ok();
  if (C.limited('forgot:' + C.clientIp(event), 8, 3600e3) || C.limited('forgot:' + email, 3, 3600e3)) return ok();   /* silencieux */
  if (email === C.ADMIN_EMAIL()) return ok();
  const row = await C.getUser(email);
  if (row) {
    const fp = crypto.createHash('sha256').update(String(row.password || '')).digest('hex').slice(0, 16);
    const token = C.signToken({ sub: email, purpose: 'reset', fp }, 30 * 60);
    const link = C.SITE_URL() + '/?reset=' + token;
    await C.sendMail(email, 'Réinitialisation de votre mot de passe — ArriverCanada',
      '<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:24px"><h2 style="color:#0C2340">Nouveau mot de passe</h2><p>Cliquez ci-dessous pour choisir un nouveau mot de passe (lien valable 30 minutes) :</p><p><a href="' + link + '" style="background:#D52B1E;color:#fff;padding:10px 20px;border-radius:20px;text-decoration:none">Choisir un mot de passe</a></p><p style="color:#777;font-size:12px">Si vous n\'avez rien demandé, ignorez ce message : votre mot de passe actuel reste valable.</p></div>');
  }
  return ok();                                                                   /* même réponse que le compte existe ou non */
}

async function reset(event, b) {
  if (C.limited('reset:' + C.clientIp(event), 10, 3600e3)) return fail(429, 'Trop de tentatives.');
  const pl = C.verifyToken(String(b.token || '')); const pw = String(b.password || '');
  if (!pl || pl.purpose !== 'reset' || !C.isEmail(pl.sub)) return fail(400, 'Lien invalide ou expiré. Refaites une demande.');
  if (pw.length < 8 || pw.length > 128) return fail(400, 'Mot de passe : 8 caractères minimum.');
  const row = await C.getUser(pl.sub);
  if (!row || pl.sub === C.ADMIN_EMAIL()) return fail(400, 'Lien invalide ou expiré. Refaites une demande.');
  const fp = crypto.createHash('sha256').update(String(row.password || '')).digest('hex').slice(0, 16);
  if (fp !== pl.fp) return fail(400, 'Ce lien a déjà été utilisé. Refaites une demande.');   /* usage unique */
  await C.sb('PATCH', '/rest/v1/users?email=eq.' + C.q(pl.sub), { password: C.pbkdf2Hash(pw) });
  return ok();
}

async function adminResetPassword(event, b) {
  const who = C.principal(event); if (!who || !who.admin) return fail(403, 'Réservé à l\'administrateur.');
  const email = clip(b.email, 120).toLowerCase(); if (!C.isEmail(email) || email === C.ADMIN_EMAIL()) return fail(400, 'Adresse invalide.');
  const row = await C.getUser(email); if (!row) return fail(404, 'Compte introuvable.');
  const temp = String(b.newPassword || '') || crypto.randomBytes(9).toString('base64url');
  if (temp.length < 8) return fail(400, 'Mot de passe : 8 caractères minimum.');
  await C.sb('PATCH', '/rest/v1/users?email=eq.' + C.q(email), { password: C.pbkdf2Hash(temp) });
  return ok({ temp });
}

exports.handler = async (event) => {
  try {
    if (event.httpMethod !== 'POST') return fail(405, 'Méthode non autorisée.');
    const b = C.parseJSON(event); if (!b) return fail(400, 'Requête invalide.');
    switch (b.action) {
      case 'register': return await register(event, b);
      case 'login': return await login(event, b);
      case 'me': return await me(event);
      case 'forgot': return await forgot(event, b);
      case 'reset': return await reset(event, b);
      case 'admin-reset-password': return await adminResetPassword(event, b);
      default: return fail(400, 'Action inconnue.');
    }
  } catch (e) {
    console.error('auth error:', e && e.message);
    return fail(e && e.status ? e.status : 500, e && e.status === 500 ? e.message : 'Erreur serveur. Réessayez.');
  }
};
