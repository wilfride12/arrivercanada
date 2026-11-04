'use strict';
/* Reçoit les événements Stripe (signature vérifiée) et active / désactive le plan Pro automatiquement. */
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

const TOLERANCE_SEC = 300;

function verifyStripeSignature(payload, sigHeader, secret) {
  if (!sigHeader || !secret) return false;
  const parts = {}; String(sigHeader).split(',').forEach(kv => { const i = kv.indexOf('='); if (i > 0) { const k = kv.slice(0, i).trim(), v = kv.slice(i + 1).trim(); (parts[k] = parts[k] || []).push(v); } });
  const t = parseInt((parts.t || [])[0], 10); if (!t) return false;
  if (Math.abs(Math.floor(Date.now() / 1000) - t) > TOLERANCE_SEC) return false;
  const expected = crypto.createHmac('sha256', secret).update(t + '.' + payload).digest('hex');
  return (parts.v1 || []).some(sig => { try { const a = Buffer.from(sig, 'hex'), b = Buffer.from(expected, 'hex'); return a.length === b.length && crypto.timingSafeEqual(a, b); } catch (e) { return false; } });
}

const normEmail = (e) => (C.isEmail(String(e || '').trim().toLowerCase()) ? String(e).trim().toLowerCase() : null);
/* Stripe n'accepte que lettres, chiffres, « - » et « _ » dans client_reference_id : le site y met l'adresse encodée en base64url. */
function decodeRef(ref) {
  if (!ref) return null;
  const raw = normEmail(ref); if (raw) return raw;
  try { return normEmail(Buffer.from(String(ref), 'base64url').toString('utf8')); } catch (e) { return null; }
}

/* Active le Pro. Retourne true si un compte a été mis à jour. */
async function activate(emails, customerId) {
  for (const email of emails.filter(Boolean)) {
    if (email === C.ADMIN_EMAIL()) return true;                                  /* l'admin n'a pas besoin de plan */
    const body = { plan: 'pro' }; if (customerId) body.stripe_customer_id = customerId;
    let r = await C.sb('PATCH', '/rest/v1/users?email=eq.' + C.q(email), body);
    if (!r.ok && customerId) r = await C.sb('PATCH', '/rest/v1/users?email=eq.' + C.q(email), { plan: 'pro' });   /* colonne stripe_customer_id pas encore créée */
    if (!r.ok) throw new Error('Mise à jour impossible (' + r.status + ')');
    if (Array.isArray(r.data) && r.data.length) return true;
  }
  /* Aucun compte avec ces adresses : on garde le paiement en attente jusqu'à l'inscription. */
  const first = emails.find(Boolean);
  if (first) { try { await C.sb('POST', '/rest/v1/pending_pro', { email: first, source: 'stripe' }); } catch (e) { /* table absente */ } }
  return false;
}
async function deactivate(customerId, email) {
  let filter = null;
  if (customerId) {
    const r = await C.sb('GET', '/rest/v1/users?stripe_customer_id=eq.' + C.q(customerId) + '&select=email,plan&limit=5');
    if (r.ok && Array.isArray(r.data) && r.data.length) filter = r.data;
  }
  if (!filter && email) { const row = await C.getUser(email); if (row) filter = [row]; }
  if (!filter) return false;
  for (const row of filter) {
    const em = String(row.email).toLowerCase();
    if (em === C.ADMIN_EMAIL() || row.plan === 'admin') continue;                /* jamais l'administrateur */
    const r = await C.sb('PATCH', '/rest/v1/users?email=eq.' + C.q(em), { plan: 'gratuit' });
    if (!r.ok) throw new Error('Mise à jour impossible (' + r.status + ')');
  }
  return true;
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return C.json(405, { error: 'Méthode non autorisée.' });
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) return C.json(500, { error: 'STRIPE_WEBHOOK_SECRET manquant.' });
  const payload = C.rawBody(event);                                              /* corps brut : indispensable pour la signature */
  if (!verifyStripeSignature(payload, C.header(event, 'stripe-signature'), secret)) return C.json(400, { error: 'Signature invalide.' });
  let evt; try { evt = JSON.parse(payload); } catch (e) { return C.json(400, { error: 'JSON invalide.' }); }
  const o = (evt && evt.data && evt.data.object) || {};
  try {
    switch (evt.type) {
      case 'checkout.session.completed': {
        const paid = o.payment_status === 'paid' || o.payment_status === 'no_payment_required';
        if (!paid) break;
        const emails = [decodeRef(o.client_reference_id), normEmail(o.customer_details && o.customer_details.email), normEmail(o.customer_email)];
        await activate([...new Set(emails)], o.customer || null);
        break;
      }
      case 'invoice.paid':
      case 'invoice.payment_succeeded': {
        if (o.status && o.status !== 'paid') break;
        await activate([normEmail(o.customer_email)], o.customer || null);
        break;
      }
      case 'customer.subscription.updated': {
        if (['active', 'trialing'].includes(o.status)) {
          let em = null;
          if (o.customer) { const r = await C.sb('GET', '/rest/v1/users?stripe_customer_id=eq.' + C.q(o.customer) + '&select=email&limit=1'); em = r.ok && r.data && r.data[0] && r.data[0].email; }
          if (em) await activate([String(em).toLowerCase()], o.customer);
        } else if (['canceled', 'unpaid', 'incomplete_expired'].includes(o.status)) await deactivate(o.customer, null);
        break;                                                                   /* « past_due » : on laisse Stripe réessayer, accès maintenu */
      }
      case 'customer.subscription.deleted':
        await deactivate(o.customer, null);
        break;
      default: break;                                                            /* autres événements : ignorés */
    }
    return C.json(200, { received: true });
  } catch (e) {
    console.error('webhook error:', e && e.message);
    return C.json(500, { error: 'Traitement échoué ; Stripe réessaiera.' });     /* 500 => Stripe renvoie l'événement */
  }
};
exports._verify = verifyStripeSignature;
