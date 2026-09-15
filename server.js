'use strict';
/* ============================================================================
   XYVEN WORLD — server.js
   ----------------------------------------------------------------------------
   Node.js + Express backend for the XYVEN WORLD interface.

   • Serves index.html (the full front-end application)
   • Dynamically generates the ADMIN COMMAND CENTER at /admin.html
   • Complete REST API with sessions, consent, OTP and device profiles
   • Secure by default: Helmet, rate limiting, signed HttpOnly cookies,
     scrypt password hashing, strict input validation, no plaintext OTPs
   • Data storage: local JSON datastore (auto-created) or /data on Render

   Run:  node server.js
   ============================================================================ */

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/* ============================================================================
   1. CONFIGURATION
   ============================================================================ */

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PROD = NODE_ENV === 'production';

// Session secret — MUST be set in production.
let SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET) {
  SESSION_SECRET = crypto.randomBytes(32).toString('hex');
  if (IS_PROD) {
    console.warn('[XYVEN] WARNING: SESSION_SECRET not set. Using an ephemeral key.');
    console.warn('[XYVEN] Set SESSION_SECRET in your environment for stable sessions.');
  }
}

// Persistent disk on Render mounts at /data
const DATA_DIR = fs.existsSync('/data') ? '/data' : __dirname;
const DATA_FILE = path.join(DATA_DIR, 'xyven-data.json');

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;  // 30 days (user session)
const ADMIN_TTL_MS = 2 * 60 * 60 * 1000;          // 2 hours  (admin session)
const OTP_TTL_MS = 5 * 60 * 1000;                 // 5 minutes
const OTP_MAX_ATTEMPTS = 5;
const OTP_MAX_REQUESTS = 5;                       // per 10 min per session

const COOKIE_USER = 'xyven_sid';
const COOKIE_ADMIN = 'xyven_admin';

/* ============================================================================
   2. DATA LAYER — JSON datastore (parameterized / in-memory safe operations)
   ============================================================================ */

let db = {
  users: [],
  adminSessions: {},
  events: [],
  meta: { created: new Date().toISOString(), version: 1 }
};

function ensureShape() {
  if (!db || typeof db !== 'object') db = {};
  if (!Array.isArray(db.users)) db.users = [];
  if (!db.adminSessions || typeof db.adminSessions !== 'object') db.adminSessions = {};
  if (!Array.isArray(db.events)) db.events = [];
  if (!db.meta || typeof db.meta !== 'object') db.meta = { created: new Date().toISOString(), version: 1 };
}

function loadDB() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, 'utf8');
      db = JSON.parse(raw);
      console.log('[XYVEN] Datastore loaded from ' + DATA_FILE);
    } else {
      console.log('[XYVEN] No datastore found. Creating a fresh one at ' + DATA_FILE);
    }
  } catch (err) {
    console.error('[XYVEN] Failed to read datastore:', err.message);
    console.error('[XYVEN] Starting with an empty in-memory datastore.');
  }
  ensureShape();
}

let saveTimer = null;
function saveDB() {
  // Small debounce so bursts of writes do not thrash the disk.
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    try {
      const tmp = DATA_FILE + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
      fs.renameSync(tmp, DATA_FILE);
    } catch (err) {
      console.error('[XYVEN] Failed to persist datastore:', err.message);
    }
  }, 120);
}

function saveDBNow() {
  try {
    const tmp = DATA_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
    fs.renameSync(tmp, DATA_FILE);
  } catch (err) {
    console.error('[XYVEN] Failed to persist datastore:', err.message);
  }
}

/* ---------- retention: prune expired OTPs and admin sessions ---------- */
function pruneData() {
  const now = Date.now();
  let changed = false;

  Object.keys(db.adminSessions).forEach((token) => {
    if (!db.adminSessions[token] || db.adminSessions[token].expires < now) {
      delete db.adminSessions[token];
      changed = true;
    }
  });

  db.users.forEach((u) => {
    if (u.otp && u.otp.expires < now) {
      u.otp = null;
      changed = true;
    }
  });

  // Keep the global event log bounded.
  if (db.events.length > 5000) {
    db.events = db.events.slice(-3000);
    changed = true;
  }

  if (changed) saveDB();
}
setInterval(pruneData, 10 * 60 * 1000).unref();

/* ============================================================================
   3. CRYPTO / SESSION UTILITIES
   ============================================================================ */

function randomId(bytes) {
  return crypto.randomBytes(bytes || 16).toString('hex');
}

function hmac(value) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(String(value)).digest('hex');
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/* ---------- password hashing (scrypt, no external dependency) ---------- */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return salt + ':' + hash;
}

function verifyPassword(password, stored) {
  if (typeof stored !== 'string' || stored.indexOf(':') < 0) return false;
  const parts = stored.split(':');
  const salt = parts[0];
  const expected = parts[1];
  let actual;
  try {
    actual = crypto.scryptSync(password, salt, 64).toString('hex');
  } catch (err) {
    return false;
  }
  return safeEqual(actual, expected);
}

/* ---------- signed cookie values ---------- */
function signValue(value) {
  return value + '.' + hmac(value).slice(0, 40);
}

function unsignValue(signed) {
  if (typeof signed !== 'string') return null;
  const idx = signed.lastIndexOf('.');
  if (idx < 0) return null;
  const value = signed.slice(0, idx);
  const sig = signed.slice(idx + 1);
  const expected = hmac(value).slice(0, 40);
  if (sig.length !== expected.length) return null;
  if (!safeEqual(sig, expected)) return null;
  return value;
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i < 0) return;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (!k) return;
    try { out[k] = decodeURIComponent(v); } catch (e) { out[k] = v; }
  });
  return out;
}

function setCookie(res, name, value, opts) {
  opts = opts || {};
  const parts = [name + '=' + encodeURIComponent(value)];
  parts.push('Path=' + (opts.path || '/'));
  if (opts.maxAge) parts.push('Max-Age=' + Math.floor(opts.maxAge / 1000));
  if (opts.httpOnly !== false) parts.push('HttpOnly');
  parts.push('SameSite=' + (opts.sameSite || 'Lax'));
  if (IS_PROD) parts.push('Secure');
  res.append('Set-Cookie', parts.join('; '));
}

function clearCookie(res, name) {
  setCookie(res, name, '', { maxAge: 0, httpOnly: true });
}

/* ============================================================================
   4. VALIDATION UTILITIES
   ============================================================================ */

function cleanString(value, max) {
  if (typeof value !== 'string') return '';
  return value.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max || 200);
}

function cleanDigits(value, max) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/\D/g, '').slice(0, max || 15);
}

function isEmailLike(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function maskPhone(country, number) {
  if (!number) return null;
  const tail = number.slice(-4);
  const stars = '*'.repeat(Math.max(0, number.length - 4));
  return (country || '') + ' ' + stars + tail;
}

/* ============================================================================
   5. EVENT LOG
   ============================================================================ */

function recordEvent(label, kind, userId, req) {
  let actor = null;
  if (req && req.headers) {
    // Non-reversible, truncated actor fingerprint for audit purposes only.
    const raw = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim();
    if (raw) actor = hmac('ip:' + raw).slice(0, 12);
  }
  const evt = {
    id: randomId(8),
    label: label,
    kind: kind || 'ok',
    at: new Date().toISOString(),
    userId: userId || null,
    actor: actor
  };
  db.events.push(evt);
  if (db.events.length > 5000) db.events = db.events.slice(-3000);
  saveDB();
  return evt;
}

/* ============================================================================
   6. APP SETUP
   ============================================================================ */

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'blob:'],
      fontSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: IS_PROD ? [] : null
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: 'same-origin' },
  referrerPolicy: { policy: 'no-referrer' },
  hsts: IS_PROD ? { maxAge: 15552000, includeSubDomains: true } : false
}));

/* ---------- same-origin CORS policy ---------- */
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const host = req.headers.host;
  if (origin && host) {
    try {
      const parsed = new URL(origin);
      if (parsed.host === host) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Vary', 'Origin');
      }
    } catch (e) { /* ignore malformed origin */ }
  }
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    return res.sendStatus(204);
  }
  next();
});

app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));

/* ---------- rate limiting ---------- */
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 180,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'rate_limited', message: 'Too many requests. Please slow down.' }
});

const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 12,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'rate_limited', message: 'Too many verification attempts. Try again later.' }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { error: 'rate_limited', message: 'Too many login attempts. Try again in 15 minutes.' }
});

app.use('/api/', apiLimiter);

/* ============================================================================
   7. ADMIN CREDENTIALS
   ============================================================================ */

const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || 'admin').toLowerCase();

let ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || null;

if (!ADMIN_PASSWORD_HASH) {
  const plain = process.env.ADMIN_PASSWORD || 'xyven-admin';
  ADMIN_PASSWORD_HASH = hashPassword(plain);
  if (!process.env.ADMIN_PASSWORD) {
    console.warn('[XYVEN] WARNING: Using the default admin password.');
    console.warn('[XYVEN] Set ADMIN_USERNAME and ADMIN_PASSWORD (or ADMIN_PASSWORD_HASH) in production.');
  }
}

/* ============================================================================
   8. SESSION HELPERS
   ============================================================================ */

function findUserBySessionId(sessionId) {
  if (!sessionId) return null;
  return db.users.find((u) => u.sessionId === sessionId) || null;
}

function createUserSession() {
  const sessionId = randomId(24);
  const user = {
    id: randomId(8),
    sessionId: sessionId,
    consent: null,
    phone: null,
    phoneVerified: false,
    otp: null,
    otpRequests: [],
    device: null,
    createdAt: new Date().toISOString(),
    lastActive: new Date().toISOString(),
    deleted: false,
    events: []
  };
  db.users.push(user);
  saveDB();
  return user;
}

function pushUserEvent(user, label, kind) {
  if (!user) return;
  user.events.push({ label: label, kind: kind || 'ok', at: new Date().toISOString() });
  if (user.events.length > 200) user.events = user.events.slice(-120);
}

/** Reads (or creates) the caller's user session. */
function ensureUserSession(req, res) {
  const cookies = parseCookies(req);
  const sessionId = unsignValue(cookies[COOKIE_USER]);
  let user = findUserBySessionId(sessionId);

  if (!user) {
    user = createUserSession();
    setCookie(res, COOKIE_USER, signValue(user.sessionId), {
      maxAge: SESSION_TTL_MS,
      httpOnly: true,
      sameSite: 'Lax'
    });
    pushUserEvent(user, 'SESSION CREATED', 'ok');
    recordEvent('USER SESSION CREATED', 'ok', user.id, req);
    saveDB();
  } else {
    user.lastActive = new Date().toISOString();
    saveDB();
  }
  return user;
}

function isAdmin(req) {
  const cookies = parseCookies(req);
  const token = unsignValue(cookies[COOKIE_ADMIN]);
  if (!token) return null;
  const record = db.adminSessions[token];
  if (!record) return null;
  if (record.expires < Date.now()) {
    delete db.adminSessions[token];
    saveDB();
    return null;
  }
  return record;
}

function requireAdmin(req, res, next) {
  const admin = isAdmin(req);
  if (!admin) {
    return res.status(401).json({ error: 'unauthorized', message: 'Administrator authentication required.' });
  }
  req.admin = admin;
  next();
}

/* ============================================================================
   9. SERIALIZERS
   ============================================================================ */

function collectedList(user) {
  const out = ['Session identifier'];
  if (user.consent) out.push('Consent choice');
  if (user.phone && user.phone.number) out.push('Phone number');
  if (user.phoneVerified) out.push('Phone verification status');
  if (user.device) out.push('Browser / device profile');
  return out;
}

function publicUser(user) {
  return {
    sessionId: user.sessionId,
    consent: user.consent || 'not_recorded',
    phone: user.phone ? maskPhone(user.phone.country, user.phone.number) : null,
    otpVerified: !!user.phoneVerified,
    device: user.device || null,
    createdAt: user.createdAt,
    lastActive: user.lastActive,
    collected: collectedList(user),
    events: user.events.map((e) => ({ label: e.label, kind: e.kind, at: e.at }))
  };
}

function adminUserSummary(user) {
  return {
    id: user.id,
    sessionId: user.sessionId,
    phone: user.phone ? maskPhone(user.phone.country, user.phone.number) : null,
    hasPhone: !!(user.phone && user.phone.number),
    consent: user.consent || 'not_recorded',
    otpStatus: user.phoneVerified ? 'verified' : (user.otp ? 'pending' : 'none'),
    device: user.device ? user.device.deviceType : null,
    browser: user.device ? user.device.browser : null,
    os: user.device ? user.device.os : null,
    timezone: user.device ? user.device.timezone : null,
    createdAt: user.createdAt,
    lastActive: user.lastActive,
    deleted: !!user.deleted
  };
}

function adminUserDetail(user) {
  const base = adminUserSummary(user);
  base.screen = user.device ? user.device.screenResolution : null;
  base.viewport = user.device ? user.device.viewport : null;
  base.language = user.device ? user.device.language : null;
  base.browserVersion = user.device ? user.device.browserVersion : null;
  base.online = user.device ? user.device.online : null;
  base.events = user.events.map((e) => ({ label: e.label, kind: e.kind, at: e.at }));
  return base;
}

/* ============================================================================
   10. ADMIN HTML — dynamically generated command center at /admin.html
   ============================================================================ */

function renderAdminHTML() {
  return [
'<!DOCTYPE html>',
'<html lang="en">',
'<head>',
'<meta charset="UTF-8" />',
'<meta name="viewport" content="width=device-width, initial-scale=1.0" />',
'<meta name="robots" content="noindex,nofollow" />',
'<meta name="theme-color" content="#03060a" />',
'<title>XYVEN COMMAND CENTER // RESTRICTED</title>',
'<style>',
':root{--bg:#03060a;--red:#ff2b3d;--red-dim:rgba(255,43,61,.35);--neon:#00ff9c;--neon-dim:rgba(0,255,156,.22);--orange:#ff9a2e;--txt:#d9f8ea;--muted:#5f7d72;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}',
'*,*::before,*::after{box-sizing:border-box}',
'html,body{height:100%}',
'body{margin:0;background:var(--bg);color:var(--txt);font-family:var(--mono);font-size:14px;line-height:1.55;overflow-x:hidden;-webkit-font-smoothing:antialiased}',
'body::before{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;background:radial-gradient(900px 620px at 12% 8%,rgba(255,43,61,.10),transparent 62%),radial-gradient(800px 620px at 88% 92%,rgba(0,255,156,.07),transparent 60%),linear-gradient(180deg,#03060a,#04070c 50%,#03060a)}',
'button,input,select{font-family:inherit;font-size:inherit;color:inherit}',
'button{cursor:pointer;border:0;background:none}',
'.hidden{display:none !important}',
'::selection{background:rgba(255,43,61,.35);color:#fff}',
'#mx,.fx{position:fixed;inset:0;pointer-events:none}',
'#mx{z-index:1;opacity:.30}',
'.fx-grid{z-index:1;opacity:.30;background-image:linear-gradient(rgba(255,43,61,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(255,43,61,.05) 1px,transparent 1px);background-size:56px 56px;animation:gm 24s linear infinite;mask-image:radial-gradient(circle at 50% 45%,#000 0%,transparent 78%);-webkit-mask-image:radial-gradient(circle at 50% 45%,#000 0%,transparent 78%)}',
'@keyframes gm{from{background-position:0 0,0 0}to{background-position:0 56px,56px 0}}',
'.fx-scan{z-index:6;opacity:.42;background:repeating-linear-gradient(to bottom,rgba(0,0,0,0) 0px,rgba(0,0,0,0) 2px,rgba(0,0,0,.30) 3px,rgba(0,0,0,.30) 4px);mix-blend-mode:multiply}',
'.fx-scan::after{content:"";position:absolute;left:0;right:0;height:30%;background:linear-gradient(180deg,transparent,rgba(255,43,61,.07),transparent);animation:sw 7s linear infinite}',
'@keyframes sw{0%{top:-32%}100%{top:106%}}',
'.fx-vig{z-index:5;background:radial-gradient(ellipse at center,transparent 38%,rgba(0,0,0,.80) 100%)}',
'.fx-smoke{z-index:2;opacity:.55;background:radial-gradient(600px 380px at 18% 22%,rgba(120,0,14,.35),transparent 70%),radial-gradient(680px 420px at 82% 78%,rgba(60,0,8,.42),transparent 72%),radial-gradient(900px 520px at 50% 110%,rgba(255,43,61,.10),transparent 70%);animation:smoke 14s ease-in-out infinite alternate}',
'@keyframes smoke{0%{transform:translate3d(0,0,0) scale(1)}100%{transform:translate3d(-2%,-1.5%,0) scale(1.06)}}',
'.stage{position:fixed;inset:0;z-index:10;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:clamp(16px,4vw,48px);overflow-y:auto;opacity:0;visibility:hidden;transform:translateY(14px) scale(.985);transition:opacity .5s ease,transform .5s cubic-bezier(.22,1,.36,1),visibility .5s}',
'.stage.active{opacity:1;visibility:visible;transform:none}',
'.wrap{width:100%;max-width:1180px;margin:auto}',
'.panel{position:relative;background:rgba(7,14,18,.62);border:1px solid var(--red-dim);border-radius:16px;backdrop-filter:blur(14px) saturate(140%);-webkit-backdrop-filter:blur(14px) saturate(140%);box-shadow:0 0 0 1px rgba(0,0,0,.5) inset,0 24px 60px rgba(0,0,0,.65),0 0 48px rgba(255,43,61,.10);padding:clamp(18px,3vw,32px)}',
'.panel.green{border-color:var(--neon-dim);box-shadow:0 0 0 1px rgba(0,0,0,.5) inset,0 24px 60px rgba(0,0,0,.65),0 0 48px rgba(0,255,156,.08)}',
'.corner{position:absolute;width:16px;height:16px;border:1px solid var(--red);opacity:.6}',
'.corner.tl{top:8px;left:8px;border-right:0;border-bottom:0}',
'.corner.tr{top:8px;right:8px;border-left:0;border-bottom:0}',
'.corner.bl{bottom:8px;left:8px;border-right:0;border-top:0}',
'.corner.br{bottom:8px;right:8px;border-left:0;border-top:0}',
'.eyebrow{font-size:11px;letter-spacing:.34em;text-transform:uppercase;color:var(--muted);display:flex;align-items:center;gap:10px;margin-bottom:14px}',
'.eyebrow::before{content:"";width:26px;height:1px;background:linear-gradient(90deg,var(--red),transparent)}',
'h1,h2,h3{margin:0;font-weight:700;letter-spacing:.02em}',
'h1{font-size:clamp(22px,4.4vw,38px);line-height:1.14}',
'h3{font-size:12px;letter-spacing:.24em;text-transform:uppercase;color:var(--red)}',
'.neon{color:var(--neon);text-shadow:0 0 12px rgba(0,255,156,.55)}',
'.red{color:var(--red);text-shadow:0 0 12px rgba(255,43,61,.5)}',
'.orange{color:var(--orange);text-shadow:0 0 12px rgba(255,154,46,.45)}',
'.muted{color:var(--muted)}',
'.small{font-size:12px}',
'.btn{position:relative;display:inline-flex;align-items:center;justify-content:center;gap:10px;padding:14px 26px;border-radius:12px;border:1px solid var(--red);background:linear-gradient(180deg,rgba(255,43,61,.20),rgba(255,43,61,.04));color:#ffe3e6;font-weight:700;letter-spacing:.16em;font-size:12px;text-transform:uppercase;transition:transform .18s ease,box-shadow .25s ease,background .25s ease;box-shadow:0 0 26px rgba(255,43,61,.22)}',
'.btn:hover{background:linear-gradient(180deg,rgba(255,43,61,.34),rgba(255,43,61,.08));box-shadow:0 0 40px rgba(255,43,61,.48);transform:translateY(-2px)}',
'.btn:active{transform:translateY(0)}',
'.btn:disabled{opacity:.4;cursor:not-allowed;transform:none;box-shadow:none}',
'.btn.green{border-color:var(--neon);color:var(--neon);background:linear-gradient(180deg,rgba(0,255,156,.14),rgba(0,255,156,.03));box-shadow:0 0 26px rgba(0,255,156,.18)}',
'.btn.green:hover{box-shadow:0 0 40px rgba(0,255,156,.4);background:linear-gradient(180deg,rgba(0,255,156,.26),rgba(0,255,156,.06))}',
'.btn.ghost{border-color:rgba(255,255,255,.18);color:#b9d6cb;background:rgba(255,255,255,.03);box-shadow:none}',
'.btn.ghost:hover{border-color:var(--neon);color:var(--neon);box-shadow:0 0 24px rgba(0,255,156,.18)}',
'.btn.sm{padding:9px 15px;font-size:10.5px;letter-spacing:.12em}',
'.btn.block{width:100%}',
'.btn-row{display:flex;gap:12px;flex-wrap:wrap;margin-top:22px}',
'.btn-row .btn{flex:1 1 220px}',
/* intro */
'.intro-wrap{position:relative;z-index:12;display:flex;flex-direction:column;align-items:center;gap:clamp(20px,4vh,40px);text-align:center;padding:20px}',
'.eye{position:relative;width:min(62vw,340px);height:min(62vw,340px);border-radius:50%;background:radial-gradient(circle at 50% 50%,#ff2b3d 0%,#c4081c 18%,#5a030c 42%,#180003 66%,#000 100%);box-shadow:0 0 90px rgba(255,43,61,.65),0 0 220px rgba(255,43,61,.35),inset 0 0 140px rgba(0,0,0,.92);animation:eyePulse 4.2s ease-in-out infinite}',
'.eye::before{content:"";position:absolute;inset:0;margin:auto;width:32%;height:32%;border-radius:50%;background:radial-gradient(circle at 50% 50%,#000 0%,#040000 55%,#1c0005 100%);box-shadow:inset 0 0 44px rgba(255,43,61,.85),0 0 40px rgba(0,0,0,.9);animation:pupil 6s ease-in-out infinite}',
'.eye::after{content:"";position:absolute;inset:13%;border-radius:50%;border:2px solid rgba(255,43,61,.5);box-shadow:0 0 44px rgba(255,43,61,.55) inset,0 0 34px rgba(255,43,61,.45);animation:spin 16s linear infinite}',
'@keyframes eyePulse{0%,100%{filter:brightness(1) saturate(1)}50%{filter:brightness(1.22) saturate(1.25)}}',
'@keyframes pupil{0%,100%{transform:translate(0,0) scale(1)}25%{transform:translate(-6px,-4px) scale(1.04)}50%{transform:translate(5px,3px) scale(.97)}75%{transform:translate(-3px,5px) scale(1.02)}}',
'@keyframes spin{to{transform:rotate(360deg)}}',
'.intro-term{min-height:120px;font-size:clamp(12px,1.7vw,14px);color:#ffb9c1;letter-spacing:.05em;display:flex;flex-direction:column;gap:7px;align-items:center}',
'.intro-term .l{white-space:pre-wrap}',
'.intro-big{margin-top:10px;font-size:clamp(18px,4vw,34px);font-weight:800;letter-spacing:.08em;color:#fff;text-shadow:0 0 26px rgba(255,43,61,.85),0 0 60px rgba(255,43,61,.45);min-height:1.3em}',
'.cursor{display:inline-block;width:11px;height:1.05em;vertical-align:-3px;margin-left:6px;background:var(--red);box-shadow:0 0 14px var(--red);animation:bl 1s steps(1) infinite}',
'@keyframes bl{0%,49%{opacity:1}50%,100%{opacity:0}}',
'.intro-status{position:fixed;bottom:18px;left:0;right:0;z-index:13;display:flex;gap:clamp(12px,3vw,34px);justify-content:center;flex-wrap:wrap;font-size:10.5px;letter-spacing:.16em;color:#8d6a6f}',
'.intro-status span{display:inline-flex;align-items:center;gap:8px}',
'.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--red);box-shadow:0 0 12px var(--red);animation:pd 1.5s infinite}',
'.dot.g{background:var(--neon);box-shadow:0 0 12px var(--neon)}',
'.dot.o{background:var(--orange);box-shadow:0 0 12px var(--orange)}',
'@keyframes pd{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.42;transform:scale(.76)}}',
'.glitch{position:relative;animation:gsk 2.8s infinite}',
'.glitch::before,.glitch::after{content:attr(data-text);position:absolute;left:0;top:0;width:100%;overflow:hidden}',
'.glitch::before{color:var(--orange);clip-path:inset(0 0 62% 0);animation:ga 2.4s infinite linear alternate-reverse}',
'.glitch::after{color:var(--neon);clip-path:inset(58% 0 0 0);animation:gb 2.1s infinite linear alternate-reverse}',
'@keyframes ga{0%{transform:translate(0,0)}20%{transform:translate(-3px,-2px)}40%{transform:translate(2px,1px)}60%{transform:translate(-2px,2px)}80%{transform:translate(3px,-1px)}100%{transform:translate(0,0)}}',
'@keyframes gb{0%{transform:translate(0,0)}25%{transform:translate(3px,2px)}50%{transform:translate(-2px,-1px)}75%{transform:translate(2px,-2px)}100%{transform:translate(0,0)}}',
'@keyframes gsk{0%,92%,100%{transform:none}93%{transform:translateX(-2px) skewX(-1.4deg)}95%{transform:translateX(2px) skewX(1.2deg)}97%{transform:none}}',
/* login */
'.field{display:flex;flex-direction:column;gap:8px;margin-top:16px}',
'.field label{font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted)}',
'.input{width:100%;padding:14px 16px;border-radius:12px;border:1px solid rgba(255,255,255,.12);background:rgba(0,0,0,.5);color:#ffe9ec;outline:none;transition:border-color .2s,box-shadow .2s}',
'.input:focus{border-color:var(--red);box-shadow:0 0 0 3px rgba(255,43,61,.14),0 0 26px rgba(255,43,61,.22)}',
'select.input{appearance:none;background-image:linear-gradient(45deg,transparent 50%,var(--red) 50%),linear-gradient(135deg,var(--red) 50%,transparent 50%);background-position:calc(100% - 20px) 50%,calc(100% - 14px) 50%;background-size:6px 6px,6px 6px;background-repeat:no-repeat}',
'.err{margin-top:14px;color:var(--red);font-size:12px;letter-spacing:.06em;min-height:18px}',
/* dashboard */
'.dash{width:100%;max-width:1280px;margin:0 auto;padding:clamp(16px,3vw,30px) clamp(12px,3vw,26px) 60px}',
'.topbar{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;margin-bottom:20px}',
'.brand{display:flex;align-items:center;gap:12px}',
'.brand .mk{width:34px;height:34px;border-radius:9px;border:1px solid var(--red);display:grid;place-items:center;color:var(--red);font-weight:800;box-shadow:0 0 22px rgba(255,43,61,.35);text-shadow:0 0 12px rgba(255,43,61,.7)}',
'.brand .nm{font-size:13px;letter-spacing:.26em;color:#ffd9dd}',
'.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:20px}',
'.stat{position:relative;padding:16px;border-radius:14px;border:1px solid var(--red-dim);background:linear-gradient(160deg,rgba(255,43,61,.07),rgba(0,0,0,.4));box-shadow:0 0 30px rgba(255,43,61,.07),inset 0 0 40px rgba(0,0,0,.5);overflow:hidden}',
'.stat::after{content:"";position:absolute;top:0;left:-60%;width:60%;height:100%;background:linear-gradient(90deg,transparent,rgba(255,43,61,.10),transparent);animation:sh 5.5s ease-in-out infinite}',
'@keyframes sh{0%{left:-70%}55%{left:130%}100%{left:130%}}',
'.stat .k{font-size:10px;letter-spacing:.22em;color:var(--muted);text-transform:uppercase}',
'.stat .v{margin-top:9px;font-size:clamp(20px,3vw,28px);font-weight:800;color:var(--red);text-shadow:0 0 18px rgba(255,43,61,.5)}',
'.stat.g{border-color:var(--neon-dim);background:linear-gradient(160deg,rgba(0,255,156,.07),rgba(0,0,0,.4))}',
'.stat.g .v{color:var(--neon);text-shadow:0 0 18px rgba(0,255,156,.5)}',
'.stat.g::after{background:linear-gradient(90deg,transparent,rgba(0,255,156,.10),transparent)}',
'.toolbar{display:flex;gap:12px;flex-wrap:wrap;align-items:center;margin:18px 0}',
'.toolbar .input{flex:1 1 240px;padding:11px 14px;font-size:12.5px}',
'.toolbar select.input{flex:0 0 190px;padding:11px 14px;font-size:12.5px}',
'.tbl-wrap{overflow-x:auto;border-radius:12px;border:1px solid rgba(255,255,255,.07)}',
'table{width:100%;border-collapse:collapse;font-size:12px;min-width:900px}',
'thead th{position:sticky;top:0;background:rgba(6,10,14,.97);text-align:left;padding:12px 14px;font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid rgba(255,255,255,.09);white-space:nowrap}',
'tbody td{padding:12px 14px;border-bottom:1px solid rgba(255,255,255,.05);color:#c6e6da;white-space:nowrap}',
'tbody tr{cursor:pointer;transition:background .18s}',
'tbody tr:hover{background:rgba(255,43,61,.07)}',
'.chip{font-size:9.5px;letter-spacing:.13em;padding:4px 9px;border-radius:999px;border:1px solid;white-space:nowrap;display:inline-block}',
'.chip.ok{color:var(--neon);border-color:var(--neon-dim);background:rgba(0,255,156,.09)}',
'.chip.bad{color:var(--red);border-color:var(--red-dim);background:rgba(255,43,61,.10)}',
'.chip.warn{color:var(--orange);border-color:rgba(255,154,46,.4);background:rgba(255,154,46,.09)}',
'.chip.na{color:var(--muted);border-color:rgba(255,255,255,.12);background:rgba(255,255,255,.03)}',
'.pager{display:flex;gap:8px;align-items:center;justify-content:flex-end;margin-top:16px;flex-wrap:wrap;font-size:11.5px;color:var(--muted)}',
'.pager button{padding:7px 13px;border-radius:9px;border:1px solid rgba(255,255,255,.14);color:#b9d6cb;background:rgba(255,255,255,.03);font-size:11px;letter-spacing:.1em}',
'.pager button:hover:not(:disabled){border-color:var(--neon);color:var(--neon)}',
'.pager button:disabled{opacity:.35;cursor:not-allowed}',
'.timeline{position:relative;padding-left:26px;margin-top:10px;max-height:340px;overflow-y:auto}',
'.timeline::before{content:"";position:absolute;left:7px;top:6px;bottom:6px;width:1px;background:linear-gradient(180deg,var(--neon),rgba(255,43,61,.5))}',
'.tl-item{position:relative;padding:8px 0;display:flex;gap:12px;align-items:baseline;flex-wrap:wrap}',
'.tl-item::before{content:"";position:absolute;left:-24px;top:14px;width:9px;height:9px;border-radius:50%;background:var(--neon);box-shadow:0 0 12px var(--neon)}',
'.tl-item.warn::before{background:var(--orange);box-shadow:0 0 12px var(--orange)}',
'.tl-item.bad::before{background:var(--red);box-shadow:0 0 12px var(--red)}',
'.tl-time{font-size:10.5px;letter-spacing:.12em;color:var(--muted);min-width:150px}',
'.tl-label{font-size:12.5px;color:#c8e8dc}',
/* modal */
'.modal{position:fixed;inset:0;z-index:40;display:flex;align-items:center;justify-content:center;padding:20px;background:rgba(0,0,0,.82);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);animation:fin .22s ease}',
'@keyframes fin{from{opacity:0}to{opacity:1}}',
'.modal-box{width:100%;max-width:680px;max-height:88vh;overflow-y:auto;position:relative;background:rgba(8,14,18,.96);border:1px solid var(--red-dim);border-radius:18px;padding:clamp(20px,3vw,30px);box-shadow:0 40px 120px rgba(0,0,0,.85),0 0 60px rgba(255,43,61,.14);animation:min .28s cubic-bezier(.22,1,.36,1)}',
'@keyframes min{from{opacity:0;transform:translateY(18px) scale(.97)}to{opacity:1;transform:none}}',
'.kv{display:grid;grid-template-columns:auto 1fr;gap:9px 20px;font-size:12.5px;margin-top:16px}',
'.kv dt{color:var(--muted);letter-spacing:.12em;font-size:10px;text-transform:uppercase}',
'.kv dd{margin:0;color:#dcf6ea;word-break:break-all}',
'.toast-wrap{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);z-index:60;display:flex;flex-direction:column;gap:10px;align-items:center;pointer-events:none;width:min(92vw,520px)}',
'.toast{padding:12px 18px;border-radius:12px;border:1px solid var(--red-dim);background:rgba(6,10,12,.96);color:#ffd9dd;font-size:12px;letter-spacing:.06em;box-shadow:0 0 30px rgba(0,0,0,.7);animation:tin .3s ease;width:100%;text-align:center}',
'.toast.ok{border-color:var(--neon-dim);color:#d6fff0}',
'@keyframes tin{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}',
'.flash{position:fixed;inset:0;z-index:55;background:#ff2b3d;opacity:0;pointer-events:none}',
'.flash.go{animation:fo .42s ease}',
'@keyframes fo{0%{opacity:.18}100%{opacity:0}}',
'.shake{animation:shk .42s cubic-bezier(.36,.07,.19,.97)}',
'@keyframes shk{10%,90%{transform:translateX(-1.5px)}20%,80%{transform:translateX(2.5px)}30%,50%,70%{transform:translateX(-3.5px)}40%,60%{transform:translateX(3.5px)}}',
'.empty{padding:34px;text-align:center;color:var(--muted);font-size:12.5px;letter-spacing:.1em}',
'@media (prefers-reduced-motion: reduce){*,*::before,*::after{animation-duration:.001ms !important;animation-iteration-count:1 !important;transition-duration:.001ms !important}#mx{opacity:.08}}',
'@media (max-width:640px){.btn{padding:12px 16px;font-size:11px;letter-spacing:.1em}.btn-row .btn{flex:1 1 100%}.kv{grid-template-columns:1fr;gap:3px 0}.kv dd{margin-bottom:10px}.tl-time{min-width:auto}.toolbar select.input{flex:1 1 100%}}',
'</style>',
'</head>',
'<body>',
'<canvas id="mx" aria-hidden="true"></canvas>',
'<div class="fx fx-grid" aria-hidden="true"></div>',
'<div class="fx fx-smoke" aria-hidden="true"></div>',
'<div class="fx fx-vig" aria-hidden="true"></div>',
'<div class="fx fx-scan" aria-hidden="true"></div>',
'<div class="flash" id="flash" aria-hidden="true"></div>',
'',
'<!-- ===================== DEVIL INTRO ===================== -->',
'<section class="stage active" id="s-intro">',
'  <div class="intro-wrap">',
'    <div class="eye" aria-hidden="true"></div>',
'    <div class="intro-term" id="introTerm"></div>',
'    <div class="intro-big hidden" id="introBig"><span id="introBigText"></span><span class="cursor"></span></div>',
'    <div id="introBtnWrap" class="hidden" style="margin-top:8px">',
'      <button class="btn" id="introBtn">ENTER COMMAND CENTER &rarr;</button>',
'    </div>',
'  </div>',
'  <div class="intro-status">',
'    <span><i class="dot"></i>DEVIL MODE ONLINE</span>',
'    <span><i class="dot g"></i>XYVEN CORE CONNECTED</span>',
'    <span><i class="dot o"></i>WAITING FOR COMMAND</span>',
'  </div>',
'</section>',
'',
'<!-- ===================== ADMIN LOGIN ===================== -->',
'<section class="stage" id="s-login">',
'  <div class="wrap" style="max-width:520px">',
'    <div class="panel">',
'      <span class="corner tl"></span><span class="corner tr"></span><span class="corner bl"></span><span class="corner br"></span>',
'      <div class="eyebrow">restricted access</div>',
'      <h1>ADMIN <span class="red">LOGIN</span></h1>',
'      <p class="small muted" style="margin-top:10px">Authenticate to access the XYVEN command center. All access is audit-logged.</p>',
'      <div class="field">',
'        <label for="au">USERNAME / EMAIL</label>',
'        <input class="input" id="au" autocomplete="username" spellcheck="false" />',
'      </div>',
'      <div class="field">',
'        <label for="ap">PASSWORD</label>',
'        <input class="input" id="ap" type="password" autocomplete="current-password" />',
'      </div>',
'      <div class="err" id="loginErr"></div>',
'      <button class="btn block" id="loginBtn" style="margin-top:18px">LOGIN</button>',
'      <p class="small muted" style="margin-top:18px">Credentials are verified server-side with scrypt hashing. Nothing is validated in the browser.</p>',
'    </div>',
'  </div>',
'</section>',
'',
'<!-- ===================== ADMIN DASHBOARD ===================== -->',
'<section class="stage" id="s-dash">',
'  <div class="dash">',
'    <div class="topbar">',
'      <div class="brand">',
'        <div class="mk">X</div>',
'        <div>',
'          <div class="nm">XYVEN COMMAND CENTER</div>',
'          <div class="small muted" id="whoami">—</div>',
'        </div>',
'      </div>',
'      <div style="display:flex;gap:10px;flex-wrap:wrap">',
'        <button class="btn ghost sm" id="refreshBtn">REFRESH</button>',
'        <button class="btn ghost sm" id="logoutBtn">LOGOUT</button>',
'      </div>',
'    </div>',
'',
'    <div class="stats" id="stats"></div>',
'',
'    <div class="panel green">',
'      <span class="corner tl"></span><span class="corner tr"></span>',
'      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">',
'        <h3 style="color:var(--neon)">USER REGISTRY</h3>',
'        <span class="chip ok" id="userCountChip">0 RECORDS</span>',
'      </div>',
'      <div class="toolbar">',
'        <input class="input" id="search" placeholder="Search phone, ID, browser, OS, timezone…" />',
'        <select class="input" id="fConsent">',
'          <option value="">ALL CONSENT STATES</option>',
'          <option value="granted">CONSENT GRANTED</option>',
'          <option value="declined">CONSENT DECLINED</option>',
'          <option value="not_recorded">NOT RECORDED</option>',
'        </select>',
'        <select class="input" id="fOtp">',
'          <option value="">ALL OTP STATES</option>',
'          <option value="verified">VERIFIED</option>',
'          <option value="pending">PENDING</option>',
'          <option value="none">NONE</option>',
'        </select>',
'      </div>',
'      <div class="tbl-wrap">',
'        <table>',
'          <thead><tr>',
'            <th>ID</th><th>PHONE</th><th>CONSENT</th><th>OTP</th><th>DEVICE</th>',
'            <th>BROWSER</th><th>OS</th><th>TIMEZONE</th><th>CREATED AT</th>',
'          </tr></thead>',
'          <tbody id="userRows"></tbody>',
'        </table>',
'      </div>',
'      <div class="pager" id="pager"></div>',
'    </div>',
'',
'    <div class="panel" style="margin-top:22px">',
'      <span class="corner bl"></span><span class="corner br"></span>',
'      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">',
'        <h3>SECURITY EVENT TIMELINE</h3>',
'        <button class="btn ghost sm" id="clearFilterBtn">ALL EVENTS</button>',
'      </div>',
'      <div class="timeline" id="events"></div>',
'    </div>',
'',
'    <p class="small muted" style="text-align:center;margin-top:30px;line-height:1.9">',
'      XYVEN COMMAND CENTER — authorised administrators only. All actions are audit-logged.<br />',
'      Only consent-based, non-sensitive session data is displayed.',
'    </p>',
'  </div>',
'</section>',
'',
'<div class="modal hidden" id="modal"><div class="modal-box" id="modalBox"></div></div>',
'<div class="toast-wrap" id="toasts"></div>',
'',
'<script>',
'(function(){',
'"use strict";',
'var $=function(s){return document.querySelector(s);};',
'var RM=window.matchMedia("(prefers-reduced-motion: reduce)").matches;',
'var PAGE=1,LIMIT=15,TOTAL=0;',
'',
'function sleep(ms){return new Promise(function(r){setTimeout(r,RM?Math.min(ms,60):ms);});}',
'function api(p,o){',
'  return fetch(p,Object.assign({credentials:"same-origin",headers:{"Content-Type":"application/json"}},o||{}))',
'    .then(function(r){return r.json().catch(function(){return {};}).then(function(j){',
'      if(!r.ok){var e=new Error(j.message||("HTTP "+r.status));e.status=r.status;throw e;}',
'      return j;',
'    });});',
'}',
'function toast(m,ok){',
'  var t=document.createElement("div");',
'  t.className="toast"+(ok?" ok":"");',
'  t.textContent=m;',
'  $("#toasts").appendChild(t);',
'  setTimeout(function(){t.style.opacity="0";t.style.transition="opacity .4s";},2600);',
'  setTimeout(function(){t.remove();},3200);',
'}',
'function flash(){var f=$("#flash");f.classList.remove("go");void f.offsetWidth;f.classList.add("go");}',
'function shake(){if(RM)return;document.body.classList.remove("shake");void document.body.offsetWidth;document.body.classList.add("shake");setTimeout(function(){document.body.classList.remove("shake");},460);}',
'function screen(id){',
'  var all=document.querySelectorAll(".stage");',
'  for(var i=0;i<all.length;i++)all[i].classList.remove("active");',
'  var el=document.getElementById(id);',
'  if(el){el.classList.add("active");el.scrollTop=0;}',
'}',
'function esc(s){',
'  if(s===null||s===undefined)return "—";',
'  return String(s).replace(/[&<>"]/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;"}[c];});',
'}',
'',
'/* ---------- red matrix particles ---------- */',
'(function(){',
'  var c=document.getElementById("mx");if(!c)return;',
'  var ctx=c.getContext("2d"),chars="01XYVEN<>/\\\\[]{}#$%&*+=ABCDEF",size=16,cols,drops;',
'  function rs(){c.width=window.innerWidth;c.height=window.innerHeight;cols=Math.floor(c.width/size);drops=[];for(var i=0;i<cols;i++)drops[i]=Math.random()*-60;}',
'  rs();window.addEventListener("resize",rs);',
'  function draw(){',
'    ctx.fillStyle="rgba(3,6,10,.12)";ctx.fillRect(0,0,c.width,c.height);',
'    ctx.font=size+"px monospace";',
'    for(var i=0;i<cols;i++){',
'      var ch=chars[Math.floor(Math.random()*chars.length)];',
'      ctx.fillStyle=Math.random()>.97?"rgba(255,154,46,.85)":"rgba(255,43,61,.60)";',
'      ctx.fillText(ch,i*size,drops[i]*size);',
'      if(drops[i]*size>c.height&&Math.random()>.975)drops[i]=0;',
'      drops[i]+=.6;',
'    }',
'  }',
'  if(!RM)setInterval(draw,70);',
'})();',
'',
'/* ---------- typing helper ---------- */',
'function typeInto(el,text,speed){',
'  return new Promise(function(res){',
'    var i=0;',
'    if(RM){el.textContent=text;return res();}',
'    (function tick(){',
'      el.textContent=text.slice(0,++i);',
'      if(i>=text.length)return res();',
'      setTimeout(tick,speed+Math.random()*speed*.7);',
'    })();',
'  });',
'}',
'',
'/* ---------- devil intro ---------- */',
'var INTRO_A=["> ACCESSING XYVEN COMMAND CENTER...","> ADMIN DETECTED...","> MASTER ACCESS GRANTED..."];',
'var INTRO_B=["HELLO BOSS...","I AM WAITING FOR YOUR ORDER."];',
'var INTRO_C=["SYSTEM IS READY.","COMMAND CENTER IS ONLINE.","LET\\'S BREAK THE LIMITS."];',
'',
'async function runIntro(){',
'  var term=$("#introTerm");',
'  for(var i=0;i<INTRO_A.length;i++){',
'    var d=document.createElement("div");',
'    d.className="l";',
'    term.appendChild(d);',
'    await typeInto(d,INTRO_A[i],24);',
'    await sleep(220);',
'  }',
'  await sleep(420);',
'  var big=$("#introBig"),bigText=$("#introBigText");',
'  big.classList.remove("hidden");',
'  for(var a=0;a<INTRO_B.length;a++){',
'    big.classList.add("glitch");',
'    big.setAttribute("data-text",INTRO_B[a]);',
'    await typeInto(bigText,INTRO_B[a],56);',
'    if(a<INTRO_B.length-1){await sleep(500);bigText.textContent="";}',
'  }',
'  shake();',
'  await sleep(1500);',
'  big.classList.remove("glitch");',
'  big.removeAttribute("data-text");',
'  bigText.textContent="";',
'  for(var b=0;b<INTRO_C.length;b++){',
'    await typeInto(bigText,INTRO_C[b],42);',
'    if(b<INTRO_C.length-1){await sleep(420);bigText.textContent="";}',
'  }',
'  await sleep(700);',
'  $("#introBtnWrap").classList.remove("hidden");',
'}',
'',
'$("#introBtn").addEventListener("click",async function(){',
'  flash();',
'  try{',
'    var me=await api("/api/admin/me");',
'    if(me&&me.authenticated){await openDashboard(me);return;}',
'  }catch(e){}',
'  screen("s-login");',
'  setTimeout(function(){$("#au").focus();},260);',
'});',
'',
'/* ---------- login ---------- */',
'async function doLogin(){',
'  var u=$("#au").value.trim(),p=$("#ap").value,err=$("#loginErr"),btn=$("#loginBtn");',
'  err.textContent="";',
'  if(!u||!p){err.textContent="Username and password are required.";shake();return;}',
'  btn.disabled=true;btn.textContent="AUTHENTICATING...";',
'  try{',
'    await api("/api/admin/login",{method:"POST",body:JSON.stringify({username:u,password:p})});',
'    flash();',
'    $("#ap").value="";',
'    var me=await api("/api/admin/me");',
'    await openDashboard(me);',
'  }catch(e){',
'    err.textContent=e.message||"Login failed.";',
'    shake();',
'  }finally{',
'    btn.disabled=false;btn.textContent="LOGIN";',
'  }',
'}',
'$("#loginBtn").addEventListener("click",doLogin);',
'$("#ap").addEventListener("keydown",function(e){if(e.key==="Enter")doLogin();});',
'$("#au").addEventListener("keydown",function(e){if(e.key==="Enter")$("#ap").focus();});',
'',
'/* ---------- dashboard ---------- */',
'async function openDashboard(me){',
'  screen("s-dash");',
'  $("#whoami").textContent="AUTHENTICATED AS "+(me.username||"admin").toUpperCase()+" // SESSION "+(me.sessionId||"—").slice(0,10).toUpperCase();',
'  await Promise.all([loadStats(),loadUsers(),loadEvents()]);',
'}',
'',
'async function loadStats(){',
'  try{',
'    var d=await api("/api/admin/dashboard");',
'    var s=d.stats||{};',
'    var items=[',
'      ["TOTAL USERS",s.totalUsers,false],',
'      ["VERIFIED NUMBERS",s.verifiedNumbers,true],',
'      ["CONSENT GRANTED",s.consentGranted,true],',
'      ["CONSENT DECLINED",s.consentDeclined,false],',
'      ["ACTIVE SESSIONS",s.activeSessions,true],',
'      ["SECURITY EVENTS",s.securityEvents,false]',
'    ];',
'    var box=$("#stats");box.innerHTML="";',
'    items.forEach(function(it){',
'      var el=document.createElement("div");',
'      el.className="stat"+(it[2]?" g":"");',
'      el.innerHTML=\'<div class="k">\'+esc(it[0])+\'</div><div class="v">\'+esc(it[1]===undefined?0:it[1])+\'</div>\';',
'      box.appendChild(el);',
'    });',
'  }catch(e){toast("Stats unavailable: "+e.message);}',
'}',
'',
'function consentChip(c){',
'  if(c==="granted")return \'<span class="chip ok">GRANTED</span>\';',
'  if(c==="declined")return \'<span class="chip bad">DECLINED</span>\';',
'  return \'<span class="chip na">NOT SET</span>\';',
'}',
'function otpChip(s){',
'  if(s==="verified")return \'<span class="chip ok">VERIFIED</span>\';',
'  if(s==="pending")return \'<span class="chip warn">PENDING</span>\';',
'  return \'<span class="chip na">NONE</span>\';',
'}',
'',
'async function loadUsers(){',
'  var q=$("#search").value.trim();',
'  var consent=$("#fConsent").value;',
'  var otp=$("#fOtp").value;',
'  var url="/api/admin/users?page="+PAGE+"&limit="+LIMIT;',
'  if(q)url+="&search="+encodeURIComponent(q);',
'  if(consent)url+="&consent="+encodeURIComponent(consent);',
'  if(otp)url+="&otp="+encodeURIComponent(otp);',
'  try{',
'    var d=await api(url);',
'    TOTAL=d.total||0;',
'    var rows=$("#userRows");rows.innerHTML="";',
'    $("#userCountChip").textContent=TOTAL+" RECORD"+(TOTAL===1?"":"S");',
'    if(!d.users||!d.users.length){',
'      rows.innerHTML=\'<tr><td colspan="9"><div class="empty">NO RECORDS MATCH THE CURRENT FILTERS</div></td></tr>\';',
'    }else{',
'      d.users.forEach(function(u){',
'        var tr=document.createElement("tr");',
'        tr.innerHTML=',
'          "<td>"+esc(u.id)+"</td>"+',
'          "<td>"+(u.phone?esc(u.phone):\'<span class="chip na">NOT SHARED</span>\')+"</td>"+',
'          "<td>"+consentChip(u.consent)+"</td>"+',
'          "<td>"+otpChip(u.otpStatus)+"</td>"+',
'          "<td>"+esc(u.device)+"</td>"+',
'          "<td>"+esc(u.browser)+"</td>"+',
'          "<td>"+esc(u.os)+"</td>"+',
'          "<td>"+esc(u.timezone)+"</td>"+',
'          "<td>"+esc(new Date(u.createdAt).toLocaleString())+"</td>";',
'        tr.addEventListener("click",function(){openUser(u.id);});',
'        rows.appendChild(tr);',
'      });',
'    }',
'    renderPager();',
'  }catch(e){',
'    if(e.status===401){screen("s-login");toast("Session expired. Please log in again.");return;}',
'    toast("Could not load users: "+e.message);',
'  }',
'}',
'',
'function renderPager(){',
'  var pages=Math.max(1,Math.ceil(TOTAL/LIMIT));',
'  var p=$("#pager");p.innerHTML="";',
'  var info=document.createElement("span");',
'  info.textContent="PAGE "+PAGE+" / "+pages+"  •  "+TOTAL+" TOTAL";',
'  p.appendChild(info);',
'  var prev=document.createElement("button");prev.textContent="PREV";',
'  prev.disabled=PAGE<=1;',
'  prev.addEventListener("click",function(){PAGE--;loadUsers();});',
'  var next=document.createElement("button");next.textContent="NEXT";',
'  next.disabled=PAGE>=pages;',
'  next.addEventListener("click",function(){PAGE++;loadUsers();});',
'  p.appendChild(prev);p.appendChild(next);',
'}',
'',
'/* ---------- user modal ---------- */',
'async function openUser(id){',
'  try{',
'    var u=await api("/api/admin/users/"+encodeURIComponent(id));',
'    var rows=[',
'      ["USER ID",u.id],["PHONE",u.phone||"NOT SHARED"],["CONSENT STATUS",(u.consent||"").toUpperCase()],',
'      ["OTP STATUS",(u.otpStatus||"").toUpperCase()],["DEVICE",u.device],["BROWSER",u.browser+" "+(u.browserVersion||"")],',
'      ["OS",u.os],["SCREEN",u.screen],["VIEWPORT",u.viewport],["LANGUAGE",u.language],',
'      ["TIMEZONE",u.timezone],["ONLINE",u.online],["CREATED",new Date(u.createdAt).toLocaleString()],',
'      ["LAST ACTIVE",new Date(u.lastActive).toLocaleString()]',
'    ];',
'    var html=\'<span class="corner tl"></span><span class="corner tr"></span>\';',
'    html+=\'<div class="eyebrow">restricted record</div>\';',
'    html+=\'<h1>USER <span class="red">SECURITY PROFILE</span></h1>\';',
'    html+=\'<dl class="kv">\';',
'    rows.forEach(function(r){html+="<dt>"+esc(r[0])+"</dt><dd>"+esc(r[1])+"</dd>";});',
'    html+=\'</dl>\';',
'    if(u.events&&u.events.length){',
'      html+=\'<h3 style="margin-top:24px">USER EVENT LOG</h3><div class="timeline">\';',
'      u.events.forEach(function(e){',
'        var cls=e.kind==="ok"?"":(e.kind==="warn"?" warn":" bad");',
'        html+=\'<div class="tl-item\'+cls+\'"><span class="tl-time">\'+esc(new Date(e.at).toLocaleTimeString())+\'</span><span class="tl-label">\'+esc(e.label)+\'</span></div>\';',
'      });',
'      html+=\'</div>\';',
'    }',
'    html+=\'<div class="btn-row">\';',
'    html+=\'<button class="btn ghost" id="anonBtn">ANONYMIZE USER</button>\';',
'    html+=\'<button class="btn" id="delBtn">DELETE USER DATA</button>\';',
'    html+=\'<button class="btn ghost" id="closeBtn">CLOSE</button>\';',
'    html+=\'</div>\';',
'    $("#modalBox").innerHTML=html;',
'    $("#modal").classList.remove("hidden");',
'',
'    $("#closeBtn").addEventListener("click",closeModal);',
'    $("#anonBtn").addEventListener("click",function(){actOnUser(id,"anonymize");});',
'    $("#delBtn").addEventListener("click",function(){actOnUser(id,"delete");});',
'  }catch(e){',
'    toast("Could not load user: "+e.message);',
'  }',
'}',
'',
'function closeModal(){$("#modal").classList.add("hidden");$("#modalBox").innerHTML="";}',
'$("#modal").addEventListener("click",function(e){if(e.target===$("#modal"))closeModal();});',
'',
'async function actOnUser(id,action){',
'  var label=action==="delete"?"DELETE all data for this user?":"ANONYMIZE this user record?";',
'  if(!window.confirm(label))return;',
'  try{',
'    if(action==="delete"){',
'      await api("/api/admin/users/"+encodeURIComponent(id),{method:"DELETE"});',
'      toast("User data deleted.",true);',
'    }else{',
'      await api("/api/admin/users/"+encodeURIComponent(id)+"/anonymize",{method:"POST"});',
'      toast("User record anonymized.",true);',
'    }',
'    closeModal();',
'    await Promise.all([loadStats(),loadUsers(),loadEvents()]);',
'  }catch(e){toast("Action failed: "+e.message);}',
'}',
'',
'/* ---------- events ---------- */',
'async function loadEvents(){',
'  try{',
'    var d=await api("/api/admin/events?limit=80");',
'    var box=$("#events");box.innerHTML="";',
'    if(!d.events||!d.events.length){',
'      box.innerHTML=\'<div class="empty">NO SECURITY EVENTS RECORDED</div>\';',
'      return;',
'    }',
'    d.events.forEach(function(e){',
'      var cls=e.kind==="ok"?"":(e.kind==="warn"?" warn":" bad");',
'      var el=document.createElement("div");',
'      el.className="tl-item"+cls;',
'      el.innerHTML=\'<span class="tl-time">\'+esc(new Date(e.at).toLocaleString())+\'</span><span class="tl-label">\'+esc(e.label)+\'</span>\';',
'      box.appendChild(el);',
'    });',
'  }catch(e){',
'    if(e.status===401)return;',
'    toast("Events unavailable: "+e.message);',
'  }',
'}',
'',
'/* ---------- controls ---------- */',
'var searchTimer=null;',
'$("#search").addEventListener("input",function(){',
'  clearTimeout(searchTimer);',
'  searchTimer=setTimeout(function(){PAGE=1;loadUsers();},320);',
'});',
'$("#fConsent").addEventListener("change",function(){PAGE=1;loadUsers();});',
'$("#fOtp").addEventListener("change",function(){PAGE=1;loadUsers();});',
'$("#refreshBtn").addEventListener("click",function(){loadStats();loadUsers();loadEvents();toast("Dashboard refreshed.",true);});',
'$("#clearFilterBtn").addEventListener("click",function(){$("#search").value="";$("#fConsent").value="";$("#fOtp").value="";PAGE=1;loadUsers();});',
'$("#logoutBtn").addEventListener("click",async function(){',
'  try{await api("/api/admin/logout",{method:"POST"});}catch(e){}',
'  toast("Logged out.",true);',
'  screen("s-login");',
'  $("#au").value="";$("#ap").value="";',
'});',
'',
'/* ---------- boot ---------- */',
'runIntro();',
'})();',
'</script>',
'</body>',
'</html>'
  ].join('\n');
}

/* ============================================================================
   11. PAGE ROUTES
   ============================================================================ */

app.get('/admin.html', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  res.type('html').send(renderAdminHTML());
});

app.get('/admin', (req, res) => res.redirect('/admin.html'));

app.get('/healthz', (req, res) => {
  res.json({ status: 'ok', service: 'xyven-world', env: NODE_ENV, time: new Date().toISOString() });
});

const INDEX_FILE = path.join(__dirname, 'index.html');

app.get('/', (req, res) => {
  res.setHeader('Cache-Control', 'no-cache');
  res.sendFile(INDEX_FILE, (err) => {
    if (err) {
      res.status(500).type('html').send(
        '<pre style="color:#0f9;background:#03060a;padding:24px;font-family:monospace">' +
        'XYVEN WORLD — index.html not found next to server.js.\n' +
        'Place index.html in the same directory as server.js and restart.</pre>'
      );
    }
  });
});

/* ============================================================================
   12. PUBLIC API — user session, consent, phone, device
   ============================================================================ */

/* ---------- POST /api/consent ---------- */
app.post('/api/consent', (req, res, next) => {
  try {
    const user = ensureUserSession(req, res);
    const granted = req.body && req.body.granted === true;

    user.consent = granted ? 'granted' : 'declined';
    user.lastActive = new Date().toISOString();

    pushUserEvent(user, granted ? 'CONSENT RECEIVED' : 'CONSENT DECLINED', granted ? 'ok' : 'warn');
    recordEvent(granted ? 'CONSENT RECEIVED' : 'CONSENT DECLINED', granted ? 'ok' : 'warn', user.id, req);
    saveDB();

    res.json({ ok: true, consent: user.consent, sessionId: user.sessionId });
  } catch (err) { next(err); }
});

/* ---------- POST /api/phone/request-otp ---------- */
app.post('/api/phone/request-otp', otpLimiter, (req, res, next) => {
  try {
    const user = ensureUserSession(req, res);

    if (user.consent !== 'granted') {
      return res.status(403).json({
        error: 'consent_required',
        message: 'Phone collection requires explicit consent. Please allow consent first, or continue without optional data.'
      });
    }

    const country = cleanString(req.body && req.body.country, 8) || '+91';
    if (!/^\+\d{1,4}$/.test(country)) {
      return res.status(400).json({ error: 'invalid_country', message: 'Invalid country code.' });
    }

    const digits = cleanDigits(req.body && req.body.phone, 15);
    if (digits.length < 6 || digits.length > 15) {
      return res.status(400).json({ error: 'invalid_phone', message: 'Enter a valid phone number (6–15 digits).' });
    }

    // Per-session request throttle (in addition to the IP limiter)
    const now = Date.now();
    user.otpRequests = (user.otpRequests || []).filter((t) => now - t < 10 * 60 * 1000);
    if (user.otpRequests.length >= OTP_MAX_REQUESTS) {
      return res.status(429).json({ error: 'otp_throttled', message: 'Too many code requests. Please wait a few minutes.' });
    }
    user.otpRequests.push(now);

    // Generate code and store ONLY a keyed hash — never plaintext.
    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    user.otp = {
      hash: hmac('otp:' + user.sessionId + ':' + code),
      expires: now + OTP_TTL_MS,
      attempts: 0,
      createdAt: new Date().toISOString()
    };
    user.phone = { country: country, number: digits };
    user.phoneVerified = false;
    user.lastActive = new Date().toISOString();

    pushUserEvent(user, 'VERIFICATION CODE REQUESTED', 'warn');
    recordEvent('VERIFICATION CODE REQUESTED', 'warn', user.id, req);
    saveDB();

    // Demo mode: no SMS provider configured on this deployment.
    const smsConfigured = !!(process.env.SMS_PROVIDER_KEY && process.env.SMS_PROVIDER_URL);

    const payload = {
      ok: true,
      masked: maskPhone(country, digits),
      expiresInSeconds: Math.floor(OTP_TTL_MS / 1000),
      demo: !smsConfigured
    };
    if (!smsConfigured) {
      payload.devCode = code;
      payload.notice = 'DEMO MODE — no SMS provider configured. This code is shown for development testing only.';
    }
    res.json(payload);
  } catch (err) { next(err); }
});

/* ---------- POST /api/phone/verify-otp ---------- */
app.post('/api/phone/verify-otp', otpLimiter, (req, res, next) => {
  try {
    const user = ensureUserSession(req, res);

    if (!user.otp) {
      return res.status(400).json({ error: 'no_otp', message: 'No active verification code. Please request a new one.' });
    }
    if (user.otp.expires < Date.now()) {
      user.otp = null;
      saveDB();
      return res.status(400).json({ error: 'otp_expired', message: 'This code has expired. Please request a new one.' });
    }
    if (user.otp.attempts >= OTP_MAX_ATTEMPTS) {
      user.otp = null;
      saveDB();
      return res.status(429).json({ error: 'otp_locked', message: 'Too many incorrect attempts. Please request a new code.' });
    }

    const code = cleanDigits(req.body && req.body.code, 6);
    if (code.length !== 6) {
      return res.status(400).json({ error: 'invalid_code', message: 'Enter the complete 6-digit code.' });
    }

    const expected = hmac('otp:' + user.sessionId + ':' + code);
    if (!safeEqual(expected, user.otp.hash)) {
      user.otp.attempts += 1;
      saveDB();
      return res.status(400).json({ error: 'invalid_code', message: 'Incorrect code. Please try again.' });
    }

    user.phoneVerified = true;
    user.otp = null;
    user.lastActive = new Date().toISOString();

    pushUserEvent(user, 'PHONE VERIFIED', 'ok');
    recordEvent('PHONE VERIFIED', 'ok', user.id, req);
    saveDB();

    res.json({ ok: true, verified: true, phone: maskPhone(user.phone.country, user.phone.number) });
  } catch (err) { next(err); }
});

/* ---------- POST /api/device ---------- */
const ALLOWED_DEVICE_FIELDS = [
  'deviceType', 'browser', 'browserVersion', 'os',
  'screenResolution', 'viewport', 'language', 'timezone', 'online'
];

app.post('/api/device', (req, res, next) => {
  try {
    const user = ensureUserSession(req, res);
    const body = req.body || {};

    if (user.consent !== 'granted') {
      // Decline path — nothing is stored beyond the session identifier.
      pushUserEvent(user, 'DEVICE PROFILE SKIPPED (LIMITED MODE)', 'warn');
      saveDB();
      return res.json({ ok: true, stored: false, mode: 'limited' });
    }

    const profile = {};
    ALLOWED_DEVICE_FIELDS.forEach((key) => {
      if (body[key] !== undefined && body[key] !== null) {
        profile[key] = cleanString(body[key], 120);
      }
    });

    user.device = profile;
    user.lastActive = new Date().toISOString();

    pushUserEvent(user, 'DEVICE PROFILE CREATED', 'ok');
    recordEvent('DEVICE PROFILE CREATED', 'ok', user.id, req);
    saveDB();

    res.json({ ok: true, stored: true, profile: profile });
  } catch (err) { next(err); }
});

/* ---------- GET /api/me ---------- */
app.get('/api/me', (req, res, next) => {
  try {
    const user = ensureUserSession(req, res);
    res.setHeader('Cache-Control', 'no-store');
    res.json(publicUser(user));
  } catch (err) { next(err); }
});

/* ---------- DELETE /api/me — user-initiated erasure ---------- */
app.delete('/api/me', (req, res, next) => {
  try {
    const cookies = parseCookies(req);
    const sessionId = unsignValue(cookies[COOKIE_USER]);
    const user = findUserBySessionId(sessionId);

    if (user) {
      user.consent = 'declined';
      user.phone = null;
      user.phoneVerified = false;
      user.otp = null;
      user.otpRequests = [];
      user.device = null;
      user.deleted = true;
      user.events = [];
      pushUserEvent(user, 'USER DATA DELETED / ANONYMIZED', 'bad');
      saveDBNow();
      recordEvent('USER DATA DELETED BY USER', 'bad', user.id, req);
    }

    clearCookie(res, COOKIE_USER);
    res.json({ ok: true, deleted: true });
  } catch (err) { next(err); }
});

/* ============================================================================
   13. ADMIN API
   ============================================================================ */

/* ---------- POST /api/admin/login ---------- */
app.post('/api/admin/login', loginLimiter, (req, res, next) => {
  try {
    const username = cleanString(req.body && req.body.username, 120).toLowerCase();
    const password = typeof (req.body && req.body.password) === 'string' ? req.body.password : '';

    if (!username || !password) {
      return res.status(400).json({ error: 'invalid_input', message: 'Username and password are required.' });
    }
    if (password.length > 200) {
      return res.status(400).json({ error: 'invalid_input', message: 'Invalid credentials.' });
    }

    const usernameOk = safeEqual(username, ADMIN_USERNAME);
    const passwordOk = verifyPassword(password, ADMIN_PASSWORD_HASH);

    // Constant-time-ish: always perform both checks before responding.
    if (!usernameOk || !passwordOk) {
      recordEvent('FAILED ADMIN LOGIN ATTEMPT', 'bad', null, req);
      return res.status(401).json({ error: 'invalid_credentials', message: 'Invalid username or password.' });
    }

    const token = randomId(32);
    db.adminSessions[token] = {
      username: ADMIN_USERNAME,
      createdAt: new Date().toISOString(),
      expires: Date.now() + ADMIN_TTL_MS,
      actor: hmac('ip:' + ((req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim())).slice(0, 12)
    };
    saveDB();

    setCookie(res, COOKIE_ADMIN, signValue(token), {
      maxAge: ADMIN_TTL_MS,
      httpOnly: true,
      sameSite: 'Strict'
    });

    recordEvent('ADMIN LOGIN SUCCESS', 'ok', null, req);
    res.json({ ok: true, username: ADMIN_USERNAME, sessionId: token.slice(0, 16) });
  } catch (err) { next(err); }
});

/* ---------- GET /api/admin/me ---------- */
app.get('/api/admin/me', (req, res) => {
  const admin = isAdmin(req);
  if (!admin) return res.status(401).json({ authenticated: false });
  res.json({
    authenticated: true,
    username: admin.username,
    sessionId: admin.actor || 'admin',
    expires: admin.expires
  });
});

/* ---------- POST /api/admin/logout ---------- */
app.post('/api/admin/logout', (req, res) => {
  const cookies = parseCookies(req);
  const token = unsignValue(cookies[COOKIE_ADMIN]);
  if (token && db.adminSessions[token]) {
    delete db.adminSessions[token];
    saveDB();
    recordEvent('ADMIN LOGOUT', 'warn', null, req);
  }
  clearCookie(res, COOKIE_ADMIN);
  res.json({ ok: true });
});

/* ---------- GET /api/admin/dashboard ---------- */
app.get('/api/admin/dashboard', requireAdmin, (req, res, next) => {
  try {
    const now = Date.now();
    const activeWindow = 30 * 60 * 1000;

    const users = db.users;
    const stats = {
      totalUsers: users.length,
      verifiedNumbers: users.filter((u) => u.phoneVerified).length,
      consentGranted: users.filter((u) => u.consent === 'granted').length,
      consentDeclined: users.filter((u) => u.consent === 'declined').length,
      activeSessions: users.filter((u) => {
        const t = new Date(u.lastActive).getTime();
        return !isNaN(t) && now - t < activeWindow;
      }).length,
      securityEvents: db.events.length
    };

    res.setHeader('Cache-Control', 'no-store');
    res.json({ ok: true, stats: stats, generatedAt: new Date().toISOString() });
  } catch (err) { next(err); }
});

/* ---------- GET /api/admin/users ---------- */
app.get('/api/admin/users', requireAdmin, (req, res, next) => {
  try {
    const search = cleanString(req.query.search, 120).toLowerCase();
    const consent = cleanString(req.query.consent, 20).toLowerCase();
    const otp = cleanString(req.query.otp, 20).toLowerCase();

    let page = parseInt(req.query.page, 10);
    let limit = parseInt(req.query.limit, 10);
    if (!Number.isFinite(page) || page < 1) page = 1;
    if (!Number.isFinite(limit) || limit < 1) limit = 25;
    if (limit > 100) limit = 100;

    let list = db.users.slice();

    if (consent) list = list.filter((u) => (u.consent || 'not_recorded') === consent);

    if (otp) {
      list = list.filter((u) => {
        const status = u.phoneVerified ? 'verified' : (u.otp ? 'pending' : 'none');
        return status === otp;
      });
    }

    if (search) {
      list = list.filter((u) => {
        const haystack = [
          u.id, u.sessionId,
          u.phone ? u.phone.country + u.phone.number : '',
          u.consent,
          u.device ? u.device.deviceType : '',
          u.device ? u.device.browser : '',
          u.device ? u.device.browserVersion : '',
          u.device ? u.device.os : '',
          u.device ? u.device.timezone : '',
          u.device ? u.device.language : ''
        ].join(' ').toLowerCase();
        return haystack.indexOf(search) >= 0;
      });
    }

    list.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    const total = list.length;
    const start = (page - 1) * limit;
    const paged = list.slice(start, start + limit).map(adminUserSummary);

    res.setHeader('Cache-Control', 'no-store');
    res.json({ ok: true, total: total, page: page, limit: limit, users: paged });
  } catch (err) { next(err); }
});

/* ---------- GET /api/admin/users/:id ---------- */
app.get('/api/admin/users/:id', requireAdmin, (req, res, next) => {
  try {
    const id = cleanString(req.params.id, 40);
    const user = db.users.find((u) => u.id === id);
    if (!user) return res.status(404).json({ error: 'not_found', message: 'User not found.' });

    res.setHeader('Cache-Control', 'no-store');
    res.json(adminUserDetail(user));
  } catch (err) { next(err); }
});

/* ---------- DELETE /api/admin/users/:id ---------- */
app.delete('/api/admin/users/:id', requireAdmin, (req, res, next) => {
  try {
    const id = cleanString(req.params.id, 40);
    const idx = db.users.findIndex((u) => u.id === id);
    if (idx < 0) return res.status(404).json({ error: 'not_found', message: 'User not found.' });

    db.users.splice(idx, 1);
    saveDBNow();
    recordEvent('ADMIN DELETED USER ' + id, 'bad', id, req);

    res.json({ ok: true, deleted: id });
  } catch (err) { next(err); }
});

/* ---------- POST /api/admin/users/:id/anonymize ---------- */
app.post('/api/admin/users/:id/anonymize', requireAdmin, (req, res, next) => {
  try {
    const id = cleanString(req.params.id, 40);
    const user = db.users.find((u) => u.id === id);
    if (!user) return res.status(404).json({ error: 'not_found', message: 'User not found.' });

    user.phone = null;
    user.phoneVerified = false;
    user.otp = null;
    user.otpRequests = [];
    user.device = null;
    user.consent = 'declined';
    user.deleted = true;
    user.events = [];
    pushUserEvent(user, 'RECORD ANONYMIZED BY ADMIN', 'bad');
    saveDBNow();

    recordEvent('ADMIN ANONYMIZED USER ' + id, 'warn', id, req);
    res.json({ ok: true, anonymized: id });
  } catch (err) { next(err); }
});

/* ---------- GET /api/admin/events ---------- */
app.get('/api/admin/events', requireAdmin, (req, res, next) => {
  try {
    let limit = parseInt(req.query.limit, 10);
    if (!Number.isFinite(limit) || limit < 1) limit = 100;
    if (limit > 500) limit = 500;

    const events = db.events.slice(-limit).reverse().map((e) => ({
      id: e.id,
      label: e.label,
      kind: e.kind,
      at: e.at,
      userId: e.userId
    }));

    res.setHeader('Cache-Control', 'no-store');
    res.json({ ok: true, events: events, total: db.events.length });
  } catch (err) { next(err); }
});

/* ============================================================================
   14. 404 + ERROR HANDLING
   ============================================================================ */

app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'not_found', message: 'Endpoint not found.' });
  }
  next();
});

// SPA-style fallback: unknown non-API GET routes return the main app.
app.get(/^\/(?!api\/|admin).*/, (req, res) => {
  res.setHeader('Cache-Control', 'no-cache');
  res.sendFile(INDEX_FILE, (err) => {
    if (err) res.status(404).type('text').send('Not found');
  });
});

// Central error handler — never leak stack traces to clients.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);

  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'invalid_json', message: 'Malformed request body.' });
  }
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'payload_too_large', message: 'Request body is too large.' });
  }

  console.error('[XYVEN] Unhandled error:', err && err.message ? err.message : err);

  if (req.path && req.path.startsWith('/api/')) {
    return res.status(500).json({ error: 'server_error', message: 'An internal error occurred.' });
  }
  res.status(500).type('text').send('Internal server error');
});

/* ============================================================================
   15. BOOT
   ============================================================================ */

loadDB();

const server = app.listen(PORT, () => {
  const line = '─'.repeat(64);
  console.log('\n' + line);
  console.log('  XYVEN WORLD — COMMAND INTERFACE ONLINE');
  console.log(line);
  console.log('  Interface   : http://localhost:' + PORT + '/');
  console.log('  Admin panel : http://localhost:' + PORT + '/admin.html');
  console.log('  Datastore   : ' + DATA_FILE);
  console.log('  Environment : ' + NODE_ENV);
  console.log('  Admin user  : ' + ADMIN_USERNAME);
  if (!process.env.ADMIN_PASSWORD && !process.env.ADMIN_PASSWORD_HASH) {
    console.log('  Admin pass  : xyven-admin   (DEFAULT — change before deploying)');
  }
  if (!process.env.SESSION_SECRET) {
    console.log('  Secret      : ephemeral (set SESSION_SECRET for stable sessions)');
  }
  console.log('  SMS mode    : ' + (process.env.SMS_PROVIDER_KEY ? 'provider configured' : 'DEMO (codes shown in UI)'));
  console.log(line + '\n');
});

function shutdown(signal) {
  console.log('\n[XYVEN] ' + signal + ' received. Persisting datastore and shutting down…');
  saveDBNow();
  server.close(() => {
    console.log('[XYVEN] Shutdown complete.');
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 5000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('unhandledRejection', (reason) => {
  console.error('[XYVEN] Unhandled rejection:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('[XYVEN] Uncaught exception:', err);
  saveDBNow();
});
