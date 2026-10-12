import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import fs from 'fs';
import path from 'path';
import { DATA_DIR, secret, settings } from './config.js';
import { JsonStore } from './store.js';
import { generateSecret, verifyTotp, otpauthUri } from './totp.js';

const DUMMY_HASH = '$2a$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ012345';

const usersStore = new JsonStore('users.json', { users: [] }, { critical: true });

export function listUsers() {
  return usersStore.data.users;
}

export function findUser(username) {
  return usersStore.data.users.find(u => u.username === username);
}

export function userDirs(username) {
  const base = path.join(DATA_DIR, 'users', username);
  return {
    base,
    files: path.join(base, 'files'),
    trash: path.join(base, 'trash'),
    thumbs: path.join(base, 'thumbs') // derived thumbnail cache (not user-visible)
  };
}

const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{1,31}$/;

export function createUser({ username, password, isAdmin = false, quotaMB = null }) {
  username = String(username || '').toLowerCase().trim();
  if (!USERNAME_RE.test(username)) {
    throw new Error('Username must be 2-32 chars: lowercase letters, numbers, dot, dash, underscore.');
  }
  if (findUser(username)) throw new Error('User already exists.');
  if (!password || String(password).length < 6) throw new Error('Password must be at least 6 characters.');
  const now = Date.now();
  const user = {
    username,
    passwordHash: bcrypt.hashSync(String(password), 10),
    isAdmin: !!isAdmin,
    quotaMB: quotaMB === null || quotaMB === undefined ? settings.defaultQuotaMB : Math.max(0, Number(quotaMB) || 0),
    createdAt: now,
    passwordChangedAt: now
  };
  usersStore.data.users.push(user);
  usersStore.save();
  const dirs = userDirs(username);
  fs.mkdirSync(dirs.files, { recursive: true });
  fs.mkdirSync(dirs.trash, { recursive: true });
  return user;
}

export function updateUser(username, patch) {
  const user = findUser(username);
  if (!user) throw new Error('User not found.');
  if (patch.password !== undefined && patch.password !== '') {
    if (String(patch.password).length < 6) throw new Error('Password must be at least 6 characters.');
    user.passwordHash = bcrypt.hashSync(String(patch.password), 10);
    // Invalidate any existing session tokens issued before this change.
    user.passwordChangedAt = Date.now();
  }
  if (patch.isAdmin !== undefined) user.isAdmin = !!patch.isAdmin;
  if (patch.quotaMB !== undefined) user.quotaMB = Math.max(0, Number(patch.quotaMB) || 0);
  usersStore.save();
  return user;
}

export function deleteUser(username) {
  const idx = usersStore.data.users.findIndex(u => u.username === username);
  if (idx === -1) throw new Error('User not found.');
  usersStore.data.users.splice(idx, 1);
  usersStore.save();
  // User files stay on disk under /data/users/<name> so an accidental
  // account deletion never destroys data; the admin can remove the folder.
}

export function verifyPassword(username, password) {
  const user = findUser(String(username || '').toLowerCase().trim());
  if (!user) {
    // Burn comparable time so missing users aren't distinguishable by timing.
    bcrypt.compareSync(String(password || ''), DUMMY_HASH);
    return null;
  }
  return bcrypt.compareSync(String(password || ''), user.passwordHash) ? user : null;
}

// --- Two-factor (TOTP) ---
export function totpEnabled(user) { return !!(user && user.totpSecret); }

export function beginTotpSetup(username) {
  const user = findUser(username);
  if (!user) throw new Error('User not found.');
  const s = generateSecret();
  user.totpPending = s; // held until confirmed with a valid code
  usersStore.save();
  return { secret: s, otpauth: otpauthUri(s, username, settings.siteName || 'My Cloud') };
}

export function confirmTotp(username, code) {
  const user = findUser(username);
  if (!user) throw new Error('User not found.');
  if (!user.totpPending) throw new Error('Start two-factor setup first.');
  if (!verifyTotp(user.totpPending, code)) throw new Error('That code is incorrect. Try again.');
  user.totpSecret = user.totpPending;
  delete user.totpPending;
  const codes = [];
  user.recovery = [];
  for (let i = 0; i < 10; i++) {
    const c = crypto.randomBytes(5).toString('hex');
    codes.push(c);
    user.recovery.push(bcrypt.hashSync(c, 10));
  }
  usersStore.save();
  return codes; // shown once
}

export function disableTotp(username) {
  const user = findUser(username);
  if (!user) throw new Error('User not found.');
  delete user.totpSecret;
  delete user.totpPending;
  delete user.recovery;
  usersStore.save();
}

// Second login factor: a TOTP code or a one-time recovery code (consumed).
export function verifySecondFactor(username, code) {
  const user = findUser(username);
  if (!user || !user.totpSecret) return false;
  if (verifyTotp(user.totpSecret, code)) return true;
  const clean = String(code || '').replace(/\s/g, '').toLowerCase();
  const idx = (user.recovery || []).findIndex(h => bcrypt.compareSync(clean, h));
  if (idx !== -1) { user.recovery.splice(idx, 1); usersStore.save(); return true; }
  return false;
}

// --- App passwords (for WebDAV / Basic auth, which can't do interactive 2FA) ---
export function listAppPasswords(username) {
  const u = findUser(username);
  return (u?.appPasswords || []).map(({ hash, ...a }) => a);
}

export function addAppPassword(username, label) {
  const u = findUser(username);
  if (!u) throw new Error('User not found.');
  const token = crypto.randomBytes(15).toString('base64url');
  u.appPasswords = u.appPasswords || [];
  const id = crypto.randomBytes(4).toString('hex');
  u.appPasswords.push({ id, label: String(label || 'App').slice(0, 40), hash: bcrypt.hashSync(token, 10), createdAt: Date.now() });
  usersStore.save();
  return { id, token };
}

export function removeAppPassword(username, id) {
  const u = findUser(username);
  if (!u) return;
  u.appPasswords = (u.appPasswords || []).filter(a => a.id !== id);
  usersStore.save();
}

// WebDAV/Basic auth: an app password always works; the account password works
// only when 2FA is off (otherwise it would be a 2FA bypass).
export function verifyDavAuth(username, secret) {
  const u = findUser(String(username || '').toLowerCase().trim());
  if (!u) { bcrypt.compareSync(String(secret || ''), DUMMY_HASH); return null; }
  for (const ap of (u.appPasswords || [])) {
    if (bcrypt.compareSync(String(secret || ''), ap.hash)) return u;
  }
  if (u.totpSecret) return null; // must use an app password
  return bcrypt.compareSync(String(secret || ''), u.passwordHash) ? u : null;
}

// --- Stateless signed session tokens (survive restarts, no session table) ---

function hmac(data) {
  return crypto.createHmac('sha256', secret).update(data).digest('base64url');
}

export function makeSessionToken(username) {
  const user = findUser(username);
  const payload = Buffer.from(JSON.stringify({
    u: username,
    pv: user?.passwordChangedAt || 0,
    exp: Date.now() + settings.sessionDays * 86400000
  })).toString('base64url');
  return payload + '.' + hmac(payload);
}

export function verifySessionToken(token) {
  if (!token || typeof token !== 'string') return null;
  const dot = token.lastIndexOf('.');
  if (dot === -1) return null;
  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = hmac(payload);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data.u || Date.now() > data.exp) return null;
    const user = findUser(data.u);
    if (!user) return null;
    // Reject tokens issued before the user's last password change.
    if ((data.pv || 0) !== (user.passwordChangedAt || 0)) return null;
    return user;
  } catch {
    return null;
  }
}

function getCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) return decodeURIComponent(part.slice(eq + 1).trim());
  }
  return null;
}

// Operators terminating TLS at a proxy that doesn't forward X-Forwarded-Proto
// can force the Secure flag with MYCLOUD_FORCE_SECURE_COOKIE=1.
const FORCE_SECURE_COOKIE = /^(1|true|yes)$/i.test(process.env.MYCLOUD_FORCE_SECURE_COOKIE || '');

export function sessionCookie(token, secure = false) {
  const maxAge = settings.sessionDays * 86400;
  // Secure is added when the request arrived over HTTPS (or forced), so
  // HTTP-only LAN installs (common on Unraid) still work while HTTPS gets it.
  const flag = secure || FORCE_SECURE_COOKIE ? '; Secure' : '';
  return `mycloud_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${flag}`;
}

export const clearSessionCookie = 'mycloud_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0';

export function authMiddleware(req, res, next) {
  const user = verifySessionToken(getCookie(req, 'mycloud_session'));
  if (!user) return res.status(401).json({ error: 'Not signed in.' });
  req.user = user;
  next();
}

export function adminMiddleware(req, res, next) {
  if (!req.user?.isAdmin) return res.status(403).json({ error: 'Admin access required.' });
  next();
}

// --- Login rate limiting (in-memory) ---
// Two independent buckets: per-IP (stops a single host hammering) and
// per-username (stops a distributed IP-rotation spray against one account,
// which per-IP limiting alone can't catch on IPv6 / botnets).
const WINDOW_MS = 15 * 60000;
const MAX_PER_IP = 20;
const MAX_PER_USER = 10;
const ipAttempts = new Map();
const userAttempts = new Map();

function bump(map, key, max, now) {
  let e = map.get(key);
  if (!e || now > e.resetAt) e = { count: 0, resetAt: now + WINDOW_MS };
  e.count++;
  map.set(key, e);
  return e.count > max;
}

// Cleared on a successful login so a legitimate user isn't locked out by
// their own earlier typos.
export function clearLoginAttempts(username) {
  if (username) userAttempts.delete(String(username).toLowerCase().trim());
}

// Periodic sweep off the hot path so the maps can't grow unbounded and
// login requests never pay an O(n) scan.
setInterval(() => {
  const now = Date.now();
  for (const m of [ipAttempts, userAttempts]) {
    for (const [k, v] of m) if (now > v.resetAt) m.delete(k);
  }
}, WINDOW_MS).unref?.();

export function loginRateLimit(req, res, next) {
  const now = Date.now();
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const username = String(req.body?.username || '').toLowerCase().trim();
  const ipBlocked = bump(ipAttempts, ip, MAX_PER_IP, now);
  const userBlocked = username && bump(userAttempts, username, MAX_PER_USER, now);
  if (ipBlocked || userBlocked) {
    return res.status(429).json({ error: 'Too many login attempts. Try again in a few minutes.' });
  }
  next();
}

// General-purpose per-IP limiter for the public (unauthenticated) share surface.
// Buckets by IPv6 /64 so a single allocation can't rotate addresses freely.
const publicBuckets = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of publicBuckets) if (now > v.resetAt) publicBuckets.delete(k);
}, 60000).unref?.();

function ipKey(req) {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  if (ip.includes(':')) return ip.split(':').slice(0, 4).join(':'); // IPv6 /64
  return ip;
}

export function publicRateLimit({ max = 120, windowMs = 60000 } = {}) {
  return (req, res, next) => {
    const now = Date.now();
    const key = ipKey(req);
    let e = publicBuckets.get(key);
    if (!e || now > e.resetAt) e = { count: 0, resetAt: now + windowMs };
    e.count++;
    publicBuckets.set(key, e);
    if (e.count > max) return res.status(429).json({ error: 'Too many requests. Slow down.' });
    next();
  };
}
