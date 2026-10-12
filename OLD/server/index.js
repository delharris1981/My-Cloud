import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { PORT, settings, saveSettings } from './config.js';
import {
  listUsers, findUser, createUser, updateUser, deleteUser, verifyPassword,
  makeSessionToken, sessionCookie, clearSessionCookie,
  authMiddleware, adminMiddleware, loginRateLimit, clearLoginAttempts, publicRateLimit, userDirs,
  totpEnabled, verifySecondFactor, beginTotpSetup, confirmTotp, disableTotp,
  listAppPasswords, addAppPassword, removeAppPassword
} from './auth.js';
import QRCode from 'qrcode';
import { filesRouter, trashRouter, purgeOldTrash, pruneThumbs, purgeOldSessions } from './files.js';
import { sharesRouter, publicRouter, deleteSharesForUser } from './shares.js';
import { davRouter } from './webdav.js';
import { dirSize } from './fsutil.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const app = express();
app.disable('x-powered-by');
// Trust only private/loopback proxies (a reverse proxy on the LAN), NOT
// arbitrary clients — otherwise a remote caller could spoof X-Forwarded-For
// to forge req.ip and bypass the login rate-limiter. Override with
// MYCLOUD_TRUST_PROXY (e.g. a hop count) for unusual topologies.
app.set('trust proxy', process.env.MYCLOUD_TRUST_PROXY || 'loopback, linklocal, uniquelocal');

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

// --- Auth & setup ---

const needsSetup = () => listUsers().length === 0;

app.get('/api/status', (req, res) => {
  res.json({ needsSetup: needsSetup(), siteName: settings.siteName });
});

app.post('/api/setup', express.json(), (req, res) => {
  if (!needsSetup()) return res.status(403).json({ error: 'Setup already completed.' });
  try {
    const user = createUser({ username: req.body.username, password: req.body.password, isAdmin: true });
    res.setHeader('Set-Cookie', sessionCookie(makeSessionToken(user.username), req.secure));
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// express.json first so the per-username rate-limit bucket can read the body.
app.post('/api/auth/login', express.json(), loginRateLimit, (req, res) => {
  const user = verifyPassword(req.body.username, req.body.password);
  if (!user) return res.status(403).json({ error: 'Wrong username or password.' });
  if (totpEnabled(user)) {
    const code = req.body.code;
    if (!code) return res.json({ twofa: true }); // prompt for a code, no session yet
    if (!verifySecondFactor(user.username, code)) {
      return res.status(403).json({ error: 'Incorrect authentication code.', twofa: true });
    }
  }
  clearLoginAttempts(user.username);
  res.setHeader('Set-Cookie', sessionCookie(makeSessionToken(user.username), req.secure));
  res.json({ ok: true });
});

// --- Two-factor management (all require an active session) ---
app.post('/api/auth/2fa/setup', authMiddleware, express.json(), wrap(async (req, res) => {
  const { secret, otpauth } = beginTotpSetup(req.user.username);
  const qr = await QRCode.toDataURL(otpauth, { margin: 1, width: 220 });
  res.json({ secret, otpauth, qr });
}));

app.post('/api/auth/2fa/enable', authMiddleware, express.json(), (req, res) => {
  try {
    const recovery = confirmTotp(req.user.username, req.body.code);
    res.json({ ok: true, recovery });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/auth/2fa/disable', authMiddleware, express.json(), (req, res) => {
  if (!verifyPassword(req.user.username, req.body.password)) {
    return res.status(403).json({ error: 'Current password is wrong.' });
  }
  disableTotp(req.user.username);
  res.json({ ok: true });
});

// --- App passwords (for WebDAV under 2FA) ---
app.get('/api/auth/apppw', authMiddleware, (req, res) => {
  res.json({ appPasswords: listAppPasswords(req.user.username) });
});
app.post('/api/auth/apppw', authMiddleware, express.json(), (req, res) => {
  const { id, token } = addAppPassword(req.user.username, req.body.label);
  res.json({ id, token });
});
app.delete('/api/auth/apppw/:id', authMiddleware, (req, res) => {
  removeAppPassword(req.user.username, req.params.id);
  res.json({ ok: true });
});

app.post('/api/auth/logout', (req, res) => {
  res.setHeader('Set-Cookie', clearSessionCookie);
  res.json({ ok: true });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json({
    username: req.user.username,
    isAdmin: req.user.isAdmin,
    quotaMB: req.user.quotaMB || 0,
    siteName: settings.siteName,
    allowPublicShares: settings.allowPublicShares !== false,
    totpEnabled: totpEnabled(req.user)
  });
});

app.post('/api/auth/password', authMiddleware, express.json(), (req, res) => {
  const { current, next: nextPw } = req.body;
  if (!verifyPassword(req.user.username, current)) {
    return res.status(403).json({ error: 'Current password is wrong.' });
  }
  try {
    updateUser(req.user.username, { password: nextPw });
    // Changing the password bumps passwordChangedAt, which invalidates the
    // current token — re-issue one so the user isn't logged out of this session.
    res.setHeader('Set-Cookie', sessionCookie(makeSessionToken(req.user.username), req.secure));
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// --- Files, trash, shares ---

app.use('/api/files', authMiddleware, express.json({ limit: '1mb' }), filesRouter);
app.use('/api/trash', authMiddleware, express.json({ limit: '1mb' }), trashRouter);
// WebDAV — mounted before the JSON parsers so PUT bodies stream raw.
app.use('/dav', davRouter);
app.use('/api/shares', express.json({ limit: '1mb' }), sharesRouter);
// Rate-limit the unauthenticated share surface. Tighter budget for the
// expensive zip/upload paths; looser for info/list/download of single files.
app.use('/s/api/:token/upload', publicRateLimit({ max: 30, windowMs: 60000 }));
app.use('/s/api/:token/download', publicRateLimit({ max: 60, windowMs: 60000 }));
app.use('/s', publicRateLimit({ max: 240, windowMs: 60000 }), publicRouter);

// --- Admin ---

const admin = express.Router();
admin.use(authMiddleware, adminMiddleware, express.json({ limit: '1mb' }));

admin.get('/users', wrap(async (req, res) => {
  const users = [];
  for (const u of listUsers()) {
    let used = 0;
    try {
      used = await dirSize(userDirs(u.username).files);
    } catch { /* ignore */ }
    users.push({
      username: u.username,
      isAdmin: u.isAdmin,
      quotaMB: u.quotaMB || 0,
      createdAt: u.createdAt,
      usedBytes: used
    });
  }
  res.json({ users });
}));

admin.post('/users', (req, res) => {
  try {
    const u = createUser(req.body);
    res.json({ ok: true, username: u.username });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

admin.patch('/users/:username', (req, res) => {
  const target = findUser(req.params.username);
  if (!target) return res.status(404).json({ error: 'User not found.' });
  // Demotion = isAdmin present and falsy (0, "", null all count, not just false).
  const demoting = 'isAdmin' in req.body && !req.body.isAdmin;
  if (demoting && target.isAdmin) {
    if (target.username === req.user.username) {
      return res.status(400).json({ error: 'You cannot remove your own admin access.' });
    }
    if (listUsers().filter(u => u.isAdmin).length <= 1) {
      return res.status(400).json({ error: 'Cannot remove the last administrator.' });
    }
  }
  try {
    updateUser(target.username, req.body);
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

admin.delete('/users/:username', (req, res) => {
  if (req.params.username === req.user.username) {
    return res.status(400).json({ error: 'You cannot delete your own account.' });
  }
  try {
    deleteUser(req.params.username);
    deleteSharesForUser(req.params.username);
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

admin.get('/settings', (req, res) => res.json({ settings }));
const clampNonNeg = v => Math.max(0, Math.floor(Number(v) || 0));
admin.patch('/settings', (req, res) => {
  const patch = {};
  if (typeof req.body.siteName === 'string' && req.body.siteName.trim()) patch.siteName = req.body.siteName.trim().slice(0, 60);
  // Clamp to >= 0: a negative retention would flip the purge cutoff into the
  // future and wipe all trash; a negative quota would reject every upload.
  if (req.body.defaultQuotaMB !== undefined) patch.defaultQuotaMB = clampNonNeg(req.body.defaultQuotaMB);
  if (req.body.trashRetentionDays !== undefined) patch.trashRetentionDays = clampNonNeg(req.body.trashRetentionDays);
  if (req.body.allowPublicShares !== undefined) patch.allowPublicShares = !!req.body.allowPublicShares;
  res.json({ settings: saveSettings(patch) });
});

app.use('/api/admin', admin);

// --- Static frontend ---

const publicDir = path.join(__dirname, '..', 'public');
app.use(express.static(publicDir, { index: false, maxAge: '1h' }));

app.get('/s/:token', (req, res) => res.sendFile(path.join(publicDir, 'share.html')));
app.get('/', (req, res) => res.sendFile(path.join(publicDir, 'index.html')));

app.use((req, res) => res.status(404).json({ error: 'Not found.' }));

// Error handler — keep messages terse, log details server-side.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  const status = err.status || (err.code === 'ENOENT' ? 404 : 500);
  if (status >= 500) console.error(err);
  res.status(status).json({
    error: status === 404 ? 'Not found.' : (err.status ? err.message : 'Server error.')
  });
});

// Hourly housekeeping: trash auto-purge + thumbnail-cache cap.
setInterval(() => {
  for (const u of listUsers()) {
    purgeOldTrash(u.username, settings.trashRetentionDays).catch(() => {});
    pruneThumbs(u.username).catch(() => {});
    purgeOldSessions(u.username).catch(() => {});
  }
}, 3600000).unref();

app.listen(PORT, () => {
  console.log(`My Cloud listening on port ${PORT}`);
  if (needsSetup()) console.log('No users yet — open the web UI to create the first admin account.');
});
