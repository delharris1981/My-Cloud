import express from 'express';
import crypto from 'crypto';
import fsp from 'fs/promises';
import path from 'path';
import bcrypt from 'bcryptjs';
import { JsonStore } from './store.js';
import { settings } from './config.js';
import { userDirs, authMiddleware, findUser } from './auth.js';
import { safeJoin, listDir, realContained } from './fsutil.js';
import { withLock } from './locks.js';
import { sendFile, sendZip, sendZipItems, streamUpload, isMultipart } from './files.js';

// Absolute cap on a single anonymous drop-box upload request, independent of
// the owner's quota (which may be unlimited). Prevents disk-fill via shares.
const MAX_PUBLIC_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024; // 2 GB

const sharesStore = new JsonStore('shares.json', { shares: [] });

// Debounced persistence for the frequently-bumped download counter, so a
// shared video (dozens of range requests) doesn't rewrite shares.json each hit.
let saveTimer = null;
function scheduleSharesSave() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => { saveTimer = null; sharesStore.save(); }, 5000);
  saveTimer.unref?.();
}

const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function findShare(token) {
  return sharesStore.data.shares.find(s => s.token === token);
}

function shareExpired(share) {
  return share.expiresAt && Date.now() > share.expiresAt;
}

function shareAbs(share) {
  return safeJoin(userDirs(share.owner).files, share.path);
}

// --- Authenticated management API ---

export const sharesRouter = express.Router();
sharesRouter.use(authMiddleware);

sharesRouter.get('/', (req, res) => {
  const mine = sharesStore.data.shares
    .filter(s => s.owner === req.user.username)
    .map(({ passwordHash, ...s }) => ({ ...s, hasPassword: !!passwordHash }));
  res.json({ shares: mine });
});

sharesRouter.post('/', wrap(async (req, res) => {
  if (!settings.allowPublicShares) {
    return res.status(403).json({ error: 'Public share links are disabled by the administrator.' });
  }
  const { path: sharePath, paths, password, expiresDays, allowUpload } = req.body;
  const filesRoot = userDirs(req.user.username).files;
  const base = {
    token: crypto.randomBytes(16).toString('base64url'),
    owner: req.user.username,
    passwordHash: password ? bcrypt.hashSync(String(password), 10) : null,
    expiresAt: expiresDays ? Date.now() + Number(expiresDays) * 86400000 : null,
    createdAt: Date.now(),
    downloads: 0
  };
  let share;
  if (Array.isArray(paths) && paths.length > 1) {
    // Multi-item share: a selection of files/folders, downloaded together.
    const items = [];
    for (const p of paths) {
      const abs = safeJoin(filesRoot, p);
      if (await fsp.stat(abs).catch(() => null)) items.push(String(p).replace(/\\/g, '/').replace(/^\/+/, ''));
    }
    if (!items.length) return res.status(404).json({ error: 'None of the selected items were found.' });
    share = { ...base, isMulti: true, items, isDir: true, allowUpload: false };
  } else {
    const single = sharePath || (Array.isArray(paths) && paths[0]);
    const abs = safeJoin(filesRoot, single);
    const st = await fsp.stat(abs).catch(() => null);
    if (!st) return res.status(404).json({ error: 'File not found.' });
    share = {
      ...base,
      path: String(single).replace(/\\/g, '/').replace(/^\/+/, ''),
      isDir: st.isDirectory(),
      allowUpload: !!allowUpload && st.isDirectory()
    };
  }
  sharesStore.data.shares.push(share);
  sharesStore.save();
  const { passwordHash, ...pub } = share;
  res.json({ share: { ...pub, hasPassword: !!passwordHash } });
}));

sharesRouter.delete('/:token', (req, res) => {
  const idx = sharesStore.data.shares.findIndex(
    s => s.token === req.params.token && s.owner === req.user.username
  );
  if (idx === -1) return res.status(404).json({ error: 'Share not found.' });
  sharesStore.data.shares.splice(idx, 1);
  sharesStore.save();
  res.json({ ok: true });
});

export function deleteSharesForUser(username) {
  sharesStore.data.shares = sharesStore.data.shares.filter(s => s.owner !== username);
  sharesStore.save();
}

// --- Public access (no login) ---

export const publicRouter = express.Router();

// Per-share unlock cookie so password entry sticks for the browser session.
function shareCookieName(token) {
  return 'mycloud_share_' + crypto.createHash('sha256').update(token).digest('hex').slice(0, 16);
}

function shareUnlocked(req, share) {
  if (!share.passwordHash) return true;
  const header = req.headers.cookie || '';
  const name = shareCookieName(share.token);
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq !== -1 && part.slice(0, eq).trim() === name) {
      const val = part.slice(eq + 1).trim();
      const expected = crypto.createHmac('sha256', share.passwordHash).update(share.token).digest('hex');
      const a = Buffer.from(val);
      const b = Buffer.from(expected);
      if (a.length === b.length && crypto.timingSafeEqual(a, b)) return true;
    }
  }
  return false;
}

function loadShare(req, res) {
  const share = findShare(req.params.token);
  if (!share || shareExpired(share)) {
    res.status(404).json({ error: 'This share does not exist or has expired.' });
    return null;
  }
  return share;
}

function itemAbs(share, index) {
  const i = parseInt(index, 10);
  if (!Number.isInteger(i) || i < 0 || i >= share.items.length) {
    const e = new Error('Invalid item.'); e.status = 400; throw e;
  }
  return safeJoin(userDirs(share.owner).files, share.items[i]);
}

publicRouter.get('/api/:token/info', wrap(async (req, res) => {
  const share = loadShare(req, res);
  if (!share) return;
  if (!shareUnlocked(req, share)) {
    return res.json({ locked: true, name: null });
  }
  if (share.isMulti) {
    return res.json({ locked: false, name: share.items.length + ' items', isDir: true, isMulti: true, size: null, allowUpload: false });
  }
  const abs = shareAbs(share);
  const st = await fsp.stat(abs).catch(() => null);
  if (!st) return res.status(404).json({ error: 'The shared file no longer exists.' });
  res.json({
    locked: false,
    name: path.basename(abs) || share.owner,
    isDir: share.isDir,
    size: st.isDirectory() ? null : st.size,
    allowUpload: !!share.allowUpload
  });
}));

publicRouter.post('/api/:token/unlock', express.json(), wrap(async (req, res) => {
  const share = loadShare(req, res);
  if (!share) return;
  if (!share.passwordHash) return res.json({ ok: true });
  if (!bcrypt.compareSync(String(req.body.password || ''), share.passwordHash)) {
    return res.status(403).json({ error: 'Wrong password.' });
  }
  const val = crypto.createHmac('sha256', share.passwordHash).update(share.token).digest('hex');
  const secure = req.secure || /^(1|true|yes)$/i.test(process.env.MYCLOUD_FORCE_SECURE_COOKIE || '') ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${shareCookieName(share.token)}=${val}; Path=/; HttpOnly; SameSite=Lax${secure}`);
  res.json({ ok: true });
}));

publicRouter.get('/api/:token/list', wrap(async (req, res) => {
  const share = loadShare(req, res);
  if (!share) return;
  if (!shareUnlocked(req, share)) return res.status(403).json({ error: 'Password required.' });
  if (share.isMulti) {
    const entries = [];
    for (let i = 0; i < share.items.length; i++) {
      const abs = safeJoin(userDirs(share.owner).files, share.items[i]);
      const st = await fsp.stat(abs).catch(() => null);
      if (st) entries.push({ i, name: path.basename(abs), isDir: st.isDirectory(), size: st.isDirectory() ? 0 : st.size, mtime: st.mtimeMs });
    }
    return res.json({ entries, isMulti: true });
  }
  if (!share.isDir) return res.status(400).json({ error: 'Not a folder share.' });
  const abs = safeJoin(shareAbs(share), req.query.path);
  const st = await fsp.stat(abs).catch(() => null);
  if (!st || !st.isDirectory()) return res.status(404).json({ error: 'Folder not found.' });
  res.json({ entries: await listDir(abs) });
}));

publicRouter.get('/api/:token/download', wrap(async (req, res) => {
  const share = loadShare(req, res);
  if (!share) return;
  if (!shareUnlocked(req, share)) return res.status(403).json({ error: 'Password required.' });

  if (share.isMulti) {
    share.downloads = (share.downloads || 0) + 1;
    scheduleSharesSave();
    if (req.query.i === undefined) {
      // Download all selected items as one zip.
      const items = [];
      for (let i = 0; i < share.items.length; i++) {
        const abs = safeJoin(userDirs(share.owner).files, share.items[i]);
        const st = await fsp.stat(abs).catch(() => null);
        if (st && await realContained(userDirs(share.owner).files, abs)) {
          items.push({ abs, name: path.basename(abs), isDir: st.isDirectory() });
        }
      }
      if (!items.length) return res.status(404).json({ error: 'Nothing to download.' });
      return sendZipItems(res, items, 'files.zip', { level: 0 });
    }
    const abs = itemAbs(share, req.query.i);
    if (!await realContained(userDirs(share.owner).files, abs)) return res.status(404).json({ error: 'Not found.' });
    const st = await fsp.stat(abs).catch(() => null);
    if (!st) return res.status(404).json({ error: 'File not found.' });
    if (st.isDirectory()) return sendZip(res, abs, (path.basename(abs) || 'folder') + '.zip', { level: 0 });
    return sendFile(req, res, abs, { download: req.query.dl !== '0' });
  }

  const shareRoot = shareAbs(share);
  let abs = shareRoot;
  if (share.isDir && req.query.path) abs = safeJoin(abs, req.query.path);
  // Refuse symlinks resolving outside the shared folder.
  if (!await realContained(shareRoot, abs)) return res.status(404).json({ error: 'File not found.' });
  const st = await fsp.stat(abs).catch(() => null);
  if (!st) return res.status(404).json({ error: 'File not found.' });
  // Count a download once per file fetch — not per HTTP range request (video
  // scrubbing fires many). Only the initial (non-range or range-from-0) hit.
  const range = req.headers.range;
  if (!range || /^bytes=0-/.test(range)) {
    share.downloads = (share.downloads || 0) + 1;
    scheduleSharesSave();
  }
  // level 0 (store) for public zips: cheaper CPU, and media is already compressed.
  if (st.isDirectory()) return sendZip(res, abs, (path.basename(abs) || 'share') + '.zip', { level: 0 });
  sendFile(req, res, abs, { download: req.query.dl !== '0' });
}));

// Drop-box style uploads into folder shares that allow it.
publicRouter.post('/api/:token/upload', wrap(async (req, res) => {
  const share = loadShare(req, res);
  if (!share) return;
  if (!shareUnlocked(req, share)) return res.status(403).json({ error: 'Password required.' });
  if (!share.isDir || !share.allowUpload) return res.status(403).json({ error: 'Uploads not allowed on this share.' });
  if (!isMultipart(req)) return res.status(400).json({ error: 'Expected a multipart upload.' });
  // Honor whatever subfolder the visitor navigated into, bounded to the share.
  const destDir = req.query.path ? safeJoin(shareAbs(share), req.query.path) : shareAbs(share);
  const dst = await fsp.stat(destDir).catch(() => null);
  if (!dst || !dst.isDirectory()) return res.status(404).json({ error: 'Folder not found.' });

  const owner = findUser(share.owner);
  const quotaBytes = (owner?.quotaMB || 0) * 1024 * 1024; // 0 = unlimited
  // Uploads land in the share root, no client subpaths; enforce the owner's
  // quota AND an absolute cap so an anonymous visitor can't fill the disk.
  await withLock('quota:' + share.owner, () => streamUpload(req, res, {
    username: share.owner,
    destDir,
    allowSubdirs: false,
    quotaBytes,
    maxBytes: MAX_PUBLIC_UPLOAD_BYTES,
    outOfSpaceMsg: 'The owner is out of storage space.'
  }));
}));
