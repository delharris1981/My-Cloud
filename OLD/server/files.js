import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import fsp from 'fs/promises';
import path from 'path';
import Busboy from 'busboy';
import archiver from 'archiver';
import mime from 'mime-types';
import sharp from 'sharp';
import { userDirs } from './auth.js';
import { withLock } from './locks.js';
import {
  safeJoin, validName, listDir, dirSize, uniqueName,
  copyRecursive, moveEntry, searchFiles, statEntry, realContained
} from './fsutil.js';

const MAX_UPLOAD_FILES = 10000;
const MAX_ZIP_ENTRIES = 10000;

function trashId() {
  return Date.now() + '-' + crypto.randomBytes(5).toString('hex');
}

export const filesRouter = express.Router();

function root(req) {
  return userDirs(req.user.username).files;
}

function trashRoot(req) {
  return userDirs(req.user.username).trash;
}

const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Streams a file with range support (needed for video/audio scrubbing).
export function sendFile(req, res, abs, { download = false, name = null } = {}) {
  const st = fs.statSync(abs);
  const filename = name || path.basename(abs);
  const type = mime.lookup(filename) || 'application/octet-stream';
  res.setHeader('Content-Type', type);
  res.setHeader('Accept-Ranges', 'bytes');
  // Sandbox script-capable document types so uploaded HTML/SVG can't run
  // scripts against the app origin (stored XSS via upload).
  if (/html|svg|xml/.test(type)) {
    res.setHeader('Content-Security-Policy', 'sandbox');
  }
  const disposition = download ? 'attachment' : 'inline';
  res.setHeader('Content-Disposition', `${disposition}; filename*=UTF-8''${encodeURIComponent(filename)}`);

  const range = req.headers.range;
  if (range) {
    const m = /^bytes=(\d*)-(\d*)$/.exec(range);
    if (m) {
      let start = m[1] === '' ? null : parseInt(m[1], 10);
      let end = m[2] === '' ? null : parseInt(m[2], 10);
      if (start === null) {
        start = Math.max(0, st.size - (end ?? 0));
        end = st.size - 1;
      } else if (end === null || end >= st.size) {
        end = st.size - 1;
      }
      if (start <= end && start < st.size) {
        res.status(206);
        res.setHeader('Content-Range', `bytes ${start}-${end}/${st.size}`);
        res.setHeader('Content-Length', end - start + 1);
        fs.createReadStream(abs, { start, end }).pipe(res);
        return;
      }
      res.status(416).setHeader('Content-Range', `bytes */${st.size}`);
      return res.end();
    }
  }
  res.setHeader('Content-Length', st.size);
  fs.createReadStream(abs).pipe(res);
}

// Cap simultaneous on-the-fly zip streams so a burst (especially on public
// shares) can't pin every CPU. Public callers pass a lower compression level.
let activeZips = 0;
const MAX_ACTIVE_ZIPS = 4;

// Stream a zip built by `build(archive)`. Enforces the concurrency cap.
function streamArchive(res, zipName, level, build) {
  if (activeZips >= MAX_ACTIVE_ZIPS) {
    res.setHeader('Retry-After', '5');
    return res.status(503).json({ error: 'Server busy compressing other downloads. Try again shortly.' });
  }
  activeZips++;
  let finished = false;
  const done = () => { if (finished) return; finished = true; activeZips = Math.max(0, activeZips - 1); };
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(zipName)}`);
  const archive = archiver('zip', { zlib: { level } });
  archive.on('error', () => { done(); res.destroy(); });
  archive.on('end', done);
  res.on('close', done);
  archive.pipe(res);
  build(archive);
  archive.finalize();
}

export function sendZip(res, abs, zipName, { level = 1 } = {}) {
  streamArchive(res, zipName, level, a => a.directory(abs, path.basename(abs)));
}

// Zip a list of { abs, name, isDir } entries (for multi-item shares/selections).
export function sendZipItems(res, items, zipName, { level = 1 } = {}) {
  streamArchive(res, zipName, level, a => {
    for (const it of items) {
      if (it.isDir) a.directory(it.abs, it.name);
      else a.file(it.abs, { name: it.name });
    }
  });
}

filesRouter.get('/list', wrap(async (req, res) => {
  const abs = safeJoin(root(req), req.query.path);
  const st = await fsp.stat(abs);
  if (!st.isDirectory()) return res.status(400).json({ error: 'Not a folder.' });
  res.json({ entries: await listDir(abs) });
}));

filesRouter.get('/download', wrap(async (req, res) => {
  const filesRoot = root(req);
  const abs = safeJoin(filesRoot, req.query.path);
  // Reject symlinks that resolve outside the user's root (planted out-of-band).
  if (!await realContained(filesRoot, abs)) return res.status(404).json({ error: 'Not found.' });
  const st = await fsp.stat(abs);
  if (st.isDirectory()) return sendZip(res, abs, path.basename(abs) + '.zip');
  sendFile(req, res, abs, { download: req.query.dl !== '0' });
}));

// Server-generated, disk-cached thumbnails for images. Cache lives outside the
// user's files dir so it isn't listed and doesn't count toward quota.
const THUMB_EXT = new Set(['jpg', 'jpeg', 'png', 'webp', 'gif', 'avif', 'tiff', 'tif', 'bmp']);
const THUMB_MAX_INPUT = 60 * 1024 * 1024; // don't try to decode enormous files

filesRouter.get('/thumb', wrap(async (req, res) => {
  const rel = String(req.query.path || '');
  const ext = path.extname(rel).slice(1).toLowerCase();
  if (!THUMB_EXT.has(ext)) return res.status(415).json({ error: 'No thumbnail for this type.' });
  const filesRoot = root(req);
  const abs = safeJoin(filesRoot, rel);
  if (!await realContained(filesRoot, abs)) return res.status(404).json({ error: 'Not found.' });
  const st = await fsp.stat(abs).catch(() => null);
  if (!st || st.isDirectory()) return res.status(404).json({ error: 'Not found.' });
  if (st.size > THUMB_MAX_INPUT) return res.status(413).json({ error: 'Image too large to thumbnail.' });

  const size = Math.min(512, Math.max(64, parseInt(req.query.s, 10) || 256));
  const dirs = userDirs(req.user.username);
  // Key by path + mtime + size so edits and different sizes get fresh thumbs.
  const key = crypto.createHash('sha1')
    .update(rel + '|' + Math.round(st.mtimeMs) + '|' + st.size + '|' + size).digest('hex');
  const cacheFile = path.join(dirs.thumbs, key + '.webp');

  res.setHeader('Content-Type', 'image/webp');
  res.setHeader('Cache-Control', 'private, max-age=86400');
  res.setHeader('ETag', '"' + key + '"');
  if (req.headers['if-none-match'] === '"' + key + '"') return res.status(304).end();

  if (fs.existsSync(cacheFile)) return fs.createReadStream(cacheFile).pipe(res);

  try {
    const buf = await sharp(abs, { failOn: 'none', pages: 1 })
      .rotate() // honor EXIF orientation
      .resize(size, size, { fit: 'inside', withoutEnlargement: true })
      .webp({ quality: 72 })
      .toBuffer();
    fs.mkdirSync(dirs.thumbs, { recursive: true });
    fs.writeFile(cacheFile, buf, () => {}); // cache write is best-effort
    res.end(buf);
  } catch {
    res.status(422).json({ error: 'Could not render thumbnail.' });
  }
}));

// Zip an arbitrary selection of entries from one folder.
filesRouter.post('/zip', wrap(async (req, res) => {
  const { dir, names } = req.body;
  if (!Array.isArray(names) || names.length === 0) return res.status(400).json({ error: 'Nothing selected.' });
  if (names.length > MAX_ZIP_ENTRIES) return res.status(400).json({ error: 'Too many items selected.' });
  const dirAbs = safeJoin(root(req), dir);
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent('files.zip')}`);
  const archive = archiver('zip', { zlib: { level: 1 } });
  archive.on('error', () => res.destroy());
  archive.pipe(res);
  for (const name of names) {
    if (!validName(name)) continue;
    const abs = path.join(dirAbs, name);
    const st = await fsp.stat(abs).catch(() => null);
    if (!st) continue;
    if (st.isDirectory()) archive.directory(abs, name);
    else archive.file(abs, { name });
  }
  archive.finalize();
}));

// Total on-disk footprint for a user: files, trash, AND in-progress resumable
// upload parts. Counting trash stops a fill -> delete -> fill bypass; counting
// upload parts stops many concurrent sessions from bypassing quota.
export async function usedBytes(username) {
  const d = userDirs(username);
  const [f, t, u] = await Promise.all([
    dirSize(d.files),
    dirSize(d.trash).catch(() => 0),
    dirSize(path.join(d.base, 'uploads')).catch(() => 0)
  ]);
  return f + t + u;
}

async function quotaRemaining(req) {
  const quotaMB = req.user.quotaMB || 0;
  if (!quotaMB) return Infinity;
  return quotaMB * 1024 * 1024 - await usedBytes(req.user.username);
}

export function isMultipart(req) {
  return /multipart\/form-data/i.test(req.headers['content-type'] || '');
}

// Shared, robust multipart receiver used by both the authenticated upload and
// the public drop-box. ALWAYS resolves its promise (even on a Busboy throw) so
// the per-user quota lock can never be wedged. Enforces the owner's quota and
// an absolute byte cap, cleans up every temp file on any exit path.
export function streamUpload(req, res, {
  username, destDir, allowSubdirs, quotaBytes, maxBytes = Infinity, outOfSpaceMsg = 'Storage quota exceeded.'
}) {
  return new Promise(resolve => {
    let usedStart = 0;
    let projected = 0;
    let quotaExceeded = false;
    let tooMany = false;
    let fileCount = 0;
    let responded = false;
    const saved = [];
    const pending = [];
    const open = new Set(); // rec = { out, tmp, aborted }

    const wipe = () => {
      for (const rec of open) {
        rec.aborted = true;
        try { rec.out.destroy(); } catch { /* ignore */ }
        fs.rm(rec.tmp, { force: true }, () => {});
      }
      open.clear();
    };
    const respond = (status, body) => {
      if (responded) return;
      responded = true;
      res.status(status).json(body);
      resolve();
    };
    const finish = () => {
      if (quotaExceeded) return respond(413, { error: outOfSpaceMsg, saved });
      if (tooMany) return respond(413, { error: 'Too many files in one upload.', saved });
      respond(200, { saved });
    };
    const cap = Math.min(quotaBytes || Infinity, maxBytes);

    // Compute starting usage only when a limit actually applies.
    const usagePromise = cap === Infinity ? Promise.resolve(0) : usedBytes(username).catch(() => 0);
    usagePromise.then(used => {
      usedStart = used || 0;
      let busboy;
      try {
        // preservePath keeps subfolder paths in the filename (e.g. folder
        // uploads) — busboy strips to basename otherwise. Traversal is still
        // blocked by the '.'/'..' filter, validName, and safeJoin below.
        busboy = Busboy({ headers: req.headers, preservePath: true, limits: { files: MAX_UPLOAD_FILES + 1 } });
      } catch {
        // Malformed Content-Type / missing boundary throws here — must still
        // resolve the lock and answer the client.
        return respond(400, { error: 'Expected a valid multipart upload.' });
      }

      busboy.on('file', (field, stream, info) => {
        pending.push(new Promise(doneFile => {
          const rec = { out: null, tmp: null, aborted: false };
          const drop = () => { open.delete(rec); if (rec.tmp) fs.rm(rec.tmp, { force: true }, () => {}); };
          try {
            if (++fileCount > MAX_UPLOAD_FILES) { tooMany = true; stream.resume(); return doneFile(); }
            const relName = String(info.filename || 'unnamed').replace(/\\/g, '/');
            const parts = relName.split('/').filter(p => p && p !== '.' && p !== '..');
            if (parts.length === 0 || parts.some(p => !validName(p))) { stream.resume(); return doneFile(); }
            const fileName = parts.pop();
            const dir = (allowSubdirs && parts.length) ? safeJoin(destDir, parts.join('/')) : destDir;
            fs.mkdirSync(dir, { recursive: true });
            rec.tmp = path.join(dir, '.' + crypto.randomBytes(8).toString('hex') + '.uploading');
            rec.out = fs.createWriteStream(rec.tmp);
            open.add(rec);

            stream.on('data', chunk => {
              projected += chunk.length;
              if (cap !== Infinity && usedStart + projected > cap) {
                quotaExceeded = true;
                rec.aborted = true;
                stream.unpipe(rec.out);
                rec.out.destroy();
                stream.resume();
              }
            });
            rec.out.on('close', () => {
              open.delete(rec);
              if (rec.aborted) { fs.rm(rec.tmp, { force: true }, () => {}); return doneFile(); }
              try {
                const finalName = uniqueName(dir, fileName);
                fs.renameSync(rec.tmp, path.join(dir, finalName));
                saved.push((allowSubdirs && parts.length) ? parts.join('/') + '/' + finalName : finalName);
              } catch { fs.rm(rec.tmp, { force: true }, () => {}); }
              doneFile();
            });
            rec.out.on('error', () => { drop(); doneFile(); });
            // Source error: mark aborted and tear down so no partial file commits.
            stream.on('error', () => { rec.aborted = true; try { rec.out.destroy(); } catch { /* ignore */ } drop(); doneFile(); });
            stream.pipe(rec.out);
          } catch {
            // Any synchronous failure is contained here, never crashing the process.
            rec.aborted = true;
            drop();
            stream.resume();
            doneFile();
          }
        }));
      });

      busboy.on('close', async () => { await Promise.all(pending); finish(); });
      busboy.on('error', () => { wipe(); respond(400, { error: 'Upload failed.' }); });
      req.on('aborted', () => { wipe(); if (!responded) { responded = true; resolve(); } });
      try { req.pipe(busboy); } catch { wipe(); respond(400, { error: 'Upload failed.' }); }
    }).catch(() => { wipe(); if (!responded) { responded = true; try { res.sendStatus(500); } catch { /* ignore */ } resolve(); } });
  });
}

filesRouter.post('/upload', wrap(async (req, res) => {
  if (!isMultipart(req)) return res.status(400).json({ error: 'Expected a multipart upload.' });
  const filesRoot = root(req);
  const destDir = safeJoin(filesRoot, req.query.path);
  const st = await fsp.stat(destDir).catch(() => null);
  if (!st || !st.isDirectory()) return res.status(400).json({ error: 'Destination folder not found.' });
  const quotaBytes = (req.user.quotaMB || 0) * 1024 * 1024; // 0 = unlimited
  // Serialize per user so concurrent uploads can't collectively exceed quota.
  await withLock('quota:' + req.user.username, () =>
    streamUpload(req, res, { username: req.user.username, destDir, allowSubdirs: true, quotaBytes }));
}));

// --- Resumable / chunked uploads ---
// A session writes bytes into a .part file under the user's uploads/ dir; a
// dropped connection resumes from the current part size. On complete, the part
// is committed into the destination (quota-checked, atomically renamed).
const MAX_SESSION_AGE = 24 * 3600000;

function sessionsDir(username) { return path.join(userDirs(username).base, 'uploads'); }

async function readSessionMeta(username, id) {
  if (!validName(id)) return null;
  try {
    return JSON.parse(await fsp.readFile(path.join(sessionsDir(username), id + '.json'), 'utf8'));
  } catch { return null; }
}

filesRouter.post('/upload/session', wrap(async (req, res) => {
  const { path: destPath, name, size } = req.body;
  if (!validName(name)) return res.status(400).json({ error: 'Invalid file name.' });
  const total = Number(size);
  if (!Number.isFinite(total) || total < 0) return res.status(400).json({ error: 'Invalid size.' });
  const destDir = safeJoin(root(req), destPath);
  const st = await fsp.stat(destDir).catch(() => null);
  if (!st || !st.isDirectory()) return res.status(400).json({ error: 'Destination folder not found.' });
  const remaining = await quotaRemaining(req);
  if (total > remaining) return res.status(413).json({ error: 'Storage quota exceeded.' });

  const dir = sessionsDir(req.user.username);
  fs.mkdirSync(dir, { recursive: true });
  const id = Date.now().toString(36) + crypto.randomBytes(6).toString('hex');
  const meta = { id, destPath: String(destPath || ''), name, size: total, createdAt: Date.now() };
  await fsp.writeFile(path.join(dir, id + '.json'), JSON.stringify(meta));
  await fsp.writeFile(path.join(dir, id + '.part'), ''); // start empty
  res.json({ id, offset: 0 });
}));

filesRouter.get('/upload/session/:id', wrap(async (req, res) => {
  const meta = await readSessionMeta(req.user.username, req.params.id);
  if (!meta) return res.status(404).json({ error: 'Session not found.' });
  const part = path.join(sessionsDir(req.user.username), req.params.id + '.part');
  const st = await fsp.stat(part).catch(() => null);
  res.json({ id: meta.id, offset: st ? st.size : 0, size: meta.size, name: meta.name });
}));

filesRouter.put('/upload/session/:id', express.raw({ type: '*/*', limit: '64mb' }), wrap(async (req, res) => {
  const username = req.user.username;
  const meta = await readSessionMeta(username, req.params.id);
  if (!meta) return res.status(404).json({ error: 'Session not found.' });
  const part = path.join(sessionsDir(username), req.params.id + '.part');
  const current = (await fsp.stat(part).catch(() => ({ size: 0 }))).size;
  const offset = parseInt(req.query.offset, 10);
  // Strict sequential append; on mismatch tell the client where to resume.
  if (offset !== current) return res.status(409).json({ error: 'Offset mismatch.', offset: current });
  const chunk = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
  if (current + chunk.length > meta.size) return res.status(413).json({ error: 'Exceeds declared size.' });
  const remaining = await quotaRemaining(req);
  if (chunk.length > remaining) return res.status(413).json({ error: 'Storage quota exceeded.' });
  await fsp.appendFile(part, chunk);
  res.json({ offset: current + chunk.length });
}));

filesRouter.post('/upload/session/:id/complete', wrap(async (req, res) => {
  const username = req.user.username;
  await withLock('quota:' + username, async () => {
    const meta = await readSessionMeta(username, req.params.id);
    if (!meta) return res.status(404).json({ error: 'Session not found.' });
    const dir = sessionsDir(username);
    const part = path.join(dir, req.params.id + '.part');
    const st = await fsp.stat(part).catch(() => null);
    if (!st) return res.status(404).json({ error: 'Upload data missing.' });
    if (st.size !== meta.size) return res.status(400).json({ error: 'Upload incomplete.', offset: st.size });
    const destDir = safeJoin(root(req), meta.destPath);
    if (!fs.existsSync(destDir)) return res.status(400).json({ error: 'Destination folder is gone.' });
    const remaining = await quotaRemaining(req);
    if (st.size > remaining) return res.status(413).json({ error: 'Storage quota exceeded.' });
    const finalName = uniqueName(destDir, meta.name);
    await moveEntry(part, path.join(destDir, finalName));
    await fsp.rm(path.join(dir, req.params.id + '.json'), { force: true });
    res.json({ saved: meta.destPath ? meta.destPath + '/' + finalName : finalName });
  });
}));

filesRouter.delete('/upload/session/:id', wrap(async (req, res) => {
  if (!validName(req.params.id)) return res.status(400).json({ error: 'Invalid id.' });
  const dir = sessionsDir(req.user.username);
  await fsp.rm(path.join(dir, req.params.id + '.part'), { force: true });
  await fsp.rm(path.join(dir, req.params.id + '.json'), { force: true });
  res.json({ ok: true });
}));

// Remove abandoned upload sessions. Called from the hourly timer.
export async function purgeOldSessions(username) {
  const dir = sessionsDir(username);
  let names;
  try { names = await fsp.readdir(dir); } catch { return; }
  const cutoff = Date.now() - MAX_SESSION_AGE;
  for (const n of names) {
    if (!n.endsWith('.json')) continue;
    try {
      const meta = JSON.parse(await fsp.readFile(path.join(dir, n), 'utf8'));
      if (meta.createdAt < cutoff) {
        await fsp.rm(path.join(dir, meta.id + '.part'), { force: true });
        await fsp.rm(path.join(dir, n), { force: true });
      }
    } catch { /* skip */ }
  }
}

filesRouter.post('/mkdir', wrap(async (req, res) => {
  const { path: dirPath, name } = req.body;
  if (!validName(name)) return res.status(400).json({ error: 'Invalid folder name.' });
  const parent = safeJoin(root(req), dirPath);
  const abs = path.join(parent, name);
  if (fs.existsSync(abs)) return res.status(409).json({ error: 'Already exists.' });
  await fsp.mkdir(abs);
  res.json({ ok: true });
}));

filesRouter.post('/rename', wrap(async (req, res) => {
  const { path: itemPath, newName } = req.body;
  if (!validName(newName)) return res.status(400).json({ error: 'Invalid name.' });
  const abs = safeJoin(root(req), itemPath);
  if (abs === root(req)) return res.status(400).json({ error: 'Invalid path.' });
  const dest = path.join(path.dirname(abs), newName);
  if (fs.existsSync(dest)) return res.status(409).json({ error: 'A file with that name already exists.' });
  await fsp.rename(abs, dest);
  res.json({ ok: true });
}));

async function bulkTransfer(req, res, mode) {
  const filesRoot = root(req);
  const { paths, dest } = req.body;
  if (!Array.isArray(paths) || paths.length === 0) return res.status(400).json({ error: 'Nothing selected.' });
  const destAbs = safeJoin(filesRoot, dest);
  const destSt = await fsp.stat(destAbs).catch(() => null);
  if (!destSt || !destSt.isDirectory()) return res.status(400).json({ error: 'Destination folder not found.' });

  const run = async () => {
    // Copying adds bytes, so enforce quota; moving within the same root doesn't.
    if (mode === 'copy') {
      const remaining = await quotaRemaining(req);
      if (remaining !== Infinity) {
        let needed = 0;
        for (const p of paths) {
          const srcAbs = safeJoin(filesRoot, p);
          const stat = await fsp.lstat(srcAbs).catch(() => null);
          if (stat) needed += stat.isDirectory() ? await dirSize(srcAbs) : stat.size;
        }
        if (needed > remaining) {
          res.status(413).json({ error: 'Storage quota exceeded.' });
          return;
        }
      }
    }
    const errors = [];
    for (const p of paths) {
      try {
        const srcAbs = safeJoin(filesRoot, p);
        if (srcAbs === filesRoot) throw new Error('Invalid path.');
        // Refuse moving/copying a folder into itself or its own descendant.
        if (destAbs === srcAbs || destAbs.startsWith(srcAbs + path.sep)) {
          throw new Error('Cannot ' + mode + ' a folder into itself.');
        }
        const name = uniqueName(destAbs, path.basename(srcAbs));
        const target = path.join(destAbs, name);
        if (mode === 'copy') await copyRecursive(srcAbs, target);
        else await moveEntry(srcAbs, target);
      } catch (err) {
        errors.push({ path: p, error: err.message });
      }
    }
    res.json({ ok: errors.length === 0, errors });
  };

  // Copy/move affect quota accounting, so run under the per-user lock.
  await withLock('quota:' + req.user.username, run);
}

filesRouter.post('/move', wrap((req, res) => bulkTransfer(req, res, 'move')));
filesRouter.post('/copy', wrap((req, res) => bulkTransfer(req, res, 'copy')));

// Delete = move to trash. Trash entries get a timestamped name plus a meta
// sidecar recording where they came from so restore can put them back.
filesRouter.post('/delete', wrap(async (req, res) => {
  const { paths } = req.body;
  if (!Array.isArray(paths) || paths.length === 0) return res.status(400).json({ error: 'Nothing selected.' });
  const trash = trashRoot(req);
  fs.mkdirSync(trash, { recursive: true });
  const errors = [];
  for (const p of paths) {
    try {
      const abs = safeJoin(root(req), p);
      if (abs === root(req)) throw new Error('Invalid path.');
      await fsp.stat(abs);
      const id = trashId();
      const rel = path.relative(root(req), abs).split(path.sep).join('/');
      // Write the meta sidecar BEFORE moving the data, so a crash never leaves
      // orphaned, unrestorable, unpurgeable data in the trash.
      await fsp.writeFile(path.join(trash, id + '.meta.json'), JSON.stringify({
        originalPath: rel,
        name: path.basename(abs),
        deletedAt: Date.now()
      }));
      try {
        await moveEntry(abs, path.join(trash, id));
      } catch (err) {
        await fsp.rm(path.join(trash, id + '.meta.json'), { force: true });
        throw err;
      }
    } catch (err) {
      errors.push({ path: p, error: err.message });
    }
  }
  res.json({ ok: errors.length === 0, errors });
}));

filesRouter.get('/search', wrap(async (req, res) => {
  const q = String(req.query.q || '').trim();
  if (q.length < 1) return res.json({ results: [] });
  res.json({ results: await searchFiles(root(req), q) });
}));

filesRouter.get('/usage', wrap(async (req, res) => {
  const used = await usedBytes(req.user.username);
  res.json({ used, quotaMB: req.user.quotaMB || 0 });
}));

// Text file read/write for the built-in editor.
const MAX_EDIT_SIZE = 5 * 1024 * 1024;

filesRouter.get('/content', wrap(async (req, res) => {
  const abs = safeJoin(root(req), req.query.path);
  const st = await fsp.stat(abs);
  if (st.isDirectory()) return res.status(400).json({ error: 'Not a file.' });
  if (st.size > MAX_EDIT_SIZE) return res.status(413).json({ error: 'File too large to edit (5 MB max).' });
  res.type('text/plain').send(await fsp.readFile(abs, 'utf8'));
}));

filesRouter.put('/content', express.text({ limit: '6mb', type: '*/*' }), wrap(async (req, res) => {
  const abs = safeJoin(root(req), req.query.path);
  if (abs === root(req)) return res.status(400).json({ error: 'Invalid path.' });
  const body = typeof req.body === 'string' ? req.body : '';
  if (Buffer.byteLength(body) > MAX_EDIT_SIZE) {
    return res.status(413).json({ error: 'File too large to save (5 MB max).' });
  }
  await withLock('quota:' + req.user.username, async () => {
    const remaining = await quotaRemaining(req);
    const existing = await fsp.stat(abs).catch(() => null);
    if (existing && existing.isDirectory()) return res.status(400).json({ error: 'Not a file.' });
    const delta = Buffer.byteLength(body) - (existing ? existing.size : 0);
    if (delta > remaining) return res.status(413).json({ error: 'Storage quota exceeded.' });
    // Atomic write so a crash mid-save can't truncate the user's file.
    const tmp = abs + '.' + crypto.randomBytes(6).toString('hex') + '.tmp';
    try {
      await fsp.writeFile(tmp, body);
      await fsp.rename(tmp, abs);
    } catch (err) {
      await fsp.rm(tmp, { force: true });
      throw err;
    }
    res.json({ ok: true });
  });
}));

// --- Trash ---

export const trashRouter = express.Router();

trashRouter.get('/list', wrap(async (req, res) => {
  const trash = trashRoot(req);
  fs.mkdirSync(trash, { recursive: true });
  const names = await fsp.readdir(trash);
  const items = [];
  for (const name of names) {
    if (!name.endsWith('.meta.json')) continue;
    const id = name.slice(0, -'.meta.json'.length);
    try {
      const meta = JSON.parse(await fsp.readFile(path.join(trash, name), 'utf8'));
      const entry = await statEntry(path.join(trash, id), meta.name);
      items.push({ id, ...meta, isDir: entry.isDir, size: entry.size });
    } catch { /* orphaned meta */ }
  }
  items.sort((a, b) => b.deletedAt - a.deletedAt);
  res.json({ items });
}));

trashRouter.post('/restore', wrap(async (req, res) => {
  const { ids } = req.body;
  if (!Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: 'Nothing selected.' });
  const trash = trashRoot(req);
  await withLock('quota:' + req.user.username, async () => {
    let remaining = await quotaRemaining(req);
    const errors = [];
    for (const id of ids) {
      try {
        if (!validName(id)) throw new Error('Invalid id.');
        const metaFile = path.join(trash, id + '.meta.json');
        const meta = JSON.parse(await fsp.readFile(metaFile, 'utf8'));
        const srcAbs = path.join(trash, id);
        const stat = await fsp.lstat(srcAbs).catch(() => null);
        if (!stat) throw new Error('Trashed item is missing.');
        const size = stat.isDirectory() ? await dirSize(srcAbs) : stat.size;
        if (size > remaining) throw new Error('Storage quota exceeded.');
        const destAbs = safeJoin(root(req), meta.originalPath);
        const destDir = path.dirname(destAbs);
        fs.mkdirSync(destDir, { recursive: true });
        const finalName = uniqueName(destDir, path.basename(destAbs));
        await moveEntry(srcAbs, path.join(destDir, finalName));
        await fsp.rm(metaFile, { force: true });
        remaining -= size;
      } catch (err) {
        errors.push({ id, error: err.message });
      }
    }
    res.json({ ok: errors.length === 0, errors });
  });
}));

trashRouter.post('/delete', wrap(async (req, res) => {
  const { ids } = req.body;
  if (!Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: 'Nothing selected.' });
  const trash = trashRoot(req);
  for (const id of ids) {
    if (!validName(id)) continue;
    await fsp.rm(path.join(trash, id), { recursive: true, force: true });
    await fsp.rm(path.join(trash, id + '.meta.json'), { force: true });
  }
  res.json({ ok: true });
}));

trashRouter.post('/empty', wrap(async (req, res) => {
  const trash = trashRoot(req);
  const names = await fsp.readdir(trash).catch(() => []);
  for (const name of names) {
    await fsp.rm(path.join(trash, name), { recursive: true, force: true });
  }
  res.json({ ok: true });
}));

// Cap the per-user thumbnail cache (stale thumbs accumulate as files change).
// Keeps the newest MAX by mtime, deletes the rest. Called from the hourly timer.
export async function pruneThumbs(username, max = 4000) {
  const dir = userDirs(username).thumbs;
  let names;
  try {
    names = await fsp.readdir(dir);
  } catch {
    return;
  }
  if (names.length <= max) return;
  const stats = [];
  for (const n of names) {
    const st = await fsp.stat(path.join(dir, n)).catch(() => null);
    if (st) stats.push({ n, m: st.mtimeMs });
  }
  stats.sort((a, b) => b.m - a.m);
  for (const { n } of stats.slice(max)) await fsp.rm(path.join(dir, n), { force: true });
}

// Purge trash items older than retention. Called on a timer from index.js.
// Retention 0 means "keep forever" for normal items, but we still sweep
// orphaned data (data with no meta sidecar) so a crash mid-delete can't leak
// space permanently.
export async function purgeOldTrash(username, retentionDays) {
  const trash = userDirs(username).trash;
  let names;
  try {
    names = await fsp.readdir(trash);
  } catch {
    return;
  }
  const metaIds = new Set(
    names.filter(n => n.endsWith('.meta.json')).map(n => n.slice(0, -'.meta.json'.length))
  );

  // 1) Expire items whose meta says they're older than retention.
  if (retentionDays > 0) {
    const cutoff = Date.now() - retentionDays * 86400000;
    for (const name of names) {
      if (!name.endsWith('.meta.json')) continue;
      const id = name.slice(0, -'.meta.json'.length);
      try {
        const meta = JSON.parse(await fsp.readFile(path.join(trash, name), 'utf8'));
        if (meta.deletedAt < cutoff) {
          await fsp.rm(path.join(trash, id), { recursive: true, force: true });
          await fsp.rm(path.join(trash, name), { force: true });
          metaIds.delete(id);
        }
      } catch { /* skip */ }
    }
  }

  // 2) Sweep orphans: data files/dirs with no meta, and meta with no data.
  //    Give a 1-hour grace so an in-progress delete isn't reaped mid-flight.
  const orphanCutoff = Date.now() - 3600000;
  for (const name of names) {
    try {
      if (name.endsWith('.meta.json')) {
        const id = name.slice(0, -'.meta.json'.length);
        if (!names.includes(id)) {
          const st = await fsp.stat(path.join(trash, name)).catch(() => null);
          if (st && st.mtimeMs < orphanCutoff) await fsp.rm(path.join(trash, name), { force: true });
        }
      } else if (!metaIds.has(name)) {
        const st = await fsp.lstat(path.join(trash, name)).catch(() => null);
        if (st && st.mtimeMs < orphanCutoff) await fsp.rm(path.join(trash, name), { recursive: true, force: true });
      }
    } catch { /* skip */ }
  }
}
