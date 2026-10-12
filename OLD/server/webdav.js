// Minimal WebDAV server exposing each user's files/ directory so My Cloud can
// be mounted as a network drive (Finder, Windows, mobile apps, rclone, etc.).
// Stateless over the same filesystem — no database, consistent with the app.
import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import fsp from 'fs/promises';
import path from 'path';
import mime from 'mime-types';
import { verifyDavAuth, userDirs } from './auth.js';
import { safeJoin, realContained } from './fsutil.js';

export const davRouter = express.Router();
const MOUNT = '/dav';
const ALLOW = 'OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, COPY, MOVE, PROPFIND, PROPPATCH, LOCK, UNLOCK';

// --- Basic auth with a short success cache (WebDAV re-sends credentials on
// every request; caching avoids a bcrypt verification per request). ---
const authCache = new Map(); // sha256(header) -> { username, exp }
const AUTH_TTL = 5 * 60000;

function basicAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const fail = () => {
    res.setHeader('WWW-Authenticate', 'Basic realm="My Cloud", charset="UTF-8"');
    res.status(401).end('Authentication required');
  };
  if (!header.startsWith('Basic ')) return fail();
  const key = crypto.createHash('sha256').update(header).digest('hex');
  const cached = authCache.get(key);
  if (cached && Date.now() < cached.exp) { req.davUser = cached.username; return next(); }
  let decoded;
  try { decoded = Buffer.from(header.slice(6), 'base64').toString('utf8'); } catch { return fail(); }
  const i = decoded.indexOf(':');
  if (i === -1) return fail();
  const user = verifyDavAuth(decoded.slice(0, i), decoded.slice(i + 1));
  if (!user) return fail();
  authCache.set(key, { username: user.username, exp: Date.now() + AUTH_TTL });
  req.davUser = user.username;
  next();
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of authCache) if (now > v.exp) authCache.delete(k);
}, AUTH_TTL).unref?.();

davRouter.use(basicAuth);
// Buffer (and thereby drain) small control-method bodies; PUT streams its body.
davRouter.use((req, res, next) => {
  if (req.method === 'PUT') return next();
  express.text({ type: () => true, limit: '2mb' })(req, res, () => next());
});

// --- Helpers ---
const rootOf = req => userDirs(req.davUser).files;
const absOf = req => safeJoin(rootOf(req), decodeURIComponent(req.path.replace(/^\/+/, '')));
const xmlEscape = s => String(s).replace(/[<>&'"]/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;' }[c]));

function hrefFor(relPath, isDir) {
  const enc = relPath.split('/').filter(Boolean).map(encodeURIComponent).join('/');
  let h = MOUNT + (enc ? '/' + enc : '/');
  if (isDir && !h.endsWith('/')) h += '/';
  return h;
}

function propXml(relPath, st) {
  const isDir = st.isDirectory();
  const name = relPath.split('/').filter(Boolean).pop() || '';
  const type = isDir ? '' : (mime.lookup(name) || 'application/octet-stream');
  const etag = '"' + crypto.createHash('sha1').update(relPath + st.mtimeMs + st.size).digest('hex').slice(0, 16) + '"';
  return `<D:response><D:href>${xmlEscape(hrefFor(relPath, isDir))}</D:href>` +
    `<D:propstat><D:prop>` +
    `<D:displayname>${xmlEscape(name)}</D:displayname>` +
    `<D:resourcetype>${isDir ? '<D:collection/>' : ''}</D:resourcetype>` +
    (isDir ? '' : `<D:getcontentlength>${st.size}</D:getcontentlength><D:getcontenttype>${xmlEscape(type)}</D:getcontenttype>`) +
    `<D:getlastmodified>${new Date(st.mtimeMs).toUTCString()}</D:getlastmodified>` +
    `<D:creationdate>${new Date(st.birthtimeMs || st.mtimeMs).toISOString()}</D:creationdate>` +
    `<D:getetag>${etag}</D:getetag>` +
    `</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>`;
}

function destOf(req) {
  const dest = req.headers.destination;
  if (!dest) return null;
  let p;
  try { p = new URL(dest, 'http://x').pathname; } catch { return null; }
  if (!p.startsWith(MOUNT)) return null;
  return safeJoin(rootOf(req), decodeURIComponent(p.slice(MOUNT.length).replace(/^\/+/, '')));
}

// --- Method handlers ---
async function propfind(req, res) {
  const root = rootOf(req);
  const abs = absOf(req);
  if (!await realContained(root, abs)) return res.status(404).end();
  const st = await fsp.stat(abs).catch(() => null);
  if (!st) return res.status(404).end();
  const depth = req.headers.depth === undefined ? '1' : String(req.headers.depth);
  const relBase = '/' + path.relative(root, abs).split(path.sep).filter(Boolean).join('/');
  const base = relBase === '/' ? '' : relBase;

  let body = '<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">';
  body += propXml(base, st);
  if (st.isDirectory() && depth !== '0') {
    for (const n of await fsp.readdir(abs).catch(() => [])) {
      if (n.endsWith('.uploading')) continue;
      const cst = await fsp.stat(path.join(abs, n)).catch(() => null);
      if (cst) body += propXml(base + '/' + n, cst);
    }
  }
  body += '</D:multistatus>';
  res.status(207).type('application/xml; charset=utf-8').end(body);
}

function proppatch(req, res) {
  // Accept and no-op (Finder/Windows set metadata like timestamps).
  res.status(207).type('application/xml; charset=utf-8').end(
    `<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:"><D:response>` +
    `<D:href>${xmlEscape(req.originalUrl)}</D:href><D:propstat><D:status>HTTP/1.1 200 OK</D:status></D:propstat>` +
    `</D:response></D:multistatus>`);
}

function lock(req, res) {
  // We don't enforce locks (single-user tree); issue a token so clients that
  // require locking before writing (Finder, Windows) proceed.
  const token = 'opaquelocktoken:' + crypto.randomUUID();
  res.setHeader('Lock-Token', `<${token}>`);
  res.status(200).type('application/xml; charset=utf-8').end(
    `<?xml version="1.0" encoding="utf-8"?><D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock>` +
    `<D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope><D:depth>infinity</D:depth>` +
    `<D:timeout>Second-3600</D:timeout><D:locktoken><D:href>${token}</D:href></D:locktoken>` +
    `</D:activelock></D:lockdiscovery></D:prop>`);
}

async function get(req, res) {
  const abs = absOf(req);
  if (!await realContained(rootOf(req), abs)) return res.status(404).end();
  const st = await fsp.stat(abs).catch(() => null);
  if (!st) return res.status(404).end();
  if (st.isDirectory()) { res.setHeader('Content-Type', 'text/plain'); return res.end('Collection'); }
  res.setHeader('Content-Type', mime.lookup(abs) || 'application/octet-stream');
  res.setHeader('Content-Length', st.size);
  res.setHeader('Accept-Ranges', 'bytes');
  const range = req.headers.range && /^bytes=(\d*)-(\d*)$/.exec(req.headers.range);
  if (range && req.method === 'GET') {
    let start = range[1] === '' ? st.size - parseInt(range[2], 10) : parseInt(range[1], 10);
    let end = range[2] === '' ? st.size - 1 : Math.min(parseInt(range[2], 10), st.size - 1);
    start = Math.max(0, start);
    if (start <= end) {
      res.status(206);
      res.setHeader('Content-Range', `bytes ${start}-${end}/${st.size}`);
      res.setHeader('Content-Length', end - start + 1);
      return fs.createReadStream(abs, { start, end }).pipe(res);
    }
  }
  if (req.method === 'HEAD') return res.end();
  fs.createReadStream(abs).pipe(res);
}

async function put(req, res) {
  const abs = absOf(req);
  if (abs === rootOf(req)) return res.status(409).end();
  if (!fs.existsSync(path.dirname(abs))) return res.status(409).end();
  if (fs.existsSync(abs) && fs.statSync(abs).isDirectory()) return res.status(409).end();
  const existed = fs.existsSync(abs);
  const tmp = abs + '.' + crypto.randomBytes(6).toString('hex') + '.uploading';
  try {
    await new Promise((resolve, reject) => {
      const out = fs.createWriteStream(tmp);
      req.pipe(out);
      out.on('finish', resolve);
      out.on('error', reject);
      req.on('aborted', () => { out.destroy(); reject(new Error('aborted')); });
    });
  } catch (err) {
    await fsp.rm(tmp, { force: true });
    throw err;
  }
  await fsp.rename(tmp, abs);
  res.status(existed ? 204 : 201).end();
}

async function del(req, res) {
  const abs = absOf(req);
  if (abs === rootOf(req)) return res.status(403).end();
  if (!fs.existsSync(abs)) return res.status(404).end();
  await fsp.rm(abs, { recursive: true, force: true });
  res.status(204).end();
}

async function mkcol(req, res) {
  const abs = absOf(req);
  if (fs.existsSync(abs)) return res.status(405).end();
  if (!fs.existsSync(path.dirname(abs))) return res.status(409).end();
  await fsp.mkdir(abs);
  res.status(201).end();
}

async function copyMove(req, res) {
  const src = absOf(req);
  const dest = destOf(req);
  if (!dest) return res.status(400).end();
  if (src === rootOf(req)) return res.status(403).end();
  if (!fs.existsSync(src)) return res.status(404).end();
  if (dest === src || dest.startsWith(src + path.sep)) return res.status(403).end();
  const overwrite = (req.headers.overwrite || 'T').toUpperCase() !== 'F';
  const destExists = fs.existsSync(dest);
  if (destExists && !overwrite) return res.status(412).end();
  if (!fs.existsSync(path.dirname(dest))) return res.status(409).end();
  if (destExists) await fsp.rm(dest, { recursive: true, force: true });
  if (req.method === 'MOVE') {
    await fsp.rename(src, dest).catch(async err => {
      if (err.code === 'EXDEV') { await fsp.cp(src, dest, { recursive: true }); await fsp.rm(src, { recursive: true, force: true }); }
      else throw err;
    });
  } else {
    await fsp.cp(src, dest, { recursive: true });
  }
  res.status(destExists ? 204 : 201).end();
}

// --- Single dispatcher (custom WebDAV verbs aren't Express route helpers). ---
davRouter.use((req, res) => {
  const handle = fn => Promise.resolve(fn(req, res)).catch(err => {
    const status = err.status || (err.code === 'ENOENT' ? 404 : 500);
    if (status >= 500) console.error('webdav:', err);
    if (!res.headersSent) res.status(status).end();
  });
  switch (req.method) {
    case 'OPTIONS':
      res.setHeader('Allow', ALLOW);
      res.setHeader('DAV', '1, 2');
      res.setHeader('MS-Author-Via', 'DAV');
      return res.status(204).end();
    case 'PROPFIND': return handle(propfind);
    case 'PROPPATCH': return proppatch(req, res);
    case 'GET':
    case 'HEAD': return handle(get);
    case 'PUT': return handle(put);
    case 'DELETE': return handle(del);
    case 'MKCOL': return handle(mkcol);
    case 'COPY':
    case 'MOVE': return handle(copyMove);
    case 'LOCK': return lock(req, res);
    case 'UNLOCK': return res.status(204).end();
    default:
      res.setHeader('Allow', ALLOW);
      return res.status(405).end();
  }
});
