import fs from 'fs';
import fsp from 'fs/promises';
import path from 'path';

// Resolve a client-supplied relative path inside a root, refusing traversal.
// Returns the absolute path or throws.
export function safeJoin(root, relPath) {
  const rel = String(relPath || '').replace(/\\/g, '/');
  const resolved = path.resolve(root, '.' + path.posix.sep + rel);
  const rootResolved = path.resolve(root);
  if (resolved !== rootResolved && !resolved.startsWith(rootResolved + path.sep)) {
    const err = new Error('Invalid path.');
    err.status = 400;
    throw err;
  }
  return resolved;
}

// Resolve symlinks and confirm the real target is still inside root. safeJoin
// only guards the lexical path; this catches a symlink placed out-of-band (e.g.
// via SMB into /data) that points outside the user's area. Returns the real
// path if contained, else null.
export async function realContained(root, abs) {
  try {
    const [realRoot, realAbs] = await Promise.all([fsp.realpath(root), fsp.realpath(abs)]);
    if (realAbs === realRoot || realAbs.startsWith(realRoot + path.sep)) return realAbs;
  } catch { /* missing target */ }
  return null;
}

export function validName(name) {
  if (typeof name !== 'string' || name.length === 0 || name.length > 255) return false;
  if (name === '.' || name === '..') return false;
  if (name.includes('/') || name.includes('\\')) return false;
  for (const ch of name) {
    if (ch.charCodeAt(0) < 32) return false;
  }
  return true;
}

export async function statEntry(abs, name) {
  const st = await fsp.stat(abs);
  return {
    name,
    isDir: st.isDirectory(),
    size: st.isDirectory() ? 0 : st.size,
    mtime: st.mtimeMs
  };
}

export async function listDir(abs) {
  const names = await fsp.readdir(abs);
  const entries = [];
  for (const name of names) {
    try {
      entries.push(await statEntry(path.join(abs, name), name));
    } catch {
      // Skip entries that vanish or can't be stat'd mid-listing.
    }
  }
  return entries;
}

const MAX_DEPTH = 40;

export async function dirSize(abs, depth = 0) {
  if (depth > MAX_DEPTH) return 0;
  let total = 0;
  let entries;
  try {
    entries = await fsp.readdir(abs, { withFileTypes: true });
  } catch {
    return 0;
  }
  for (const e of entries) {
    const p = path.join(abs, e.name);
    // Only descend into real directories and size real files — never follow
    // symlinks (avoids escaping the root and cycle blow-ups).
    if (e.isDirectory()) total += await dirSize(p, depth + 1);
    else if (e.isFile()) {
      try {
        total += (await fsp.lstat(p)).size;
      } catch { /* vanished */ }
    }
  }
  return total;
}

// "photo.jpg" -> "photo (1).jpg" until the name is free in dir.
export function uniqueName(dir, name) {
  if (!fs.existsSync(path.join(dir, name))) return name;
  const ext = path.extname(name);
  const base = name.slice(0, name.length - ext.length);
  for (let i = 1; i < 10000; i++) {
    const candidate = `${base} (${i})${ext}`;
    if (!fs.existsSync(path.join(dir, candidate))) return candidate;
  }
  throw new Error('Could not find a unique name.');
}

export async function copyRecursive(src, dest) {
  await fsp.cp(src, dest, { recursive: true, errorOnExist: true, force: false });
}

export async function moveEntry(src, dest) {
  try {
    await fsp.rename(src, dest);
  } catch (err) {
    if (err.code === 'EXDEV') {
      // Cross-device (e.g. trash on another mount): copy then delete.
      await fsp.cp(src, dest, { recursive: true });
      await fsp.rm(src, { recursive: true, force: true });
    } else {
      throw err;
    }
  }
}

export async function searchFiles(root, query, limit = 200) {
  const q = query.toLowerCase();
  const results = [];
  async function walk(dir, rel, depth) {
    if (results.length >= limit || depth > MAX_DEPTH) return;
    let entries;
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (results.length >= limit) return;
      const childRel = rel ? rel + '/' + e.name : e.name;
      if (e.name.toLowerCase().includes(q)) {
        try {
          results.push({ path: childRel, ...(await statEntry(path.join(dir, e.name), e.name)) });
        } catch { /* vanished */ }
      }
      if (e.isDirectory()) await walk(path.join(dir, e.name), childRel, depth + 1);
    }
  }
  await walk(root, '', 0);
  return results;
}
