/* Public share page. */
'use strict';

const $ = id => document.getElementById(id);
const token = location.pathname.split('/').pop();
const base = '/s/api/' + encodeURIComponent(token);
let currentPath = '';
let shareInfo = null;

function toast(msg, isError = false) {
  const el = document.createElement('div');
  el.className = 'toast' + (isError ? ' error' : '');
  el.textContent = msg;
  $('toasts').appendChild(el);
  setTimeout(() => el.remove(), isError ? 5000 : 3000);
}

function fmtSize(bytes) {
  if (bytes === 0) return '0 B';
  if (!bytes && bytes !== 0) return '';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
}

const IMG_EXT = new Set(['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'avif']);
const VID_EXT = new Set(['mp4', 'webm', 'mov', 'm4v', 'ogv']);
const AUD_EXT = new Set(['mp3', 'wav', 'ogg', 'flac', 'm4a', 'aac', 'opus']);

function extOf(name) {
  const i = name.lastIndexOf('.');
  return i === -1 ? '' : name.slice(i + 1).toLowerCase();
}
function iconFor(e) {
  if (e.isDir) return '📁';
  const ext = extOf(e.name);
  if (IMG_EXT.has(ext)) return '🖼️';
  if (VID_EXT.has(ext)) return '🎬';
  if (AUD_EXT.has(ext)) return '🎵';
  if (ext === 'pdf') return '📕';
  return '📄';
}

function dlUrl(p, inline) {
  return base + '/download' + (p ? '?path=' + encodeURIComponent(p) : '') +
    (inline ? (p ? '&' : '?') + 'dl=0' : '');
}

async function fetchInfo() {
  const res = await fetch(base + '/info');
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    $('share-error-text').textContent = data.error || 'This share does not exist or has expired.';
    $('share-error').classList.remove('hidden');
    return;
  }
  const info = await res.json();
  if (info.locked) {
    $('lock-screen').classList.remove('hidden');
    return;
  }
  shareInfo = info;
  renderShare();
}

$('lock-form').addEventListener('submit', async e => {
  e.preventDefault();
  const res = await fetch(base + '/unlock', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: $('lock-password').value })
  });
  if (res.ok) {
    $('lock-screen').classList.add('hidden');
    fetchInfo();
  } else {
    const data = await res.json().catch(() => ({}));
    const err = $('lock-error');
    err.textContent = data.error || 'Wrong password.';
    err.classList.remove('hidden');
  }
});

function renderShare() {
  $('share-content').classList.remove('hidden');
  $('share-name').textContent = shareInfo.name;
  document.title = shareInfo.name + ' — Shared with you';

  if (shareInfo.isMulti) {
    $('share-icon').textContent = '🗂️';
    $('share-meta').textContent = 'Shared items';
    $('btn-share-download').href = base + '/download';
    $('btn-share-download').textContent = '⬇ Download all (.zip)';
    loadMulti();
  } else if (shareInfo.isDir) {
    $('share-icon').textContent = '📁';
    $('share-meta').textContent = 'Shared folder';
    $('btn-share-download').href = dlUrl(currentPath, false);
    $('btn-share-download').textContent = '⬇ Download all (.zip)';
    if (shareInfo.allowUpload) $('btn-share-upload').classList.remove('hidden');
    loadFolder('');
  } else {
    $('share-icon').textContent = iconFor({ isDir: false, name: shareInfo.name });
    $('share-meta').textContent = fmtSize(shareInfo.size);
    $('btn-share-download').href = dlUrl('', false);
    $('share-list').classList.add('hidden');
    renderInlinePreview(shareInfo.name, dlUrl('', true));
  }
}

function renderInlinePreview(name, url) {
  const box = $('share-preview-inline');
  box.innerHTML = '';
  const ext = extOf(name);
  if (IMG_EXT.has(ext)) {
    const img = document.createElement('img');
    img.src = url;
    img.style.maxWidth = '100%';
    img.style.borderRadius = '10px';
    box.appendChild(img);
  } else if (VID_EXT.has(ext)) {
    const v = document.createElement('video');
    v.src = url;
    v.controls = true;
    v.style.maxWidth = '100%';
    v.style.borderRadius = '10px';
    box.appendChild(v);
  } else if (AUD_EXT.has(ext)) {
    const a = document.createElement('audio');
    a.src = url;
    a.controls = true;
    box.appendChild(a);
  } else if (ext === 'pdf') {
    const f = document.createElement('iframe');
    f.src = url;
    f.style.width = '100%';
    f.style.height = '75vh';
    f.style.border = 'none';
    f.style.borderRadius = '10px';
    box.appendChild(f);
  }
}

async function loadMulti() {
  const res = await fetch(base + '/list');
  if (!res.ok) return toast('Could not load items.', true);
  const data = await res.json();
  const entries = data.entries.sort((a, b) =>
    (b.isDir - a.isDir) || a.name.localeCompare(b.name, undefined, { numeric: true }));
  const list = $('share-list');
  list.innerHTML = '';
  $('share-preview-inline').innerHTML = '';
  for (const e of entries) {
    const el = document.createElement('div');
    el.className = 'entry';
    const thumb = document.createElement('div');
    thumb.className = 'thumb';
    thumb.textContent = iconFor(e);
    const name = document.createElement('div');
    name.className = 'ename';
    name.textContent = e.name;
    const meta = document.createElement('div');
    meta.className = 'emeta';
    meta.textContent = e.isDir ? 'Folder' : fmtSize(e.size);
    const dl = document.createElement('a');
    dl.className = 'btn sm';
    dl.textContent = '⬇';
    dl.style.textDecoration = 'none';
    const itemUrl = base + '/download?i=' + e.i;
    dl.href = itemUrl;
    dl.addEventListener('click', ev => ev.stopPropagation());
    el.append(thumb, name, meta, dl);
    el.addEventListener('click', () => {
      const ext = extOf(e.name);
      if (!e.isDir && (IMG_EXT.has(ext) || VID_EXT.has(ext) || AUD_EXT.has(ext) || ext === 'pdf')) {
        renderInlinePreview(e.name, itemUrl + '&dl=0');
        $('share-preview-inline').scrollIntoView({ behavior: 'smooth' });
      } else {
        window.location.href = itemUrl;
      }
    });
    list.appendChild(el);
  }
}

async function loadFolder(path) {
  currentPath = path;
  $('btn-share-download').href = dlUrl(path, false);
  const res = await fetch(base + '/list?path=' + encodeURIComponent(path));
  if (!res.ok) return toast('Could not load folder.', true);
  const data = await res.json();
  const entries = data.entries.sort((a, b) =>
    (b.isDir - a.isDir) || a.name.localeCompare(b.name, undefined, { numeric: true }));

  const crumbs = $('share-breadcrumbs');
  crumbs.classList.remove('hidden');
  crumbs.innerHTML = '';
  const mkCrumb = (label, target, current) => {
    const b = document.createElement('button');
    b.className = 'crumb' + (current ? ' current' : '');
    b.textContent = label;
    if (!current) b.addEventListener('click', () => loadFolder(target));
    return b;
  };
  const parts = path ? path.split('/') : [];
  crumbs.appendChild(mkCrumb(shareInfo.name, '', parts.length === 0));
  let acc = '';
  parts.forEach((p, i) => {
    const sep = document.createElement('span');
    sep.className = 'crumb-sep';
    sep.textContent = '›';
    crumbs.appendChild(sep);
    acc = acc ? acc + '/' + p : p;
    crumbs.appendChild(mkCrumb(p, acc, i === parts.length - 1));
  });

  const list = $('share-list');
  list.innerHTML = '';
  $('share-preview-inline').innerHTML = '';
  if (!entries.length) {
    list.innerHTML = '<div class="empty-state" style="padding:40px"><p class="muted">Empty folder</p></div>';
    return;
  }
  for (const e of entries) {
    const el = document.createElement('div');
    el.className = 'entry';
    const thumb = document.createElement('div');
    thumb.className = 'thumb';
    thumb.textContent = iconFor(e);
    const name = document.createElement('div');
    name.className = 'ename';
    name.textContent = e.name;
    const meta = document.createElement('div');
    meta.className = 'emeta';
    meta.textContent = e.isDir ? 'Folder' : fmtSize(e.size);
    const dl = document.createElement('a');
    dl.className = 'btn sm';
    dl.textContent = '⬇';
    dl.style.textDecoration = 'none';
    const childPath = path ? path + '/' + e.name : e.name;
    dl.href = dlUrl(childPath, false);
    dl.addEventListener('click', ev => ev.stopPropagation());
    el.append(thumb, name, meta, dl);
    el.addEventListener('click', () => {
      if (e.isDir) return loadFolder(childPath);
      const ext = extOf(e.name);
      if (IMG_EXT.has(ext) || VID_EXT.has(ext) || AUD_EXT.has(ext) || ext === 'pdf') {
        renderInlinePreview(e.name, dlUrl(childPath, true));
        $('share-preview-inline').scrollIntoView({ behavior: 'smooth' });
      } else {
        window.location.href = dlUrl(childPath, false);
      }
    });
    list.appendChild(el);
  }
}

// Drop-box uploads for folder shares that allow it.
$('btn-share-upload').addEventListener('click', () => $('share-file-input').click());
$('share-file-input').addEventListener('change', async e => {
  const files = [...e.target.files];
  e.target.value = '';
  if (!files.length) return;
  const form = new FormData();
  files.forEach(f => form.append('files', f, f.name));
  const res = await fetch(base + '/upload', { method: 'POST', body: form });
  if (res.ok) {
    toast('Uploaded ' + files.length + ' file' + (files.length === 1 ? '' : 's'));
    if (currentPath === '') loadFolder('');
  } else {
    const data = await res.json().catch(() => ({}));
    toast(data.error || 'Upload failed.', true);
  }
});

fetchInfo();
