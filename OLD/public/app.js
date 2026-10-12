/* My Cloud — vanilla JS frontend, no build step. */
'use strict';

const $ = id => document.getElementById(id);

// ---------- API helper ----------
async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: opts.body && !(opts.body instanceof FormData) ? { 'Content-Type': 'application/json' } : {},
    ...opts,
    body: opts.body && !(opts.body instanceof FormData) && typeof opts.body !== 'string'
      ? JSON.stringify(opts.body) : opts.body
  });
  if (res.status === 401 && !path.startsWith('/api/auth') && !path.startsWith('/api/status')) {
    showAuth();
    throw new Error('Not signed in.');
  }
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON */ }
  if (!res.ok) throw new Error((data && data.error) || 'Request failed.');
  return data;
}

// ---------- Toasts ----------
function toast(msg, isError = false) {
  const el = document.createElement('div');
  el.className = 'toast' + (isError ? ' error' : '');
  el.textContent = msg;
  $('toasts').appendChild(el);
  setTimeout(() => el.remove(), isError ? 5000 : 3000);
}

// ---------- Formatting ----------
function fmtSize(bytes) {
  if (bytes === 0) return '0 B';
  if (!bytes && bytes !== 0) return '';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
}
function fmtDate(ms) {
  return new Date(ms).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

const IMG_EXT = new Set(['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'avif', 'ico']);
// Types the server can generate a thumbnail for (superset excludes svg/ico).
const THUMB_EXT = new Set(['jpg', 'jpeg', 'png', 'webp', 'gif', 'avif', 'tiff', 'tif', 'bmp']);
const VID_EXT = new Set(['mp4', 'webm', 'mov', 'm4v', 'mkv', 'ogv']);
const AUD_EXT = new Set(['mp3', 'wav', 'ogg', 'flac', 'm4a', 'aac', 'opus']);
const TXT_EXT = new Set(['txt', 'md', 'log', 'json', 'js', 'ts', 'css', 'html', 'xml', 'yml', 'yaml',
  'sh', 'py', 'ini', 'conf', 'cfg', 'csv', 'env', 'toml', 'sql', 'c', 'cpp', 'h', 'java', 'go', 'rs', 'rb', 'php']);

function extOf(name) {
  const i = name.lastIndexOf('.');
  return i === -1 ? '' : name.slice(i + 1).toLowerCase();
}
function iconFor(entry) {
  if (entry.isDir) return '📁';
  const ext = extOf(entry.name);
  if (IMG_EXT.has(ext)) return '🖼️';
  if (VID_EXT.has(ext)) return '🎬';
  if (AUD_EXT.has(ext)) return '🎵';
  if (ext === 'pdf') return '📕';
  if (['zip', 'tar', 'gz', '7z', 'rar', 'xz'].includes(ext)) return '🗜️';
  if (TXT_EXT.has(ext)) return '📄';
  if (['doc', 'docx', 'odt'].includes(ext)) return '📝';
  if (['xls', 'xlsx', 'ods'].includes(ext)) return '📊';
  if (['ppt', 'pptx', 'odp'].includes(ext)) return '📽️';
  return '📄';
}
function previewKind(name) {
  const ext = extOf(name);
  if (IMG_EXT.has(ext)) return 'image';
  if (VID_EXT.has(ext)) return 'video';
  if (AUD_EXT.has(ext)) return 'audio';
  if (ext === 'pdf') return 'pdf';
  if (TXT_EXT.has(ext)) return 'text';
  return null;
}

// ---------- State ----------
const state = {
  user: null,
  path: '',            // current folder, '' = root
  entries: [],
  selected: new Set(), // names within current folder
  viewMode: localStorage.getItem('mycloud_view') || 'grid',
  currentView: 'files'
};

function joinPath(dir, name) {
  return dir ? dir + '/' + name : name;
}
function fileUrl(p, dl) {
  return '/api/files/download?path=' + encodeURIComponent(p) + (dl ? '' : '&dl=0');
}

// ---------- Auth screens ----------
let isSetupMode = false;

function showAuth() {
  $('main-screen').classList.add('hidden');
  $('auth-screen').classList.remove('hidden');
}

async function initAuth() {
  const status = await api('/api/status');
  document.title = status.siteName || 'My Cloud';
  isSetupMode = status.needsSetup;
  if (isSetupMode) {
    $('auth-title').textContent = 'Welcome!';
    $('auth-subtitle').textContent = 'Create the first admin account to get started.';
    $('auth-password2').classList.remove('hidden');
    $('auth-submit').textContent = 'Create account';
  } else {
    $('auth-title').textContent = status.siteName || 'My Cloud';
    $('auth-subtitle').textContent = 'Sign in to your files';
    $('auth-password2').classList.add('hidden');
    $('auth-submit').textContent = 'Sign in';
  }
}

$('auth-form').addEventListener('submit', async e => {
  e.preventDefault();
  const errEl = $('auth-error');
  errEl.classList.add('hidden');
  const username = $('auth-username').value.trim();
  const password = $('auth-password').value;
  try {
    if (isSetupMode) {
      if (password !== $('auth-password2').value) throw new Error('Passwords do not match.');
      await api('/api/setup', { method: 'POST', body: { username, password } });
    } else {
      const code = $('auth-code').value.trim();
      const r = await api('/api/auth/login', { method: 'POST', body: { username, password, code: code || undefined } });
      if (r && r.twofa) {
        // Second factor required: reveal the code field and wait for re-submit.
        $('auth-code').classList.remove('hidden');
        $('auth-subtitle').textContent = 'Enter the code from your authenticator app';
        $('auth-submit').textContent = 'Verify';
        setTimeout(() => $('auth-code').focus(), 50);
        return;
      }
    }
    $('auth-password').value = '';
    $('auth-password2').value = '';
    $('auth-code').value = '';
    $('auth-code').classList.add('hidden');
    await enterApp();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.classList.remove('hidden');
  }
});

$('btn-logout').addEventListener('click', async () => {
  await api('/api/auth/logout', { method: 'POST' });
  state.user = null;
  await initAuth();
  showAuth();
});

async function enterApp() {
  const me = await api('/api/auth/me');
  state.user = me;
  document.title = me.siteName || 'My Cloud';
  $('brand-name').textContent = me.siteName || 'My Cloud';
  $('user-name').textContent = me.username;
  $('nav-admin').classList.toggle('hidden', !me.isAdmin);
  $('auth-screen').classList.add('hidden');
  $('main-screen').classList.remove('hidden');
  switchView('files');
  refreshUsage();
}

async function refreshUsage() {
  try {
    const u = await api('/api/files/usage');
    const w = $('usage-widget');
    w.classList.remove('hidden');
    if (u.quotaMB > 0) {
      const total = u.quotaMB * 1024 * 1024;
      const pct = Math.min(100, (u.used / total) * 100);
      $('usage-fill').style.width = pct + '%';
      $('usage-fill').style.background = pct > 90 ? 'var(--danger)' : 'var(--accent)';
      $('usage-text').textContent = `${fmtSize(u.used)} of ${fmtSize(total)} used`;
    } else {
      $('usage-fill').style.width = '100%';
      $('usage-fill').style.background = 'var(--border)';
      $('usage-text').textContent = `${fmtSize(u.used)} used`;
    }
  } catch { /* non-fatal */ }
}

// ---------- View switching ----------
function switchView(view) {
  state.currentView = view;
  document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === view));
  for (const v of ['files', 'search', 'shares', 'trash', 'admin']) {
    $('view-' + v).classList.toggle('hidden', v !== view);
  }
  $('files-actions').style.visibility = view === 'files' ? 'visible' : 'hidden';
  document.querySelector('.sidebar').classList.remove('open');
  if (view === 'files') loadFiles(state.path);
  else if (view === 'shares') loadShares();
  else if (view === 'trash') loadTrash();
  else if (view === 'admin') loadAdmin();
}

document.querySelectorAll('.nav-item').forEach(b =>
  b.addEventListener('click', () => switchView(b.dataset.view)));
$('btn-menu').addEventListener('click', () => document.querySelector('.sidebar').classList.toggle('open'));

// ---------- Files view ----------
async function loadFiles(path) {
  try {
    const data = await api('/api/files/list?path=' + encodeURIComponent(path));
    state.path = path;
    state.entries = data.entries.sort((a, b) =>
      (b.isDir - a.isDir) || a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' }));
    state.selected.clear();
    renderBreadcrumbs();
    renderEntries();
    updateSelectionBar();
  } catch (err) {
    if (err.message !== 'Not signed in.') toast(err.message, true);
    if (path !== '') loadFiles('');
  }
}

function renderBreadcrumbs() {
  const el = $('breadcrumbs');
  el.innerHTML = '';
  const parts = state.path ? state.path.split('/') : [];
  const mk = (label, target, current) => {
    const b = document.createElement('button');
    b.className = 'crumb' + (current ? ' current' : '');
    b.textContent = label;
    if (!current) b.addEventListener('click', () => loadFiles(target));
    return b;
  };
  el.appendChild(mk('Home', '', parts.length === 0));
  let acc = '';
  parts.forEach((p, i) => {
    const sep = document.createElement('span');
    sep.className = 'crumb-sep';
    sep.textContent = '›';
    el.appendChild(sep);
    acc = acc ? acc + '/' + p : p;
    el.appendChild(mk(p, acc, i === parts.length - 1));
  });
}

function renderEntries() {
  const list = $('file-list');
  list.className = 'file-list ' + (state.viewMode === 'grid' ? 'grid-mode' : 'list-mode');
  list.innerHTML = '';
  $('empty-state').classList.toggle('hidden', state.entries.length > 0);

  for (const entry of state.entries) {
    const el = document.createElement('div');
    el.className = 'entry' + (state.selected.has(entry.name) ? ' selected' : '');
    el.dataset.name = entry.name;

    const thumb = document.createElement('div');
    thumb.className = 'thumb';
    if (!entry.isDir && THUMB_EXT.has(extOf(entry.name)) && entry.size < 60 * 1024 * 1024) {
      const img = document.createElement('img');
      img.loading = 'lazy';
      const s = state.viewMode === 'grid' ? 256 : 64;
      img.src = '/api/files/thumb?path=' + encodeURIComponent(joinPath(state.path, entry.name)) + '&s=' + s;
      img.alt = '';
      img.onerror = () => { thumb.textContent = iconFor(entry); };
      thumb.appendChild(img);
    } else {
      thumb.textContent = iconFor(entry);
    }

    const name = document.createElement('div');
    name.className = 'ename';
    name.textContent = entry.name;
    name.title = entry.name;

    const meta = document.createElement('div');
    meta.className = 'emeta';
    meta.textContent = (entry.isDir ? '' : fmtSize(entry.size) + ' · ') + fmtDate(entry.mtime);

    el.append(thumb, name, meta);

    el.addEventListener('click', e => {
      if (e.ctrlKey || e.metaKey) {
        toggleSelect(entry.name);
      } else if (e.shiftKey && state.selected.size) {
        rangeSelect(entry.name);
      } else {
        openEntry(entry);
      }
    });
    el.addEventListener('contextmenu', e => {
      e.preventDefault();
      if (!state.selected.has(entry.name)) {
        state.selected.clear();
        state.selected.add(entry.name);
        renderSelectionOnly();
      }
      showContextMenu(e.clientX, e.clientY, entry);
    });
    list.appendChild(el);
  }
}

function renderSelectionOnly() {
  document.querySelectorAll('#file-list .entry').forEach(el =>
    el.classList.toggle('selected', state.selected.has(el.dataset.name)));
  updateSelectionBar();
}

function toggleSelect(name) {
  if (state.selected.has(name)) state.selected.delete(name);
  else state.selected.add(name);
  renderSelectionOnly();
}

function rangeSelect(name) {
  const names = state.entries.map(e => e.name);
  const anchors = [...state.selected].map(n => names.indexOf(n)).filter(i => i !== -1);
  const target = names.indexOf(name);
  if (target === -1 || anchors.length === 0) return toggleSelect(name);
  const from = Math.min(...anchors, target);
  const to = Math.max(...anchors, target);
  for (let i = from; i <= to; i++) state.selected.add(names[i]);
  renderSelectionOnly();
}

function updateSelectionBar() {
  const bar = $('selection-bar');
  bar.classList.toggle('hidden', state.selected.size === 0);
  $('selection-count').textContent = state.selected.size + ' selected';
}

$('sel-clear').addEventListener('click', () => {
  state.selected.clear();
  renderSelectionOnly();
});

function openEntry(entry) {
  if (entry.isDir) {
    loadFiles(joinPath(state.path, entry.name));
  } else if (previewKind(entry.name)) {
    openPreview(entry);
  } else {
    window.location.href = fileUrl(joinPath(state.path, entry.name), true);
  }
}

// ---------- View toggle ----------
$('btn-view-toggle').addEventListener('click', () => {
  state.viewMode = state.viewMode === 'grid' ? 'list' : 'grid';
  localStorage.setItem('mycloud_view', state.viewMode);
  renderEntries();
  renderSelectionOnly();
});

// ---------- Context menu ----------
function showContextMenu(x, y, entry) {
  const menu = $('context-menu');
  menu.innerHTML = '';
  const multi = state.selected.size > 1;
  const add = (label, fn, danger) => {
    const b = document.createElement('button');
    if (danger) b.className = 'danger';
    b.textContent = label;
    b.addEventListener('click', () => { hideContextMenu(); fn(); });
    menu.appendChild(b);
  };
  const sep = () => menu.appendChild(document.createElement('hr'));

  if (!multi) {
    if (entry.isDir) add('📂 Open', () => openEntry(entry));
    else if (previewKind(entry.name)) add('👁 Preview', () => openPreview(entry));
    add('⬇ Download', () => downloadSelection());
    if (state.user?.allowPublicShares) add('🔗 Share…', () => shareDialog(joinPath(state.path, entry.name)));
    sep();
    add('✏️ Rename…', () => renameDialog(entry));
  } else {
    add('⬇ Download as zip', () => downloadSelection());
    if (state.user?.allowPublicShares) add('🔗 Share…', () => shareDialog(selectedPaths()));
  }
  add('📦 Move to…', () => movePickerDialog('move'));
  add('📋 Copy to…', () => movePickerDialog('copy'));
  sep();
  add('🗑 Delete', () => deleteSelection(), true);

  menu.classList.remove('hidden');
  const rect = menu.getBoundingClientRect();
  menu.style.left = Math.min(x, window.innerWidth - rect.width - 8) + 'px';
  menu.style.top = Math.min(y, window.innerHeight - rect.height - 8) + 'px';
}
function hideContextMenu() {
  $('context-menu').classList.add('hidden');
}
document.addEventListener('click', hideContextMenu);
document.addEventListener('scroll', hideContextMenu, true);

// ---------- Selection actions ----------
function selectedPaths() {
  return [...state.selected].map(n => joinPath(state.path, n));
}

async function downloadSelection() {
  const names = [...state.selected];
  if (names.length === 1) {
    window.location.href = fileUrl(joinPath(state.path, names[0]), true);
    return;
  }
  // Multi-select: server streams a zip from a POST via a temp form.
  const res = await fetch('/api/files/zip', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ dir: state.path, names })
  });
  if (!res.ok) return toast('Download failed.', true);
  const blob = await res.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'files.zip';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 30000);
}

async function deleteSelection() {
  const paths = selectedPaths();
  try {
    const r = await api('/api/files/delete', { method: 'POST', body: { paths } });
    if (r.errors?.length) toast(r.errors[0].error, true);
    else toast(paths.length + (paths.length === 1 ? ' item' : ' items') + ' moved to trash');
    loadFiles(state.path);
    refreshUsage();
  } catch (err) {
    toast(err.message, true);
  }
}

$('sel-download').addEventListener('click', downloadSelection);
$('sel-delete').addEventListener('click', deleteSelection);
$('sel-move').addEventListener('click', () => movePickerDialog('move'));
$('sel-copy').addEventListener('click', () => movePickerDialog('copy'));

// ---------- Modal helper ----------
function openModal(title, bodyEl, actions) {
  $('modal-title').textContent = title;
  const body = $('modal-body');
  body.innerHTML = '';
  body.appendChild(bodyEl);
  const actEl = $('modal-actions');
  actEl.innerHTML = '';
  for (const a of actions) {
    const b = document.createElement('button');
    b.className = 'btn ' + (a.kind || '');
    b.textContent = a.label;
    b.addEventListener('click', a.onClick);
    actEl.appendChild(b);
  }
  $('modal').classList.remove('hidden');
  const firstInput = bodyEl.querySelector('input, textarea');
  if (firstInput) setTimeout(() => firstInput.focus(), 50);
}
function closeModal() {
  $('modal').classList.add('hidden');
}
$('modal').addEventListener('click', e => {
  if (e.target === $('modal')) closeModal();
});

function fieldEl(labelText, inputEl) {
  const wrap = document.createElement('div');
  wrap.className = 'field';
  const label = document.createElement('label');
  label.textContent = labelText;
  wrap.append(label, inputEl);
  return wrap;
}

// ---------- New folder / rename ----------
$('btn-new-folder').addEventListener('click', () => {
  const input = document.createElement('input');
  input.placeholder = 'Folder name';
  const body = fieldEl('Name', input);
  const submit = async () => {
    try {
      await api('/api/files/mkdir', { method: 'POST', body: { path: state.path, name: input.value.trim() } });
      closeModal();
      loadFiles(state.path);
    } catch (err) {
      toast(err.message, true);
    }
  };
  input.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
  openModal('New folder', body, [
    { label: 'Cancel', onClick: closeModal },
    { label: 'Create', kind: 'primary', onClick: submit }
  ]);
});

function renameDialog(entry) {
  const input = document.createElement('input');
  input.value = entry.name;
  const body = fieldEl('New name', input);
  const submit = async () => {
    try {
      await api('/api/files/rename', {
        method: 'POST',
        body: { path: joinPath(state.path, entry.name), newName: input.value.trim() }
      });
      closeModal();
      loadFiles(state.path);
    } catch (err) {
      toast(err.message, true);
    }
  };
  input.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
  openModal('Rename', body, [
    { label: 'Cancel', onClick: closeModal },
    { label: 'Rename', kind: 'primary', onClick: submit }
  ]);
}

// ---------- Move / copy folder picker ----------
async function movePickerDialog(mode) {
  const paths = selectedPaths();
  const wrap = document.createElement('div');
  const picker = document.createElement('div');
  picker.className = 'folder-picker';
  const crumbEl = document.createElement('div');
  crumbEl.className = 'card-sub';
  crumbEl.style.marginBottom = '8px';
  wrap.append(crumbEl, picker);
  let current = '';
  let chosen = '';

  async function render(dir) {
    current = dir;
    chosen = dir;
    crumbEl.textContent = 'Destination: /' + dir;
    picker.innerHTML = '';
    if (dir !== '') {
      const up = document.createElement('button');
      up.className = 'fp-item';
      up.textContent = '⬆️ ..';
      up.addEventListener('click', () => render(dir.split('/').slice(0, -1).join('/')));
      picker.appendChild(up);
    }
    try {
      const data = await api('/api/files/list?path=' + encodeURIComponent(dir));
      for (const e of data.entries.filter(e => e.isDir)) {
        // Don't offer to move a folder into itself.
        const full = joinPath(dir, e.name);
        if (mode === 'move' && paths.some(p => full === p || full.startsWith(p + '/'))) continue;
        const b = document.createElement('button');
        b.className = 'fp-item';
        b.textContent = '📁 ' + e.name;
        b.addEventListener('click', () => render(full));
        picker.appendChild(b);
      }
    } catch (err) {
      toast(err.message, true);
    }
  }
  await render('');

  openModal((mode === 'move' ? 'Move' : 'Copy') + ' ' + paths.length + (paths.length === 1 ? ' item' : ' items'), wrap, [
    { label: 'Cancel', onClick: closeModal },
    {
      label: mode === 'move' ? 'Move here' : 'Copy here',
      kind: 'primary',
      onClick: async () => {
        try {
          const r = await api('/api/files/' + mode, { method: 'POST', body: { paths, dest: chosen } });
          if (r.errors?.length) toast(r.errors[0].error, true);
          closeModal();
          loadFiles(state.path);
          refreshUsage();
        } catch (err) {
          toast(err.message, true);
        }
      }
    }
  ]);
}

// ---------- Share dialog ----------
// target: a single path string, or an array of paths for a multi-item share.
function shareDialog(target) {
  const multi = Array.isArray(target);
  const pw = document.createElement('input');
  pw.type = 'password';
  pw.placeholder = 'Optional password';
  pw.autocomplete = 'new-password';
  const exp = document.createElement('select');
  exp.innerHTML = '<option value="">Never expires</option><option value="1">1 day</option>' +
    '<option value="7">7 days</option><option value="30">30 days</option><option value="90">90 days</option>';
  const wrap = document.createElement('div');
  wrap.append(fieldEl('Password protection', pw), fieldEl('Expires', exp));

  const upCheck = document.createElement('input');
  upCheck.type = 'checkbox';
  if (!multi) {
    const upWrap = document.createElement('label');
    upWrap.className = 'check';
    upWrap.append(upCheck, document.createTextNode('Allow visitors to upload (folders only)'));
    wrap.appendChild(upWrap);
  }

  const title = multi ? 'Share ' + target.length + ' items' : 'Share “' + target.split('/').pop() + '”';
  openModal(title, wrap, [
    { label: 'Cancel', onClick: closeModal },
    {
      label: 'Create link',
      kind: 'primary',
      onClick: async () => {
        try {
          const body = { password: pw.value || undefined, expiresDays: exp.value || undefined };
          if (multi) body.paths = target;
          else { body.path = target; body.allowUpload = upCheck.checked; }
          const r = await api('/api/shares', { method: 'POST', body });
          closeModal();
          showShareLink(r.share);
        } catch (err) {
          toast(err.message, true);
        }
      }
    }
  ]);
}

function showShareLink(share) {
  const url = location.origin + '/s/' + share.token;
  const wrap = document.createElement('div');
  const row = document.createElement('div');
  row.className = 'share-link-row';
  const input = document.createElement('input');
  input.value = url;
  input.readOnly = true;
  const copy = document.createElement('button');
  copy.className = 'btn primary';
  copy.textContent = 'Copy';
  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(url);
      toast('Link copied');
    } catch {
      input.select();
      document.execCommand('copy');
      toast('Link copied');
    }
  });
  row.append(input, copy);
  const note = document.createElement('p');
  note.className = 'muted';
  note.style.fontSize = '13px';
  note.textContent = 'Anyone with this link' + (share.hasPassword ? ' and the password' : '') + ' can access it.';
  wrap.append(row, note);
  openModal('Share link created', wrap, [{ label: 'Done', kind: 'primary', onClick: closeModal }]);
  input.select();
}

// ---------- Uploads ----------
$('btn-upload').addEventListener('click', () => $('file-input').click());
$('file-input').addEventListener('change', e => {
  if (e.target.files.length) uploadFiles([...e.target.files]);
  e.target.value = '';
});

const CHUNK_THRESHOLD = 8 * 1024 * 1024;   // files bigger than this go chunked
const CHUNK_SIZE = 5 * 1024 * 1024;

function showUploadPanel(title) {
  const panel = $('upload-panel');
  panel.classList.remove('hidden');
  $('upload-title').textContent = title;
  $('upload-detail').textContent = '';
  $('upload-fill').style.width = '0';
}
function setUploadProgress(loaded, total) {
  $('upload-fill').style.width = (total ? (loaded / total) * 100 : 0) + '%';
  $('upload-detail').textContent = `${fmtSize(loaded)} of ${fmtSize(total)}`;
}

// Route uploads: big top-level files use resumable chunks; everything else
// (small files, folder-structure uploads) uses the multipart batch.
async function uploadFiles(files, relNames = null) {
  const names = files.map((f, i) => relNames ? relNames[i] : (f.webkitRelativePath || f.name));
  const small = [], smallNames = [], big = [];
  files.forEach((f, i) => {
    if (f.size > CHUNK_THRESHOLD && !names[i].includes('/')) big.push(f);
    else { small.push(f); smallNames.push(names[i]); }
  });
  try {
    if (small.length) await uploadMultipart(small, smallNames);
    for (const f of big) await uploadChunked(f);
  } finally {
    loadFiles(state.path);
    refreshUsage();
  }
}

function uploadMultipart(files, names) {
  return new Promise(resolve => {
    const form = new FormData();
    files.forEach((f, i) => form.append('files', f, names[i]));
    const total = files.reduce((s, f) => s + f.size, 0);
    showUploadPanel(`Uploading ${files.length} file${files.length === 1 ? '' : 's'}…`);
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/files/upload?path=' + encodeURIComponent(state.path));
    xhr.upload.onprogress = e => { if (e.lengthComputable) setUploadProgress(e.loaded, e.total); };
    xhr.onload = () => {
      let data = {}; try { data = JSON.parse(xhr.responseText); } catch { /* ignore */ }
      if (xhr.status === 200) {
        $('upload-title').textContent = 'Upload complete';
        toast(`Uploaded ${data.saved?.length ?? files.length} file${(data.saved?.length ?? files.length) === 1 ? '' : 's'}`);
        setTimeout(() => $('upload-panel').classList.add('hidden'), 1600);
      } else {
        $('upload-title').textContent = 'Upload failed';
        toast(data.error || 'Upload failed.', true);
      }
      resolve();
    };
    xhr.onerror = () => { $('upload-title').textContent = 'Upload failed'; toast('Upload failed — connection error.', true); resolve(); };
    xhr.send(form);
  });
}

// Resumable upload for a single large file. Survives a dropped connection:
// the session id is remembered so a retry resumes from the server's offset.
async function uploadChunked(file) {
  showUploadPanel(`Uploading ${file.name}…`);
  const key = 'mycloud_up_' + state.path + '|' + file.name + '|' + file.size + '|' + file.lastModified;
  let id = localStorage.getItem(key);
  let offset = 0;
  try {
    if (id) {
      // Resume an existing session if the server still has it.
      const st = await api('/api/files/upload/session/' + id).catch(() => null);
      if (st && st.size === file.size) offset = st.offset;
      else { id = null; localStorage.removeItem(key); }
    }
    if (!id) {
      const s = await api('/api/files/upload/session', {
        method: 'POST',
        body: { path: state.path, name: file.name, size: file.size }
      });
      id = s.id;
      localStorage.setItem(key, id);
      offset = 0;
    }
    while (offset < file.size) {
      const end = Math.min(offset + CHUNK_SIZE, file.size);
      const chunk = file.slice(offset, end);
      const res = await putChunkWithRetry(id, offset, chunk);
      if (res.status === 409) { offset = res.offset; continue; } // re-sync to server
      offset = res.offset;
      setUploadProgress(offset, file.size);
    }
    await api('/api/files/upload/session/' + id + '/complete', { method: 'POST' });
    localStorage.removeItem(key);
    $('upload-title').textContent = 'Upload complete';
    toast('Uploaded ' + file.name);
    setTimeout(() => $('upload-panel').classList.add('hidden'), 1600);
  } catch (err) {
    $('upload-title').textContent = 'Upload paused';
    $('upload-detail').textContent = 'Will resume if you upload it again.';
    toast(err.message || 'Upload interrupted — retry to resume.', true);
  }
}

async function putChunkWithRetry(id, offset, chunk, tries = 4) {
  for (let attempt = 0; ; attempt++) {
    try {
      const res = await fetch('/api/files/upload/session/' + id + '?offset=' + offset, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: chunk
      });
      const data = await res.json().catch(() => ({}));
      if (res.status === 409) return { status: 409, offset: data.offset };
      if (!res.ok) throw new Error(data.error || 'Chunk upload failed.');
      return { status: 200, offset: data.offset };
    } catch (err) {
      if (attempt >= tries) throw err;
      await new Promise(r => setTimeout(r, 500 * (attempt + 1))); // backoff then retry
    }
  }
}
$('upload-close').addEventListener('click', () => $('upload-panel').classList.add('hidden'));

// Drag & drop, including dropped folders via webkitGetAsEntry.
const dropZone = $('drop-zone');
let dragDepth = 0;
dropZone.addEventListener('dragenter', e => {
  e.preventDefault();
  if (state.currentView !== 'files') return;
  dragDepth++;
  dropZone.classList.add('dragover');
});
dropZone.addEventListener('dragover', e => e.preventDefault());
dropZone.addEventListener('dragleave', () => {
  dragDepth = Math.max(0, dragDepth - 1);
  if (dragDepth === 0) dropZone.classList.remove('dragover');
});
dropZone.addEventListener('drop', async e => {
  e.preventDefault();
  dragDepth = 0;
  dropZone.classList.remove('dragover');
  const items = [...(e.dataTransfer.items || [])];
  const entries = items.map(i => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
  if (entries.length && entries.some(en => en.isDirectory)) {
    const files = [];
    const names = [];
    async function walkEntry(entry, prefix) {
      if (entry.isFile) {
        const file = await new Promise((ok, bad) => entry.file(ok, bad));
        files.push(file);
        names.push(prefix + entry.name);
      } else if (entry.isDirectory) {
        const reader = entry.createReader();
        let batch;
        do {
          batch = await new Promise((ok, bad) => reader.readEntries(ok, bad));
          for (const child of batch) await walkEntry(child, prefix + entry.name + '/');
        } while (batch.length);
      }
    }
    try {
      for (const entry of entries) await walkEntry(entry, '');
    } catch {
      toast('Could not read the dropped folder.', true);
      return;
    }
    if (files.length) uploadFiles(files, names);
  } else if (e.dataTransfer.files.length) {
    uploadFiles([...e.dataTransfer.files]);
  }
});

// ---------- Preview ----------
const previewState = { list: [], index: -1, isText: false, dirty: false };

function previewableEntries() {
  return state.entries.filter(e => !e.isDir && previewKind(e.name));
}

function openPreview(entry) {
  previewState.list = previewableEntries();
  previewState.index = previewState.list.findIndex(e => e.name === entry.name);
  renderPreview();
  $('preview').classList.remove('hidden');
}

function renderPreview() {
  const entry = previewState.list[previewState.index];
  if (!entry) return closePreview();
  const body = $('preview-body');
  body.innerHTML = '';
  previewState.isText = false;
  previewState.dirty = false;
  $('preview-name').textContent = entry.name;
  const p = joinPath(state.path, entry.name);
  const kind = previewKind(entry.name);
  const url = fileUrl(p, false);

  if (kind === 'image') {
    const img = document.createElement('img');
    img.src = url;
    body.appendChild(img);
  } else if (kind === 'video') {
    const v = document.createElement('video');
    v.src = url;
    v.controls = true;
    v.autoplay = true;
    body.appendChild(v);
  } else if (kind === 'audio') {
    const a = document.createElement('audio');
    a.src = url;
    a.controls = true;
    a.autoplay = true;
    body.appendChild(a);
  } else if (kind === 'pdf') {
    const f = document.createElement('iframe');
    f.src = url;
    body.appendChild(f);
  } else if (kind === 'text') {
    previewState.isText = true;
    const ta = document.createElement('textarea');
    ta.spellcheck = false;
    ta.value = 'Loading…';
    ta.disabled = true;
    body.appendChild(ta);
    const actions = document.createElement('div');
    actions.className = 'preview-editor-actions';
    const save = document.createElement('button');
    save.className = 'btn primary sm';
    save.textContent = 'Save';
    save.addEventListener('click', async () => {
      try {
        await api('/api/files/content?path=' + encodeURIComponent(p), {
          method: 'PUT',
          headers: { 'Content-Type': 'text/plain' },
          body: ta.value
        });
        previewState.dirty = false;
        toast('Saved');
      } catch (err) {
        toast(err.message, true);
      }
    });
    actions.appendChild(save);
    body.appendChild(actions);
    fetch('/api/files/content?path=' + encodeURIComponent(p))
      .then(async r => {
        if (!r.ok) throw new Error((await r.json()).error || 'Cannot open file.');
        return r.text();
      })
      .then(text => {
        ta.value = text;
        ta.disabled = false;
        ta.addEventListener('input', () => { previewState.dirty = true; });
      })
      .catch(err => { ta.value = err.message; });
  }

  $('preview-download').onclick = () => { window.location.href = fileUrl(p, true); };
  const many = previewState.list.length > 1;
  $('preview-prev').style.visibility = many ? 'visible' : 'hidden';
  $('preview-next').style.visibility = many ? 'visible' : 'hidden';
}

function closePreview() {
  if (previewState.isText && previewState.dirty && !confirm('Discard unsaved changes?')) return;
  $('preview').classList.add('hidden');
  $('preview-body').innerHTML = '';
}
function previewStep(dir) {
  if (previewState.isText && previewState.dirty && !confirm('Discard unsaved changes?')) return;
  const n = previewState.list.length;
  previewState.index = (previewState.index + dir + n) % n;
  renderPreview();
}
$('preview-close').addEventListener('click', closePreview);
$('preview-prev').addEventListener('click', () => previewStep(-1));
$('preview-next').addEventListener('click', () => previewStep(1));
document.addEventListener('keydown', e => {
  if ($('preview').classList.contains('hidden')) return;
  if (previewState.isText && e.target.tagName === 'TEXTAREA' && e.key !== 'Escape') return;
  if (e.key === 'Escape') closePreview();
  else if (e.key === 'ArrowLeft') previewStep(-1);
  else if (e.key === 'ArrowRight') previewStep(1);
});

// ---------- Search ----------
let searchTimer = null;
$('search-input').addEventListener('input', e => {
  clearTimeout(searchTimer);
  const q = e.target.value.trim();
  if (!q) {
    if (state.currentView === 'search' || !$('view-search').classList.contains('hidden')) switchView('files');
    return;
  }
  searchTimer = setTimeout(() => runSearch(q), 300);
});

async function runSearch(q) {
  try {
    const data = await api('/api/files/search?q=' + encodeURIComponent(q));
    for (const v of ['files', 'shares', 'trash', 'admin']) $('view-' + v).classList.add('hidden');
    $('view-search').classList.remove('hidden');
    $('search-title').textContent = `Search “${q}” — ${data.results.length} result${data.results.length === 1 ? '' : 's'}`;
    const list = $('search-results');
    list.innerHTML = '';
    for (const r of data.results) {
      const el = document.createElement('div');
      el.className = 'entry';
      el.innerHTML = '';
      const thumb = document.createElement('div');
      thumb.className = 'thumb';
      thumb.textContent = iconFor(r);
      const name = document.createElement('div');
      name.className = 'ename';
      name.textContent = r.path;
      const meta = document.createElement('div');
      meta.className = 'emeta';
      meta.textContent = r.isDir ? 'Folder' : fmtSize(r.size);
      el.append(thumb, name, meta);
      el.addEventListener('click', () => {
        $('search-input').value = '';
        if (r.isDir) {
          switchView('files');
          loadFiles(r.path);
        } else {
          const dir = r.path.split('/').slice(0, -1).join('/');
          switchView('files');
          loadFiles(dir).then(() => {
            const entry = state.entries.find(en => en.name === r.name);
            if (entry && previewKind(entry.name)) openPreview(entry);
          });
        }
      });
      list.appendChild(el);
    }
  } catch (err) {
    toast(err.message, true);
  }
}

// ---------- Shares view ----------
async function loadShares() {
  try {
    const data = await api('/api/shares');
    const list = $('shares-list');
    list.innerHTML = '';
    if (!data.shares.length) {
      list.innerHTML = '<div class="empty-state"><div class="empty-icon">🔗</div><p>No shared links yet</p>' +
        '<p class="muted">Right-click a file and choose Share</p></div>';
      return;
    }
    for (const s of data.shares) {
      const card = document.createElement('div');
      card.className = 'card';
      const row = document.createElement('div');
      row.className = 'card-row';
      const info = document.createElement('div');
      const title = document.createElement('div');
      title.className = 'card-title';
      title.textContent = (s.isDir ? '📁 ' : '📄 ') + ('/' + s.path);
      const sub = document.createElement('div');
      sub.className = 'card-sub';
      const bits = [`Created ${fmtDate(s.createdAt)}`, `${s.downloads || 0} downloads`];
      if (s.expiresAt) bits.push((Date.now() > s.expiresAt ? 'Expired ' : 'Expires ') + fmtDate(s.expiresAt));
      sub.textContent = bits.join(' · ');
      info.append(title, sub);
      const badges = document.createElement('div');
      badges.style.display = 'flex';
      badges.style.gap = '5px';
      if (s.hasPassword) badges.innerHTML += '<span class="badge">🔒 password</span>';
      if (s.allowUpload) badges.innerHTML += '<span class="badge">⬆ uploads</span>';
      if (s.expiresAt && Date.now() > s.expiresAt) badges.innerHTML += '<span class="badge warn">expired</span>';
      const actions = document.createElement('div');
      actions.className = 'card-actions';
      const copyBtn = document.createElement('button');
      copyBtn.className = 'btn sm';
      copyBtn.textContent = 'Copy link';
      copyBtn.addEventListener('click', async () => {
        await navigator.clipboard.writeText(location.origin + '/s/' + s.token).catch(() => {});
        toast('Link copied');
      });
      const delBtn = document.createElement('button');
      delBtn.className = 'btn sm danger';
      delBtn.textContent = 'Remove';
      delBtn.addEventListener('click', async () => {
        await api('/api/shares/' + encodeURIComponent(s.token), { method: 'DELETE' });
        loadShares();
      });
      actions.append(copyBtn, delBtn);
      row.append(info, badges, actions);
      card.appendChild(row);
      list.appendChild(card);
    }
  } catch (err) {
    toast(err.message, true);
  }
}

// ---------- Trash view ----------
async function loadTrash() {
  try {
    const data = await api('/api/trash/list');
    const list = $('trash-list');
    list.className = 'file-list list-mode';
    list.innerHTML = '';
    if (!data.items.length) {
      list.innerHTML = '<div class="empty-state"><div class="empty-icon">🗑️</div><p>Trash is empty</p></div>';
      return;
    }
    for (const item of data.items) {
      const el = document.createElement('div');
      el.className = 'entry';
      el.style.cursor = 'default';
      const thumb = document.createElement('div');
      thumb.className = 'thumb';
      thumb.textContent = item.isDir ? '📁' : iconFor(item);
      const name = document.createElement('div');
      name.className = 'ename';
      name.textContent = item.originalPath;
      const meta = document.createElement('div');
      meta.className = 'emeta';
      meta.textContent = 'Deleted ' + fmtDate(item.deletedAt);
      const restoreBtn = document.createElement('button');
      restoreBtn.className = 'btn sm';
      restoreBtn.textContent = 'Restore';
      restoreBtn.addEventListener('click', async () => {
        const r = await api('/api/trash/restore', { method: 'POST', body: { ids: [item.id] } }).catch(err => toast(err.message, true));
        if (r?.errors?.length) toast(r.errors[0].error, true);
        loadTrash();
        refreshUsage();
      });
      const delBtn = document.createElement('button');
      delBtn.className = 'btn sm danger';
      delBtn.textContent = 'Delete forever';
      delBtn.addEventListener('click', async () => {
        await api('/api/trash/delete', { method: 'POST', body: { ids: [item.id] } }).catch(err => toast(err.message, true));
        loadTrash();
      });
      el.append(thumb, name, meta, restoreBtn, delBtn);
      list.appendChild(el);
    }
  } catch (err) {
    toast(err.message, true);
  }
}

$('btn-empty-trash').addEventListener('click', () => {
  const p = document.createElement('p');
  p.textContent = 'Permanently delete everything in the trash? This cannot be undone.';
  openModal('Empty trash', p, [
    { label: 'Cancel', onClick: closeModal },
    {
      label: 'Empty trash',
      kind: 'danger',
      onClick: async () => {
        await api('/api/trash/empty', { method: 'POST' }).catch(err => toast(err.message, true));
        closeModal();
        loadTrash();
      }
    }
  ]);
});

// ---------- Admin view ----------
async function loadAdmin() {
  try {
    const [usersData, settingsData] = await Promise.all([
      api('/api/admin/users'),
      api('/api/admin/settings')
    ]);
    const list = $('users-list');
    list.innerHTML = '';
    for (const u of usersData.users) {
      const card = document.createElement('div');
      card.className = 'card';
      const row = document.createElement('div');
      row.className = 'card-row';
      const info = document.createElement('div');
      const title = document.createElement('div');
      title.className = 'card-title';
      title.textContent = u.username;
      const sub = document.createElement('div');
      sub.className = 'card-sub';
      sub.textContent = `${fmtSize(u.usedBytes)} used` +
        (u.quotaMB ? ` of ${fmtSize(u.quotaMB * 1024 * 1024)}` : ' · no quota') +
        ` · joined ${fmtDate(u.createdAt)}`;
      info.append(title, sub);
      const badges = document.createElement('div');
      if (u.isAdmin) badges.innerHTML = '<span class="badge">admin</span>';
      const actions = document.createElement('div');
      actions.className = 'card-actions';
      const editBtn = document.createElement('button');
      editBtn.className = 'btn sm';
      editBtn.textContent = 'Edit';
      editBtn.addEventListener('click', () => userDialog(u));
      actions.appendChild(editBtn);
      if (u.username !== state.user.username) {
        const delBtn = document.createElement('button');
        delBtn.className = 'btn sm danger';
        delBtn.textContent = 'Delete';
        delBtn.addEventListener('click', () => deleteUserDialog(u.username));
        actions.appendChild(delBtn);
      }
      row.append(info, badges, actions);
      card.appendChild(row);
      list.appendChild(card);
    }
    $('set-sitename').value = settingsData.settings.siteName;
    $('set-quota').value = settingsData.settings.defaultQuotaMB;
    $('set-trash').value = settingsData.settings.trashRetentionDays;
    $('set-shares').checked = settingsData.settings.allowPublicShares !== false;
  } catch (err) {
    toast(err.message, true);
  }
}

function userDialog(existing) {
  const nameInput = document.createElement('input');
  nameInput.placeholder = 'username';
  nameInput.autocomplete = 'off';
  if (existing) {
    nameInput.value = existing.username;
    nameInput.disabled = true;
  }
  const pwInput = document.createElement('input');
  pwInput.type = 'password';
  pwInput.placeholder = existing ? 'Leave blank to keep current' : 'Password (min 6 chars)';
  pwInput.autocomplete = 'new-password';
  const quotaInput = document.createElement('input');
  quotaInput.type = 'number';
  quotaInput.min = '0';
  quotaInput.value = existing ? existing.quotaMB : '';
  quotaInput.placeholder = '0 = unlimited';
  const adminWrap = document.createElement('label');
  adminWrap.className = 'check';
  const adminCheck = document.createElement('input');
  adminCheck.type = 'checkbox';
  adminCheck.checked = existing ? existing.isAdmin : false;
  adminWrap.append(adminCheck, document.createTextNode('Administrator'));

  const wrap = document.createElement('div');
  wrap.append(fieldEl('Username', nameInput), fieldEl('Password', pwInput), fieldEl('Quota (MB)', quotaInput), adminWrap);

  openModal(existing ? 'Edit ' + existing.username : 'Add user', wrap, [
    { label: 'Cancel', onClick: closeModal },
    {
      label: existing ? 'Save' : 'Create',
      kind: 'primary',
      onClick: async () => {
        try {
          if (existing) {
            await api('/api/admin/users/' + encodeURIComponent(existing.username), {
              method: 'PATCH',
              body: { password: pwInput.value || undefined, quotaMB: quotaInput.value, isAdmin: adminCheck.checked }
            });
          } else {
            await api('/api/admin/users', {
              method: 'POST',
              body: {
                username: nameInput.value.trim(),
                password: pwInput.value,
                quotaMB: quotaInput.value === '' ? undefined : quotaInput.value,
                isAdmin: adminCheck.checked
              }
            });
          }
          closeModal();
          loadAdmin();
        } catch (err) {
          toast(err.message, true);
        }
      }
    }
  ]);
}

function deleteUserDialog(username) {
  const p = document.createElement('p');
  p.textContent = `Delete user “${username}”? Their files stay on disk under /data/users/${username} until you remove them manually.`;
  openModal('Delete user', p, [
    { label: 'Cancel', onClick: closeModal },
    {
      label: 'Delete user',
      kind: 'danger',
      onClick: async () => {
        try {
          await api('/api/admin/users/' + encodeURIComponent(username), { method: 'DELETE' });
          closeModal();
          loadAdmin();
        } catch (err) {
          toast(err.message, true);
        }
      }
    }
  ]);
}

$('btn-add-user').addEventListener('click', () => userDialog(null));

$('settings-form').addEventListener('submit', async e => {
  e.preventDefault();
  try {
    await api('/api/admin/settings', {
      method: 'PATCH',
      body: {
        siteName: $('set-sitename').value,
        defaultQuotaMB: $('set-quota').value,
        trashRetentionDays: $('set-trash').value,
        allowPublicShares: $('set-shares').checked
      }
    });
    toast('Settings saved');
    const me = await api('/api/auth/me');
    state.user = me;
    $('brand-name').textContent = me.siteName;
    document.title = me.siteName;
  } catch (err) {
    toast(err.message, true);
  }
});

// ---------- Theme toggle: auto -> dark -> light ----------
const THEME_ICONS = { auto: '🌓', dark: '🌙', light: '☀️' };
function applyTheme(mode) {
  if (mode === 'auto') {
    delete document.documentElement.dataset.theme;
    localStorage.removeItem('mycloud_theme');
  } else {
    document.documentElement.dataset.theme = mode;
    localStorage.setItem('mycloud_theme', mode);
  }
  const btn = $('btn-theme');
  btn.textContent = THEME_ICONS[mode];
  btn.title = 'Theme: ' + mode;
}
applyTheme(localStorage.getItem('mycloud_theme') || 'auto');
$('btn-theme').addEventListener('click', () => {
  const order = ['auto', 'dark', 'light'];
  const current = localStorage.getItem('mycloud_theme') || 'auto';
  const next = order[(order.indexOf(current) + 1) % order.length];
  applyTheme(next);
  toast('Theme: ' + (next === 'auto' ? 'auto (follows your device)' : next));
});

// ---------- Account & security ----------
$('btn-account').addEventListener('click', openSecurityModal);

async function openSecurityModal() {
  const wrap = document.createElement('div');
  const section = (title) => {
    const h = document.createElement('h4');
    h.textContent = title;
    h.style.cssText = 'margin:18px 0 8px;font-size:14px';
    wrap.appendChild(h);
  };

  // Change password
  section('Change password');
  const cur = Object.assign(document.createElement('input'), { type: 'password', placeholder: 'Current password', autocomplete: 'current-password' });
  const next = Object.assign(document.createElement('input'), { type: 'password', placeholder: 'New password (min 6)', autocomplete: 'new-password' });
  const pwBtn = document.createElement('button');
  pwBtn.className = 'btn sm';
  pwBtn.textContent = 'Update password';
  pwBtn.addEventListener('click', async () => {
    try {
      await api('/api/auth/password', { method: 'POST', body: { current: cur.value, next: next.value } });
      cur.value = ''; next.value = '';
      toast('Password changed');
    } catch (err) { toast(err.message, true); }
  });
  const pwRow = document.createElement('div');
  pwRow.style.cssText = 'display:flex;flex-direction:column;gap:8px';
  pwRow.append(cur, next, pwBtn);
  wrap.appendChild(pwRow);

  // Two-factor
  section('Two-factor authentication');
  const twofaBox = document.createElement('div');
  twofaBox.style.cssText = 'display:flex;align-items:center;gap:10px;flex-wrap:wrap';
  if (state.user.totpEnabled) {
    twofaBox.innerHTML = '<span class="badge">enabled</span>';
    const off = document.createElement('button');
    off.className = 'btn sm danger';
    off.textContent = 'Turn off';
    off.addEventListener('click', () => disable2fa());
    twofaBox.appendChild(off);
  } else {
    const p = document.createElement('span');
    p.className = 'muted';
    p.style.fontSize = '13px';
    p.textContent = 'Add a code from an authenticator app at sign-in.';
    const on = document.createElement('button');
    on.className = 'btn sm primary';
    on.textContent = 'Set up';
    on.addEventListener('click', () => setup2fa());
    twofaBox.append(p, on);
  }
  wrap.appendChild(twofaBox);

  // App passwords
  section('App passwords');
  const apInfo = document.createElement('p');
  apInfo.className = 'muted';
  apInfo.style.fontSize = '13px';
  apInfo.textContent = state.user.totpEnabled
    ? 'With 2FA on, WebDAV needs an app password (your normal password won\'t work there).'
    : 'Optional: dedicated passwords for WebDAV / apps you can revoke individually.';
  const apList = document.createElement('div');
  const apAddRow = document.createElement('div');
  apAddRow.className = 'share-link-row';
  const apLabel = Object.assign(document.createElement('input'), { placeholder: 'Label (e.g. Laptop)' });
  const apAdd = document.createElement('button');
  apAdd.className = 'btn primary';
  apAdd.textContent = 'Create';
  apAdd.addEventListener('click', async () => {
    try {
      const r = await api('/api/auth/apppw', { method: 'POST', body: { label: apLabel.value.trim() || 'App' } });
      apLabel.value = '';
      showAppPasswordToken(r.token);
    } catch (err) { toast(err.message, true); }
  });
  apAddRow.append(apLabel, apAdd);
  wrap.append(apInfo, apList, apAddRow);

  async function renderAppPws() {
    const data = await api('/api/auth/apppw').catch(() => ({ appPasswords: [] }));
    apList.innerHTML = '';
    for (const a of data.appPasswords) {
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;align-items:center;gap:8px;padding:5px 0;font-size:13px';
      const name = document.createElement('span');
      name.style.flex = '1';
      name.textContent = a.label;
      const rev = document.createElement('button');
      rev.className = 'btn sm danger';
      rev.textContent = 'Revoke';
      rev.addEventListener('click', async () => {
        await api('/api/auth/apppw/' + encodeURIComponent(a.id), { method: 'DELETE' }).catch(() => {});
        renderAppPws();
      });
      row.append(name, rev);
      apList.appendChild(row);
    }
  }
  renderAppPws();

  openModal('Account & security', wrap, [{ label: 'Close', kind: 'primary', onClick: closeModal }]);
}

function showAppPasswordToken(token) {
  const wrap = document.createElement('div');
  const p = document.createElement('p');
  p.className = 'muted';
  p.style.fontSize = '13px';
  p.textContent = 'Use this as the password in your WebDAV client. It won\'t be shown again.';
  const row = document.createElement('div');
  row.className = 'share-link-row';
  const input = Object.assign(document.createElement('input'), { value: token, readOnly: true });
  const copy = document.createElement('button');
  copy.className = 'btn primary';
  copy.textContent = 'Copy';
  copy.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(token); toast('Copied'); }
    catch { input.select(); document.execCommand('copy'); toast('Copied'); }
  });
  row.append(input, copy);
  wrap.append(p, row);
  openModal('App password created', wrap, [{ label: 'Done', kind: 'primary', onClick: () => { closeModal(); openSecurityModal(); } }]);
  input.select();
}

async function setup2fa() {
  let data;
  try { data = await api('/api/auth/2fa/setup', { method: 'POST' }); }
  catch (err) { return toast(err.message, true); }
  const wrap = document.createElement('div');
  const img = document.createElement('img');
  img.src = data.qr;
  img.alt = 'QR code';
  img.style.cssText = 'display:block;margin:0 auto;border-radius:8px;background:#fff;padding:6px';
  const hint = document.createElement('p');
  hint.className = 'muted';
  hint.style.cssText = 'font-size:13px;text-align:center';
  hint.innerHTML = 'Scan with your authenticator app, or enter this key:<br><code style="user-select:all">' + data.secret + '</code>';
  const code = Object.assign(document.createElement('input'), { placeholder: '6-digit code', inputMode: 'numeric', autocomplete: 'one-time-code' });
  wrap.append(img, hint, fieldEl('Enter the code to confirm', code));
  openModal('Set up two-factor', wrap, [
    { label: 'Cancel', onClick: closeModal },
    {
      label: 'Enable',
      kind: 'primary',
      onClick: async () => {
        try {
          const r = await api('/api/auth/2fa/enable', { method: 'POST', body: { code: code.value.trim() } });
          state.user.totpEnabled = true;
          showRecoveryCodes(r.recovery);
        } catch (err) { toast(err.message, true); }
      }
    }
  ]);
  setTimeout(() => code.focus(), 50);
}

function showRecoveryCodes(codes) {
  const wrap = document.createElement('div');
  const p = document.createElement('p');
  p.className = 'muted';
  p.style.fontSize = '13px';
  p.textContent = 'Save these recovery codes somewhere safe. Each can be used once if you lose your authenticator.';
  const pre = document.createElement('pre');
  pre.style.cssText = 'background:var(--panel-2);padding:12px;border-radius:8px;font-size:14px;user-select:all;line-height:1.8';
  pre.textContent = codes.join('\n');
  wrap.append(p, pre);
  openModal('Two-factor enabled ✓', wrap, [{ label: 'Done', kind: 'primary', onClick: () => { closeModal(); toast('Two-factor is on'); } }]);
}

function disable2fa() {
  const pw = Object.assign(document.createElement('input'), { type: 'password', placeholder: 'Current password', autocomplete: 'current-password' });
  const wrap = document.createElement('div');
  wrap.append(fieldEl('Confirm your password to turn off 2FA', pw));
  openModal('Turn off two-factor', wrap, [
    { label: 'Cancel', onClick: closeModal },
    {
      label: 'Turn off',
      kind: 'danger',
      onClick: async () => {
        try {
          await api('/api/auth/2fa/disable', { method: 'POST', body: { password: pw.value } });
          state.user.totpEnabled = false;
          closeModal();
          toast('Two-factor turned off');
        } catch (err) { toast(err.message, true); }
      }
    }
  ]);
}

// ---------- Connect a drive (WebDAV) ----------
$('btn-connect').addEventListener('click', () => {
  const url = location.origin + '/dav/';
  const wrap = document.createElement('div');
  const row = document.createElement('div');
  row.className = 'share-link-row';
  const input = document.createElement('input');
  input.value = url;
  input.readOnly = true;
  const copy = document.createElement('button');
  copy.className = 'btn primary';
  copy.textContent = 'Copy';
  copy.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(url); toast('URL copied'); }
    catch { input.select(); document.execCommand('copy'); toast('URL copied'); }
  });
  row.append(input, copy);
  const help = document.createElement('div');
  help.className = 'muted';
  help.style.fontSize = '13px';
  help.style.marginTop = '10px';
  help.innerHTML =
    'Mount your files as a network drive using your My Cloud username and password:' +
    '<ul style="margin:8px 0 0;padding-left:18px;line-height:1.6">' +
    '<li><b>Windows:</b> This PC → Map network drive → the URL above</li>' +
    '<li><b>macOS:</b> Finder → Go → Connect to Server → the URL above</li>' +
    '<li><b>Linux / rclone / mobile:</b> add a WebDAV remote pointing at the URL</li>' +
    '</ul>' +
    '<p style="margin:10px 0 0">Use <b>HTTPS</b> for connections outside your home network.</p>';
  wrap.append(row, help);
  openModal('Connect a drive (WebDAV)', wrap, [{ label: 'Done', kind: 'primary', onClick: closeModal }]);
  input.select();
});

// ---------- PWA service worker ----------
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js').catch(() => {}));
}

// ---------- Boot ----------
(async function boot() {
  await initAuth();
  try {
    await enterApp();
  } catch {
    showAuth();
  }
})();
