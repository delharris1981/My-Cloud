// My Cloud front-end enhancements.
//
// This file is deliberately tiny and entirely optional: every feature it adds
// has a working no-JavaScript path. With scripting disabled you can log in,
// browse, upload, create folders, rename, move, delete, restore from trash,
// create share links, and upload to a drop box. Only live search, multi-select,
// and inline progress degrade.
//
// htmx is vendored locally (no CDN) so the Content-Security-Policy can forbid
// inline and third-party scripts.
(function () {
  'use strict';

  // --- CSRF for fetch-based calls ---
  // htmx needs the token on every mutating request. Forms carry it in a hidden
  // field; this header covers fetch() and htmx.
  function csrfToken() {
    var el = document.querySelector('input[name="csrf_token"]');
    return el ? el.value : '';
  }

  document.body.addEventListener('htmx:configRequest', function (evt) {
    var verb = (evt.detail.verb || 'get').toUpperCase();
    if (verb === 'GET' || verb === 'HEAD') return;
    evt.detail.headers['X-CSRF-Token'] = csrfToken();
  });

  // --- Toasts ---
  // A server handler can set HX-Trigger to raise a toast without any
  // client-side template work.
  function toast(message, kind) {
    var host = document.getElementById('toasts');
    if (!host) return;
    var el = document.createElement('div');
    el.className = 'toast' + (kind ? ' ' + kind : '');
    el.textContent = message;
    host.appendChild(el);
    setTimeout(function () {
      el.classList.add('fade');
      setTimeout(function () { el.remove(); }, 400);
    }, 4000);
  }
  window.myCloudToast = toast;

  document.body.addEventListener('mycloud:toast', function (evt) {
    var d = evt.detail || {};
    toast(d.message || '', d.kind || '');
  });

  // --- Session expiry ---
  // A 401 from any htmx request means the session died mid-use; send the user
  // to the login page rather than leaving a half-broken screen.
  document.body.addEventListener('htmx:responseError', function (evt) {
    if (evt.detail.xhr && evt.detail.xhr.status === 401) {
      window.location.href = '/login';
    }
  });

  // --- Multi-select ---
  // Selection is real: each row carries a checkbox named "selected", and the
  // value is written back into the URL so a reload preserves it.
  function syncSelectionToURL() {
    var checked = Array.prototype.slice.call(
      document.querySelectorAll('input[name="selected"]:checked')
    ).map(function (i) { return i.value; });
    var url = new URL(window.location.href);
    url.searchParams.delete('selected');
    checked.forEach(function (v) { url.searchParams.append('selected', v); });
    history.replaceState(null, '', url);
  }
  document.body.addEventListener('change', function (evt) {
    if (evt.target && evt.target.name === 'selected') {
      evt.target.closest('.file-item').classList.toggle('selected', evt.target.checked);
      syncSelectionToURL();
    }
  });

  // Ctrl/Cmd+A inside the browser selects everything visible.
  document.body.addEventListener('keydown', function (evt) {
    if (!(evt.ctrlKey || evt.metaKey) || evt.key !== 'a') return;
    var boxes = document.querySelectorAll('.file-item input[name="selected"]');
    if (!boxes.length) return;
    evt.preventDefault();
    boxes.forEach(function (b) { b.checked = true; b.closest('.file-item').classList.add('selected'); });
    syncSelectionToURL();
  });

  // --- Drag and drop upload ---
  // A convenience only. The upload form above it works without any of this.
  var drop = document.querySelector('.upload-form');
  if (drop && 'FormData' in window && window.fetch) {
    ['dragenter', 'dragover'].forEach(function (ev) {
      drop.addEventListener(ev, function (e) {
        e.preventDefault();
        drop.classList.add('dragging');
      });
    });
    ['dragleave', 'drop'].forEach(function (ev) {
      drop.addEventListener(ev, function (e) {
        e.preventDefault();
        drop.classList.remove('dragging');
      });
    });
    drop.addEventListener('drop', function (e) {
      var files = e.dataTransfer && e.dataTransfer.files;
      if (!files || !files.length) return;
      var data = new FormData();
      Array.prototype.forEach.call(files, function (f) { data.append('files', f); });
      var path = new URLSearchParams(window.location.search).get('path') || '';
      var progress = document.getElementById('upload-progress');
      var req = new XMLHttpRequest();
      req.open('POST', '/files/upload?path=' + encodeURIComponent(path));
      req.setRequestHeader('X-CSRF-Token', csrfToken());
      req.upload.onprogress = function (e) {
        if (progress && e.lengthComputable) progress.value = (e.loaded / e.total) * 100;
      };
      req.onload = function () {
        if (req.status >= 200 && req.status < 300) window.location.reload();
        else toast('Upload failed.', 'error');
      };
      req.send(data);
    });
  }

  // --- Resumable chunk upload ---
  // Only engaged for files above the threshold; smaller files use the single
  // multipart POST, which is the same code path the no-JS form uses.
  var CHUNK_THRESHOLD = 8 * 1024 * 1024;
  var CHUNK_SIZE = 4 * 1024 * 1024;

  function uploadResumable(file, path, onProgress) {
    var qs = '?path=' + encodeURIComponent(path) + '&filename=' + encodeURIComponent(file.name) +
             '&total=' + file.size + '&csrf_token=' + encodeURIComponent(csrfToken());
    return fetch('/files/upload/session' + qs, {
      method: 'POST',
      headers: { 'X-CSRF-Token': csrfToken() },
      credentials: 'same-origin'
    }).then(function (r) { return r.json(); }).then(function (sess) {
      var offset = 0;
      function sendChunk() {
        if (offset >= file.size) return finish();
        var end = Math.min(offset + CHUNK_SIZE, file.size);
        var blob = file.slice(offset, end);
        return fetch('/files/upload/session/' + sess.id + '?path=' + encodeURIComponent(path), {
          method: 'PUT',
          headers: {
            'Content-Range': 'bytes ' + offset + '-' + (end - 1) + '/' + file.size,
            'X-CSRF-Token': csrfToken()
          },
          body: blob,
          credentials: 'same-origin'
        }).then(function (r) {
          if (!r.ok) throw new Error('chunk failed');
          offset = end;
          if (onProgress) onProgress(offset / file.size);
          return sendChunk();
        });
      }
      function finish() {
        var body = new URLSearchParams({ filename: file.name, csrf_token: csrfToken() });
        return fetch('/files/upload/session/' + sess.id + '/complete?path=' + encodeURIComponent(path), {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': csrfToken() },
          body: body.toString(),
          credentials: 'same-origin'
        });
      }
      return sendChunk();
    });
  }
  window.myCloudUploadResumable = uploadResumable;

  // Intercept the plain file input: route big files through the chunked path.
  document.body.addEventListener('change', function (evt) {
    var input = evt.target;
    if (!input.matches || !input.matches('.upload-form input[type=file]')) return;
    if (!window.fetch || typeof uploadResumable !== 'function') return;
    var files = Array.prototype.slice.call(input.files || []);
    var path = new URLSearchParams(window.location.search).get('path') || '';
    var progress = document.getElementById('upload-progress');
    var chain = Promise.resolve();
    var chunked = files.filter(function (f) { return f.size > CHUNK_THRESHOLD; });
    if (!chunked.length) return; // small files: let the normal form submit
    evt.preventDefault();
    chunked.forEach(function (f) {
      chain = chain.then(function () {
        return uploadResumable(f, path, function (frac) {
          if (progress) progress.value = frac * 100;
        });
      });
    });
    chain.then(function () { window.location.reload(); })
         .catch(function () { toast('Upload failed.', 'error'); });
  });

  // --- Theme toggle ---
  var toggle = document.getElementById('theme-toggle');
  if (toggle) {
    toggle.addEventListener('click', function () {
      var root = document.documentElement;
      var next = root.dataset.theme === 'light' ? 'dark' : 'light';
      root.dataset.theme = next;
      try { localStorage.setItem('mycloud_theme', next); } catch (e) {}
    });
  }
})();