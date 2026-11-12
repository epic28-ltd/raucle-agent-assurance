// SPDX-License-Identifier: Apache-2.0
/* Hosted-login hook for the hosted operator surfaces — ONE physical copy,
   served by BOTH apps at /static/hosted-auth-hook.js (raucle-console and
   oaa_investigation_ui; the file lives in this package under assets/).
   Each SPA references it with a plain parser-blocking <script> in the
   position its inline block used to sit, so window.fetch is interposed
   BEFORE any page script runs its first fetch (behaviour identical to the
   former per-page inline blocks; the duplicate-inline-block Sonar debt is
   the reason it moved here).
   Three jobs, in order:
   1. interpose same-origin fetches so every /api|/coverage|/assurance call
      carries the session bearer once a session exists (sessionStorage only
      - tab-scoped, never localStorage, never a cookie);
   2. capture the IdP redirect (?code=...&state=...) and exchange it at
      POST /api/oidc/callback; a login that fails yields no session and
      the page stays on its shell (fail-closed);
   3. probe /api/session/config (public) and, with OIDC enabled and no
      valid session, send the operator to /api/oidc/login. */

(function () {
  'use strict';
  var _fetch = window.fetch.bind(window);
  var TOKEN_KEY = 'oaa_hosted_session';
  function authHeaders() {
    var t = null;
    try { t = sessionStorage.getItem(TOKEN_KEY); } catch (e) { t = null; }
    return t ? { 'Authorization': 'Bearer ' + t } : {};
  }
  window.oaaAuthHeaders = authHeaders;
  window.fetch = function (input, init) {
    try {
      var url = typeof input === 'string' ? input : ((input && input.url) || '');
      if (url.indexOf('/api/') === 0 || url.indexOf('/coverage/') === 0 ||
          url.indexOf('/assurance/') === 0) {
        init = init || {};
        var headers = new Headers(init.headers || {});
        var auth = authHeaders();
        for (var k in auth) { headers.set(k, auth[k]); }
        init.headers = headers;
      }
    } catch (e) { /* the interposer must never break a fetch */ }
    return _fetch(input, init);
  };
  function qs(name) {
    return new URLSearchParams(window.location.search).get(name);
  }
  var code = qs('code');
  var state = qs('state');
  if (code && state) {
    history.replaceState(null, '', window.location.pathname);
    fetch('/api/oidc/callback', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code: code, state: state })
    }).then(function (r) { return r.json(); }).then(function (d) {
      if (d && d.session_token) {
        try { sessionStorage.setItem(TOKEN_KEY, d.session_token); } catch (e) {}
        window.location.reload();
      } else {
        /* no session on doubt: stay on the shell, honest empty state */
      }
    }).catch(function () { /* exchange failed: fail closed, stay here */ });
    return;
  }
  if (qs('error')) { history.replaceState(null, '', window.location.pathname); }
  fetch('/api/session/config').then(function (r) { return r.json(); }).then(function (cfg) {
    if (!cfg || !cfg.oidc_enabled) { return; }
    return fetch('/api/session/me', { headers: authHeaders() }).then(function (me) {
      if (me.status === 403) { window.location.href = '/api/oidc/login'; }
    });
  }).catch(function () { /* config probe failed: leave the page as-is */ });
})();
