// ===== USER ACCOUNTS (browser-only demo: localStorage, no server) =====
// Sign up, log in, log out, "forgot password" with a reset code sent to the e-mail address.
// A browser-only project has no mail server: the e-mail is written in a "simulated mailbox" shown on the login page.
// Demo project: the password is saved as typed in the browser (no hashing). A real site must store a salted hash (bcrypt / Argon2) on a server.
(function (root) {
  "use strict";

  var USERS_KEY = "ssad_users", SESSION_KEY = "ssad_session", RESET_KEY = "ssad_resets",
      MAIL_KEY = "ssad_mailbox", FAIL_KEY = "ssad_fails";
  var MAX_FAILS = 5, LOCK_MS = 10000, CODE_TTL_MS = 10 * 60 * 1000, MAX_CODE_TRIES = 5, ROUNDS = 5000;
  var authScriptUrl = typeof document !== "undefined" && document.currentScript
    ? document.currentScript.src : "";

  // ---------- storage (every access protected: private windows may refuse it) ----------
  function load(key, def) { try { var v = JSON.parse(localStorage.getItem(key)); return v == null ? def : v; } catch (e) { return def; } }
  function save(key, val) { try { localStorage.setItem(key, JSON.stringify(val)); return true; } catch (e) { return false; } }

  // ---------- SHA-256 (constants computed from the primes, no table to copy) ----------
  var K = [], H0 = [];
  (function () {
    var n = 2, count = 0;
    while (count < 64) {
      var prime = true;
      for (var d = 2; d * d <= n; d++) if (n % d === 0) { prime = false; break; }
      if (prime) {
        if (count < 8) H0.push(Math.floor((Math.sqrt(n) % 1) * 4294967296) >>> 0);
        K.push(Math.floor((Math.cbrt(n) % 1) * 4294967296) >>> 0);
        count++;
      }
      n++;
    }
  })();
  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
  function sha256(str) {
    var bytes = new TextEncoder().encode(str), len = bytes.length;
    var total = ((len + 9 + 63) >> 6) << 6, buf = new Uint8Array(total);
    buf.set(bytes); buf[len] = 0x80;
    var dv = new DataView(buf.buffer);
    dv.setUint32(total - 8, Math.floor((len * 8) / 4294967296)); dv.setUint32(total - 4, (len * 8) >>> 0);
    var h = H0.slice(), w = new Array(64);
    for (var off = 0; off < total; off += 64) {
      var i;
      for (i = 0; i < 16; i++) w[i] = dv.getUint32(off + 4 * i);
      for (i = 16; i < 64; i++) {
        var s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        var s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (i = 0; i < 64; i++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25), ch = (e & f) ^ (~e & g);
        var t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22), maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
      h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
    }
    return h.map(function (x) { return ("00000000" + x.toString(16)).slice(-8); }).join("");
  }
  function slowHash(salt, secret) {
    var x = salt + ":" + secret;
    for (var i = 0; i < ROUNDS; i++) x = sha256(x + salt);
    return x;
  }
  function randomHex(bytes) {
    var a = new Uint8Array(bytes); crypto.getRandomValues(a);
    return Array.prototype.map.call(a, function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
  }
  function randomCode() {                       // 6 digits, no modulo bias
    var buf = new Uint32Array(1), lim = Math.floor(4294967296 / 1000000) * 1000000;
    do { crypto.getRandomValues(buf); } while (buf[0] >= lim);
    return ("000000" + (buf[0] % 1000000)).slice(-6);
  }

  // ---------- validation ----------
  function normEmail(e) { return String(e || "").trim().toLowerCase(); }
  // Format name@domain.tld (letters, digits, . _ % + - before @ ; domain with at least one dot ; letters-only ending of 2+ letters)
  // + detection of typos on the well-known providers (gmail.con, gmial.com, hotmial.com ...)
  var PROVIDERS = ["gmail.com", "yahoo.com", "yahoo.fr", "hotmail.com", "hotmail.fr", "outlook.com", "outlook.fr", "live.com", "icloud.com", "usthb.dz", "esi.dz"];
  function dist(a, b) {                       // Levenshtein distance
    var d = [], i, j;
    for (i = 0; i <= a.length; i++) { d[i] = [i]; }
    for (j = 1; j <= b.length; j++) d[0][j] = j;
    for (i = 1; i <= a.length; i++) for (j = 1; j <= b.length; j++)
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    return d[a.length][b.length];
  }
  function checkEmail(e) {
    e = String(e || "").trim().toLowerCase();
    var m = /^([a-z0-9]+(?:[._%+-][a-z0-9]+)*)@((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})$/.exec(e);
    if (!m) return "Invalid e-mail. Use the form name@gmail.com (example: maria@gmail.com).";
    var domain = m[2];
    if (PROVIDERS.indexOf(domain) < 0) {
      for (var i = 0; i < PROVIDERS.length; i++)
        if (dist(domain, PROVIDERS[i]) <= 2 && domain.split(".")[0].length >= 4) return "Did you mean @" + PROVIDERS[i] + " ? “@" + domain + "” looks like a typing mistake.";
      return "E-mail domain not accepted: “@" + domain + "”. Use one of: " + PROVIDERS.map(function (p) { return "@" + p; }).join(", ") + ".";
    }
    return "";
  }

  var PW_RULES = "At least 8 characters, with at least one uppercase letter, one lowercase letter and one special character (example: + _ # ? ! @ $ %).";
  function checkPassword(pw) {
    if (pw.length < 8) return "The password must contain at least 8 characters (it has " + pw.length + ").";
    if (/\s/.test(pw)) return "The password must not contain spaces.";
    if (!/[a-z]/.test(pw)) return "The password must contain at least one lowercase letter (a-z).";
    if (!/[A-Z]/.test(pw)) return "The password must contain at least one uppercase letter (A-Z).";
    if (!/[^A-Za-z0-9]/.test(pw)) return "The password must contain at least one special character (example: + _ # ? ! @ $ %).";
    return "";
  }

  // ---------- accounts ----------
  function users() { return load(USERS_KEY, {}); }

  function signup(name, email, pw, pw2) {
    name = String(name || "").trim(); email = normEmail(email);
    if (name.length < 2) return { ok: false, error: "Please enter your name (at least 2 characters)." };
    var e = checkEmail(email); if (e) return { ok: false, error: e };
    e = checkPassword(pw); if (e) return { ok: false, error: e };
    if (pw !== pw2) return { ok: false, error: "The two passwords are not the same." };
    var all = users();
    if (all[email]) return { ok: false, error: "This e-mail is already used. Log in or use “Forgot password?”." };
    var taken = Object.keys(all).some(function (k) { return all[k].name.trim().toLowerCase() === name.toLowerCase(); });
    if (taken) return { ok: false, error: "This name is already used. Choose another name." };
    all[email] = { name: name, email: email, password: pw, created: Date.now() };
    if (!save(USERS_KEY, all)) return { ok: false, error: "The browser refused to store the account (private window?)." };
    return { ok: true };
  }

  function login(email, pw) {
    email = normEmail(email);
    var fails = load(FAIL_KEY, {}), f = fails[email] || { n: 0, until: 0 }, now = Date.now();
    if (f.until > now) return { ok: false, locked: true, wait: Math.ceil((f.until - now) / 1000),
      error: "Temporarily blocked after too many failed attempts. Try again in " + Math.ceil((f.until - now) / 1000) + " second(s)." };
    var u = users()[email];
    if (u && (u.password !== undefined ? u.password === pw : slowHash(u.salt, pw) === u.hash)) {
      delete fails[email]; save(FAIL_KEY, fails);
      save(SESSION_KEY, { email: u.email, name: u.name });
      return { ok: true };
    }
    f.n += 1;
    if (f.n >= MAX_FAILS) { f = { n: 0, until: now + LOCK_MS }; fails[email] = f; save(FAIL_KEY, fails);
      return { ok: false, locked: true, wait: LOCK_MS / 1000, error: "Too many failed attempts. Login blocked for " + LOCK_MS / 1000 + " seconds." }; }
    fails[email] = f; save(FAIL_KEY, fails);
    // Account created by an older version of the site (password stored as salt/hash): it cannot be checked any more.
    // Resetting the password with "Forgot password?" rewrites it in the current format.
    var legacy = u && u.password === undefined;
    return { ok: false, error: "Incorrect e-mail or password. " + (MAX_FAILS - f.n) + " attempt(s) remaining before the temporary block."
      + (legacy ? "\nThis account was created with an older version of the site. Click “Forgot password?” to choose a new password." : "") };
  }

  function current() { var s = load(SESSION_KEY, null); return s && s.email && users()[s.email] ? s : null; }
  function logout() { try { localStorage.removeItem(SESSION_KEY); sessionStorage.setItem("ssad_loggedout", "1"); } catch (e) {} }
  function pageUrl(relativePath) {
    if (!relativePath) return relativePath;
    if (relativePath.indexOf("/") !== -1 || relativePath.indexOf("\\") !== -1) return relativePath;
    try {
      if (authScriptUrl) return new URL(relativePath, authScriptUrl).href;
    } catch (e) {}
    return relativePath;
  }

  // Called at the top of every protected page: not logged in -> login page
  function requireLogin(loginPage) {
    if (!current()) { location.replace(pageUrl(loginPage || "login.html")); return false; }
    return true;
  }

  // ---------- forgot password ----------
  // Step 1: the user types the e-mail. If an account exists, a 6-digit code is "sent" (written in the simulated mailbox).
  // The answer is the same whether the account exists or not (nobody can discover which e-mails are registered).
  // Real e-mail through EmailJS when emailjs-config.js is filled, otherwise simulated mailbox.
  function emailConfigured() {
    var c = root.EMAILJS_CONFIG;
    return !!(c && c.serviceId && c.templateId && c.publicKey);
  }
  function sendRealMail(to, name, code) {
    var c = root.EMAILJS_CONFIG;
    return fetch("https://api.emailjs.com/api/v1.0/email/send", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ service_id: c.serviceId, template_id: c.templateId, user_id: c.publicKey,
        template_params: { to_email: to, to_name: name, code: code, app_name: "Encryption and Security Framework" } })
    }).then(function (r) {
      return r.text().then(function (t) { if (!r.ok) throw new Error(t || ("HTTP " + r.status)); });
    });
  }

  // Returns a Promise -> { ok, mode: "email" | "simulation", error }
  function requestReset(email) {
    email = normEmail(email);
    var e = checkEmail(email); if (e) return Promise.resolve({ ok: false, error: e });
    var u = users()[email];
    if (!u) return Promise.resolve({ ok: false, error: "No account was found with this e-mail on this browser. Create an account first (accounts are saved in the browser where they were created)." });
    var code = randomCode(), salt = randomHex(8), resets = load(RESET_KEY, {});
    resets[email] = { salt: salt, hash: sha256(salt + ":" + code), exp: Date.now() + CODE_TTL_MS, tries: 0 };
    save(RESET_KEY, resets);
    if (emailConfigured()) {
      return sendRealMail(email, u.name, code).then(function () { return { ok: true, mode: "email" }; })
        .catch(function (err) {
          delete resets[email]; save(RESET_KEY, resets);
          return { ok: false, error: "The e-mail could not be sent (" + String(err.message || err).slice(0, 160) + "). Check emailjs-config.js and your internet connection." };
        });
    }
    var mails = load(MAIL_KEY, []);
    mails.unshift({ to: email, subject: "Reset your password", time: Date.now(),
      body: "Hello " + u.name + ",\nyour password reset code is: " + code + "\nIt is valid for 10 minutes. If you did not ask for it, ignore this message." });
    save(MAIL_KEY, mails.slice(0, 20));
    return Promise.resolve({ ok: true, mode: "simulation" });
  }

  function mailboxOf(email) {
    email = normEmail(email);
    return load(MAIL_KEY, []).filter(function (m) { return m.to === email; }).slice(0, 3);
  }

  // Step 2: e-mail + code + new password
  function resetPassword(email, code, pw, pw2) {
    email = normEmail(email); code = String(code || "").trim();
    var resets = load(RESET_KEY, {}), r = resets[email], bad = "Invalid or expired code. Ask for a new one.";
    if (!r || r.exp < Date.now()) return { ok: false, error: bad };
    var e = checkPassword(pw); if (e) return { ok: false, error: e };
    if (pw !== pw2) return { ok: false, error: "The two passwords are not the same." };
    if (sha256(r.salt + ":" + code) !== r.hash) {
      r.tries += 1;
      if (r.tries >= MAX_CODE_TRIES) { delete resets[email]; save(RESET_KEY, resets); return { ok: false, error: "Too many wrong codes. Ask for a new one." }; }
      save(RESET_KEY, resets);
      return { ok: false, error: "Wrong code. " + (MAX_CODE_TRIES - r.tries) + " attempt(s) left." };
    }
    var all = users(), u = all[email];
    if (!u) return { ok: false, error: bad };
    u.password = pw; delete u.salt; delete u.hash;
    save(USERS_KEY, all);
    delete resets[email]; save(RESET_KEY, resets);
    var fails = load(FAIL_KEY, {}); delete fails[email]; save(FAIL_KEY, fails);
    return { ok: true };
  }

  // ---------- small user bar (name + log out) on the protected pages ----------
  function mountUserBar() {
    var box = document.getElementById("userbar"), u = current();
    if (!box || !u) return;
    box.innerHTML = "";
    var who = document.createElement("span"); who.className = "who"; who.textContent = "👤 " + u.name;
    var btn = document.createElement("button"); btn.type = "button"; btn.textContent = "⎋ Log out";
    btn.addEventListener("click", function () { logout(); location.replace(pageUrl("login.html")); });
    box.appendChild(who); box.appendChild(btn);
    var hello = document.getElementById("user-hello"); if (hello) hello.textContent = u.name;
  }
  if (typeof document !== "undefined") document.addEventListener("DOMContentLoaded", mountUserBar);

  root.Auth = { signup: signup, login: login, logout: logout, current: current, requireLogin: requireLogin,
    requestReset: requestReset, resetPassword: resetPassword, mailboxOf: mailboxOf,
    checkPassword: checkPassword, PW_RULES: PW_RULES, checkEmail: checkEmail, _sha256: sha256 };
  if (typeof module !== "undefined") module.exports = root.Auth;
})(typeof window !== "undefined" ? window : globalThis);