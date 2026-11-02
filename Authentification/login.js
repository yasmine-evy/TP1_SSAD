// ===== LOGIN PAGE: log in / create an account / forgot password =====
(function () {
  "use strict";
  const $ = function (id) { return document.getElementById(id); };
  const loginScriptUrl = document.currentScript ? document.currentScript.src : "";

  function projectUrl(relativePath) {
    try {
      if (loginScriptUrl) return new URL(relativePath, loginScriptUrl).href;
    } catch (e) {}
    return relativePath;
  }

  // Already logged in: go straight to the home page
  if (Auth.current()) { location.replace(projectUrl("../index.html")); return; }

  // Message after a log out
  try { if (sessionStorage.getItem("ssad_loggedout")) { sessionStorage.removeItem("ssad_loggedout"); setTimeout(function () { show($("l-msg"), "✓ You have been logged out.", "ok"); }, 0); } } catch (e) {}

  let resetEmail = "";          // e-mail used in the "forgot password" flow
  let lockTimer = null;

  // ---------- messages ----------
  function show(box, text, kind) {                       // kind: "erreur" | "ok" | ""
    box.className = "resultat" + (kind ? " " + kind : "");
    box.style.whiteSpace = "pre-line";
    box.textContent = text;
  }
  function clear(box) { box.className = "resultat"; box.textContent = ""; }

  // ---------- views ----------
  const VIEWS = ["login", "signup", "forgot1", "forgot2"];
  function go(view) {
    VIEWS.forEach(function (v) { $("view-" + v).hidden = v !== view; });
    const tabbed = view === "login" || view === "signup";
    $("auth-tabs").style.display = tabbed ? "" : "none";
    $("tab-login").setAttribute("aria-selected", String(view === "login"));
    $("tab-signup").setAttribute("aria-selected", String(view === "signup"));
    const first = $("view-" + view).querySelector("input");
    if (first) first.focus();
  }
  $("auth-tabs").addEventListener("click", function (e) {
    const b = e.target.closest("[data-view]"); if (b) go(b.getAttribute("data-view"));
  });
  document.querySelectorAll("[data-go]").forEach(function (b) {
    b.addEventListener("click", function () { go(b.getAttribute("data-go")); });
  });

  // ---------- log in ----------
  function lockButton(seconds) {
    const btn = $("l-btn");
    clearInterval(lockTimer);
    let left = seconds;
    btn.disabled = true;
    lockTimer = setInterval(function () {
      left -= 1;
      if (left <= 0) { clearInterval(lockTimer); btn.disabled = false; clear($("l-msg")); }
      else show($("l-msg"), "Temporarily blocked after too many failed attempts. Try again in " + left + " second(s).", "erreur");
    }, 1000);
  }
  $("view-login").addEventListener("submit", function (e) {
    e.preventDefault();
    const r = Auth.login($("l-email").value, $("l-pw").value);
    if (r.ok) { location.replace(projectUrl("../index.html")); return; }
    show($("l-msg"), r.error, "erreur");
    $("l-pw").value = "";
    if (r.locked) lockButton(r.wait);
  });

  // ---------- create an account ----------
  $("s-pw").addEventListener("input", function () {
    const v = $("s-pw").value, err = v ? Auth.checkPassword(v) : "";
    $("s-rules").textContent = v && !err ? "✓ Password accepted." : (err || "At least 8 characters, with at least one uppercase letter, one lowercase letter and one special character (example: + _ # ? ! @ $ %).");
    $("s-rules").style.color = v && !err ? "var(--ok)" : "";
  });
  $("view-signup").addEventListener("submit", function (e) {
    e.preventDefault();
    const r = Auth.signup($("s-name").value, $("s-email").value, $("s-pw").value, $("s-pw2").value);
    if (!r.ok) { show($("s-msg"), r.error, "erreur"); return; }
    const email = $("s-email").value;
    ["s-name", "s-email", "s-pw", "s-pw2"].forEach(function (id) { $(id).value = ""; });
    clear($("s-msg"));
    go("login");
    $("l-email").value = email.trim();
    $("l-pw").focus();
    show($("l-msg"), "✓ Account created. You can now log in.", "ok");
  });

  // ---------- forgot password ----------
  function renderMailbox() {
    const mails = Auth.mailboxOf(resetEmail), box = $("mailbox");
    box.innerHTML = "";
    const title = document.createElement("div");
    title.className = "mailbox-title";
    title.textContent = "📧 Mailbox of " + resetEmail + " (simulation)";
    box.appendChild(title);
    if (!mails.length) {
      const p = document.createElement("p"); p.className = "petit"; p.textContent = "No message: no account uses this e-mail.";
      box.appendChild(p); return;
    }
    mails.forEach(function (m) {
      const d = document.createElement("div"); d.className = "mail";
      const s = document.createElement("div"); s.className = "mail-subject"; s.textContent = m.subject + " — " + new Date(m.time).toLocaleTimeString();
      const b = document.createElement("div"); b.className = "mail-body"; b.textContent = m.body;
      d.appendChild(s); d.appendChild(b); box.appendChild(d);
    });
    const note = document.createElement("p"); note.className = "petit";
    note.textContent = "A browser-only project has no mail server, so the e-mail is shown here. With a server, the code would arrive in your real inbox.";
    box.appendChild(note);
  }
  $("view-forgot1").addEventListener("submit", function (e) {
    e.preventDefault();
    const btn = $("view-forgot1").querySelector("button[type=submit]");
    btn.disabled = true; show($("f-msg"), "Sending…", "");
    Auth.requestReset($("f-email").value).then(function (r) {
      btn.disabled = false;
      if (!r.ok) { show($("f-msg"), r.error, "erreur"); return; }
      resetEmail = $("f-email").value.trim().toLowerCase();
      clear($("f-msg"));
      $("f2-text").textContent = r.mode === "email"
        ? "A 6-digit code was sent to " + resetEmail + ". Open your mailbox (check the spam folder too). It is valid for 10 minutes."
        : "A 6-digit code has been sent to " + resetEmail + ". It is valid for 10 minutes.";
      ["r-code", "r-pw", "r-pw2"].forEach(function (id) { $(id).value = ""; });
      clear($("r-msg"));
      if (r.mode === "simulation") { $("mailbox").hidden = false; renderMailbox(); } else { $("mailbox").hidden = true; }
      go("forgot2");
    });
  });
  $("view-forgot2").addEventListener("submit", function (e) {
    e.preventDefault();
    const r = Auth.resetPassword(resetEmail, $("r-code").value, $("r-pw").value, $("r-pw2").value);
    if (!r.ok) { show($("r-msg"), r.error, "erreur"); return; }
    go("login");
    $("l-email").value = resetEmail;
    $("l-pw").value = "";
    $("l-pw").focus();
    show($("l-msg"), "✓ Password changed. Log in with your new password.", "ok");
  });
})();