// ===== PASSWORD SYSTEM =====
// Alphabets of the 3 password types required by the assignment
const T1 = ["0", "1"];                    // Type 1: 3 characters, each 0 or 1
const T2 = ["1", "2", "3", "4"];          // Type 2: 4 characters, each 1..4
const T3 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+*".split("");  // Type 3: 64 characters

// dict = dictionary of the attacker, sorted from the most to the least common
const TYPES = {
  1: { alphabet: T1, length: 3,    label: '"0" or "1"',                 dict: ["000", "111", "101", "010"] },
  2: { alphabet: T2, length: 4,    label: '"1", "2", "3" or "4"',       dict: ["1234", "4321", "1111", "2222", "3333", "4444", "1212", "2121", "1122", "3412"] },
  3: { alphabet: T3, length: null, label: "a-z, A-Z, 0-9, + or *",
       dict: ["123456", "password", "12345678", "qwerty", "azerty", "abc123", "admin", "letmein", "welcome", "football",
              "monkey", "dragon", "master", "Passw0rd", "Password1", "iloveyou", "sunshine", "123456789", "111111", "Admin123"] }
};

// ---------- Secure random (crypto, not Math.random) ----------
function randIndex(n) {
  const lim = Math.floor(4294967296 / n) * n;     // rejection sampling: no bias
  const buf = new Uint32Array(1);
  do { crypto.getRandomValues(buf); } while (buf[0] >= lim);
  return buf[0] % n;
}
function randomPassword(alphabet, len) {
  let s = "";
  for (let i = 0; i < len; i++) s += alphabet[randIndex(alphabet.length)];
  return s;
}

// ---------- Validation ----------
// Returns { ok, reason, fix }: fix = what the user must do when the password is refused.
function checkPwd(pwd, type) {
  const t = TYPES[type];
  const allowed = t.alphabet.join(", ");
  if (pwd.length === 0)
    return { ok: false, reason: "The field is empty.", fix: "Type your password" + (t.length !== null ? " (exactly " + t.length + " characters)" : "") + ", or click Generate." };
  if (t.length !== null && pwd.length !== t.length) {
    const diff = Math.abs(t.length - pwd.length);
    return { ok: false, reason: "Wrong length: must be exactly " + t.length + " characters, but you entered " + pwd.length + ".",
             fix: (pwd.length < t.length ? "Add " : "Remove ") + diff + " character(s)." };
  }
  if (t.length === null && pwd.length > 32)
    return { ok: false, reason: "Too long: " + pwd.length + " characters (maximum 32).", fix: "Remove " + (pwd.length - 32) + " character(s)." };
  for (let i = 0; i < pwd.length; i++) {
    if (!t.alphabet.includes(pwd[i]))
      return { ok: false, reason: 'Character #' + (i + 1) + ' ("' + pwd[i] + '") is not allowed. Only ' + t.label + ' are allowed.',
               fix: 'Replace character #' + (i + 1) + ' by one of: ' + (type === 3 ? "a-z, A-Z, 0-9, +, *" : allowed) + "." };
  }
  let reason = "Valid Type " + type + " password: " + pwd.length + " character(s), all from " + t.label + ".";
  if (t.dict.includes(pwd)) reason += "  ⚠ But this password is in the common-password dictionary: a dictionary attack finds it immediately. Choose another one.";
  return { ok: true, reason: reason, fix: "" };
}

// ---------- Formatting ----------
function fmtDuration(sec) {
  if (sec < 1) return (sec * 1000).toFixed(2) + " ms";
  if (sec < 60) return sec.toFixed(1) + " s";
  if (sec < 3600) return (sec / 60).toFixed(1) + " min";
  if (sec < 86400) return (sec / 3600).toFixed(1) + " h";
  const days = sec / 86400;
  if (days < 365) return days.toFixed(1) + " days";
  const years = days / 365.25;
  return (years < 1e6 ? years.toFixed(1) : years.toExponential(1)) + " years";
}
function fmtMs(ms) { return ms < 0.01 ? "< 0.01 ms" : ms.toFixed(2) + " ms"; }
function fmtBig(n) { return n < 1e6 ? n.toLocaleString("en-US") : n.toExponential(2); }

// ---------- Attacks, used only by the tests of part 1 (interfaces + protections: parts 2 and 3) ----------
// ATTACK 1: dictionary ----------
// Tries the list in order (most common first) and stops at the first match.
function dictionaryAttack(target, type) {
  const list = TYPES[type].dict;
  const t0 = performance.now();
  let tries = 0, found = false;
  for (const w of list) { tries++; if (w === target) { found = true; break; } }
  return { found: found, tries: tries, ms: performance.now() - t0 };
}

// ---------- ATTACK 2: brute force (minimal work) ----------
//  - Types 1 and 2: the length is known, so only that length is enumerated (8 or 256 candidates).
//  - Type 3: the length is unknown, so lengths 1, 2, 3... are tried in order (shortest first).
// An "odometer" counter avoids building strings. Stops after budgetMs (then the time is extrapolated).
function bruteForce(target, type, budgetMs) {
  const t = TYPES[type], A = t.alphabet, base = A.length;
  const tgt = Array.from(target).map(function (c) { return A.indexOf(c); });
  const minLen = t.length !== null ? t.length : 1;
  const maxLen = t.length !== null ? t.length : 32;
  const t0 = performance.now();
  let tries = 0;
  for (let L = minLen; L <= maxLen; L++) {
    const idx = new Array(L).fill(0);
    for (;;) {
      tries++;
      if (L === tgt.length) {
        let same = true;
        for (let i = 0; i < L; i++) if (idx[i] !== tgt[i]) { same = false; break; }
        if (same) return { found: true, tries: tries, ms: performance.now() - t0, timedOut: false };
      }
      let p = L - 1;
      while (p >= 0 && ++idx[p] === base) { idx[p] = 0; p--; }
      if (p < 0) break;                                         // all candidates of this length done
      if ((tries & 0xFFFF) === 0 && performance.now() - t0 > budgetMs)
        return { found: false, tries: tries, ms: performance.now() - t0, timedOut: true };
    }
  }
  return { found: false, tries: tries, ms: performance.now() - t0, timedOut: false };
}

// Worst-case time to exhaust the space of length L at `rate` tries per second
function worstCase(base, L, rate) { return Math.pow(base, L) / rate; }

if (typeof module !== "undefined") {
  module.exports = { TYPES, checkPwd, dictionaryAttack, bruteForce, fmtDuration, worstCase, randomPassword };
}

// ===== USER INTERFACE (browser only) =====
if (typeof document !== "undefined") {
  const $ = function (id) { return document.getElementById(id); };
  const esc = function (s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;"); };
  const table = function (head, rows) {
    return "<div class='table-wrap' style='max-height:none'><table class='t'><thead><tr>" + head.map(function (h) { return "<th>" + h + "</th>"; }).join("") +
      "</tr></thead><tbody>" + rows.join("") + "</tbody></table></div>";
  };
  const randomFor = function (type) {
    const t = TYPES[type];
    return randomPassword(t.alphabet, t.length !== null ? t.length : Math.max(1, Math.min(32, parseInt($("len3").value) || 8)));
  };

  // ---------- G1: generator ----------
  window.genPwd = function (type) { $("pwd" + type).value = randomFor(type); window.checkInput(type); };
  window.checkInput = function (type) {
    const r = checkPwd($("pwd" + type).value, type);
    const res = $("res" + type);
    res.style.whiteSpace = "pre-line";
    res.textContent = r.ok ? "✔ ACCEPTED — " + r.reason
                           : "✘ REFUSED — " + r.reason + "\nWhat to do: " + r.fix;
    res.className = "resultat" + (r.ok ? "" : " erreur");
    res.style.letterSpacing = "0"; res.style.fontSize = ".95rem"; res.style.fontFamily = "inherit";
  };
  window.updateCombo3 = function () {
    const len = Math.max(1, Math.min(32, parseInt($("len3").value) || 8));
    const txt = "64^" + len + " ≈ " + Math.pow(64, len).toExponential(2);
    $("combo3").textContent = "Alphabet: 64 characters — length " + len + " → " + txt + " combinations";
    $("len3Show").textContent = len;
    $("space3").innerHTML = "<b>" + txt + "</b>";
  };

  // Run both attacks on the 3 passwords of section 1 (generate one when the field is empty or invalid)
  window.runAttackTests = function () {
    const rows = [];
    let rate = null;
    for (let type = 1; type <= 3; type++) {
      let pwd = $("pwd" + type).value;
      if (!checkPwd(pwd, type).ok) { genPwd(type); pwd = $("pwd" + type).value; }
      const space = Math.pow(TYPES[type].alphabet.length, pwd.length);
      const d = dictionaryAttack(pwd, type);
      const b = bruteForce(pwd, type, 1500);
      if (type === 3 && b.tries > 1000 && b.ms > 0) rate = b.tries / (b.ms / 1000);
      let bf = b.found ? "found in " + fmtBig(b.tries) + " tries (" + fmtMs(b.ms) + ")"
                       : "not found within 1.5 s (" + fmtBig(b.tries) + " tries, " + fmtMs(b.ms) + ")";
      if (b.timedOut && rate) bf += "<br>Estimated time for all " + fmtBig(space) + " combinations at " + fmtBig(Math.round(rate)) + " tries/s: <strong>" + fmtDuration(worstCase(64, pwd.length, rate)) + "</strong>";
      rows.push("<tr><td>Type " + type + "<br><span class='mono'>" + esc(pwd) + "</span></td><td>" + fmtBig(space) + "</td>" +
        "<td>" + (d.found ? "<b>found</b> in " + d.tries + " tries" : "not found") + " (" + fmtMs(d.ms) + ")</td><td>" + bf + "</td></tr>");
    }
    $("resAttacks").innerHTML = table(["Password", "Combinations", "Dictionary attack", "Brute force"], rows);
  };

  updateCombo3();
}
