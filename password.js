// ===== PASSWORD SYSTEM =====
// Alphabets of the 3 password types required by the assignment
const T1 = ["0", "1"];                    // Type 1: 3 characters, each 0 or 1
const T2 = ["1", "2", "3", "4"];          // Type 2: 4 characters, each 1..4
const T3 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+*".split("");  // Type 3: 64 characters

const TYPES = {
  1: { alphabet: T1, length: 3,    label: '"0" or "1"',                 dict: ["000", "111", "101", "010"] },
  2: { alphabet: T2, length: 4,    label: '"1", "2", "3" or "4"',       dict: ["1234", "4321", "1111", "2222", "3333", "4444", "1212", "2121", "1122", "3412"] },
  3: { alphabet: T3, length: null, label: "a-z, A-Z, 0-9, + or *",
       dict: ["password", "123456", "12345678", "azerty", "admin", "qwerty", "letmein", "welcome", "football",
              "monkey", "dragon", "master", "abc123", "Passw0rd", "Password1", "iloveyou", "sunshine"] }
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
// requiredLength = null means "any length" (Type 3)
function checkPwd(pwd, type) {
  const t = TYPES[type];
  if (pwd.length === 0) return { ok: false, reason: "The field is empty." };
  if (t.length !== null && pwd.length !== t.length)
    return { ok: false, reason: "Wrong length: must be exactly " + t.length + " characters, but you entered " + pwd.length + "." };
  for (let i = 0; i < pwd.length; i++) {
    if (!t.alphabet.includes(pwd[i]))
      return { ok: false, reason: 'Character #' + (i + 1) + ' ("' + pwd[i] + '") is not allowed. Only ' + t.label + ' are allowed.' };
  }
  let reason = "Valid: " + pwd.length + " character(s), all from " + t.label + ".";
  if (t.dict.includes(pwd)) reason += "  ⚠ But this password is in the common-password dictionary: a dictionary attack finds it immediately.";
  return { ok: true, reason: reason };
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

// ---------- Attacks ----------
// Dictionary attack: tries a list of likely passwords. Honest: if the target is not in the list, it fails.
function dictionaryAttack(target, type) {
  const list = TYPES[type].dict;
  const t0 = performance.now();
  let tries = 0, found = false;
  for (const w of list) { tries++; if (w === target) { found = true; break; } }
  return { found: found, tries: tries, ms: performance.now() - t0 };
}

// Brute force with minimal work:
//  - Types 1 and 2: the length is fixed and known, so only that length is enumerated (8 or 256 candidates).
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
      // increment the odometer
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

// ---------- Protection: lockout simulation ----------
// From the 3rd failed attempt, wait 30 s, then double the wait at each failure (max 24 h).
function lockoutSeconds(failures) {
  let total = 0;
  for (let i = 3; i <= failures; i++) total += Math.min(30 * Math.pow(2, i - 3), 86400);
  return total;
}

// ---------- SHA-256 (small synchronous implementation, for the salting demo) ----------
function sha256(msg) {
  const K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  const bytes = Array.from(new TextEncoder().encode(msg));
  const bitLen = bytes.length * 8;
  bytes.push(0x80);
  while (bytes.length % 64 !== 56) bytes.push(0);
  for (let i = 7; i >= 0; i--) bytes.push(i >= 4 ? 0 : (bitLen >>> (i * 8)) & 0xff);
  let H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  const rotr = function (x, n) { return (x >>> n) | (x << (32 - n)); };
  for (let off = 0; off < bytes.length; off += 64) {
    const w = new Array(64);
    for (let i = 0; i < 16; i++) w[i] = (bytes[off+4*i] << 24) | (bytes[off+4*i+1] << 16) | (bytes[off+4*i+2] << 8) | bytes[off+4*i+3];
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >>> 3);
      const s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    H = [H[0]+a|0, H[1]+b|0, H[2]+c|0, H[3]+d|0, H[4]+e|0, H[5]+f|0, H[6]+g|0, H[7]+h|0];
  }
  return H.map(function (x) { return (x >>> 0).toString(16).padStart(8, "0"); }).join("");
}

if (typeof module !== "undefined") {
  module.exports = { TYPES, checkPwd, dictionaryAttack, bruteForce, lockoutSeconds, sha256, fmtDuration, worstCase, randomPassword };
}

// ===== USER INTERFACE (browser only) =====
if (typeof document !== "undefined") {
  const $ = function (id) { return document.getElementById(id); };

  // Generate a random password of the given type and check it
  window.genPwd = function (type) {
    const t = TYPES[type];
    const len = t.length !== null ? t.length : Math.max(1, Math.min(32, parseInt($("len3").value) || 8));
    $("pwd" + type).value = randomPassword(t.alphabet, len);
    window.checkInput(type);
  };

  // Check what is typed in the field
  window.checkInput = function (type) {
    const r = checkPwd($("pwd" + type).value, type);
    const res = $("res" + type);
    res.textContent = (r.ok ? "✔ " : "✘ ") + r.reason;
    res.className = "resultat" + (r.ok ? "" : " erreur");
    res.style.letterSpacing = "0"; res.style.fontSize = ".95rem"; res.style.fontFamily = "inherit";
  };

  window.updateCombo3 = function () {
    const len = Math.max(1, Math.min(32, parseInt($("len3").value) || 8));
    $("combo3").textContent = "Alphabet: 64 characters — length " + len + " → 64^" + len + " ≈ " + Math.pow(64, len).toExponential(2) + " combinations";
  };

  // Run both attacks on the 3 passwords (generate one when the field is empty or invalid)
  window.runAttackTests = function () {
    const rows = [];
    let rate = null;
    for (let type = 1; type <= 3; type++) {
      let pwd = $("pwd" + type).value;
      if (!checkPwd(pwd, type).ok) { genPwd(type); pwd = $("pwd" + type).value; }
      const t = TYPES[type];
      const space = Math.pow(t.alphabet.length, pwd.length);
      const d = dictionaryAttack(pwd, type);
      const b = bruteForce(pwd, type, 1500);
      if (type === 3 && b.tries > 1000 && b.ms > 0) rate = b.tries / (b.ms / 1000);
      let bfText;
      if (b.found) bfText = "found in " + fmtBig(b.tries) + " tries (" + fmtMs(b.ms) + ")";
      else bfText = "not found within 1.5 s (" + fmtBig(b.tries) + " tries, " + fmtMs(b.ms) + ")";
      let extra = "";
      if (b.timedOut && rate) extra = "<br>Estimated time to try all " + fmtBig(space) + " combinations at " + fmtBig(Math.round(rate)) + " tries/s: <strong>" + fmtDuration(worstCase(64, pwd.length, rate)) + "</strong> (on this one thread).";
      rows.push("<tr><td>Type " + type + "<br><span class='mono'>" + pwd.replace(/</g, "&lt;") + "</span></td><td>" + fmtBig(space) + "</td>" +
        "<td>" + (d.found ? "<b>found</b> in " + d.tries + " tries" : "not found") + " (" + fmtMs(d.ms) + ")</td>" +
        "<td>" + bfText + extra + "</td></tr>");
    }
    $("resAttacks").innerHTML = "<div class='table-wrap' style='max-height:none'><table class='t'><thead><tr><th>Password</th><th>Combinations</th><th>Dictionary attack</th><th>Brute force</th></tr></thead><tbody>" + rows.join("") + "</tbody></table></div>";
  };

  // Lockout simulation
  window.runLockout = function () {
    const cases = [["Type 1", 8], ["Type 2", 256]];
    const rows = cases.map(function (c) {
      const failures = c[1] - 1;                      // worst case: the last candidate is the right one
      return "<tr><td>" + c[0] + " (" + c[1] + " combinations)</td><td>almost instant</td><td><b>" + fmtDuration(lockoutSeconds(failures)) + "</b></td></tr>";
    });
    $("resLockout").innerHTML = "<div class='table-wrap' style='max-height:none'><table class='t'><thead><tr><th>Worst case</th><th>Without lockout</th><th>With lockout</th></tr></thead><tbody>" + rows.join("") + "</tbody></table></div>";
  };

  // Hash + salt demo
  window.runSalt = function () {
    const pwd = $("saltPwd").value || "password";
    const saltA = randomPassword(T3, 8), saltB = randomPassword(T3, 8);
    $("resSalt").textContent =
      "Without salt (same for everybody):\n  SHA-256(" + pwd + ") = " + sha256(pwd) +
      "\n\nUser A, salt = " + saltA + ":\n  SHA-256(" + saltA + pwd + ") = " + sha256(saltA + pwd) +
      "\n\nUser B, salt = " + saltB + ":\n  SHA-256(" + saltB + pwd + ") = " + sha256(saltB + pwd) +
      "\n\nSame password, three different hashes: a precomputed table (rainbow table) becomes useless.";
  };

  updateCombo3();
}
