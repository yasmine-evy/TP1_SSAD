// ===== PASSWORD SYSTEM =====
// Alphabets of the 3 password types required by the assignment
const T1 = ["0", "1"];                    // Type 1: 3 characters, each 0 or 1
const T2 = ["1", "2", "3", "4"];          // Type 2: 4 characters, each 1..4
const T3 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+*".split("");  // Type 3: 64 characters

// dict = dictionary of the attacker, sorted from the most to the least common
const TYPES = {
  1: { alphabet: T1, length: 3,    label: '"0" or "1"',                 dict: ["000", "111", "101", "010", "001", "011", "100", "110"] },
  2: { alphabet: T2, length: 4,    label: '"1", "2", "3" or "4"',       dict: ["1234", "4321", "1111", "2222", "3333", "4444", "1212", "2121", "1122", "3412", "1342", "2143", "1243", "1324", "1423", "1432", "2134", "2314", "2341", "2413", "2431", "3124", "3142", "3214", "3241", "3421", "4123", "4132", "4213", "4231", "4312", "1221", "2112", "3443", "4334", "1231", "2342", "3413", "4124", "1431"] },
  3: { alphabet: T3, length: null, label: "a-z, A-Z, 0-9, + or *",
       dict: ["123456", "password", "12345678", "qwerty", "azerty", "abc123", "admin", "letmein", "welcome", "football",
              "monkey", "dragon", "master", "Passw0rd", "Password1", "iloveyou", "sunshine", "123456789", "111111", "Admin123",
              "12345", "1234567", "1234567890", "123123", "000000", "654321", "987654321", "qwertyuiop", "qwerty123", "qwerty1",
              "password1", "Password", "passw0rd", "pass123", "admin123", "admin1", "administrator", "root", "root123", "user",
              "user123", "test", "test123", "guest", "guest123", "login", "login123", "welcome1", "welcome123", "hello",
              "hello123", "hello1", "changeme", "default", "secret", "secret123", "access", "access123", "manager", "manager123",
              "superman", "batman", "spiderman", "starwars", "pokemon", "naruto", "michael", "jennifer", "jessica", "daniel",
              "robert", "thomas", "charlie", "george", "computer", "internet", "service", "server", "database", "security",
              "summer", "summer1", "summer123", "winter", "winter1", "spring", "spring1", "autumn", "freedom", "whatever",
              "trustno1", "princess", "princess1", "baseball", "basketball", "soccer", "hockey", "liverpool", "chelsea", "arsenal",
              "barcelona", "realmadrid", "mercedes", "mustang", "harley", "matrix", "tigger", "ginger", "pepper", "cookie",
              "maggie", "bailey", "buster", "shadow", "snoopy", "jordan", "jordan23", "donald", "michelle", "andrew",
              "joshua", "matthew", "anthony", "william", "richard", "christopher", "samantha", "amanda", "melissa", "nicole",
              "victoria", "andrea", "jasmine", "flower", "flowers", "butterfly", "angel", "angels", "diamond", "rainbow",
              "coffee", "chocolate", "strawberry", "banana", "orange", "apple", "cheese", "pizza", "london", "paris",
              "france", "england", "america", "canada", "algeria", "usthb", "school", "student", "teacher", "education",
              "lovely", "beautiful", "sweetheart", "honey", "babygirl", "babyboy", "loveme", "forever", "family", "friends",
              "friendship", "guitar", "music", "music123", "dance", "movie", "movies", "book", "books", "reading",
              "dream", "dreams", "happy", "smile", "lucky", "winner", "winner1", "killer", "hunter", "ranger",
              "warrior", "knight", "wizard", "magic", "ninja", "pirate", "eagle", "tiger", "lion", "wolf",
              "kitty", "cat123", "dog123", "horse", "rabbit", "dolphin", "shark", "flower1", "garden", "nature",
              "sunset", "sunrise", "moonlight", "starlight", "blue", "black", "white", "red", "green", "purple",
              "silver", "gold", "golden", "orange1", "pink", "violet", "1234", "12345", "123456789", "1q2w3e4r",
              "1qaz2wsx", "qazwsx", "zxcvbn", "asdfgh", "asdf123", "abc", "abcd", "abcdef", "abcdefg", "abcdefgh",
              "password123", "Password123", "passw0rd1", "P+ssword", "P*ssw0rd", "Aa123456", "Aa12345678", "Qwerty123", "Qwerty1", "Welcome1",
              "Welcome123", "Admin", "Admin1", "Admin1234", "Root123", "Test1234", "Hello123", "Love123", "Starwars", "Football1",
              "Monkey123", "Dragon123", "Master123", "Summer2024", "Winter2024", "April", "January", "October", "December", "November",
              "March", "May123", "June123", "July123", "August", "September", "2024", "2025", "2026", "0000"] }
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
function checkPwd(pwd, type, len3) {
  const t = TYPES[type];
  const need = t.length !== null ? t.length : (len3 || null);   // Type 3: the length chosen by the user
  const allowed = t.alphabet.join(", ");
  const chosen = t.length === null && need !== null ? " (the length you chose)" : "";
  if (pwd.length === 0)
    return { ok: false, reason: "The field is empty.", fix: "Type your password" + (need !== null ? " (exactly " + need + " characters)" : "") + ", or click Generate." };
  if (need !== null && pwd.length !== need) {
    const diff = Math.abs(need - pwd.length);
    return { ok: false, reason: "Wrong length: must be exactly " + need + " characters" + chosen + ", but you entered " + pwd.length + ".",
             fix: (pwd.length < need ? "Add " : "Remove ") + diff + " character(s)" + (t.length === null ? ", or change the Length field." : ".") };
  }
  if (need === null && pwd.length > 32)
    return { ok: false, reason: "Too long: " + pwd.length + " characters (maximum 32).", fix: "Remove " + (pwd.length - 32) + " character(s)." };
  for (let i = 0; i < pwd.length; i++) {
    if (!t.alphabet.includes(pwd[i]))
      return { ok: false, reason: 'Character #' + (i + 1) + ' ("' + pwd[i] + '") is not allowed. Only ' + t.label + ' are allowed.',
               fix: 'Replace character #' + (i + 1) + ' by one of: ' + (type === 3 ? "a-z, A-Z, 0-9, +, *" : allowed) + "." };
  }
  let reason = "Valid Type " + type + " password: " + pwd.length + " character(s), all from " + t.label + ".";
  return { ok: true, reason: reason, fix: "", commonPassword: isCommonPassword(pwd, type) };
}

function isCommonPassword(password, type) {
  const normalized = password.toLowerCase();
  return TYPES[type].dict.some(function (candidate) { return candidate.toLowerCase() === normalized; });
}

function isInCommonPasswordDictionary(password) {
  const normalized = password.toLowerCase();
  return Object.keys(TYPES).some(function (type) {
    return TYPES[type].dict.some(function (candidate) { return candidate.toLowerCase() === normalized; });
  });
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

const ALGO_NAMES = { caesar: "Caesar", hill: "Hill", playfair: "Playfair" };
// Default keys valid for the alphabets of the 3 types (a Hill matrix with an odd determinant is valid modulo 2, 4 and 64)
const DEFAULT_KEYS = {
  1: { caesar: 3, hill: [1, 1, 0, 1], playfair: "1" },
  2: { caesar: 3, hill: [1, 2, 3, 3], playfair: "3142" },
  3: { caesar: 3, hill: [3, 3, 2, 5], playfair: "Secret+Key*" }
};

function symbolMap(alphabet) { const m = new Map(); alphabet.forEach(function (s, i) { m.set(s, i); }); return m; }

// Turns the words of a list into index arrays (done BEFORE the timed search). Words with a forbidden symbol are skipped.
function prepareCandidates(words, alphabet) {
  const map = symbolMap(alphabet), kept = [], idx = [];
  let skipped = 0, maxLen = 1;
  for (let w = 0; w < words.length; w++) {
    const word = words[w], arr = new Int32Array(word.length);
    let ok = word.length > 0;
    for (let i = 0; ok && i < word.length; i++) { const k = map.get(word[i]); if (k === undefined) ok = false; else arr[i] = k; }
    if (!ok) { skipped++; continue; }
    kept.push(word); idx.push(arr); if (word.length > maxLen) maxLen = word.length;
  }
  return { words: kept, idx: idx, skipped: skipped, maxLen: maxLen };
}

function sameIdx(out, ol, target) {
  if (ol !== target.length) return false;
  for (let k = 0; k < ol; k++) if (out[k] !== target[k]) return false;
  return true;
}

// ---------- ATTACK 1: dictionary against an ENCRYPTED password ----------
// For each word (most common first): encrypt it with the same algorithm and key, compare with the stolen value.
// Stops at the first match. Only this loop is timed.
function dictionaryAttackEnc(targetIdx, cands, cipher) {
  const out = new Int32Array(2 * cands.maxLen + 4), n = cands.idx.length;
  const t0 = performance.now();
  for (let i = 0; i < n; i++) {
    const w = cands.idx[i];
    if (sameIdx(out, cipher.encIdx(w, w.length, out), targetIdx))
      return { found: true, password: cands.words[i], tries: i + 1, ms: performance.now() - t0, dictSize: n };
  }
  return { found: false, password: null, tries: n, ms: performance.now() - t0, dictSize: n };
}

// ---------- ATTACK 2: brute force against an ENCRYPTED password ----------
//  - The length is known by the policy (3, 4, or the length chosen for Type 3): only that length is enumerated.
//  - Without a known length: lengths 1, 2, 3... are tried in order (shortest first).
// An "odometer" counter enumerates the candidates; each one is encrypted and compared. Stops after budgetMs.
function bruteForceEnc(targetIdx, type, cipher, budgetMs, len3) {
  const t = TYPES[type], A = t.alphabet, base = A.length;
  const fixed = t.length !== null ? t.length : (len3 || null);   // the length required by the policy
  const minLen = fixed !== null ? fixed : 1;
  const maxLen = fixed !== null ? fixed : 32;
  const out = new Int32Array(2 * maxLen + 4);
  const t0 = performance.now();
  let tries = 0;
  for (let L = minLen; L <= maxLen; L++) {
    const idx = new Int32Array(L);
    for (;;) {
      tries++;
      if (sameIdx(out, cipher.encIdx(idx, L, out), targetIdx)) {
        let pw = ""; for (let i = 0; i < L; i++) pw += A[idx[i]];
        return { found: true, password: pw, tries: tries, ms: performance.now() - t0, timedOut: false };
      }
      let p = L - 1;
      while (p >= 0 && ++idx[p] === base) { idx[p] = 0; p--; }
      if (p < 0) break;                                         // all candidates of this length done
      if ((tries & 0xFFFF) === 0 && performance.now() - t0 > budgetMs)
        return { found: false, password: null, tries: tries, ms: performance.now() - t0, timedOut: true };
    }
  }
  return { found: false, password: null, tries: tries, ms: performance.now() - t0, timedOut: false };
}

// Builds one ordered, duplicate-free candidate list from every built-in and user-supplied word.
function buildFullDictionary(type, customText) {
  const base = TYPES[type].dict.slice();
  const extra = String(customText || "").split(/\r?\n/)
    .map(function (word) { return word.trim(); })
    .filter(function (word) { return word.length > 0; });
  return Array.from(new Set(base.concat(extra)));
}

// Worst-case time to exhaust the space of length L at `rate` tries per second
function worstCase(base, L, rate) { return Math.pow(base, L) / rate; }

if (typeof module !== "undefined") {
  module.exports = { TYPES, checkPwd, isCommonPassword, isInCommonPasswordDictionary, buildFullDictionary, prepareCandidates, dictionaryAttackEnc, bruteForceEnc, fmtDuration, worstCase, randomPassword };
}

// ===== USER INTERFACE (browser only) =====
if (typeof document !== "undefined") {
  const $ = function (id) { return document.getElementById(id); };
  const esc = function (s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;"); };
  const table = function (head, rows) {
    return "<div class='table-wrap' style='max-height:none'><table class='t'><thead><tr>" + head.map(function (h) { return "<th>" + h + "</th>"; }).join("") +
      "</tr></thead><tbody>" + rows.join("") + "</tbody></table></div>";
  };
  const len3Value = function () { return Math.max(1, Math.min(32, parseInt($("len3").value) || 8)); };
  const chk = function (value, type) { return checkPwd(value, type, type === 3 ? len3Value() : undefined); };
  const lenOf = function (type) { return TYPES[type].length !== null ? TYPES[type].length : len3Value(); };
  const randomFor = function (type) {
    const t = TYPES[type];
    return randomPassword(t.alphabet, t.length !== null ? t.length : len3Value());
  };
  const showError = function (box, msg) { box.className = "resultat erreur"; box.style.whiteSpace = "pre-line"; box.textContent = msg; };

  // ---------- Algorithm panels (Caesar / Hill / Playfair) of the attack blocks ----------
  // prefix: "tests", "dict" or "bf". PANELS remembers the password type shown in each panel.
  const PANELS = {};

  function paramsHtml(prefix, type, algo) {
    const A = TYPES[type].alphabet, n = A.length, d = DEFAULT_KEYS[type];
    const symbols = type === 3 ? "a-z, A-Z, 0-9, +, *" : A.join(", ");
    const shared = prefix === "tests" ? " The same key is used for the 3 types." : "";
    if (algo === "caesar") {
      return '<p class="petit hint">Alphabets a–z and A–Z (26 letters each). Key 1 to 25 (26 would not encrypt the text and shows an error). Digits, + and * are not changed by Caesar.</p>' +
        '<div class="row"><div><label for="' + prefix + '-ckey">Key</label><input type="number" id="' + prefix + '-ckey" min="1" max="25" value="' + d.caesar + '"></div>' +
        '<div><label for="' + prefix + '-cdir">Shift direction</label><select id="' + prefix + '-cdir"><option value="right">Right</option><option value="left">Left</option></select></div></div>';
    }
    if (algo === "hill") {
      return '<p class="petit hint">2×2 key matrix, all calculations modulo ' + n + (prefix === "tests" ? " (2, 4 or 64 depending on the type)" : "") + '. The determinant must be coprime with it (odd). An odd number of symbols gets one padding symbol.' + shared + '</p>' +
        '<div class="matrice">' + ["a", "b", "c", "d"].map(function (l, i) { return '<input id="' + prefix + '-h' + l + '" type="number" value="' + d.hill[i] + '" aria-label="Matrix ' + l + '">'; }).join("") + '</div>' +
        '<div class="boutons"><button type="button" onclick="randomHill(\'' + prefix + '\')">Random valid key</button></div>';
    }
    const dims = PC.gridDims(n);
    return '<p class="petit hint">Secret key made of symbols of the alphabet (' + symbols + '). The grid is built from the key. Equal neighbours and an odd end get a padding symbol.' + shared + '</p>' +
      '<label for="' + prefix + '-pkey">Secret key</label><input type="text" id="' + prefix + '-pkey" value="' + esc(prefix === "tests" ? "1" : d.playfair) + '" autocomplete="off">';
  }

  function renderCipherPanel(prefix, type, containerId, keepAlgo) {
    PANELS[prefix] = { type: type, container: containerId };
    const box = $(containerId);
    const algo = keepAlgo && $(prefix + "-algo") ? $(prefix + "-algo").value : "caesar";
    box.innerHTML = '<div class="params"><label for="' + prefix + '-algo">Algorithm</label>' +
      '<select id="' + prefix + '-algo" onchange="onAlgoChange(\'' + prefix + '\')">' +
      Object.keys(ALGO_NAMES).map(function (a) { return '<option value="' + a + '">' + ALGO_NAMES[a] + '</option>'; }).join("") +
      '</select><div id="' + prefix + '-params"></div></div>';
    $(prefix + "-algo").value = algo;
    $(prefix + "-params").innerHTML = paramsHtml(prefix, type, algo);
  }
  window.onAlgoChange = function (prefix) {
    $(prefix + "-params").innerHTML = paramsHtml(prefix, PANELS[prefix].type, $(prefix + "-algo").value);
  };
  window.randomHill = function (prefix) {
    const k = PC.randomHillKey(TYPES[PANELS[prefix].type].alphabet.length, randIndex);
    ["a", "b", "c", "d"].forEach(function (l, i) { $(prefix + "-h" + l).value = k[i]; });
  };
  // Reads the panel and builds the cipher for the given type (throws an Error with a readable message when the key is not valid)
  function readCipher(prefix, type) {
    const A = TYPES[type].alphabet, algo = $(prefix + "-algo").value;
    let params;
    if (algo === "caesar") params = { key: $(prefix + "-ckey").value, direction: $(prefix + "-cdir").value };
    else if (algo === "hill") {
      params = { m: ["a", "b", "c", "d"].map(function (l) {
        const raw = $(prefix + "-h" + l).value.trim(), v = Number(raw);
        if (raw === "" || !Number.isInteger(v)) throw new Error("Hill: the key values must be integers.");
        return v;
      }) };
    } else params = { key: $(prefix + "-pkey").value };
    return PC.prepare(algo, A, params);
  }

  // ---------- Live warning above a field when the password does not respect the type ----------
  function liveWarn(boxId, value, type) {
    const box = $(boxId);
    if (!value) { box.className = "alerte"; box.textContent = ""; return; }
    const r = chk(value, type);
    if (r.ok) { box.className = "alerte"; box.textContent = ""; return; }
    box.className = "alerte on";
    box.textContent = "⚠ This password does not respect Type " + type + ": " + r.reason + "\nWhat to do: " + r.fix;
  }
  window.liveGen = function (type) { liveWarn("warn" + type, $("pwd" + type).value, type); };
  window.liveAttack = function (prefix) {
    const type = Number($(prefix + "-type-select").value);
    liveWarn("warn-" + prefix, $(prefix + "-form").value === "plain" ? $(prefix + "-target").value : "", type);
  };

  // ---------- Generator, validation, encryption, decryption ----------
  window.genPwd = function (type) { $("pwd" + type).value = randomFor(type); liveGen(type); window.checkInput(type); };
  window.checkInput = function (type) {
    const r = chk($("pwd" + type).value, type);
    const res = $("res" + type);
    res.style.whiteSpace = "pre-line";
    if (!r.ok) {
      res.textContent = "✘ REFUSED — " + r.reason + "\nWhat to do: " + r.fix;
      res.className = "resultat erreur";
    } else if (r.commonPassword) {
      res.textContent = "✔ Valid Type " + type + " password — " + r.reason +
        "\n⚠ This password is in our demonstration common-password list and is vulnerable to dictionary attacks. Choose a stronger password.";
      res.className = "resultat erreur";
    } else {
      res.textContent = "✔ ACCEPTED — " + r.reason +
        "\nNot found in our demonstration common-password list; this does not guarantee that the password is secure.";
      res.className = "resultat";
    }
    res.style.letterSpacing = "0"; res.style.fontSize = ".95rem"; res.style.fontFamily = "inherit";
  };
  window.updateCombo3 = function () {
    const len = len3Value();
    const txt = "64^" + len + " ≈ " + Math.pow(64, len).toExponential(2);
    $("combo3").textContent = "Alphabet: 64 characters — length " + len + " → " + txt + " combinations";
    $("len3Show").textContent = len;
    if (window.liveGen) { liveGen(3); liveAttack("dict"); liveAttack("bf"); }
    $("space3").innerHTML = "<b>" + txt + "</b>";
  };

  // ---------- Attack tests of section 1 ----------
  window.runAttackTests = function () {
    const rows = [];
    for (let type = 1; type <= 3; type++) {
      let pwd = $("pwd" + type).value;
      if (!chk(pwd, type).ok) { genPwd(type); pwd = $("pwd" + type).value; }
      let cipher;
      try { cipher = readCipher("tests", type); }
      catch (e) { rows.push("<tr><td>Type " + type + "</td><td colspan='3' style='color:#c0392b;white-space:pre-line'>" + esc(e.message) + "</td></tr>"); continue; }
      const enc = cipher.encrypt(pwd).text, tIdx = cipher.toIdx(enc);
      const space = Math.pow(TYPES[type].alphabet.length, pwd.length);
      const d = dictionaryAttackEnc(tIdx, prepareCandidates(TYPES[type].dict, TYPES[type].alphabet), cipher);
      const b = bruteForceEnc(tIdx, type, cipher, 1500, lenOf(type));
      let bf = b.found ? "found <b>" + esc(b.password) + "</b> in " + fmtBig(b.tries) + " tries (" + fmtMs(b.ms) + ")"
                       : "not found within 1.5 s (" + fmtBig(b.tries) + " tries, " + fmtMs(b.ms) + ")";
      if (b.timedOut && b.ms > 0) bf += "<br>Estimated time for all " + fmtBig(space) + " combinations at " + fmtBig(Math.round(b.tries / (b.ms / 1000))) + " tries/s: <strong>" +
        fmtDuration(worstCase(TYPES[type].alphabet.length, pwd.length, b.tries / (b.ms / 1000))) + "</strong>";
      rows.push("<tr><td>Type " + type + " · " + ALGO_NAMES[cipher.algo] + "<br><span class='mono'>" + esc(pwd) + "</span> → <span class='mono'>" + esc(enc) + "</span></td><td>" + fmtBig(space) + "</td>" +
        "<td>" + (d.found ? "<b>found</b> <span class='mono'>" + esc(d.password) + "</span> in " + d.tries + " tries" : "not found") + " (" + fmtMs(d.ms) + ")</td><td>" + bf + "</td></tr>");
    }
    $("resAttacks").innerHTML = table(["Password → encrypted", "Combinations", "Dictionary attack", "Brute force"], rows);
  };

  // ---------- Shared parts of the two attack interfaces ----------
  window.onTypeChange = function (prefix) {
    renderCipherPanel(prefix, Number($(prefix + "-type-select").value), prefix + "-cipher", true);
    $(prefix + "-result").innerHTML = "";
    liveAttack(prefix);
  };
  window.generateTarget = function (prefix) {
    const type = Number($(prefix + "-type-select").value);
    $(prefix + "-target").value = randomFor(type);
    $(prefix + "-form").value = "plain";
    $(prefix + "-result").innerHTML = "";
    liveAttack(prefix);
  };
  // Returns the plain password (or null) and the encrypted password (text + indexes) the attacker is given.
  function getTarget(prefix, type, cipher) {
    const form = $(prefix + "-form").value, raw = $(prefix + "-target").value;
    if (!raw) throw new Error("Enter or generate a target password first.");
    try {
      if (form === "plain") {
        const v = chk(raw, type);
        if (!v.ok) throw new Error("the password does not respect Type " + type + ". " + v.reason + " " + v.fix);
        const e = cipher.encrypt(raw).text; return { plain: raw, enc: e, encIdx: cipher.toIdx(e), validity: v }; }
      return { plain: null, enc: raw, encIdx: cipher.toIdx(raw) };
    } catch (e) { throw new Error("Target: " + e.message); }
  }
  function targetLines(t, cipher) {
    const noLetter = cipher.algo === "caesar" && !/[A-Za-z]/.test(t.enc);
    return "Algorithm: <b>" + ALGO_NAMES[cipher.algo] + "</b><br>" +
      (t.plain !== null ? "Original password: <b>" + esc(t.plain) + "</b><br>" : "") +
      "Encrypted password (the value the attacker has): <b>" + esc(t.enc) + "</b><br>" +
      (noLetter ? "<span class='tag'>Note</span> This password has no letters (a–z, A–Z), so Caesar leaves it unchanged: the encrypted password is the same as the original.<br>" : "");
  }
  function equivalenceNote(t, found) {
    return found && t.plain !== null && found !== t.plain
      ? "<p class='petit'>The password found (" + esc(found) + ") is not the original one (" + esc(t.plain) + ") but it gives the <b>same encrypted value</b>, so it opens the account all the same (Playfair / Hill padding).</p>" : "";
  }

  // Shown when an attack found the password: it is too weak
  function weakAdvice(type) {
    return "<div class='conseil'><b>Weak password!</b> The attack found it. Make it harder to find: add characters to it" +
      (type === 3 ? " (for example <code>+</code> or <code>*</code>, mixed with letters and digits)" : " and use a longer password") +
      ", or a symbol such as <code>#</code> or <code>.</code> if the system allows it (these two are outside the alphabets of the 3 types of this TP). " +
      "Every added character multiplies the number of combinations the attacker must try (×" + TYPES[type].alphabet.length + " per character here), and avoid common words.</div>";
  }

  // ---------- Dictionary attack interface ----------
  window.runDictionaryInterface = function () {
    const type = Number($("dict-type-select").value), box = $("dict-result");
    try {
      const cipher = readCipher("dict", type), t = getTarget("dict", type, cipher);
      const wordlist = buildFullDictionary(type, $("dict-custom").value);          // setup, outside the timed search
      const cands = prepareCandidates(wordlist, TYPES[type].alphabet);
      const r = dictionaryAttackEnc(t.encIdx, cands, cipher);
      const preview = cands.words.slice(0, Math.min(r.tries, 20));
      const attemptRows = preview.map(function (word, index) {
        const status = r.found && index + 1 === r.tries ? "<span class='tag ok'>Match</span>" : "";
        return "<tr><td>" + (index + 1) + "</td><td class='mono'>" + esc(word) + "</td><td class='mono'>" + esc(cipher.encrypt(word).text) + "</td><td>" + status + "</td></tr>";
      });
      const detailsTitle = "Showing first " + preview.length + " of " + fmtBig(r.tries) + " attempted word" + (r.tries === 1 ? "" : "s") + " (dictionary: " + fmtBig(r.dictSize) + " words)";
      const ruleNote = t.validity && !t.validity.ok ? "Target note: " + esc(t.validity.reason) : "";
      box.innerHTML = "<div class='resultat doux'>" +
        (r.found ? "<span class='tag ok'>Found</span><br>Password found: <b>" + esc(r.password) + "</b><br>" : "<span class='tag'>Not found</span><br>") +
        targetLines(t, cipher) +
        "Attempts: " + fmtBig(r.tries) + "<br>Time taken: " + fmtMs(r.ms) + "<br>Dictionary size: " + fmtBig(r.dictSize) + " unique candidate(s)" +
        (cands.skipped ? "<br>" + cands.skipped + " candidate(s) skipped: they contain symbols that are not allowed in Type " + type : "") + "</div>" +
        (r.found ? weakAdvice(type) : "") +
        equivalenceNote(t, r.found ? r.password : null) +
        (ruleNote ? "<p class='petit'>" + ruleNote + "</p>" : "") +
        "<details><summary>" + detailsTitle + "</summary>" +
        table(["#", "Attempted word", "Encrypted word", "Status"], attemptRows) + "</details>";
    } catch (e) { showError(box, e.message); }
  };

  // ---------- Brute force attack interface ----------
  window.runBruteForceInterface = function () {
    const type = Number($("bf-type-select").value), box = $("bf-result");
    try {
      const cipher = readCipher("bf", type), t = getTarget("bf", type, cipher);
      const b = bruteForceEnc(t.encIdx, type, cipher, 2000, lenOf(type));
      const base = TYPES[type].alphabet.length;
      const len = t.plain !== null ? t.plain.length : (TYPES[type].length !== null ? TYPES[type].length : t.enc.length);
      const space = Math.pow(base, len);
      let status = b.found ? "<span class='tag ok'>Found</span><br>Password found: <b>" + esc(b.password) + "</b><br>"
        : b.timedOut ? "<span class='tag'>Stopped after 2 s</span><br>" : "<span class='tag'>Not found</span><br>No password of this type gives this encrypted value.<br>";
      let est = "";
      if (b.timedOut && b.ms > 0) est = "<br>Estimated time to try all " + fmtBig(space) + " combinations at " + fmtBig(Math.round(b.tries / (b.ms / 1000))) + " tries/s: <strong>" + fmtDuration(worstCase(base, len, b.tries / (b.ms / 1000))) + "</strong>";
      box.innerHTML = "<div class='resultat doux'>" + status + targetLines(t, cipher) +
        "Attempts: " + fmtBig(b.tries) + "<br>Time taken: " + fmtMs(b.ms) + "<br>Total number of combinations: " + fmtBig(space) + est + "</div>" +
        (b.found ? weakAdvice(type) : "") +
        equivalenceNote(t, b.found ? b.password : null) +
        (t.validity && !t.validity.ok ? "<p class='petit'>Target note: " + esc(t.validity.reason) + "</p>" : "");
    } catch (e) { showError(box, e.message); }
  };

  window.checkCommonPasswordDictionary = function () {
    const password = $("common-password-check").value;
    const box = $("common-password-check-result");
    if (!password) {
      box.className = "resultat erreur";
      box.textContent = "Enter a password to check.";
      return;
    }
    if (isInCommonPasswordDictionary(password)) {
      box.className = "resultat erreur";
      box.textContent = "This password appears in the demonstration dictionaries and may be vulnerable to dictionary attacks. Choose a stronger password.";
    } else {
      box.className = "resultat";
      box.textContent = "This password was not found in the demonstration dictionaries. This does not guarantee that it is secure.";
    }
  };

  // ===== PROTECTIONS (login attempt limits) =====
let bfAttempts = 0;
let bfLockoutUntil = 0;
let loginCountdown = null;
const BF_MAX_ATTEMPTS = 5;
const BF_LOCKOUT_TIME = 10000;

function showLoginLockout() {
  const resBox = $("bf-login-result");
  const button = $("login-demo-button");
  const remainingSec = Math.max(0, Math.ceil((bfLockoutUntil - Date.now()) / 1000));
  if (remainingSec === 0) {
    clearInterval(loginCountdown);
    loginCountdown = null;
    bfAttempts = 0;
    bfLockoutUntil = 0;
    button.disabled = false;
    resBox.className = "resultat";
    resBox.textContent = "Waiting period ended. You may try again; 5 attempts are available.";
    return;
  }
  button.disabled = true;
  resBox.className = "resultat erreur";
  resBox.textContent = "Temporarily blocked after too many failed attempts. Try again in " +
    remainingSec + " second(s).";
}

window.testLoginAttempt = function () {
  const inputPwd = $("bf-login-pwd").value;
  const targetPwd = $("login-demo-password").value;
  const resBox = $("bf-login-result");
  const now = Date.now();

  if (now < bfLockoutUntil) {
    showLoginLockout();
    return;
  }
  if (bfLockoutUntil) {
    clearInterval(loginCountdown);
    loginCountdown = null;
    bfLockoutUntil = 0;
    bfAttempts = 0;
  }
  if (!targetPwd) {
    resBox.className = "resultat erreur";
    resBox.textContent = "Set a demo account password before trying to log in.";
    return;
  }
  if (!inputPwd) {
    resBox.className = "resultat erreur";
    resBox.textContent = "Enter a password to try.";
    return;
  }

  if (inputPwd === targetPwd) {
    bfAttempts = 0;
    resBox.className = "resultat";
    resBox.textContent = "Login successful. The failed-attempt counter has been reset; 5 attempts are available.";
  } else {
    bfAttempts++;
    const attemptsLeft = BF_MAX_ATTEMPTS - bfAttempts;
    if (bfAttempts >= BF_MAX_ATTEMPTS) {
      bfLockoutUntil = now + BF_LOCKOUT_TIME;
      showLoginLockout();
      loginCountdown = setInterval(showLoginLockout, 250);
    } else {
      resBox.className = "resultat erreur";
      resBox.textContent = "Incorrect password. " + attemptsLeft + " attempt(s) remaining before the temporary delay.";
    }
  }
};

$("login-demo-password").addEventListener("input", function () {
  bfAttempts = 0;
  bfLockoutUntil = 0;
  if (loginCountdown !== null) {
    clearInterval(loginCountdown);
    loginCountdown = null;
  }
  $("login-demo-button").disabled = false;
  $("bf-login-result").textContent = "Demo account password changed; 5 attempts are available.";
  $("bf-login-result").className = "resultat";
});

let bruteProtectionAttempts = 0;
let bruteProtectionLockoutUntil = 0;
let bruteProtectionCountdown = null;
const BRUTE_PROTECTION_MAX_ATTEMPTS = 3;
const BRUTE_PROTECTION_LOCKOUT_TIME = 10000;

function updateBruteProtectionLockout() {
  const result = $("bf-protection-result");
  const button = $("bf-protection-button");
  const secondsLeft = Math.max(0, Math.ceil((bruteProtectionLockoutUntil - Date.now()) / 1000));
  if (secondsLeft === 0) {
    clearInterval(bruteProtectionCountdown);
    bruteProtectionCountdown = null;
    bruteProtectionAttempts = 0;
    bruteProtectionLockoutUntil = 0;
    button.disabled = false;
    result.className = "resultat";
    result.textContent = "The waiting period has ended. You may try again.";
    return;
  }
  button.disabled = true;
  result.className = "resultat erreur";
  result.textContent = "Temporarily blocked after too many failed attempts. Try again in " +
    secondsLeft + " second(s).";
}

window.testBruteForceProtection = function () {
  const target = $("bf-protection-target").value;
  const candidate = $("bf-protection-password").value;
  const result = $("bf-protection-result");
  const now = Date.now();

  if (now < bruteProtectionLockoutUntil) {
    updateBruteProtectionLockout();
    return;
  }
  if (!target) {
    result.className = "resultat erreur";
    result.textContent = "Set a demo account password before trying to log in.";
    return;
  }
  if (!candidate) {
    result.className = "resultat erreur";
    result.textContent = "Enter a password to try.";
    return;
  }

  if (candidate === target) {
    bruteProtectionAttempts = 0;
    result.className = "resultat";
    result.textContent = "Login successful. The failed-attempt counter has been reset.";
    return;
  }

  bruteProtectionAttempts++;
  const remaining = BRUTE_PROTECTION_MAX_ATTEMPTS - bruteProtectionAttempts;
  if (remaining === 0) {
    bruteProtectionLockoutUntil = now + BRUTE_PROTECTION_LOCKOUT_TIME;
    updateBruteProtectionLockout();
    bruteProtectionCountdown = setInterval(updateBruteProtectionLockout, 250);
    return;
  }
  result.className = "resultat erreur";
  result.textContent = "Incorrect password. " + remaining + " attempt(s) remaining before the temporary block.";
};

  // ---------- Start ----------
  renderCipherPanel("tests", 3, "tests-cipher");
  renderCipherPanel("dict", Number($("dict-type-select").value), "dict-cipher");
  renderCipherPanel("bf", Number($("bf-type-select").value), "bf-cipher");
  [1, 2, 3].forEach(function (t) { $("pwd" + t).addEventListener("input", function () { liveGen(t); }); });
  ["dict", "bf"].forEach(function (p) {
    $(p + "-target").addEventListener("input", function () { liveAttack(p); });
    $(p + "-form").addEventListener("change", function () { liveAttack(p); });
  });
  updateCombo3();
}
