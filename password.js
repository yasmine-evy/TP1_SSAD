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

// ---------- PART 3: full dictionary attack ----------
// Minimal-time rules: build the list before timing, compare strings directly, and stop at the first match.

// Builds one ordered, duplicate-free candidate list from every built-in and user-supplied word.
function buildFullDictionary(type, customText) {
  const base = TYPES[type].dict.slice();
  const extra = String(customText || "").split(/\r?\n/)
    .map(function (word) { return word.trim(); })
    .filter(function (word) { return word.length > 0; });
  return Array.from(new Set(base.concat(extra)));
}

// Searches an already-built word list, measuring only the search loop and exiting as soon as it finds a match.
function dictionaryAttackFull(target, wordlist) {
  const t0 = performance.now();
  for (let i = 0; i < wordlist.length; i++) {
    if (wordlist[i] === target) {
      return { found: true, password: wordlist[i], tries: i + 1, ms: performance.now() - t0, dictSize: wordlist.length };
    }
  }
  return { found: false, password: null, tries: wordlist.length, ms: performance.now() - t0, dictSize: wordlist.length };
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

// Converts text to a hexadecimal SHA-256 hash for the protection demonstration.
async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest)).map(function (byte) { return byte.toString(16).padStart(2, "0"); }).join("");
}

// Creates a cryptographically random salt so the same password does not always have the same stored hash.
function generateSalt() {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(function (byte) { return byte.toString(16).padStart(2, "0"); }).join("");
}

// Returns the salt and salted hash that would be stored instead of a plain password.
async function protectPassword(password) {
  const salt = generateSalt();
  const hash = await sha256Hex(password + salt);
  return { salt: salt, hash: hash };
}

// Worst-case time to exhaust the space of length L at `rate` tries per second
function worstCase(base, L, rate) { return Math.pow(base, L) / rate; }

if (typeof module !== "undefined") {
  module.exports = { TYPES, checkPwd, dictionaryAttack, buildFullDictionary, dictionaryAttackFull, bruteForce, fmtDuration, worstCase, randomPassword, sha256Hex, generateSalt, protectPassword };
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

  // Generates a target for the selected type and resets the state of the two demonstrations.
  window.generateDictionaryTarget = function () {
    const type = Number($("dict-type-select").value);
    $("dict-target").value = randomFor(type);
    $("dict-result").innerHTML = "";
    $("dict-protection-result").className = "resultat";
    $("dict-protection-result").innerHTML = "";
  };

  // Builds the list once, then runs the fast dictionary search and displays the outcome and first attempts.
  window.runDictionaryInterface = function () {
    const type = Number($("dict-type-select").value);
    const target = $("dict-target").value;
    const custom = $("dict-custom").value;
    const box = $("dict-result");
    if (!target) {
      box.innerHTML = "<div class='resultat erreur'>Enter or generate a target password first.</div>";
      return;
    }

    const wordlist = buildFullDictionary(type, custom); // This setup is deliberately outside the timed search.
    const validity = checkPwd(target, type);
    const r = dictionaryAttackFull(target, wordlist);
    const preview = wordlist.slice(0, Math.min(r.tries, 20));
    const attemptRows = preview.map(function (word, index) {
      const status = r.found && index + 1 === r.tries ? "<span class='tag ok'>Match</span>" : "";
      return "<tr><td>" + (index + 1) + "</td><td class='mono'>" + esc(word) + "</td><td>" + status + "</td></tr>";
    });
    const shown = preview.length;
    const detailsTitle = "Showing first " + shown + " of " + fmtBig(r.tries) + " attempted word" + (r.tries === 1 ? "" : "s") + " (dictionary: " + fmtBig(r.dictSize) + " words)";
    const ruleNote = validity.ok
      ? "The target matches the selected Type " + type + " rules."
      : "Target note: " + esc(validity.reason);

    box.innerHTML = "<div class='resultat'>" +
      (r.found ? "<span class='tag ok'>Found</span><br>Password found: <b>" + esc(r.password) + "</b><br>" : "<span class='tag'>Not found</span><br>") +
      "Attempts: " + fmtBig(r.tries) + "<br>Time taken: " + fmtMs(r.ms) + "<br>Dictionary size: " + fmtBig(r.dictSize) + " unique candidate(s)</div>" +
      "<p class='petit'>" + ruleNote + "</p>" +
      "<details><summary>" + detailsTitle + "</summary>" +
      table(["#", "Attempted word", "Status"], attemptRows) + "</details>";
  };

  // Hashes the current target with a new random salt and displays only values suitable for storage.
  window.protectDictionaryPassword = async function () {
    const password = $("dict-target").value;
    const box = $("dict-protection-result");
    if (!password) {
      box.className = "resultat erreur";
      box.textContent = "Enter or generate a target password first.";
      return;
    }
    try {
      const protectedValue = await protectPassword(password);
      box.className = "resultat";
      box.innerHTML = "<b>Stored values (not the password)</b><br>Salt: " + esc(protectedValue.salt) + "<br>SHA-256 hash: " + esc(protectedValue.hash);
    } catch (error) {
      box.className = "resultat erreur";
      box.textContent = "This browser could not create a SHA-256 hash: " + error.message;
    }
  };
  //  BRUTE FORCE & PROTECTIONS =====

// 2. Interface pour exécuter le Brute Force optimisé
window.runBruteForceInterface = function () {
  const type = Number($("bf-type-select").value);
  const target = $("bf-target").value;
  const box = $("bf-result");

  if (!target) {
    box.innerHTML = "<div class='resultat erreur'>Veuillez d'abord entrer ou générer un mot de passe cible.</div>";
    return;
  }

  const validity = checkPwd(target, type);
  // Appel de la fonction bruteForce existante dans password.js (budget de 2000ms max)
  const b = bruteForce(target, type, 2000);
  const space = Math.pow(TYPES[type].alphabet.length, target.length);

  box.innerHTML = "<div class='resultat'>" +
    (b.found ? "<span class='tag ok'>Trouvé !</span><br>Mot de passe trouvé : <b>" + esc(target) + "</b><br>" : "<span class='tag'>Délai dépassé / Non trouvé</span><br>") +
    "Essais réalisés : " + fmtBig(b.tries) + "<br>" +
    "Temps d'exécution : " + fmtMs(b.ms) + "<br>" +
    "Espace total des combinaisons : " + fmtBig(space) + "</div>";
};

// 3. Logique de protection (Tentatives, Throttling, Blocage)
let bfAttempts = 0;
let bfLockoutUntil = 0;
const BF_MAX_ATTEMPTS = 3;
const BF_LOCKOUT_TIME = 10000; // 10 secondes de blocage

window.testLoginAttempt = function () {
  const inputPwd = $("bf-login-pwd").value;
  const targetPwd = $("bf-target").value || "101"; // Mot de passe par défaut si vide
  const resBox = $("bf-login-result");
  const now = Date.now();

  // Vérifier le blocage temporaire (Lockout)
  if (now < bfLockoutUntil) {
    const remainingSec = Math.ceil((bfLockoutUntil - now) / 1000);
    resBox.className = "resultat erreur";
    resBox.textContent = `Accès bloqué suite à trop d'échecs. Réessayez dans ${remainingSec} seconde(s).`;
    return;
  }

  // Vérification du mot de passe
  if (inputPwd === targetPwd) {
    bfAttempts = 0; // Remise à zéro en cas de succès
    resBox.className = "resultat";
    resBox.innerHTML = "<span class='tag ok'>Succès</span> Connexion autorisée. Compteur de tentatives réinitialisé.";
  } else {
    bfAttempts++;
    const attemptsLeft = BF_MAX_ATTEMPTS - bfAttempts;
    
    if (bfAttempts >= BF_MAX_ATTEMPTS) {
      bfLockoutUntil = Date.now() + BF_LOCKOUT_TIME;
      bfAttempts = 0;
      resBox.className = "resultat erreur";
      resBox.textContent = `Trop de tentatives incorrectes (${BF_MAX_ATTEMPTS}/${BF_MAX_ATTEMPTS}). Compte bloqué pendant 10 secondes !`;
    } else {
      resBox.className = "resultat erreur";
      resBox.textContent = `Mot de passe incorrect. Tentatives restantes avant blocage : ${attemptsLeft}`;
    }
  }
};

  updateCombo3();
}
