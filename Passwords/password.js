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
  let reason = "Valid Type " + type + " Password: " + pwd.length + " character(s), all from " + t.label + ".";
  return { ok: true, reason: reason, fix: "" };
}

function analyzePassword(pw) {
  const password = pw === null || typeof pw === "undefined" ? "" : String(pw);
  const length = Array.from(password).length;
  const lower = /[a-z]/.test(password);
  const upper = /[A-Z]/.test(password);
  const digits = /\d/.test(password);
  const symbols = /[*+]/.test(password);
  const classes = [lower, upper, digits, symbols].filter(Boolean).length;
  const charsetSize = (lower ? 26 : 0) + (upper ? 26 : 0) + (digits ? 10 : 0) + (symbols ? 2 : 0);

  // Estimate entropy using the sum of character classes actually present in the password.
  const entropyBits = length > 0 && charsetSize > 0 ? length * Math.log2(charsetSize) : 0;
  const checks = {
    length: length >= 8,
    lowercase: length > 0 && lower,
    uppercase: length > 0 && upper,
    digits: length > 0 && digits,
    symbols: length > 0 && symbols
  };

  let level = "Weak";
  if (length === 0) level = "idle";
  else if (entropyBits >= 40 && entropyBits <= 60) level = "Medium";
  else if (entropyBits > 60 && length >= 12 && classes >= 3) level = "Strong";
  else if (entropyBits > 60) level = "Medium";

  return {
    level: level,
    score: Math.round(entropyBits * 10) / 10,
    entropyBits: entropyBits,
    checks: checks,
    length: length,
    charsetSize: charsetSize
  };
}

[
  ["123", "Weak"],
  ["password", "Weak"],
  ["Hello2024", "Medium"],
  ["Tr0ub4dor&3", "Medium"],
  ["k9#Vm2!xQp7$Lw", "Strong"]
].forEach(function (test) {
  console.assert(analyzePassword(test[0]).level === test[1], "Password-strength self-test failed.");
});

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
function dictionaryAttackFull(target, wordlist, encryptCandidate) {
  const transform = encryptCandidate || function (candidate) { return candidate; };
  const t0 = performance.now();
  for (let i = 0; i < wordlist.length; i++) {
    if (transform(wordlist[i]) === target) {
      return { found: true, password: wordlist[i], tries: i + 1, ms: performance.now() - t0, dictSize: wordlist.length };
    }
  }
  return { found: false, password: null, tries: wordlist.length, ms: performance.now() - t0, dictSize: wordlist.length };
}

// ---------- ATTACK 2: brute force (minimal work) ----------
// Types 1 and 2 have fixed lengths; Type 3 uses the target's visible length for this demonstration.
// An "odometer" counter avoids building strings when no cipher transform is needed.
function bruteForce(target, type, budgetMs, encryptCandidate, candidateLength) {
  const t = TYPES[type], A = t.alphabet, base = A.length;
  const tgt = Array.from(target).map(function (c) { return A.indexOf(c); });
  const minLen = t.length !== null ? t.length : (candidateLength || 1);
  const maxLen = t.length !== null ? t.length : (candidateLength || 32);
  const hasTransform = typeof encryptCandidate === "function";
  const t0 = performance.now();
  let tries = 0;
  for (let L = minLen; L <= maxLen; L++) {
    const idx = new Array(L).fill(0);
    for (;;) {
      tries++;
      if (hasTransform) {
        const candidate = idx.map(function (index) { return A[index]; }).join("");
        if (encryptCandidate(candidate) === target)
          return { found: true, password: candidate, tries: tries, ms: performance.now() - t0, timedOut: false };
      } else if (L === tgt.length) {
        let same = true;
        for (let i = 0; i < L; i++) if (idx[i] !== tgt[i]) { same = false; break; }
        if (same) return { found: true, password: target, tries: tries, ms: performance.now() - t0, timedOut: false };
      }
      let p = L - 1;
      while (p >= 0 && ++idx[p] === base) { idx[p] = 0; p--; }
      if (p < 0) break;                                         // all candidates of this length done
      const timeCheckMask = hasTransform ? 0xFF : 0xFFFF;
      if ((tries & timeCheckMask) === 0 && performance.now() - t0 > budgetMs)
        return { found: false, tries: tries, ms: performance.now() - t0, timedOut: true };
    }
  }
  return { found: false, tries: tries, ms: performance.now() - t0, timedOut: false };
}

// Worst-case time to exhaust the space of length L at `rate` tries per second
function worstCase(base, L, rate) { return Math.pow(base, L) / rate; }

if (typeof module !== "undefined") {
  module.exports = { TYPES, checkPwd, analyzePassword, isCommonPassword, isInCommonPasswordDictionary, dictionaryAttack, buildFullDictionary, dictionaryAttackFull, bruteForce, fmtDuration, worstCase, randomPassword };
}

// ===== USER INTERFACE (browser only) =====
if (typeof document !== "undefined") {
  const $ = function (id) { return document.getElementById(id); };
  const render = function (result) {
    const level = $("pwc-level");
    const bar = $("pwc-bar");
    const track = $("pwc-track");
    const levelClass = result.level === "idle" ? "idle" : result.level.toLowerCase();
    const percent = result.level === "Strong" ? 100 : result.level === "Medium" ? 66 : result.level === "Weak" ? 33 : 0;
    level.textContent = result.level === "idle" ? "Start typing..." : result.level;
    level.className = "pwc-level pwc-level-" + levelClass;
    bar.style.width = percent + "%";
    bar.className = "pwc-bar pwc-bar-" + levelClass;
    track.setAttribute("aria-valuenow", String(percent));
    $("pwc-score").textContent = result.length
      ? "Estimated entropy: " + result.score + " bits"
      : "Estimated entropy: —";

    Object.keys(result.checks).forEach(function (name) {
      const item = $("pwc-check-" + name.replace(/[A-Z]/g, function (letter) { return "-" + letter.toLowerCase(); }));
      const icon = $("pwc-icon-" + name.replace(/[A-Z]/g, function (letter) { return "-" + letter.toLowerCase(); }));
      const passed = result.checks[name];
      item.className = "pwc-check " + (passed ? "pwc-check-passed" : "pwc-check-failed");
      icon.textContent = passed ? "✓" : "✗";
      icon.setAttribute("aria-label", passed ? "Passed" : "Not met");
    });

  };
  const strengthInput = $("pwc-input");
  strengthInput.addEventListener("input", function () {
    const filteredPassword = strengthInput.value.replace(/[^A-Za-z0-9+*]/g, "");
    if (filteredPassword !== strengthInput.value) strengthInput.value = filteredPassword;
    render(analyzePassword(strengthInput.value));
  });
  render(analyzePassword(""));
  const esc = function (s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;"); };
  const table = function (head, rows) {
    return "<div class='table-wrap' style='max-height:none'><table class='t'><thead><tr>" + head.map(function (h) { return "<th>" + h + "</th>"; }).join("") +
      "</tr></thead><tbody>" + rows.join("") + "</tbody></table></div>";
  };
  const randomFor = function (type) {
    const t = TYPES[type];
    return randomPassword(t.alphabet, t.length !== null ? t.length : Math.max(1, Math.min(32, parseInt($("len3").value) || 8)));
  };
  const type3LengthError = function () {
    const length = $("len3").value;
    if (length === "") return "Length field is empty — Enter a length > 0.";
    if (Number(length) === 0) return "Length is equal to 0 — Enter a length > 0.";
    return "";
  };
  const showType3LengthError = function (message) {
    const result = $("res3");
    result.textContent = message;
    result.className = "resultat erreur";
  };

  // ---------- G1: generator ----------
  window.genPwd = function (type) {
    if (type === 3) {
      const lengthError = type3LengthError();
      if (lengthError) {
        showType3LengthError(lengthError);
        return;
      }
    }
    $("pwd" + type).value = randomFor(type);
    window.checkInput(type);
  };
  window.checkInput = function (type) {
    const password = $("pwd" + type).value;
    if (type === 3) {
      if (password.length > 0) {
        $("len3").value = String(password.length);
        window.updateCombo3();
      }
      const lengthError = type3LengthError();
      if (lengthError) {
        showType3LengthError(lengthError);
        return;
      }
    }
    const r = checkPwd(password, type);
    const res = $("res" + type);
    res.style.whiteSpace = "pre-line";
    if (!r.ok) {
      if (password.length === 0) {
        res.textContent = "No Password to check — Type in your password or Generate one.";
      } else {
        res.textContent = "✘ REFUSED — " + r.reason + "\nWhat to do: " + r.fix;
      }
      res.className = "resultat erreur";
    } else {
      res.textContent = "✔ ACCEPTED — " + r.reason;
      res.className = "resultat";
    }
    res.style.letterSpacing = "0"; res.style.fontSize = ".95rem"; res.style.fontFamily = "inherit";
  };
  window.sanitizeLength3 = function () {
    $("len3").value = $("len3").value.replace(/\D/g, "");
  };
  window.updateCombo3 = function () {
    const rawLength = $("len3").value;
    if (rawLength === "" || Number(rawLength) === 0) {
      $("combo3").textContent = "64 characters";
      return;
    }
    const len = Math.min(32, Number(rawLength));
    const txt = "64^" + len + " ≈ " + Math.pow(64, len).toExponential(2);
    $("combo3").textContent = "64 characters — length " + len + " → " + txt + " combinations";
  };

  const passwordCipherAlphabet = T3.join("");
  const readPasswordCipherKey = function (algo) {
    if (algo === "caesar") {
      const raw = $("password-cipher-shift").value.trim();
      const shift = Number(raw);
      if (!raw || !Number.isSafeInteger(shift) || shift < 1 || shift >= passwordCipherAlphabet.length)
        throw new Error("Caesar key must be an integer from 1 to 63.");
      return { key: shift, direction: $("password-cipher-direction").value };
    }
    if (algo === "hill") {
      return ["a", "b", "c", "d"].map(function (letter) {
        const raw = $("password-hill-" + letter).value.trim();
        const value = Number(raw);
        if (!raw || !Number.isSafeInteger(value)) throw new Error("Hill key must contain four integers.");
        return value;
      });
    }
    const key = $("password-playfair-key").value;
    if (!key || Array.from(key).some(function (character) { return passwordCipherAlphabet.indexOf(character) === -1; }))
      throw new Error("Playfair secret key must contain at least one character from a-z, A-Z, 0-9, + or *.");
    return { key: key, removePad: true };
  };
  const createAttackCipherContext = function (target) {
    const algo = $("password-cipher-choice").value;
    const key = readPasswordCipherKey(algo);
    const targetCiphertext = runCipher(algo, target, key, "encrypt", passwordCipherAlphabet).text;
    return {
      algorithm: algo,
      targetCiphertext: targetCiphertext,
      encryptCandidate: function (candidate) {
        return runCipher(algo, candidate, key, "encrypt", passwordCipherAlphabet).text;
      }
    };
  };
  window.clearAttackResults = function () {
    ["dict-result", "bf-result"].forEach(function (id) {
      $(id).innerHTML = "";
    });
  };
  window.updateAttackCipherFields = function () {
    const algo = $("password-cipher-choice").value;
    $("password-cipher-caesar").hidden = algo !== "caesar";
    $("password-cipher-hill").hidden = algo !== "hill";
    $("password-cipher-playfair").hidden = algo !== "playfair";
    window.clearAttackResults();
  };
  window.updateAttackCipherFields();

  const selectedAttackTypes = { dictionary: 1, bruteForce: 1 };
  const attackTargets = { dictionary: "dict-target", bruteForce: "bf-target" };
  const attackTypeSelectors = { dictionary: "dict-type-select", bruteForce: "bf-type-select" };
  const attackResults = { dictionary: "dict-result", bruteForce: "bf-result" };
  const invalidAttackTargetMessage = "This password does not meet the requirements for the selected type. Enter another password or use one of the three buttons to send a generated password.";
  window.selectAttackType = function (attack, value) {
    if (!Object.prototype.hasOwnProperty.call(attackTypeSelectors, attack)) {
      throw new Error("Unknown attack interface: " + attack);
    }
    selectedAttackTypes[attack] = Number(value);
    $(attackResults[attack]).innerHTML = "";
  };
  for (const attack of Object.keys(attackTargets)) {
    $(attackTargets[attack]).addEventListener("input", function () {
      $(attackResults[attack]).innerHTML = "";
    });
  }
  window.useGeneratedAttackPassword = function (attack, type) {
    if (!Object.prototype.hasOwnProperty.call(attackTargets, attack)) {
      throw new Error("Unknown attack interface: " + attack);
    }
    const password = $("pwd" + type).value;
    const result = checkPwd(password, type);
    const box = $(attackResults[attack]);
    selectedAttackTypes[attack] = type;
    $(attackTypeSelectors[attack]).value = String(type);
    if (!result.ok) {
      $(attackTargets[attack]).value = "";
      box.innerHTML = "";
      window.checkInput(type);
      $("pwd" + type).scrollIntoView({ behavior: "smooth", block: "center" });
      return;
    }
    $(attackTargets[attack]).value = password;
    box.innerHTML = "";
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

  // Encrypts the target and each candidate with the selected cipher before comparing ciphertexts.
  window.runDictionaryInterface = function () {
    const target = $("dict-target").value;
    const type = selectedAttackTypes.dictionary;
    const custom = $("dict-custom").value;
    const box = $("dict-result");
    if (type === null) {
      box.innerHTML = "<div class='resultat erreur'>Select a password type, then enter a valid password or use one of the three buttons to send a generated password.</div>";
      return;
    }
    if (!checkPwd(target, type).ok) {
      box.innerHTML = "<div class='resultat erreur'>" + invalidAttackTargetMessage + "</div>";
      return;
    }

    try {
      const context = createAttackCipherContext(target);
      const wordlist = buildFullDictionary(type, custom).filter(function (candidate) {
        return checkPwd(candidate, type).ok;
      });
      const r = dictionaryAttackFull(context.targetCiphertext, wordlist, context.encryptCandidate);
      const preview = wordlist.slice(0, Math.min(r.tries, 20));
      const attemptRows = preview.map(function (word, index) {
        const status = r.found && index + 1 === r.tries ? "<span class='tag ok'>Match</span>" : "";
        return "<tr><td>" + (index + 1) + "</td><td class='mono'>" + esc(word) + "</td><td>" + status + "</td></tr>";
      });
      const shown = preview.length;
      const detailsTitle = "Showing first " + shown + " of " + fmtBig(r.tries) + " attempted word" + (r.tries === 1 ? "" : "s") + " (dictionary: " + fmtBig(r.dictSize) + " valid words)";
      box.innerHTML = "<div class='resultat'>" +
        (r.found ? "<span class='tag ok'>Found</span><br>" : "<span class='tag'>Not found</span><br>") +
        "Algorithm: <b>" + esc(context.algorithm) + "</b><br>" +
        "Original password: <b>" + esc(target) + "</b><br>" +
        "Encrypted password (the value the attacker has): <b>" + esc(context.targetCiphertext) + "</b><br>" +
        "Attempts: " + fmtBig(r.tries) + "<br>Time taken: " + fmtMs(r.ms) + "<br>Dictionary size: " + fmtBig(r.dictSize) + " valid candidate(s)</div>" +
        "<details><summary>" + detailsTitle + "</summary>" +
        table(["#", "Attempted word", "Status"], attemptRows) + "</details>";
    } catch (error) {
      box.innerHTML = "<div class='resultat erreur'>" + esc(error.message) + "</div>";
    }
  };

  //  BRUTE FORCE & PROTECTIONS =====

// Encrypts every generated candidate with the selected cipher before comparing it with the encrypted target.
window.runBruteForceInterface = function () {
  const target = $("bf-target").value;
  const type = selectedAttackTypes.bruteForce;
  const box = $("bf-result");

  if (type === null) {
    box.innerHTML = "<div class='resultat erreur'>Select a password type, then enter a valid password or use one of the three buttons to send a generated password.</div>";
    return;
  }
  if (!checkPwd(target, type).ok) {
    box.innerHTML = "<div class='resultat erreur'>" + invalidAttackTargetMessage + "</div>";
    return;
  }

  try {
    const context = createAttackCipherContext(target);
    const b = bruteForce(context.targetCiphertext, type, 2000, context.encryptCandidate, target.length);
    const space = Math.pow(TYPES[type].alphabet.length, target.length);

    box.innerHTML = "<div class='resultat'>" +
      (b.found ? "<span class='tag ok'>Found!</span><br>" : "<span class='tag'>Not found</span><br>") +
      "Algorithm: <b>" + esc(context.algorithm) + "</b><br>" +
      "Original password: <b>" + esc(target) + "</b><br>" +
      "Encrypted password (the value the attacker has): <b>" + esc(context.targetCiphertext) + "</b><br>" +
      "Attempts: " + fmtBig(b.tries) + "<br>" +
      "Execution time: " + fmtMs(b.ms) + "<br>" +
      "Total combination space: " + fmtBig(space) +
      (b.timedOut ? "<br>Time limit reached; search stopped." : "") + "</div>";
  } catch (error) {
    box.innerHTML = "<div class='resultat erreur'>" + esc(error.message) + "</div>";
  }
};

let bfAttempts = 0;
let bfLockoutUntil = 0;
let loginCountdown = null;
const BF_MAX_ATTEMPTS = 5;
let bfLockoutTime = 10000;

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
      bfLockoutUntil = now + bfLockoutTime;
      bfLockoutTime += 5000;
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
  $("bf-login-result").textContent = "";
  $("bf-login-result").className = "resultat";
});

let bruteProtectionAttempts = 0;
let bruteProtectionLockoutUntil = 0;
let bruteProtectionCountdown = null;
const BRUTE_PROTECTION_MAX_ATTEMPTS = 3;
let bruteProtectionLockoutTime = 10000;

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
    bruteProtectionLockoutUntil = now + bruteProtectionLockoutTime;
    bruteProtectionLockoutTime += 5000;
    updateBruteProtectionLockout();
    bruteProtectionCountdown = setInterval(updateBruteProtectionLockout, 250);
    return;
  }
  result.className = "resultat erreur";
  result.textContent = "Incorrect password. " + remaining + " attempt(s) remaining before the temporary block.";
};

  updateCombo3();

  updateCombo3();
}