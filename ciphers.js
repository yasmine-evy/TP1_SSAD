// ===== THE THREE CIPHERS (pure functions, no HTML here) =====
function mod26(x) { return ((x % 26) + 26) % 26; }
function gcd(a, b) { return b === 0 ? a : gcd(b, a % b); }
function inverseMod(x) { for (let i = 1; i < 26; i++) if (mod26(x * i) === 1) return i; return -1; }
// Layout: letters A-Za-z plus the other characters (spaces, punctuation) kept at their place.
// prefix[i] = non-letters written just before letter i ; suffix = non-letters after the last letter.
function parseLayout(t) {
  const prefix = [], letters = [];
  let cur = "";
  for (const ch of t) {
    if (/[A-Za-z]/.test(ch)) { letters.push(ch); prefix.push(cur); cur = ""; } else cur += ch;
  }
  return { letters: letters.join(""), prefix: prefix, suffix: cur };
}
// Rebuild a text from letters + prefixes (a prefix whose letter was removed is kept)
function composeLayout(letters, prefix, suffix) {
  let out = "";
  for (let i = 0; i < prefix.length; i++) out += prefix[i] + (i < letters.length ? letters[i] : "");
  return out + suffix;
}

// Case pattern of the letters of a text (true = uppercase), and re-applying it
function letterCases(t) { return t.replace(/[^A-Za-z]/g, "").split("").map(function (ch) { return ch === ch.toUpperCase(); }); }
function applyCases(s, ups) { return s.split("").map(function (ch, i) { return ups[i] === false ? ch.toLowerCase() : ch.toUpperCase(); }).join(""); }
function cleanLetters(t) { return t.toUpperCase().replace(/[^A-Z]/g, ""); }

// ---------- CAESAR (alphabet a-z then A-Z: 52 symbols) ----------
const CAESAR_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const N = CAESAR_ALPHABET.length;   // 52
function mod52(x) { return ((x % N) + N) % N; }
function removeSpaces(t) { return t.replace(/\s+/g, ""); }

function checkCaesarKey(raw) {
  const k = Number(raw);
  if (String(raw).trim() === "" || !Number.isInteger(k)) throw new Error("Caesar: the key must be an integer.");
  const r = mod52(k);
  if (r === 0) throw new Error("Caesar: key " + k + " refused. Shifting by 0 or " + N + " (a full turn of the alphabet) leaves the text unchanged. Choose a key from 1 to " + (N - 1) + ".");
  return { shift: r, note: r !== k ? "Key " + k + " reduced to " + r + " (modulo " + N + ")." : "" };
}

function caesar(text, shift, direction, mode) {
  let eff = direction === "left" ? -shift : shift;
  if (mode === "decrypt") eff = -eff;
  let out = "";
  for (const ch of text) {
    const i = CAESAR_ALPHABET.indexOf(ch);
    out += i === -1 ? ch : CAESAR_ALPHABET[mod52(i + eff)];   // z → A, Z → a
  }
  return out;
}

function runCaesar(raw, p, mode) {
  const msg = raw;                               // spaces and punctuation are kept as they are
  if (!/[A-Za-z]/.test(msg)) throw new Error("Please enter a message containing letters.");
  const key = checkCaesarKey(p.key);
  const notes = [];
  if (key.note) notes.push(key.note);
  return { text: caesar(msg, key.shift, p.direction, mode), info: notes.join("\n"), shift: key.shift };
}

// ---------- HILL 2x2 ----------
function detInfo(k) {
  const raw = k[0] * k[3] - k[1] * k[2];
  const norm = mod26(raw), g = gcd(norm, 26);
  return { raw: raw, norm: norm, gcd: g, ok: g === 1, inv: g === 1 ? inverseMod(norm) : -1 };
}
function detText(k) {
  const di = detInfo(k);
  let t = "Determinant = a·d − b·c = " + k[0] + "×" + k[3] + " − " + k[1] + "×" + k[2] + " = " + di.raw;
  if (di.raw !== di.norm) t += "\n" + (di.raw < 0 ? "It is negative: " : "It is above 25: ") + "brought back to 0…25 → " + di.norm + " (mod 26)";
  t += "\ngcd(" + di.norm + ", 26) = " + di.gcd + (di.ok ? " → the key is valid" : " → key NOT valid (it must be 1)");
  if (di.ok) t += "\nInverse of " + di.norm + " modulo 26 = " + di.inv;
  return t;
}

function runHill(raw, k, mode) {
  const [a, b, c, d] = k;
  const di = detInfo(k);
  if (!di.ok) throw new Error("Hill: matrix not invertible modulo 26.\n" + detText(k) + "\nChoose another matrix.");
  let m = mode === "decrypt" ? [d * di.inv, -b * di.inv, -c * di.inv, a * di.inv] : [a, b, c, d];
  m = m.map(mod26);

  const lay = parseLayout(raw);
  const original = cleanLetters(raw);
  const ups = letterCases(raw);                 // case of each letter, kept in the result
  const prefix = lay.prefix.slice();            // spaces/punctuation, kept at their place
  let t = original;
  if (!t) throw new Error("Hill: write a message containing letters.");
  const notes = [detText(k)];
  if (mode === "encrypt") {
    if (t.length % 2 === 1) { t += "X"; ups.push(ups[ups.length - 1]); prefix.push(""); notes.push("Odd number of letters: an X was added before encryption."); }
    else if (original.endsWith("X")) notes.push("⚠ Even number of letters ending with X: that X will be removed when decrypting. Add one more letter to avoid it.");
  } else if (t.length % 2 === 1) {
    throw new Error("Hill: the encrypted message must have an even number of letters (it has " + t.length + "). Hill always produces an even length, so this text was probably not encrypted with Hill: check that the same algorithm was used for encryption.");
  }
  let out = "";
  for (let i = 0; i < t.length; i += 2) {
    const x = t.charCodeAt(i) - 65, y = t.charCodeAt(i + 1) - 65;
    out += String.fromCharCode(65 + mod26(m[0] * x + m[1] * y));
    out += String.fromCharCode(65 + mod26(m[2] * x + m[3] * y));
  }
  if (mode === "decrypt" && out.endsWith("X")) { out = out.slice(0, -1); notes.push("The final X (padding) was removed."); }
  out = applyCases(out, ups);
  return { text: composeLayout(out, prefix, lay.suffix), info: notes.join("\n") };
}

// ---------- PLAYFAIR ----------
function cleanPlayfair(t) { return cleanLetters(t).replace(/J/g, "I"); }

function buildTable(key) {
  const all = cleanPlayfair(key) + "ABCDEFGHIKLMNOPQRSTUVWXYZ";
  let table = "";
  for (const c of all) if (table.indexOf(c) === -1) table += c;
  return table;
}

// pairs = [letters, [case1, case2], [src1, src2]] ; src = index of the source letter (-1 for padding)
function makePairs(text, pad, ups) {
  const pairs = [];
  let i = 0;
  while (i < text.length) {
    const first = text[i], second = i + 1 < text.length ? text[i + 1] : "";
    if (second === "" || first === second) { pairs.push([first + pad, [ups[i], ups[i]], [i, -1]]); i += 1; }
    else { pairs.push([first + second, [ups[i], ups[i + 1]], [i, i + 1]]); i += 2; }
  }
  return pairs;
}

function playfairPair(pair, table, dir) {
  const p1 = table.indexOf(pair[0]), p2 = table.indexOf(pair[1]);
  let r1 = Math.floor(p1 / 5), c1 = p1 % 5, r2 = Math.floor(p2 / 5), c2 = p2 % 5;
  if (r1 === r2) { c1 = (c1 + dir + 5) % 5; c2 = (c2 + dir + 5) % 5; }
  else if (c1 === c2) { r1 = (r1 + dir + 5) % 5; r2 = (r2 + dir + 5) % 5; }
  else { const t = c1; c1 = c2; c2 = t; }
  return table[r1 * 5 + c1] + table[r2 * 5 + c2];
}

// dec = [[letters, [cases]], ...] ; returns, for each decrypted letter, whether it is a padding letter to drop
function paddingFlags(dec, pad) {
  const drop = [];
  for (let i = 0; i < dec.length; i++) {
    const f = dec[i][0][0], s = dec[i][0][1];
    drop.push(false);
    drop.push(s === pad && (i === dec.length - 1 || dec[i + 1][0][0] === f));
  }
  return drop;
}

function runPlayfair(raw, p, mode) {
  const key = cleanPlayfair(p.key), pad = cleanPlayfair(p.pad).slice(0, 1);
  let text = cleanPlayfair(raw);
  if (!key) throw new Error("Playfair: please enter a key with at least one letter.");
  if (!pad) throw new Error("Playfair: please enter one letter as the padding letter.");
  if (!text) throw new Error("Playfair: please enter a text with at least one letter.");
  const table = buildTable(key);
  const lay = parseLayout(raw);
  const ups = letterCases(raw);
  let out;
  const notes = [];
  if (mode === "encrypt") {
    const pairs = makePairs(text, pad, ups);
    const letters = [], prefix = [];
    pairs.forEach(function (q) {
      const enc = applyCases(playfairPair(q[0], table, 1), q[1]);
      for (let s = 0; s < 2; s++) { letters.push(enc[s]); prefix.push(q[2][s] >= 0 ? lay.prefix[q[2][s]] : ""); }
    });
    out = composeLayout(letters.join(""), prefix, lay.suffix);
  } else {
    if (text.length % 2 === 1) throw new Error("Playfair: the encrypted text must have an even number of letters.");
    const dec = text.match(/../g).map(function (q, i) {
      return [playfairPair(q, table, -1), [ups[2 * i], ups[2 * i + 1]]];
    });
    const flat = [], flags = p.removePad ? paddingFlags(dec, pad) : [];
    dec.forEach(function (d) { flat.push(applyCases(d[0][0], [d[1][0]]), applyCases(d[0][1], [d[1][1]])); });
    const letters = [], prefix = [];
    let carry = "";
    flat.forEach(function (ch, i) {
      if (flags[i]) { carry += lay.prefix[i]; return; }
      letters.push(ch); prefix.push(carry + lay.prefix[i]); carry = "";
    });
    out = composeLayout(letters.join(""), prefix, carry + lay.suffix);
    if (p.removePad) notes.push("Padding letters (" + pad + ") removed.");
  }
  return { text: out, info: notes.join("\n"), table: table, key: key, pad: pad };
}

// ---------- SPACES: hidden in the ciphertext, restored at decryption ----------
// Before encryption each space becomes the two letters "Qs" (Q = escape letter); a real q / Q is written "Qq" / "QQ".
// After encryption the spaces have disappeared; after decryption "Qs" turns back into a space.
function encodeSpaces(t) {
  let out = "";
  for (const ch of t) out += ch === " " ? "Qs" : (ch === "q" ? "Qq" : (ch === "Q" ? "QQ" : ch));
  return out;
}
function decodeSpaces(t) {
  let out = "";
  for (let i = 0; i < t.length; i++) {
    if (t[i] === "Q" && i + 1 < t.length) {
      const n = t[i + 1];
      if (n === "s") { out += " "; i++; continue; }
      if (n === "q") { out += "q"; i++; continue; }
      if (n === "Q") { out += "Q"; i++; continue; }
    }
    out += t[i];
  }
  return out;
}

// One entry point for the page
function runCipher(algo, raw, params, mode) {
  const f = algo === "caesar" ? runCaesar : algo === "hill" ? runHill : runPlayfair;
  if (mode === "encrypt") {
    if (!raw.replace(/\s/g, "")) throw new Error("Please enter a message.");
    const r = f(encodeSpaces(raw), params, "encrypt");
    const had = (raw.match(/ /g) || []).length;
    if (had) r.info = (r.info ? r.info + "\n" : "") + had + " space(s) hidden in the encrypted text (restored at decryption).";
    return r;
  }
  const r = f(raw, params, "decrypt");
  r.text = decodeSpaces(r.text);
  return r;
}

if (typeof module !== "undefined") module.exports = { runCipher, runCaesar, runHill, runPlayfair };
