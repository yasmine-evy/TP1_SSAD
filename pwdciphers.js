// ===== CAESAR / HILL / PLAYFAIR FOR THE PASSWORD ATTACKS =====
// Caesar works exactly like in the "Encrypt / Decrypt a message" page: alphabets a-z and A-Z (26 letters each),
// key 1 to 25, shift left or right. A key of 26 (or 0) is refused: the text would not be encrypted.
// Digits, "+" and "*" are not letters: Caesar leaves them as they are.
// Hill and Playfair work on the symbols of the alphabet of the password type (modulo 2, 4 or 64).
// Everything works on SYMBOL INDEXES (fast for the attacks). Pure functions, no HTML; browser and Node.
(function (root) {
  "use strict";

  function mod(x, n) { return ((x % n) + n) % n; }
  function gcd(a, b) { return b === 0 ? a : gcd(b, a % b); }
  function invMod(x, n) { for (let i = 1; i < n; i++) if (mod(x * i, n) === 1) return i; return -1; }

  function toIdx(str, A) {
    const out = new Int32Array(str.length);
    for (let i = 0; i < str.length; i++) {
      const k = A.indexOf(str[i]);
      if (k < 0) throw new Error('Character #' + (i + 1) + ' ("' + str[i] + '") is not in the alphabet (' + A.join(" ") + ").");
      out[i] = k;
    }
    return out;
  }
  function toStr(idx, len, A) {
    let s = "";
    for (let i = 0; i < len; i++) s += A[idx[i]];
    return s;
  }
  function sameArr(a, la, b, lb) {
    if (la !== lb) return false;
    for (let i = 0; i < la; i++) if (a[i] !== b[i]) return false;
    return true;
  }

  // ---------------- CAESAR (same rules as the message page: a-z and A-Z, key 1 to 25) ----------
  function prepCaesar(A, p) {
    const k = Number(p.key);
    if (String(p.key).trim() === "" || !Number.isInteger(k)) throw new Error("Caesar: the key must be a whole number from 1 to 25.");
    if (k === 0 || k === 26) throw new Error("Caesar: error, key " + k + " refused. A shift of " + k + " is a full turn of the alphabet: the password would not be encrypted. Choose a key from 1 to 25.");
    if (k < 1 || k > 25) throw new Error("Caesar: key " + k + " refused. The key must be between 1 and 25.");
    const left = p.direction === "left", eff = left ? -k : k;
    const n = A.length, map = new Int32Array(n), inv = new Int32Array(n);
    A.forEach(function (ch, i) {
      const c = ch.charCodeAt(0);
      let j = i;
      if (c >= 97 && c <= 122) j = A.indexOf(String.fromCharCode(97 + mod(c - 97 + eff, 26)));
      else if (c >= 65 && c <= 90) j = A.indexOf(String.fromCharCode(65 + mod(c - 65 + eff, 26)));
      if (j < 0) j = i;
      map[i] = j; inv[j] = i;
    });
    return {
      key: k,
      info: "Each letter (a–z and A–Z, 26 letters each) is shifted by " + k + " place(s) to the " + (left ? "left" : "right") + " inside its alphabet (z → a, Z → A); digits, + and * are not changed.",
      encIdx: function (inp, len, out) { for (let i = 0; i < len; i++) out[i] = map[inp[i]]; return len; },
      decIdx: function (inp, len, out) { for (let i = 0; i < len; i++) out[i] = inv[inp[i]]; return len; },
      unpad: function (dec) { return { idx: dec, note: "" }; }
    };
  }

  // ---------------- HILL 2x2 ----------------
  function hillDet(m, n) {
    const raw = m[0] * m[3] - m[1] * m[2];
    const det = mod(raw, n), g = gcd(det, n);
    let t = "Determinant = a·d − b·c = " + m[0] + "×" + m[3] + " − " + m[1] + "×" + m[2] + " = " + raw;
    if (raw !== det) t += "\nbrought back to 0…" + (n - 1) + " → " + det + " (mod " + n + ")";
    t += "\ngcd(" + det + ", " + n + ") = " + g + (g === 1 ? " → the key is valid" : " → key NOT valid (it must be 1)");
    if (g === 1) t += "\nInverse of " + det + " modulo " + n + " = " + invMod(det, n);
    return { raw: raw, det: det, ok: g === 1, text: t };
  }

  function prepHill(A, p) {
    const n = A.length, m = p.m;
    if (!Array.isArray(m) || m.length !== 4 || !m.every(function (v) { return Number.isInteger(v) && Math.abs(v) <= 1e6; }))
      throw new Error("Hill: the 4 key values must be integers.");
    const di = hillDet(m, n);
    if (!di.ok) throw new Error("Hill: matrix not invertible modulo " + n + ".\n" + di.text + "\nChoose another matrix (use the \"Random valid key\" button).");
    const inv = invMod(di.det, n);
    const E = m.map(function (v) { return mod(v, n); });
    const D = [m[3] * inv, -m[1] * inv, -m[2] * inv, m[0] * inv].map(function (v) { return mod(v, n); });
    const pad = n - 1;
    function apply(M, inp, len, out) {
      let o = 0;
      for (let i = 0; i < len; i += 2) {
        const x = inp[i], y = i + 1 < len ? inp[i + 1] : pad;
        out[o++] = (M[0] * x + M[1] * y) % n;
        out[o++] = (M[2] * x + M[3] * y) % n;
      }
      return o;
    }
    return {
      info: di.text,
      encIdx: function (inp, len, out) { return apply(E, inp, len, out); },
      decIdx: function (inp, len, out) { return apply(D, inp, len, out); },
      unpad: function (dec, expectedLen) {
        const last = dec.length - 1;
        if (expectedLen != null && expectedLen < dec.length) {
          if (dec.length - expectedLen === 1 && dec[last] === pad) return { idx: dec.slice(0, last), note: "Padding symbol removed." };
          return { idx: dec, note: "" };
        }
        if (expectedLen == null && dec.length && dec[last] === pad) return { idx: dec.slice(0, last), note: "Final padding symbol removed." };
        return { idx: dec, note: "" };
      },
      oddNote: "Odd length: one padding symbol was added before encryption."
    };
  }
  function randomHillKey(n, rand) {
    let k;
    do { k = [0, 1, 2, 3].map(function () { return rand(n); }); } while (!hillDet(k, n).ok);
    return k;
  }

  // ---------------- PLAYFAIR (grid R x C with R*C = n) ----------------
  function gridDims(n) { let best = [1, n]; for (let r = 1; r * r <= n; r++) if (n % r === 0) best = [r, n / r]; return best; }

  function prepPlayfair(A, p) {
    const n = A.length, dims = gridDims(n), R = dims[0], C = dims[1];
    const key = String(p.key || "");
    if (!key) throw new Error("Playfair: please enter a secret key (at least one symbol of the alphabet).");
    const ki = toIdx(key, A);
    const tbl = [], seen = new Array(n).fill(false);
    for (const k of ki) if (!seen[k]) { seen[k] = true; tbl.push(k); }
    for (let k = 0; k < n; k++) if (!seen[k]) tbl.push(k);
    const row = new Int32Array(n), col = new Int32Array(n);
    tbl.forEach(function (s, pos) { row[s] = Math.floor(pos / C); col[s] = pos % C; });
    const padFor = function (f) { return f === n - 1 ? 0 : n - 1; };

    function pair(x, y, d, out, o) {
      let r1 = row[x], c1 = col[x], r2 = row[y], c2 = col[y];
      if (r1 === r2) { c1 = (c1 + d + C) % C; c2 = (c2 + d + C) % C; }
      else if (c1 === c2) { r1 = (r1 + d + R) % R; r2 = (r2 + d + R) % R; }
      else { const t = c1; c1 = c2; c2 = t; }
      out[o] = tbl[r1 * C + c1]; out[o + 1] = tbl[r2 * C + c2];
    }
    function padded(inp, len) {
      const o = []; let i = 0;
      while (i < len) {
        const f = inp[i];
        if (i + 1 < len && inp[i + 1] !== f) { o.push(f, inp[i + 1]); i += 2; }
        else { o.push(f, padFor(f)); i += 1; }
      }
      return Int32Array.from(o);
    }
    function encIdx(inp, len, out) {
      let i = 0, o = 0;
      while (i < len) {
        const f = inp[i];
        if (i + 1 < len && inp[i + 1] !== f) { pair(f, inp[i + 1], 1, out, o); i += 2; }
        else { pair(f, padFor(f), 1, out, o); i += 1; }
        o += 2;
      }
      return o;
    }
    function decIdx(inp, len, out) {
      for (let i = 0; i < len; i += 2) {
        if (inp[i] === inp[i + 1]) throw new Error("Playfair: this text cannot be a Playfair ciphertext (a pair has two equal symbols).");
        pair(inp[i], inp[i + 1], -1, out, i);
      }
      return len;
    }
    function candidates(dec) {
      const c = [], pairs = dec.length / 2;
      for (let k = 0; k < pairs; k++) {
        const f = dec[2 * k], s = dec[2 * k + 1];
        if (s === padFor(f) && (k === pairs - 1 || dec[2 * k + 2] === f)) c.push(2 * k + 1);
      }
      return c;
    }
    function without(dec, drop) {
      const set = new Set(drop), o = [];
      for (let i = 0; i < dec.length; i++) if (!set.has(i)) o.push(dec[i]);
      return Int32Array.from(o);
    }
    return {
      info: "Playfair grid " + R + "×" + C + " built from the key (the key symbols come first, then the others in alphabet order). Padding symbol: " + A[n - 1] + " (or " + A[0] + " next to " + A[n - 1] + ").",
      encIdx: encIdx,
      decIdx: decIdx,
      unpad: function (dec) {
        const cand = candidates(dec);
        if (!cand.length) return { idx: dec, note: "" };
        return { idx: without(dec, cand), note: "Padding symbols removed." };
      },
      oddNote: "Padding symbols were inserted between equal symbols and at the end if needed."
    };
  }

  // prepare(algo, alphabet, params) -> cipher object
  //   caesar: { key, direction: "left"|"right" }    hill: { m: [a,b,c,d] }    playfair: { key: "SYMBOLS" }
  function prepare(algo, A, params) {
    const c = algo === "caesar" ? prepCaesar(A, params) : algo === "hill" ? prepHill(A, params) : prepPlayfair(A, params);
    c.algo = algo; c.alphabet = A;
    c.toIdx = function (s) { return toIdx(s, A); };
    c.encrypt = function (str) {
      if (!str) throw new Error("Nothing to encrypt: the password is empty.");
      const inp = toIdx(str, A), out = new Int32Array(2 * inp.length + 2);
      const ol = c.encIdx(inp, inp.length, out);
      return { text: toStr(out, ol, A), info: c.info + (ol !== inp.length && c.oddNote ? "\n" + c.oddNote : "") };
    };
    c.decrypt = function (str, expectedLen) {
      if (!str) throw new Error("Nothing to decrypt: the field is empty.");
      const inp = toIdx(str, A);
      if (algo !== "caesar" && inp.length % 2 === 1) throw new Error("An encrypted text must have an even number of symbols (it has " + inp.length + ").");
      const out = new Int32Array(inp.length + 2);
      const ol = c.decIdx(inp, inp.length, out);
      const r = c.unpad(out.slice(0, ol), expectedLen);
      return { text: toStr(r.idx, r.idx.length, A), info: c.info + (r.note ? "\n" + r.note : "") };
    };
    return c;
  }

  const api = { prepare: prepare, randomHillKey: randomHillKey, hillDet: hillDet, gridDims: gridDims, toIdx: toIdx, toStr: toStr };
  if (typeof module !== "undefined") module.exports = api;
  root.PC = api;
})(typeof window !== "undefined" ? window : globalThis);
