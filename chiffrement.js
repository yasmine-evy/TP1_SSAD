// ===== USER INTERFACE for chiffrement.html =====
const $ = function (id) { return document.getElementById(id); };

// The parameter fields of each algorithm (p = "e" for sender, "d" for receiver)
function paramsHtml(algo, p) {
  if (algo === "caesar") {
    return '<div class="params"><p class="petit hint">Alphabet a–z then A–Z (52 letters). Key 1 to 51; spaces are hidden in the encrypted text.</p>' +
      '<div class="row"><div><label for="' + p + '-ckey">Key</label><input type="number" id="' + p + '-ckey" value="3"></div>' +
      '<div><label for="' + p + '-cdir">Shift direction</label><select id="' + p + '-cdir"><option value="right">Right</option><option value="left">Left</option></select></div></div></div>';
  }
  if (algo === "hill") {
    return '<div class="params"><p class="petit hint">2×2 key matrix (negative numbers accepted). The determinant must be coprime with 26.</p>' +
      '<div class="matrice"><input id="' + p + '-ha" type="number" value="3"><input id="' + p + '-hb" type="number" value="3">' +
      '<input id="' + p + '-hc" type="number" value="2"><input id="' + p + '-hd" type="number" value="5"></div>' +
      '<div class="boutons"><button type="button" onclick="randomHillKey(\'' + p + '\')">Random valid key</button></div></div>';
  }
  return '<div class="params"><p class="petit hint">Secret key (letters) and padding letter.</p>' +
    '<label for="' + p + '-pkey">Secret key</label><input type="text" id="' + p + '-pkey" placeholder="Example: MONARCHY">' +
    '<label for="' + p + '-ppad">Padding letter</label><input type="text" id="' + p + '-ppad" maxlength="1" value="X">' +
    (p === "d" ? '<label class="check"><input type="checkbox" id="d-prem" checked> Remove the padding letters after decrypting</label>' : '') + '</div>';
}

function showParams(p) {
  const algo = $(p + "-algo").value;
  $(p + "-params").innerHTML = paramsHtml(algo, p);
  $(p + "-flaws").innerHTML = flawsHtml(algo);
  $(p + "-flaws").open = false;
  updateHistoryVisibility();
}

// ---------- Flaws and solutions of the chosen algorithm ----------
const FLAWS = {
  caesar: [
    ["<b>Key 0 or 52:</b> a full turn of the alphabet leaves the message unchanged.", true,
     "The key is reduced modulo 52 and 0 / 52 are refused. <i>Example:</i> key 55 → used as key 3."],
    ["<b>Visible spaces:</b> word lengths help to guess the text.", true,
     "Spaces disappear from the encrypted text (each one is hidden as the letters \"Qs\" before encryption) and come back at decryption: \"Hello World\" is recovered exactly."],
    ["<b>Few keys (51):</b> an attacker tries them all (brute force).", false,
     "Use a longer key that changes the shift for each letter (Vigenère) or a modern cipher (AES)."],
    ["<b>Frequency analysis:</b> the same letter always gives the same cipher letter.", false,
     "Change the shift from one letter to the next (Vigenère) to hide the frequencies."],
    ["<b>Known plaintext:</b> one pair (plain letter, cipher letter) reveals the key.", false,
     "Change the key often and never reuse it for several sensitive messages."]
  ],
  hill: [
    ["<b>Negative determinant</b> (e.g. a·d − b·c = −5): a valid key could be wrongly refused.", true,
     "The determinant is brought back to 0…25 (mod 26) before checking gcd(det, 26) = 1. <i>Example:</i> [1 2 ; 3 1] → det −5 → 21 → valid. The steps are shown after each operation."],
    ["<b>Non-invertible key:</b> if gcd(det, 26) ≠ 1 the message cannot be decrypted.", true,
     "The key is refused with an explanation; the button \"Random valid key\" gives a good one."],
    ["<b>Odd length:</b> blocks need 2 letters.", true,
     "An X is added at encryption and the final X is removed at decryption."],
    ["<b>Ambiguous padding X:</b> an even message already ending with X loses that X when decrypting.", true,
     "A warning is shown at encryption; add one more letter to avoid it."],
    ["<b>Visible spaces:</b> word lengths would leak in the encrypted text.", true,
     "Spaces disappear from the encrypted text (hidden as \"Qs\" before encryption) and come back at decryption. Cost: the encrypted text is 2 letters longer per space."],
    ["<b>Known plaintext:</b> the algorithm is linear, so 2 known blocks give the key.", false,
     "Use a bigger matrix (3×3) and add a non-linear step (affine Hill)."],
    ["<b>Same blocks → same results:</b> repetitions stay visible.", false,
     "Chain the blocks (CBC mode)."]
  ],
  playfair: [
    ["<b>Equal letters in a pair</b> (e.g. LL) cannot be encrypted.", true,
     "The padding letter is inserted between them (and at the end if the length is odd)."],
    ["<b>Padding letter removal:</b> removing it can also delete a real X of the original message.", true,
     "The padding letter is configurable and the removal can be switched off with the checkbox at decryption."],
    ["<b>Letters only, I = J:</b> spaces, digits and the J/I difference are lost.", true,
     "The table is shown so the receiver can check. Case is kept; only J → I and digits cannot be recovered."],
    ["<b>Visible spaces:</b> word lengths would leak in the encrypted text.", true,
     "Spaces disappear from the encrypted text (hidden as \"Qs\" before encryption) and come back at decryption. Cost: the encrypted text is 2 letters longer per space."],
    ["<b>Weak key:</b> a short or common key can be guessed (dictionary attack).", false,
     "Use a long, random key."],
    ["<b>Digraph frequency analysis:</b> only 600 possible pairs, common pairs (TH, HE) still appear.", false,
     "Use modern encryption (AES) for real data."],
    ["<b>Reversed pairs:</b> if AB → XY then BA → YX.", false,
     "Not fixable inside Playfair; avoid reusing the same key."]
  ]
};

function flawsHtml(algo) {
  const name = algo.charAt(0).toUpperCase() + algo.slice(1);
  let h = "<summary>Flaws and solutions — " + name + "</summary><div class='table-wrap' style='max-height:none;margin-top:10px'><table class='t'><thead><tr><th>Flaw</th><th>Solution</th></tr></thead><tbody>";
  FLAWS[algo].forEach(function (f) {
    h += "<tr><td>" + f[0] + "</td><td>" + (f[1] ? "<span class='tag ok'>Applied here</span> " : "<span class='tag'>Advice</span> ") + f[2] + "</td></tr>";
  });
  return h + "</tbody></table></div>";
}

// ---------- Caesar history (localStorage with in-memory fallback) ----------
const HKEY = "caesar_history";
let memory = [];
function readHistory() { try { return JSON.parse(localStorage.getItem(HKEY)) || []; } catch (e) { return memory; } }
function writeHistory(l) { memory = l; try { localStorage.setItem(HKEY, JSON.stringify(l)); } catch (e) {} }
function addHistory(entry) {
  entry.date = new Date().toLocaleString("en-GB");
  const l = readHistory(); l.unshift(entry); writeHistory(l.slice(0, 100)); showHistory();
}
function clearHistory() { writeHistory([]); showHistory(); }
function updateHistoryVisibility() {
  const on = $("e-algo").value === "caesar" || $("d-algo").value === "caesar";
  $("historyBloc").style.display = on ? "block" : "none";
  if (on) showHistory();
}
function showHistory() {
  const box = $("historyBox"), list = readHistory();
  box.innerHTML = "";
  if (!list.length) { box.innerHTML = '<div class="vide">History is empty.</div>'; return; }
  const table = document.createElement("table"); table.className = "t";
  table.innerHTML = "<thead><tr><th>Date</th><th>Operation</th><th>Key</th><th>Direction</th><th>Input</th><th>Result</th></tr></thead>";
  const tb = document.createElement("tbody");
  list.forEach(function (h) {
    const tr = document.createElement("tr");
    [h.date, h.operation, h.key, h.direction, h.input, h.output].forEach(function (v, i) {
      const td = document.createElement("td"); td.textContent = v; if (i >= 4) td.className = "mono"; tr.appendChild(td);
    });
    tb.appendChild(tr);
  });
  table.appendChild(tb); box.appendChild(table);
}

function readParams(algo, p) {
  if (algo === "caesar") return { key: $(p + "-ckey").value, direction: $(p + "-cdir").value };
  if (algo === "hill") {
    return ["a", "b", "c", "d"].map(function (l) {
      const raw = $(p + "-h" + l).value.trim(), v = Number(raw);
      if (raw === "" || !Number.isInteger(v)) throw new Error("Hill: the key values must be integers.");
      return v;
    });
  }
  return { key: $(p + "-pkey").value, pad: $(p + "-ppad").value, removePad: p === "d" && $(p + "-prem").checked };
}

function randomHillKey(p) {
  let k;
  do { k = [0, 1, 2, 3].map(function () { return Math.floor(Math.random() * 26); }); } while (!detInfo(k).ok);
  ["a", "b", "c", "d"].forEach(function (l, i) { $(p + "-h" + l).value = k[i]; });
}

function tableHtml(table, key) {
  let h = '<p class="petit" style="margin-bottom:0">Playfair 5×5 table (key letters in grey):</p><table class="grille">';
  for (let r = 0; r < 5; r++) {
    h += "<tr>";
    for (let c = 0; c < 5; c++) { const l = table[r * 5 + c]; h += "<td" + (key.indexOf(l) !== -1 ? ' class="k"' : "") + ">" + l + "</td>"; }
    h += "</tr>";
  }
  return h + "</table>";
}

function run(p, mode) {
  const algo = $(p + "-algo").value;
  const out = $(p + "-out"), info = $(p + "-info"), extra = $(p + "-extra");
  const input = $(p + "-msg").value;
  info.textContent = ""; extra.innerHTML = ""; out.className = "resultat";
  if (p === "e") $("e-send").style.display = "none";
  try {
    const params = readParams(algo, p);
    const r = runCipher(algo, input, params, mode);
    out.textContent = r.text;
    if (algo === "caesar") addHistory({ operation: mode === "encrypt" ? "Encryption" : "Decryption", key: r.shift, direction: params.direction === "left" ? "Left" : "Right", input: input, output: r.text });
    info.textContent = (mode === "encrypt" ? "Encrypted" : "Decrypted") + " with " + algo.charAt(0).toUpperCase() + algo.slice(1) + "." + (r.info ? "\n" + r.info : "");
    if (algo === "playfair") extra.innerHTML = tableHtml(r.table, r.key);
    if (p === "e") $("e-send").style.display = "flex";
  } catch (e) {
    out.className = "resultat erreur";
    out.style.whiteSpace = "pre-line";
    out.textContent = e.message;
  }
}

function doEncrypt() { run("e", "encrypt"); }
function doDecrypt() { run("d", "decrypt"); }

function sendToReceiver() {
  $("d-msg").value = $("e-out").textContent;
  $("d-msg").scrollIntoView({ behavior: "smooth", block: "center" });
}

showParams("e");
showParams("d");
