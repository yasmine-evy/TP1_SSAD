// ===== G1: INTEGRITY INTERFACE (choice of algorithm, message, key, Encrypt / Decrypt) =====
// The three algorithms are not rewritten here: everything goes through runCipher() of ciphers.js.
const $ = function (id) { return document.getElementById(id); };

// Key fields of the chosen algorithm
function paramsHtml(algo) {
  if (algo === "caesar") {
    return '<div class="params"><p class="petit hint">Alphabets a–z and A–Z (26 letters each). Key from 1 to 25 (26 would not encrypt the message).</p>' +
      '<div class="row"><div><label for="i-ckey">Key</label><input type="number" id="i-ckey" min="1" max="25" value="3"></div>' +
      '<div><label for="i-cdir">Shift direction</label><select id="i-cdir"><option value="right">Right</option><option value="left">Left</option></select></div></div></div>';
  }
  if (algo === "hill") {
    return '<div class="params"><p class="petit hint">2×2 key matrix. The determinant must be coprime with 26.</p>' +
      '<div class="matrice"><input id="i-ha" type="number" value="3" aria-label="a"><input id="i-hb" type="number" value="3" aria-label="b">' +
      '<input id="i-hc" type="number" value="2" aria-label="c"><input id="i-hd" type="number" value="5" aria-label="d"></div>' +
      '<div class="boutons"><button type="button" onclick="randomHillKey()">Random valid key</button></div></div>';
  }
  return '<div class="params"><p class="petit hint">Secret key (letters) and padding letter.</p>' +
    '<label for="i-pkey">Secret key</label><input type="text" id="i-pkey" placeholder="Example: MONARCHY" autocomplete="off">' +
    '<label for="i-ppad">Padding letter</label><input type="text" id="i-ppad" maxlength="1" value="X">' +
    '<label class="check"><input type="checkbox" id="i-prem" checked> Remove the padding letters after decrypting</label></div>';
}

function showParams() {
  $("i-params").innerHTML = paramsHtml($("i-algo").value);
  $("i-out").textContent = ""; $("i-out").className = "resultat";
  $("i-info").textContent = ""; $("i-use").style.display = "none";
}

function readParams(algo) {
  if (algo === "caesar") return { key: $("i-ckey").value, direction: $("i-cdir").value };
  if (algo === "hill") {
    return ["a", "b", "c", "d"].map(function (l) {
      const raw = $("i-h" + l).value.trim(), v = Number(raw);
      if (raw === "" || !Number.isInteger(v)) throw new Error("Hill: the key values must be integers.");
      return v;
    });
  }
  return { key: $("i-pkey").value, pad: $("i-ppad").value, removePad: $("i-prem").checked };
}

function randomHillKey() {
  let k;
  do { k = [0, 1, 2, 3].map(function () { return Math.floor(Math.random() * 26); }); } while (!detInfo(k).ok);
  ["a", "b", "c", "d"].forEach(function (l, i) { $("i-h" + l).value = k[i]; });
}

function run(mode) {
  const algo = $("i-algo").value, out = $("i-out"), info = $("i-info");
  out.className = "resultat"; out.style.whiteSpace = ""; info.textContent = ""; $("i-use").style.display = "none";
  try {
    const r = runCipher(algo, $("i-msg").value, readParams(algo), mode);   // <- call of the existing algorithm
    out.textContent = r.text;
    const name = algo.charAt(0).toUpperCase() + algo.slice(1);
    info.textContent = (mode === "encrypt" ? "Encrypted" : "Decrypted") + " with " + name + "." + (r.info ? "\n" + r.info : "");
    $("i-use").style.display = "flex";
  } catch (e) {
    out.className = "resultat erreur";
    out.style.whiteSpace = "pre-line";
    out.textContent = e.message;
  }
}
function doEncrypt() { run("encrypt"); }
function doDecrypt() { run("decrypt"); }
function useResult() { $("i-msg").value = $("i-out").textContent; $("i-msg").focus(); }

showParams();
