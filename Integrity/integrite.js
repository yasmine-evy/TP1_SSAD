// The integrity page reuses runCipher() from Encryption/ciphers.js.
const $ = function (id) { return document.getElementById(id); };

function paramsHtml(algo) {
  if (algo === "caesar") {
    return '<div class="params"><p class="petit hint">Alphabets a–z and A–Z. Choose a shift from 1 to 25.</p>' +
      '<div class="row"><div><label for="i-ckey">Key</label><input type="number" id="i-ckey" min="1" max="25" value="3"></div>' +
      '<div><label for="i-cdir">Shift direction</label><select id="i-cdir"><option value="right">Right</option><option value="left">Left</option></select></div></div></div>';
  }
  if (algo === "hill") {
    return '<div class="params"><p class="petit hint">2×2 key matrix. The determinant must be coprime with 26.</p>' +
      '<div class="matrice"><input id="i-ha" type="number" value="3" aria-label="a"><input id="i-hb" type="number" value="3" aria-label="b">' +
      '<input id="i-hc" type="number" value="2" aria-label="c"><input id="i-hd" type="number" value="5" aria-label="d"></div>' +
      '<div class="boutons"><button type="button" onclick="randomHillKey()">Random valid key</button></div></div>';
  }
  return '<div class="params"><p class="petit hint">Provide a secret key. Filler characters are handled automatically.</p>' +
    '<label for="i-pkey">Secret key</label><input type="text" id="i-pkey" placeholder="Example: MONARCHY" autocomplete="off">' +
    '<label class="check"><input type="checkbox" id="i-prem" checked> Remove the padding letters after decrypting</label></div>';
}

function showParams() {
  $("i-params").innerHTML = paramsHtml($("i-algo").value);
  $("i-out").textContent = "";
  $("i-out").className = "resultat";
  $("i-info").textContent = "";
  $("i-use").hidden = true;
}

function readParams(algo) {
  if (algo === "caesar") return { key: $("i-ckey").value, direction: $("i-cdir").value };
  if (algo === "hill") {
    return ["a", "b", "c", "d"].map(function (letter) {
      const raw = $("i-h" + letter).value.trim();
      const value = Number(raw);
      if (raw === "" || !Number.isInteger(value)) throw new Error("Hill: the key values must be integers.");
      return value;
    });
  }
  return { key: $("i-pkey").value, removePad: $("i-prem").checked };
}

function randomHillKey() {
  let key;
  do {
    key = [0, 1, 2, 3].map(function () { return Math.floor(Math.random() * 26); });
  } while (!detInfo(key).ok);
  ["a", "b", "c", "d"].forEach(function (letter, index) {
    $("i-h" + letter).value = key[index];
  });
}

function run(mode) {
  const algorithm = $("i-algo").value;
  const output = $("i-out");
  const info = $("i-info");
  output.className = "resultat";
  output.style.whiteSpace = "";
  info.textContent = "";
  $("i-use").hidden = true;

  try {
    const result = runCipher(algorithm, $("i-msg").value, readParams(algorithm), mode);
    output.textContent = result.text;
    const algorithmName = algorithm.charAt(0).toUpperCase() + algorithm.slice(1);
    info.textContent = (mode === "encrypt" ? "Encrypted" : "Decrypted") + " with " + algorithmName + "." +
      (result.info ? "\n" + result.info : "");
    $("i-use").hidden = false;
  } catch (error) {
    output.className = "resultat erreur";
    output.style.whiteSpace = "pre-line";
    output.textContent = error.message;
  }
}

function doEncrypt() {
  run("encrypt");
}

function doDecrypt() {
  run("decrypt");
}

function useResult() {
  $("i-msg").value = $("i-out").textContent;
  $("i-msg").focus();
}

showParams();
