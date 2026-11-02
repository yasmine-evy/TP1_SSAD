// ===== G1: INTEGRITY INTERFACE (choice of algorithm, message, key, Encrypt / Decrypt) =====
// The three algorithms are not rewritten here: everything goes through runCipher() of ciphers.js.
const $ = function (id) { return document.getElementById(id); };
const CIPHER_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+*";
let senderMessageLength = 0;
let senderPaddingMap = "-";

// Key fields of the chosen algorithm
function paramsHtml(algo) {
  if (algo === "caesar") {
    return '<div class="params">' +
      '<div class="row"><div><label for="i-ckey">Key</label><input type="number" id="i-ckey" min="1" max="63" value="3" onkeydown="blockNegativeKey(event)"></div>' +
      '<div><label for="i-cdir">Shift direction</label><select id="i-cdir"><option value="right">Right</option><option value="left">Left</option></select></div></div></div>';
  }
  if (algo === "hill") {
    return '<div class="params">' +
      '<div class="matrice"><input id="i-ha" type="number" value="3"><input id="i-hb" type="number" value="3">' +
      '<input id="i-hc" type="number" value="2"><input id="i-hd" type="number" value="5"></div>' +
      '<div class="boutons"><button type="button" onclick="randomHillKey()">Random valid key</button></div></div>';
  }
  return '<div class="params">' +
    '<label for="i-pkey">Secret key</label><input type="text" id="i-pkey" placeholder="Example: MONARCHY" pattern="[A-Za-z]*" oninput="lettersOnly(this)"></div>';
}

function tableHtml(table, key) {
  const size = Math.sqrt(table.length);
  let html = '<div class="grille-wrap"><table class="grille">';
  for (let row = 0; row < size; row++) {
    html += "<tr>";
    for (let column = 0; column < size; column++) {
      const letter = table[row * size + column];
      html += "<td" + (key.indexOf(letter) !== -1 ? ' class="k"' : "") + ">" + letter + "</td>";
    }
    html += "</tr>";
  }
  return html + "</table></div>";
}

function showParams() {
  const algo = $("i-algo").value;
  $("i-params").innerHTML = paramsHtml(algo);
  $("i-out").textContent = "";
  $("i-out").className = "resultat";
  $("i-info").textContent = "";
  $("i-extra").innerHTML = "";
  $("i-verified-message").textContent = "";
  $("i-verified-message").className = "resultat";
  $("i-integrity-result").textContent = "";
  $("i-integrity-result").className = "resultat";
  $("i-use").style.display = "none";
  resetAttackerView();
}

function readParams(algo) {
  if (algo === "caesar") {
    const raw = $("i-ckey").value.trim(), key = Number(raw);
    if (!raw || !Number.isSafeInteger(key) || key < 1 || key >= CIPHER_ALPHABET.length)
      throw new Error("Caesar key must be an integer from 1 to 63.");
    return { key: key, direction: $("i-cdir").value };
  }
  if (algo === "hill") {
    return ["a", "b", "c", "d"].map(function (letter) {
      const raw = $("i-h" + letter).value.trim(), value = Number(raw);
      if (raw === "" || !Number.isSafeInteger(value)) throw new Error("Hill: the key values must be safe integers.");
      return value;
    });
  }
  const key = $("i-pkey").value;
  if (!key || Array.from(key).some(function (character) { return CIPHER_ALPHABET.indexOf(character) === -1; }))
    throw new Error("Playfair secret key must contain at least one character from a-z, A-Z, 0-9, + or *.");
  return { key: key, removePad: true };
}

function blockNegativeKey(event) {
  if (event.key === "-") event.preventDefault();
}

function lettersOnly(input) {
  input.value = input.value.replace(/[^A-Za-z0-9*+]/g, "");
}

function randomHillKey() {
  let k;
  do { k = [0, 1, 2, 3].map(function () { return Math.floor(Math.random() * CIPHER_ALPHABET.length); }); } while (!detInfoBase(k, CIPHER_ALPHABET.length).ok);
  ["a", "b", "c", "d"].forEach(function (l, i) { $("i-h" + l).value = k[i]; });
}

function sanitizeMessage() {
  const field = $("i-msg");
  field.value = field.value.replace(/[^A-Za-z0-9*+]/g, "");
}

function calculateControlValue(value) {
  let sum = 0;
  const bytes = new TextEncoder().encode(value);
  for (const byte of bytes) sum = (sum + byte) % 65536;
  return sum.toString(16).padStart(4, "0");
}

function makePlayfairPaddingMap(message) {
  const padding = [];
  let index = 0;
  while (index < message.length) {
    if (index + 1 === message.length || message[index] === message[index + 1]) {
      padding.push("1");
      index++;
    } else {
      padding.push("0");
      index += 2;
    }
  }
  return padding.join("");
}

function recoverPlayfairMessage(rawDecrypted, expectedLength, key, ciphertext, paddingMap) {
  const pairs = rawDecrypted.match(/../g) || [];
  const firstAlphabetCharacter = CIPHER_ALPHABET[0];
  const secondAlphabetCharacter = CIPHER_ALPHABET[1];
  if (pairs.length !== paddingMap.length)
    throw new Error("The Playfair padding data is malformed.");
  let message = "";
  for (let pairIndex = 0; pairIndex < pairs.length; pairIndex++) {
    const pair = pairs[pairIndex];
    const first = pair[0], second = pair[1];
    const filler = first === firstAlphabetCharacter ? secondAlphabetCharacter : firstAlphabetCharacter;
    const nextPairStartsWithFirst = pairIndex === pairs.length - 1 || pairs[pairIndex + 1][0] === first;
    if (paddingMap[pairIndex] === "1") {
      if (second !== filler || !nextPairStartsWithFirst)
        throw new Error("The Playfair padding data does not match the decrypted text.");
      message += first;
    } else {
      if (first === second)
        throw new Error("The Playfair pair data is malformed.");
      message += first + second;
    }
  }

  if (message.length !== expectedLength || runCipher("playfair", message, { key: key, removePad: true }, "encrypt", CIPHER_ALPHABET).text !== ciphertext)
    throw new Error("The decrypted Playfair message does not match its original length.");
  return message;
}

function showModified(message) {
  $("i-integrity-result").textContent = message;
  $("i-integrity-result").className = "resultat erreur";
}

function doEncrypt() {
  const button = $("i-encrypt-button");
  const out = $("i-out");
  const info = $("i-info");
  const extra = $("i-extra");
  const message = $("i-msg").value;
  const algo = $("i-algo").value;
  out.textContent = "";
  out.className = "resultat";
  info.textContent = "";
  extra.innerHTML = "";
  senderMessageLength = 0;
  senderPaddingMap = "-";
  $("i-use").style.display = "none";
  button.disabled = true;
  try {
    if (!message || Array.from(message).some(function (character) { return CIPHER_ALPHABET.indexOf(character) === -1; }))
      throw new Error("Message must contain one or more characters from a-z, A-Z, 0-9, + or *.");
    const r = runCipher(algo, message, readParams(algo), "encrypt", CIPHER_ALPHABET);
    out.textContent = r.text;
    senderMessageLength = message.length;
    senderPaddingMap = algo === "playfair" ? makePlayfairPaddingMap(message) : "-";
    const checksumInput = r.text + "|" + senderMessageLength + "|" + senderPaddingMap;
    const controlValue = calculateControlValue(checksumInput);
    const name = algo.charAt(0).toUpperCase() + algo.slice(1);
    info.textContent = "Cipher: " + name + "\nChecksum of encrypted payload: " + controlValue +
      "\nSend as: " + r.text + "|" + controlValue + "|" + senderMessageLength + "|" + senderPaddingMap + (r.info ? "\n" + r.info : "");
    if (algo === "playfair") extra.innerHTML = tableHtml(r.table, r.key);
    $("i-use").style.display = "flex";
  } catch (e) {
    out.className = "resultat erreur";
    out.textContent = e.message;
  } finally {
    button.disabled = false;
  }
}

function doDecrypt() {
  const button = $("i-verify-button");
  const output = $("i-verified-message");
  const result = $("i-integrity-result");
  const envelope = $("i-received").value;
  const algo = $("i-algo").value;
  output.textContent = "";
  output.className = "resultat";
  result.textContent = "";
  result.className = "resultat";
  button.disabled = true;

  try {
    const parts = envelope.split("|");
    if (parts.length !== 4 || !parts[0]) throw new Error("The received value must contain encrypted text, checksum, original length, and padding data separated by '|'.");
    const ciphertext = parts[0];
    const receivedControlValue = parts[1];
    const receivedLength = parts[2];
    const paddingMap = parts[3];
    if (!/^[0-9a-f]{4}$/i.test(receivedControlValue))
      throw new Error("The received checksum value is malformed.");
    if (!/^[1-9]\d*$/.test(receivedLength) || !Number.isSafeInteger(Number(receivedLength)) || Number(receivedLength) > ciphertext.length)
      throw new Error("The received original message length is invalid.");
    const originalLength = Number(receivedLength);
    if (algo === "playfair" ? !/^[01]+$/.test(paddingMap) || paddingMap.length !== ciphertext.length / 2 : paddingMap !== "-")
      throw new Error("The received padding data is invalid.");
    const calculatedControlValue = calculateControlValue(ciphertext + "|" + receivedLength + "|" + paddingMap);
    if (calculatedControlValue.toLowerCase() !== receivedControlValue.toLowerCase()) {
      showModified(
        "Message modified , Le checksum ne correspond pas." +

        "\n• Checksum reçu (original) : " + receivedControlValue +
        "\n• Checksum calculé : " + calculatedControlValue
      );
      return;
    }

    const params = readParams(algo);
    let message;
    if (algo === "playfair") {
      params.removePad = false;
      const rawDecrypted = runCipher(algo, ciphertext, params, "decrypt", CIPHER_ALPHABET).text;
      message = recoverPlayfairMessage(rawDecrypted, originalLength, params.key, ciphertext, paddingMap);
    } else {
      message = runCipher(algo, ciphertext, params, "decrypt", CIPHER_ALPHABET).text;
      if (algo === "hill" && message.length + 1 === originalLength)
        message += CIPHER_ALPHABET[0];
      if (message.length !== originalLength)
        throw new Error("The decrypted message does not match its original length.");
    }
    output.textContent = message;
    result.textContent = "Message intact — the checksum of the encrypted message matches.";
    result.className = "resultat doux";
  } catch (error) {
    showModified("Message modified — " + error.message);
  } finally {
    button.disabled = false;
  }
}

// Builds the packet exactly as Side A sends it: ciphertext|checksum|length|padding data
function buildEnvelope() {
  const ciphertext = $("i-out").textContent;
  const checksumInput = ciphertext + "|" + senderMessageLength + "|" + senderPaddingMap;
  const controlValue = calculateControlValue(checksumInput);
  return ciphertext + "|" + controlValue + "|" + senderMessageLength + "|" + senderPaddingMap;
}

function sendToReceiver() {
  $("i-received").value = buildEnvelope();
  $("i-received").focus();
}

// ===== ATTACKER: intercept the ciphertext and alter some of its characters =====

function resetAttackerView() {
  [$("i-intercepted"), $("i-tampered")].forEach(function (box) {
    box.innerHTML = "";
    box.className = "resultat";
  });
  $("i-attack-info").textContent = "";
}

function escapeHtml(text) {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// 1. Intercept: the attacker reads the packet that Side A puts on the channel.
//    Returns the 4 fields of the packet, or throws if nothing has been sent yet.
function interceptCiphertext() {
  const ciphertext = $("i-out").textContent;
  const sent = $("i-use").style.display !== "none" && ciphertext && senderMessageLength > 0;
  if (!sent)
    throw new Error("Nothing to intercept: encrypt a message on Side A first.");
  const parts = buildEnvelope().split("|");
  return { ciphertext: parts[0], checksum: parts[1], length: parts[2], padding: parts[3] };
}

// 2. Alter: replace `count` distinct random characters of the ciphertext by a different
//    character of the cipher alphabet (same length, so the packet still looks well-formed).
//    Returns the modified text and the list of altered positions.
function modifyCiphertext(ciphertext, count) {
  const chars = Array.from(ciphertext);
  const total = Math.min(count, chars.length);
  const positions = [];
  while (positions.length < total) {
    const index = Math.floor(Math.random() * chars.length);
    if (positions.indexOf(index) === -1) positions.push(index);
  }
  positions.sort(function (a, b) { return a - b; });
  positions.forEach(function (index) {
    let replacement;
    do { replacement = CIPHER_ALPHABET[Math.floor(Math.random() * CIPHER_ALPHABET.length)]; }
    while (replacement === chars[index]);
    chars[index] = replacement;
  });
  return { text: chars.join(""), positions: positions };
}

// Shows a ciphertext, highlighting the altered positions
function highlightHtml(text, positions) {
  return Array.from(text).map(function (character, index) {
    const safe = escapeHtml(character);
    return positions.indexOf(index) !== -1 ? '<span class="tampered">' + safe + "</span>" : safe;
  }).join("");
}

// 3. Button handler: intercept, alter, then deliver the tampered packet to Side B.
function simulateAttack() {
  const button = $("i-attack-button");
  resetAttackerView();
  button.disabled = true;
  try {
    const raw = $("i-attack-count").value.trim(), requested = Number(raw);
    if (!raw || !Number.isSafeInteger(requested) || requested < 1)
      throw new Error("The number of characters to modify must be an integer of at least 1.");

    const packet = interceptCiphertext();
    let tampered, tries = 0;
    do {
      tampered = modifyCiphertext(packet.ciphertext, requested);
      tries++;
    } while (tries < 20 && calculateControlValue(tampered.text + "|" + packet.length + "|" + packet.padding) === packet.checksum);

    $("i-intercepted").innerHTML = '<div class="petit">Intercepted ciphertext</div><div class="packet">' + escapeHtml(packet.ciphertext) + "</div>";
    $("i-tampered").innerHTML = '<div class="petit">Modified ciphertext (altered characters underlined)</div><div class="packet">' +
      highlightHtml(tampered.text, tampered.positions) + "</div>";
    $("i-tampered").className = "resultat erreur";
    $("i-attack-info").textContent = "Characters modified: " + tampered.positions.length +
      " (positions " + tampered.positions.map(function (p) { return p + 1; }).join(", ") + ")" +
      "\nChecksum left unchanged: " + packet.checksum +
      "\nThe modified packet was delivered to Side B — click \"Decrypt and verify\" to check it.";

    $("i-received").value = [tampered.text, packet.checksum, packet.length, packet.padding].join("|");
  } catch (e) {
    $("i-tampered").className = "resultat erreur";
    $("i-tampered").textContent = e.message;
  } finally {
    button.disabled = false;
  }
}
showParams();