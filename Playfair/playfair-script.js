// Playfair cipher - simple version for beginners

// ---------- Get the HTML elements ----------
var keyInput = document.getElementById("key");
var textInput = document.getElementById("text");
var resultBox = document.getElementById("result");
var resultLabel = document.getElementById("resultLabel");
var errorBox = document.getElementById("error");
var matrixTable = document.getElementById("matrix");
var stepsBox = document.getElementById("steps");
var paddingInput = document.getElementById("padding");
var removeBox = document.getElementById("removePadding");

// Last result without spaces (used by the Swap button)
var lastOutput = "";

// ---------- Helper: keep only letters, uppercase, J -> I ----------
function clean(text) {
  var result = "";
  text = text.toUpperCase();
  for (var i = 0; i < text.length; i++) {
    var c = text[i];
    if (c >= "A" && c <= "Z") {
      if (c === "J") {
        c = "I";
      }
      result += c;
    }
  }
  return result;
}

// ---------- Step 1: build the 5x5 table from the key ----------
// Returns a string of 25 letters (row by row)
function buildTable(key) {
  var alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"; // no J
  var table = "";
  var all = clean(key) + alphabet;

  for (var i = 0; i < all.length; i++) {
    if (table.indexOf(all[i]) === -1) {
      table += all[i];
    }
  }
  return table;
}

// ---------- Step 2: prepare the text as pairs ----------
function makePairs(text, pad) {
  var pairs = [];
  var i = 0;

  while (i < text.length) {
    var first = text[i];
    var second = "";

    if (i + 1 < text.length) {
      second = text[i + 1];
    }

    if (second === "") {
      // last letter alone: add the padding letter
      pairs.push(first + pad);
      i = i + 1;
    } else if (first === second) {
      // same letters: insert the padding letter between them
      pairs.push(first + pad);
      i = i + 1;
    } else {
      pairs.push(first + second);
      i = i + 2;
    }
  }
  return pairs;
}

// ---------- Step 3: encrypt or decrypt one pair ----------
// direction = 1 for encrypt, -1 for decrypt
function processPair(pair, table, direction) {
  var pos1 = table.indexOf(pair[0]);
  var pos2 = table.indexOf(pair[1]);

  var row1 = Math.floor(pos1 / 5);
  var col1 = pos1 % 5;
  var row2 = Math.floor(pos2 / 5);
  var col2 = pos2 % 5;

  var new1, new2;

  if (row1 === row2) {
    // same row: move right (encrypt) or left (decrypt)
    col1 = (col1 + direction + 5) % 5;
    col2 = (col2 + direction + 5) % 5;
  } else if (col1 === col2) {
    // same column: move down (encrypt) or up (decrypt)
    row1 = (row1 + direction + 5) % 5;
    row2 = (row2 + direction + 5) % 5;
  } else {
    // rectangle: swap the columns
    var temp = col1;
    col1 = col2;
    col2 = temp;
  }

  new1 = table[row1 * 5 + col1];
  new2 = table[row2 * 5 + col2];
  return new1 + new2;
}

// ---------- Show the 5x5 table on the page ----------
function showTable(table, key) {
  var cleanKey = clean(key);
  var html = "";

  for (var row = 0; row < 5; row++) {
    html += "<tr>";
    for (var col = 0; col < 5; col++) {
      var letter = table[row * 5 + col];
      var css = "";
      if (cleanKey.indexOf(letter) !== -1) {
        css = ' class="key-letter"';
      }
      html += "<td" + css + ">" + letter + "</td>";
    }
    html += "</tr>";
  }
  matrixTable.innerHTML = html;
}

// ---------- Remove the padding letters after decrypting ----------
// "pairs" are the decrypted pairs, for example: HE LX LO
// A padding letter is removed when it is:
//   - the second letter of a pair and the next pair starts with the same
//     letter as the first one (LX + LO means we inserted X between L and L)
//   - the second letter of the last pair
function removePaddingLetters(pairs, pad) {
  var text = "";

  for (var i = 0; i < pairs.length; i++) {
    var first = pairs[i][0];
    var second = pairs[i][1];

    text += first;

    if (second === pad) {
      var isLast = (i === pairs.length - 1);
      var sameAsNext = false;
      if (!isLast) {
        sameAsNext = (pairs[i + 1][0] === first);
      }
      if (isLast || sameAsNext) {
        continue; // skip the padding letter
      }
    }
    text += second;
  }
  return text;
}

// ---------- Main function used by both buttons ----------
function run(direction) {
  errorBox.textContent = "";

  var key = clean(keyInput.value);
  var text = clean(textInput.value);
  var pad = clean(paddingInput.value);

  if (key === "") {
    errorBox.textContent = "Please enter a key with at least one letter.";
    return;
  }
  if (pad === "") {
    errorBox.textContent = "Please enter one letter as the padding letter.";
    return;
  }
  if (text === "") {
    errorBox.textContent = "Please enter a text with at least one letter.";
    return;
  }

  var table = buildTable(key);
  showTable(table, key);

  var pairs = makePairs(text, pad);
  var newPairs = [];
  var stepsHtml = "";

  for (var i = 0; i < pairs.length; i++) {
    var newPair = processPair(pairs[i], table, direction);
    newPairs.push(newPair);
    stepsHtml += "<p>" + pairs[i] + " &rarr; " + newPair + "</p>";
  }

  var output = newPairs.join("");

  if (direction === 1) {
    resultLabel.textContent = "Encrypted message (sent to B):";
    // Show the result in groups of 2 letters
    resultBox.textContent = newPairs.join(" ");
  } else {
    resultLabel.textContent = "Decrypted message (read by B):";
    if (removeBox.checked) {
      output = removePaddingLetters(newPairs, pad);
    }
    resultBox.textContent = output;
  }

  lastOutput = output;
  stepsBox.innerHTML = stepsHtml;
}

// ---------- Buttons ----------
document.getElementById("encryptBtn").onclick = function () {
  run(1);
};

document.getElementById("decryptBtn").onclick = function () {
  run(-1);
};

document.getElementById("swapBtn").onclick = function () {
  if (lastOutput === "") {
    errorBox.textContent = "There is no result to swap yet.";
    return;
  }
  errorBox.textContent = "";
  textInput.value = lastOutput; // move the result into the Text input
};

document.getElementById("clearBtn").onclick = function () {
  keyInput.value = "";
  textInput.value = "";
  resultBox.textContent = "";
  lastOutput = "";
  paddingInput.value = "X";
  resultLabel.textContent = "Nothing yet.";
  errorBox.textContent = "";
  matrixTable.innerHTML = "";
  stepsBox.textContent = "Run an encryption or decryption to see each pair.";
};

// Show an empty table when the page opens
showTable(buildTable(""), "");
