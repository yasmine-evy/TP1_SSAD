# TP SSAD – Encryption and Security Framework

Open `index.html` in a browser. No installation needed.

| File | Content |
|---|---|
| `chiffrement.html` + `ciphers.js` + `chiffrement.js` | Write a message, encrypt it with Caesar / Hill / Playfair, then decrypt it |
| `password.html` + `password.js` + `pwdciphers.js` | Passwords: the 3 types, protection with Caesar / Hill / Playfair, dictionary and brute-force attacks |

## Password page
- Creation / validation of the 3 password types (8, 256 and 64^n combinations), with a warning above the field when the password does not respect its type. Type 3 accepts only passwords of exactly the chosen Length (also in the attacks).
- Dictionary and brute-force attacks on an **encrypted** password. The attacker chooses the algorithm: Caesar, Hill or Playfair.
  Caesar works like in the message page (alphabets a-z and A-Z, key 1 to 25, left/right; 26 gives an error; digits, + and * unchanged).
  Hill and Playfair work modulo the alphabet of the type (`pwdciphers.js`). Times are measured in the browser.
- Protections: common-password check and login attempt limits (browser demonstration only).
- This is **encryption (reversible), not hashing**. Real systems store a salted hash (bcrypt, Argon2).
