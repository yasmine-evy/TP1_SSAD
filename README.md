# TP SSAD – Encryption and Security Framework

Open `index.html` in a browser. No installation needed.

| File | Content |
|---|---|
| `chiffrement.html` + `ciphers.js` + `chiffrement.js` | One page: write a message, choose the algorithm (Caesar / Hill / Playfair) to encrypt, then choose the algorithm to decrypt |
| `password.html` + `password.js` | Passwords: 3 tabs (1. Passwords, 2. Brute Force, 3. Dictionary) |

## Password page
- Creation / validation of the 3 types, number of combinations (8, 256, 64^n), and tests of dictionary and brute-force attacks with measured times.
- A dedicated dictionary-attack interface with a custom word list, early-exit search, and attempted-word preview.
- Protection demonstrations: salted SHA-256 hashing and common-password warnings at creation time.
