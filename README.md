# TP SSAD – Encryption and Security Framework

Open `index.html` in a browser. No installation needed.

| File | Content |
|---|---|
| `chiffrement.html` + `ciphers.js` + `chiffrement.js` | One page: write a message, choose the algorithm (Caesar / Hill / Playfair) to encrypt, then choose the algorithm to decrypt |
| `password.html` + `password.js` | Passwords: 3 tabs (1. Passwords, 2. Brute Force, 3. Dictionary) |

## Password page
- Create and validate the 3 password types, with the Type 3 combination count displayed dynamically.
- Configure Caesar, Hill, or Playfair and a user-provided key for the attack demonstrations; targets and candidate passwords are encrypted with the same settings before comparison.
- Dedicated dictionary and brute-force attack interfaces, plus protection demonstrations.
- A dedicated dictionary-attack interface with a custom word list, early-exit search, and attempted-word preview.
- Protection demonstrations: salted SHA-256 hashing and common-password warnings at creation time.
