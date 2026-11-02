# TP SSAD – Encryption and Security Framework

Open `index.html` in a browser. No installation needed.

| File | Content |
|---|---|
| `Authentification/login.html` + `Authentification/login.js` + `Authentification/auth.js` + `Authentification/emailjs-config.js` | Account creation, login, and password reset |
| `Encryption/chiffrement.html` + `Encryption/ciphers.js` + `Encryption/chiffrement.js` | Encrypt and decrypt messages with Caesar, Hill, or Playfair |
| `Passwords/password.html` + `Passwords/password.js` + `Passwords/pwdciphers.js` | Password generation, attacks, cipher demos, and protections |
| `Integrity/integrite.html` + `Integrity/integrite.js` | 16-bit checksum integrity check using the shared Caesar, Hill, and Playfair ciphers |
| `index.html`, `script.js`, `style.css`, `Images/logo.png` | Shared home page, scripts, styles, and logo |

## Password page
- Create and validate the 3 password types, with the Type 3 combination count displayed dynamically.
- Configure Caesar, Hill, or Playfair and a user-provided key for the attack demonstrations; targets and candidate passwords are encrypted with the same settings before comparison.
- Dedicated dictionary and brute-force attack interfaces, plus protection demonstrations.
- A dedicated dictionary-attack interface with a custom word list, early-exit search, and attempted-word preview.
- Protection demonstrations for common-password checks and rate-limited login attempts.
