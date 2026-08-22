# CIPHER/BENCH
A client-side cryptography toolkit for symmetric encryption, asymmetric encryption, digital signatures, and hashing. 

![status](https://img.shields.io/badge/status-portfolio_project-blue) ![deps](https://img.shields.io/badge/dependencies-1_(CDN)-lightgrey) ![license](https://img.shields.io/badge/license-MIT-green)

---

## Features

| Module | What it does |
|---|---|
| Text cipher | AES-256-GCM encrypt/decrypt, password-based |
| File cipher | Same thing, applied to files (up to 500 MB, in-memory) |
| Asymmetric keys | RSA-OAEP & ECDH keypair generation, hybrid encrypt/decrypt |
| Digital signatures | RSA-PSS & ECDSA, with timestamp + nonce replay protection |
| Hashing | SHA-256/384/512, plus a compare field to verify against a known hash |

## Structure

```
index.html   → markup only
style.css   → all styling
script.js       → all logic 
```

## Stack

- Web Crypto API 
- hash-wasm for Argon2id (WASM, client-side)
- HTML/CSS/JS.

## License

MIT — see [LICENSE](./LICENSE).
