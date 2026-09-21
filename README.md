# CIPHER/BENCH
A client-side cryptography toolkit for symmetric encryption, asymmetric encryption, digital signatures, and hashing. 

![status](https://img.shields.io/badge/status-portfolio_project-blue) ![deps](https://img.shields.io/badge/dependencies-1_(CDN)-lightgrey) ![license](https://img.shields.io/badge/license-MIT-green)

## Features

| Module | What it does |
|---|---|
| Text cipher | AES-256-GCM encrypt/decrypt, password-based |
| File cipher | Same thing, applied to files (up to 500 MB, in-memory) |
| Asymmetric keys | RSA-OAEP & ECDH keypair generation, hybrid encrypt/decrypt |
| Digital signatures | RSA-PSS & ECDSA, with timestamp + nonce replay protection |
| Hashing | SHA-256/384/512, plus a compare field to verify against a known hash |

## Stack

— Web Crypto API<br>
— hash-wasm for Argon2id (WASM, client-side)<br>
— Vanilla JavaScript

## How to use

### Encrypt text with a password

1. Open the **Text** tab.
2. Choose a password. This is not saved anywhere. You'll need to remember it because it's the only way to decrypt the message later.
3. Type your message and click **Run cipher**.
4. You'll get back a base64 text. That's your encrypted message.
5. To read it again, switch to **Decrypt** mode, paste that same block back in, enter the same password, and run it.

### Encrypt a file with a password

1. Open the **File** tab.
2. Choose a password and select a file.
3. Click **Run cipher** — this downloads a new file ending in `.enc`. The original file isn't modified.
4. To recover it, switch to **Decrypt** mode, select the `.enc` file, enter the same password, and run it. The original filename is restored automatically.

### Send someone an encrypted message without agreeing on a password first

This uses **public/private key pairs** instead of a shared password. In short: your *public* key can be given to anyone and only encrypts messages *to* you; your *private* key stays secret and is the only thing that can decrypt them.

1. Open the **Keys** tab, under **Generate**.
2. Pick an algorithm. ECDH P-256 is the default algorithm.
3. Click **Generate key pair**. You'll get two blocks of text: a public key and a private key.
4. Save the private key somewhere safe (it's never stored by this tool). Share the public key with whoever will be sending you messages.
5. The sender pastes your public key and their message into **Encrypt to recipient**, and sends you the resulting encrypted text.
6. You paste that encrypted text and your private key into **Decrypt with my key** to read it.

### Prove a message really came from you

This uses a *different* key pair than encryption, one built for signing, not encrypting.

1. Open **Keys → Generate**, and this time pick an algorithm from the **Signing** group. ECDSA P-256 is the default algorithm.
2. Generate a key pair as before. Keep the private key; share the public key.
3. Go to **Sign message**, paste your private key and the message you want to sign, and click **Sign**. You'll get a "signed package", this bundles your message with a timestamp and a proof that only you could have produced.
4. Send that signed package (and your public key) to whoever needs to verify it.
5. They go to **Verify signature**, paste your public key and the signed package, and click **Verify**. It confirms the message is genuinely yours and unaltered, and also flags it if it's too old or has already been checked once before in that session.

### Check that a file or piece of text hasn't been altered

1. Open the **Hash** tab and pick an algorithm.
2. Provide either text or a file. Click **Compute hash**.
3. You'll get a short string (a "hash" or "digest") that uniquely represents that exact content — if even one character changes, the hash changes completely.
4. If you already have a hash to check against, paste it into the compare field and it'll tell you whether they match.

**A couple of things to keep in mind:** nothing you generate here — passwords, keys, messages — is saved anywhere. If you close the tab, it's gone, so copy or download anything you'll need again before you navigate away.

## Known limitations

— **No persistence.** Closing the tab discards all state, including generated key pairs. There is no key-storage feature, since that would introduce a storage mechanism to secure, which is outside the scope of a stateless tool.<br>
— **Replay protection is session-only.** It detects replays within the same browser tab and nothing beyond that.<br>
— **Files are capped at 500 MB**, since they are buffered fully in memory rather than streamed.

## License

MIT — see [LICENSE](./LICENSE).
