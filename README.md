# Secrets Vault 🔐🦀

A lightweight, memory-safe encrypted secrets vault and key management engine written in **Rust**.

Built with **Argon2id** password-based key derivation, **ChaCha20-Poly1305** authenticated symmetric encryption, and automatic memory zeroization via the `zeroize` crate to prevent secrets leakage in RAM.

---

## 🛡️ Security Features

- **Argon2id Key Derivation**: High memory-hard protection against brute-force and GPU/ASIC attacks.
- **Authenticated Encryption**: ChaCha20-Poly1305 AEAD ensures confidentiality and cryptographic integrity.
- **Memory Zeroization**: Internal key buffers implement `Zeroize` to scrub sensitive keying material from memory upon drop.
- **Portable Vault File**: Stores serialized ciphertext, unique 128-bit salt, and 96-bit nonce in an encrypted JSON container.

---

## 📂 Project Structure

```text
secrets-vault/
├── Cargo.toml             # Rust package configuration
├── src/
│   ├── lib.rs             # Core API exports
│   ├── crypto.rs          # Argon2id + ChaCha20-Poly1305 primitives
│   ├── vault.rs           # Key-value secret storage & serialization
│   └── main.rs            # CLI interface (set, get, list)
└── README.md              # Technical documentation
```

---

## 🚀 Usage

### Set a Secret:
```bash
cargo run -- set --key DB_PASSWORD --value "super-secret-pass" --vault ./app.vault
```

### Retrieve a Secret:
```bash
cargo run -- get --key DB_PASSWORD --vault ./app.vault
```

---

## 📜 License
MIT License • Built by [Lazarus Ebi](https://github.com/0xlazorr)
