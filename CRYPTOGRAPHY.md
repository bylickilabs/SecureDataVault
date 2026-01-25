# 🔐 Cryptography

## Algorithms

- Argon2id for password hashing
- AES-256-GCM for encryption
- HMAC-SHA256 for integrity

## Key Flow

Password → Argon2 → AES Key

## Vault

Encrypted JSON with attached HMAC signature.

No backdoors.
No recovery.
