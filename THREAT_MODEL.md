# 🚨 Threat Model

## Assets
- User files
- Master password
- Vault integrity

## Threats
- Offline tampering
- Brute force
- Unauthorized access

## Mitigations
- Argon2id hashing
- AES-256-GCM encryption
- HMAC integrity
- Session auto-lock

## Out of Scope
- Compromised OS
- Hardware attacks
- Keyloggers
