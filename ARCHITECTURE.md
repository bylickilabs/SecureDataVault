# 🏗️ Architecture

Secure Data Vault is a local-first encrypted desktop application.

## Core Components

- UI Layer (CustomTkinter)
- Auth Database (SQLite)
- Vault Storage (Encrypted File)
- Crypto Engine

## Flow

User → Login → Key Derivation → Vault Decrypt → UI Operations → Encrypt → Save

## Data Storage

auth.db: stores Argon2 password hash  
vault.vault: encrypted JSON payload

## Design Principles

- Offline-first
- Zero cloud dependencies
- Explicit security boundaries
