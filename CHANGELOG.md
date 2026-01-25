# 📄 CHANGELOG – Secure Data Vault

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and Semantic Versioning.

---

## [1.0.1] – 2026-01-25

### Added
- HMAC-SHA256 integrity protection
- Audit Log Viewer
- Live file search / filter
- File deletion
- Multi-export functionality
- Password change dialog
- Session auto-lock countdown
- Info dialog
- Toolbar actions

### Changed
- Vault encryption architecture (block-based)
- Session management logic
- UI layout and window handling

### Security
- Added explicit vault integrity verification
- Improved error handling for corrupted vaults

---

## [1.0.0] – Initial Release

- Initial vault implementation
- AES-256-GCM encryption
- Argon2id key derivation
- File import/export
- Basic session locking
