# 🔐 Secure Data Vault
**Author:** ©Thorsten  Bylicki <br>
**Company:** ©BYLICKILABS  
**App ID / Name:** `🔐 SecureDataVault`  
**Version:** `1.0.0`  
**Date:** `01/24/2026` <br>
**APP Language:** `DE` <br>
**README:** `DE` <br>

| ![](assets/logo.png) |
|---|

**Secure Data Vault** ist eine lokal betriebene Desktop-Anwendung zur sicheren Speicherung sensibler Dateien.  
Der Fokus liegt auf **starker Kryptografie**, **klarer Benutzerführung** und **vollständiger Offline-Nutzung**.

---

## 🎯 Zielsetzung

Diese Anwendung wurde entwickelt, um vertrauliche Dateien zuverlässig zu schützen – ohne Cloud-Abhängigkeiten, ohne externe Dienste und mit vollständiger Kontrolle durch den Nutzer.

---

## ✨ Funktionen

- 🔑 Masterpasswort-basierte Authentifizierung (Argon2)
- 🔒 AES-256-GCM Verschlüsselung des Tresorinhalts
- 🗄️ Lokale, verschlüsselte Tresordatei (`vault.vault`)
- 📁 Import & Export beliebiger Dateien
- 🧾 Audit-Log aller sicherheitsrelevanten Aktionen
- ⏱️ Automatische Sitzungs­sperre bei Inaktivität
- 🌙 Moderne Dark-UI (CustomTkinter)

---

## 🛡️ Sicherheitskonzept (Kurzfassung)

| Komponente          | Technologie |
|--------------------|------------|
| Passwort-Hashing    | Argon2id |
| Schlüsselableitung  | Argon2 (Low Level) |
| Verschlüsselung     | AES-256-GCM |
| Datenhaltung        | Lokal (SQLite + Vault-Datei) |
| Netzwerk            | Keine Netzwerkkommunikation |

> **Hinweis:** Ohne das Masterpasswort ist eine Wiederherstellung der Daten technisch nicht möglich.

---

## 🖥️ Voraussetzungen

- Python **3.10 oder neuer**
- Unterstützte Betriebssysteme: Windows (getestet), Linux / macOS (theoretisch)

### Benötigte Python-Pakete

```bash
pip install customtkinter argon2-cffi cryptography
```

---

## 🚀 Installation & Start

```bash
git clone https://github.com/bylickilabs/SecureDataVault.git
cd SecureDataVault
python app.py
```

Beim ersten Start wirst du aufgefordert, ein Masterpasswort zu vergeben.

---

## 📂 Projektstruktur

```text
.
├── app.py           # Hauptanwendung
├── auth.db          # Passwort-Hash (lokal)
├── vault.vault      # Verschlüsselter Tresor
└── README.md
```

---

## 📸 Benutzeroberfläche

- Login mit Masterpasswort
- Dateiübersicht mit Metadaten
- Ein-Klick-Import & Export
- Sperrfunktion mit automatischem Timeout

---

## ⚠️ Haftungsausschluss

Diese Software wird **ohne Garantie** bereitgestellt.  
Der Autor übernimmt keine Haftung für Datenverlust durch falsche Bedienung oder vergessene Passwörter.

---

## 👨‍💻 Autor

**Thorsten Bylicki**  
Bylickilabs Software Solutions

🔗 GitHub: https://github.com/bylickilabs

---

## 📜 Lizenz

Dieses Projekt ist aktuell **nicht explizit lizenziert**.  
Bitte kontaktiere den Autor vor kommerzieller Nutzung.
