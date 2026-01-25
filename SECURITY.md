# 🔐 Secure Data Vault

## Sicherheitsrichtlinie

Dieses Dokument beschreibt das Sicherheitsmodell, die Meldewege für Schwachstellen sowie empfohlene Best Practices für den Betrieb von Secure Data Vault.
Secure Data Vault ist als **lokale Offline-Sicherheitsanwendung** konzipiert. Es existiert keine aktive Netzwerkkommunikation innerhalb der Anwendung.

---

## 📌 Verantwortungsbereich

Secure Data Vault verfolgt ein *Offline-First*-Prinzip:

- Keine Cloud-Anbindung
- Keine Telemetrie
- Keine Hintergrunddienste
- Keine externen APIs

Alle Daten verbleiben ausschließlich auf dem lokalen System des Nutzers.

Der Anwender trägt die vollständige Verantwortung für:

- Datensicherung
- Passwortverwaltung
- Systemintegrität
- Zugriffsschutz auf Betriebssystemebene

---

## 🔑 Kryptografisches Design

Secure Data Vault verwendet etablierte Industriestandards:

| Bereich | Technologie |
|-------|------------|
| Passwort-Hashing | Argon2id |
| Schlüsselableitung | Argon2 Low-Level |
| Verschlüsselung | AES-256-GCM |
| Integrität | HMAC-SHA256 |
| Salt | 128 Bit zufällig |
| Nonce | 96 Bit zufällig |
| Vault Format | JSON Payload + AES Block + HMAC |

### Architektur

1. Masterpasswort → Argon2id Hash (SQLite)
2. Masterpasswort + Salt → symmetrischer AES-Schlüssel
3. Vault-Payload → AES-256-GCM Verschlüsselung
4. Ciphertext → HMAC-SHA256 Signatur

Manipulierte Tresore werden vor der Entschlüsselung erkannt.

---

## 🧾 Auditierung

Alle sicherheitsrelevanten Aktionen werden protokolliert:

- Tresor öffnen
- Datei importieren
- Datei exportieren
- Datei löschen
- Passwort ändern
- Sperrvorgänge

Das Audit-Log ist Bestandteil des verschlüsselten Tresors.

---

## ⏱️ Session-Sicherheit

- Automatische Sperre nach Inaktivität (Standard: 300 Sekunden)
- Countdown-Anzeige
- Explizite Sperrfunktion
- Schlüssel wird aus dem Speicher entfernt

---

## 🚨 Bedrohungsmodell

Abgedeckte Szenarien:

- Offline-Dateimanipulation
- Brute-Force auf Vault-Datei
- Integritätsverletzung
- Unbefugter Zugriff bei unbeaufsichtigter Session

Nicht abgedeckt:

- Keylogger
- kompromittierte Betriebssysteme
- RAM-Dumps
- Hardware-Angriffe
- Social Engineering

Secure Data Vault ist kein Ersatz für ein sicheres Betriebssystem.

---

## 🛑 Passwort-Wiederherstellung

Aus Sicherheitsgründen existiert **keine Passwort-Reset-Funktion**.

Vergessene Masterpasswörter führen zum vollständigen Datenverlust.

Dies ist eine bewusste Designentscheidung.

---

## 📦 Updates

Derzeit existiert kein Auto-Update-Mechanismus.

Neue Versionen werden ausschließlich über GitHub veröffentlicht.

Empfohlene Vorgehensweise:

1. Backup von vault.vault
2. Update der Anwendung
3. Test in isolierter Umgebung

---

## 🧪 Responsible Disclosure

Falls du eine Sicherheitslücke findest:

Bitte KEINE öffentlichen Issues erstellen.

Stattdessen verantwortungsvoll melden:

📧 bylicki@mail.de

Erforderliche Angaben:

- Beschreibung der Schwachstelle
- Reproduktionsschritte
- betroffene Version
- Proof of Concept (falls vorhanden)

Du erhältst innerhalb von 72 Stunden eine Rückmeldung.

---

## 🛠️ Best Practices

- Verwende ein starkes, einzigartiges Masterpasswort
- Aktiviere OS-Festplattenverschlüsselung
- Sichere vault.vault regelmäßig extern
- Sperre die Anwendung bei Verlassen des Arbeitsplatzes
- Halte dein Betriebssystem aktuell

---

## ⚠️ Haftungsausschluss

Diese Software wird ohne Garantie bereitgestellt.

Der Autor übernimmt keine Haftung für Datenverlust, Sicherheitsvorfälle oder Fehlkonfigurationen.

---

## 👨‍💻 Maintainer

Thorsten Bylicki  
Bylickilabs Software Solutions  

GitHub: https://github.com/bylickilabs
