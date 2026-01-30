import os
import json
import time
import sqlite3
import base64
import hashlib
import hmac
import webbrowser
from pathlib import Path
from datetime import datetime

import customtkinter as ctk
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tkinter import filedialog

APP_NAME = "Secure Data Vault"
APP_VERSION = "1.0.1"
APP_COMPANY = "©Bylickilabs Software Solutions"
APP_AUTHOR = "©Thorsten Bylicki"
GITHUB_URL = "https://github.com/bylickilabs"

BASE_DIR = Path(__file__).parent
DB_FILE = BASE_DIR / "auth.db"
VAULT_FILE = BASE_DIR / "vault.vault"

PASSWORD_HASHER = PasswordHasher()
SESSION_TIMEOUT = 300


def init_db():
    with sqlite3.connect(DB_FILE) as db:
        db.execute("CREATE TABLE IF NOT EXISTS auth (id INTEGER PRIMARY KEY, password_hash TEXT NOT NULL)")
        db.commit()


def has_password():
    with sqlite3.connect(DB_FILE) as db:
        return db.execute("SELECT 1 FROM auth LIMIT 1").fetchone() is not None


def store_password(password):
    hashed = PASSWORD_HASHER.hash(password)
    with sqlite3.connect(DB_FILE) as db:
        db.execute("DELETE FROM auth")
        db.execute("INSERT INTO auth (password_hash) VALUES (?)", (hashed,))
        db.commit()


def verify_password(password):
    with sqlite3.connect(DB_FILE) as db:
        row = db.execute("SELECT password_hash FROM auth LIMIT 1").fetchone()
        if not row:
            return False
        try:
            PASSWORD_HASHER.verify(row[0], password)
            return True
        except:
            return False


def derive_key(password, salt):
    return hash_secret_raw(password.encode(), salt, 4, 102400, 8, 32, Type.ID)


def encrypt_block(data, key):
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, data, None)
    sig = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    return nonce + ct + sig


def decrypt_block(blob, key):
    nonce = blob[:12]
    ct = blob[12:-32]
    sig = blob[-32:]
    exp = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, exp):
        raise ValueError("Integritätsfehler")
    return AESGCM(key).decrypt(nonce, ct, None)


class SecureVaultApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("900x650")
        self.resizable(False, False)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        init_db()

        self.key = None
        self.vault_salt = None
        self.vault_data = {}
        self.audit_log = []
        self.last_activity = time.time()

        self.container = ctk.CTkFrame(self)
        self.container.pack(fill="both", expand=True)

        self.show_login()
        self.after(1000, self.tick)


    def show_login(self):
        self.clear_container()
        frame = ctk.CTkFrame(self.container)
        frame.pack(expand=True)

        ctk.CTkLabel(frame, text=APP_NAME, font=("Segoe UI", 26, "bold")).pack(pady=10)
        ctk.CTkLabel(frame, text=f"{APP_COMPANY} • {APP_AUTHOR}", font=("Segoe UI", 12)).pack(pady=5)

        self.password_entry = ctk.CTkEntry(frame, show="*", width=320, placeholder_text="Masterpasswort")
        self.password_entry.pack(pady=8)

        if not has_password():
            self.confirm_entry = ctk.CTkEntry(frame, show="*", width=320, placeholder_text="Passwort bestätigen")
            self.confirm_entry.pack(pady=8)

        self.status_label = ctk.CTkLabel(frame, text="")
        self.status_label.pack(pady=5)

        ctk.CTkButton(frame, text="Tresor öffnen", command=self.handle_login, width=200).pack(pady=12)
        ctk.CTkButton(frame, text="GitHub", command=lambda: webbrowser.open(GITHUB_URL)).pack()


    def handle_login(self):
        password = self.password_entry.get().strip()
        if not password:
            return

        if not has_password():
            if password != self.confirm_entry.get():
                self.status_label.configure(text="Passwörter stimmen nicht überein")
                return
            store_password(password)

        if not verify_password(password):
            self.status_label.configure(text="Falsches Passwort")
            return

        if VAULT_FILE.exists():
            raw = VAULT_FILE.read_bytes()
            self.vault_salt = raw[:16]
            blob = raw[16:]
            self.key = derive_key(password, self.vault_salt)
            try:
                decrypted = decrypt_block(blob, self.key)
            except:
                self.status_label.configure(text="Beschädigter Tresor oder falsches Passwort")
                return

            vault = json.loads(decrypted)
            self.vault_data = vault["data"]
            self.audit_log = vault["audit"]
        else:
            self.vault_salt = os.urandom(16)
            self.key = derive_key(password, self.vault_salt)
            self.vault_data = {}
            self.audit_log = []

        self.log("Tresor geöffnet")
        self.show_main()


    def show_main(self):
        self.clear_container()
        self.last_activity = time.time()

        header = ctk.CTkFrame(self.container)
        header.pack(fill="x", pady=10)

        ctk.CTkLabel(header, text=f"{APP_NAME} – Tresor", font=("Segoe UI", 18, "bold")).pack(side="left", padx=10)

        ctk.CTkButton(header, text="Passwort ändern", command=self.change_pw).pack(side="right", padx=5)
        ctk.CTkButton(header, text="Audit Log", command=self.show_audit).pack(side="right", padx=5)
        ctk.CTkButton(header, text="GitHub", command=lambda: webbrowser.open(GITHUB_URL)).pack(side="right", padx=5)
        ctk.CTkButton(header, text="Info", command=self.show_info).pack(side="right", padx=5)


        self.search_entry = ctk.CTkEntry(self.container, placeholder_text="Suche…")
        self.search_entry.pack(fill="x", padx=20)
        self.search_entry.bind("<KeyRelease>", lambda e: self.refresh_list())

        self.file_box = ctk.CTkTextbox(self.container, height=350)
        self.file_box.pack(fill="both", padx=20, pady=10)
        self.refresh_list()

        bar = ctk.CTkFrame(self.container)
        bar.pack(pady=10)

        ctk.CTkButton(bar, text="Dateien hinzufügen", command=self.add_files).pack(side="left", padx=5)
        ctk.CTkButton(bar, text="Exportieren", command=self.export_selected).pack(side="left", padx=5)
        ctk.CTkButton(bar, text="Löschen", command=self.delete_selected).pack(side="left", padx=5)
        ctk.CTkButton(bar, text="Sperren", fg_color="#7a1c1c", command=self.lock).pack(side="right", padx=5)

        self.countdown_label = ctk.CTkLabel(self.container, text="")
        self.countdown_label.pack()


    def refresh_list(self):
        f = self.search_entry.get().lower()
        self.file_box.delete("1.0", "end")
        for name, meta in self.vault_data.items():
            if f in name.lower():
                self.file_box.insert("end", f"{name} | {meta['size']} Bytes | {meta['imported']}\n")


    def add_files(self):
        paths = filedialog.askopenfilenames()
        for p in paths:
            data = Path(p).read_bytes()
            self.vault_data[Path(p).name] = {
                "size": len(data),
                "imported": datetime.now().isoformat(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "content": base64.b64encode(data).decode()
            }
            self.log(f"Datei hinzugefügt: {Path(p).name}")

        self.save_vault()
        self.refresh_list()


    def export_selected(self):
        lines = self.file_box.get("1.0", "end").strip().split("\n")
        if not lines:
            return
        for line in lines:
            name = line.split("|")[0].strip()
            if name in self.vault_data:
                target = filedialog.asksaveasfilename(initialfile=name)
                if target:
                    Path(target).write_bytes(base64.b64decode(self.vault_data[name]["content"]))
                    self.log(f"Datei exportiert: {name}")
        self.save_vault()


    def delete_selected(self):
        cursor = self.file_box.index("insert").split(".")[0]
        line = self.file_box.get(f"{cursor}.0", f"{cursor}.end")
        name = line.split("|")[0].strip()
        if name in self.vault_data:
            del self.vault_data[name]
            self.log(f"Datei gelöscht: {name}")
            self.save_vault()
            self.refresh_list()


    def show_audit(self):
        win = ctk.CTkToplevel(self)
        win.title("Audit Log")
        win.geometry("700x500")
        box = ctk.CTkTextbox(win)
        box.pack(fill="both", expand=True)
        for entry in self.audit_log:
            box.insert("end", entry + "\n")


    def show_info(self):
        win = ctk.CTkToplevel(self)
        win.title("Informationen")
        win.geometry("600x500")

        box = ctk.CTkTextbox(win, width=580, height=460)
        box.pack(padx=10, pady=10, expand=True, fill="both")

        text = (
            f"{APP_NAME}\n"
            f"Version: {APP_VERSION}\n"
            f"Autor: {APP_AUTHOR}\n"
            f"Unternehmen: {APP_COMPANY}\n"
            f"GitHub: {GITHUB_URL}\n\n"
            "Diese Anwendung bietet einen verschlüsselten Datentresor, der sensible Dateien lokal schützt. "
            "Der Zugriff erfolgt über ein Masterpasswort. Dateien werden mit AES-256-GCM verschlüsselt. "
            "Zusätzlich wird ein HMAC genutzt, um die Integrität des Tresors sicherzustellen.\n\n"
            "Funktionen:\n"
            "• Tresor erstellen und öffnen\n"
            "• Dateien hinzufügen, exportieren und löschen\n"
            "• Audit-Log aller Aktionen\n"
            "• Passwort ändern\n"
            "• Dateisuche und Filter\n"
            "• Automatische Sperre mit Countdown\n"
            "• GitHub-Integration\n\n"
            "Technische Merkmale:\n"
            "• AES-GCM Verschlüsselung\n"
            "• Argon2id Key-Derivation\n"
            "• Integritätsschutz durch HMAC-SHA256\n"
            "• Lokale JSON-Struktur im verschlüsselten Tresor\n"
            "• Plattformunabhängiges Python-Desktop-UI\n\n"
            "Diese Anwendung wurde entwickelt, um professionelle Daten­sicherheit "
            "mit einer benutzerfreundlichen Oberfläche zu kombinieren."
        )

        box.insert("end", text)
        box.configure(state="disabled")

    def change_pw(self):
        win = ctk.CTkToplevel(self)
        win.title("Passwort ändern")
        win.geometry("400x250")

        e1 = ctk.CTkEntry(win, show="*", placeholder_text="Neues Passwort")
        e1.pack(pady=10)
        e2 = ctk.CTkEntry(win, show="*", placeholder_text="Wiederholen")
        e2.pack(pady=10)

        status = ctk.CTkLabel(win, text="")
        status.pack()

        def apply():
            if e1.get() != e2.get():
                status.configure(text="Nicht identisch")
                return

            pw = e1.get()
            store_password(pw)
            self.vault_salt = os.urandom(16)
            self.key = derive_key(pw, self.vault_salt)
            self.save_vault()
            self.log("Masterpasswort geändert")
            win.destroy()

        ctk.CTkButton(win, text="Ändern", command=apply).pack(pady=10)


    def log(self, text):
        self.audit_log.append(f"{datetime.now().isoformat()} – {text}")


    def save_vault(self):
        payload = json.dumps({"data": self.vault_data, "audit": self.audit_log}).encode()
        enc = encrypt_block(payload, self.key)
        VAULT_FILE.write_bytes(self.vault_salt + enc)


    def tick(self):
        if self.key:
            r = SESSION_TIMEOUT - int(time.time() - self.last_activity)
            if r <= 0:
                self.lock()
            else:
                try:
                    m, s = divmod(r, 60)
                    self.countdown_label.configure(text=f"Auto-Sperre in {m:02d}:{s:02d}")
                except:
                    pass
        self.after(1000, self.tick)



    def lock(self):
        self.save_vault()
        self.key = None
        self.show_login()


    def clear_container(self):
        for w in self.container.winfo_children():
            w.destroy()


if __name__ == "__main__":
    SecureVaultApp().mainloop()