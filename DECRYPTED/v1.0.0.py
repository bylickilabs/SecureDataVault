import os
import json
import time
import sqlite3
import base64
import hashlib
import webbrowser
from pathlib import Path
from datetime import datetime

import customtkinter as ctk
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


APP_NAME = "Secure Data Vault"
APP_VERSION = "1.0.0"
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
        db.execute("""
            CREATE TABLE IF NOT EXISTS auth (
                id INTEGER PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        """)
        db.commit()


def has_password() -> bool:
    with sqlite3.connect(DB_FILE) as db:
        return db.execute("SELECT 1 FROM auth LIMIT 1").fetchone() is not None


def store_password(password: str):
    pw_hash = PASSWORD_HASHER.hash(password)
    with sqlite3.connect(DB_FILE) as db:
        db.execute("DELETE FROM auth")
        db.execute(
            "INSERT INTO auth (password_hash) VALUES (?)",
            (pw_hash,)
        )
        db.commit()


def verify_password(password: str) -> bool:
    with sqlite3.connect(DB_FILE) as db:
        row = db.execute(
            "SELECT password_hash FROM auth LIMIT 1"
        ).fetchone()
    if not row:
        return False
    try:
        PASSWORD_HASHER.verify(row[0], password)
        return True
    except Exception:
        return False


def derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        password.encode(),
        salt,
        4,
        102400,
        8,
        32,
        Type.ID
    )


def encrypt(data: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def decrypt(blob: bytes, key: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class SecureVaultApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("900x600")
        self.minsize(900, 600)
        self.maxsize(900, 600)

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
        self.after(1000, self.check_timeout)


    def show_login(self):
        self.clear_container()

        frame = ctk.CTkFrame(self.container)
        frame.pack(expand=True)

        ctk.CTkLabel(
            frame,
            text=APP_NAME,
            font=("Segoe UI", 26, "bold")
        ).pack(pady=10)

        ctk.CTkLabel(
            frame,
            text=f"{APP_COMPANY} • {APP_AUTHOR}",
            font=("Segoe UI", 12)
        ).pack(pady=5)

        self.password_entry = ctk.CTkEntry(
            frame,
            show="*",
            width=320,
            placeholder_text="Masterpasswort"
        )
        self.password_entry.pack(pady=8)

        if not has_password():
            self.confirm_entry = ctk.CTkEntry(
                frame,
                show="*",
                width=320,
                placeholder_text="Passwort bestätigen"
            )
            self.confirm_entry.pack(pady=8)

        self.status_label = ctk.CTkLabel(frame, text="")
        self.status_label.pack(pady=5)

        ctk.CTkButton(
            frame,
            text="Tresor öffnen",
            command=self.handle_login,
            width=200
        ).pack(pady=12)

        ctk.CTkButton(
            frame,
            text="GitHub",
            command=lambda: webbrowser.open(GITHUB_URL),
            width=120
        ).pack(pady=5)

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
            nonce = raw[16:28]
            ciphertext = raw[28:]

            self.key = derive_key(password, self.vault_salt)
            try:
                decrypted = AESGCM(self.key).decrypt(nonce, ciphertext, None)
            except Exception:
                self.status_label.configure(text="Tresor beschädigt oder falsches Passwort")
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

        ctk.CTkLabel(
            header,
            text=f"{APP_NAME} – Tresor",
            font=("Segoe UI", 18, "bold")
        ).pack(side="left", padx=10)

        ctk.CTkButton(
            header,
            text="GitHub",
            command=lambda: webbrowser.open(GITHUB_URL),
            width=80
        ).pack(side="right", padx=10)

        self.file_box = ctk.CTkTextbox(self.container, height=350)
        self.file_box.pack(fill="x", padx=20, pady=10)
        self.refresh_list()

        bar = ctk.CTkFrame(self.container)
        bar.pack(pady=10)

        ctk.CTkButton(bar, text="Dateien hinzufügen", command=self.add_files).pack(side="left", padx=5)
        ctk.CTkButton(bar, text="Exportieren", command=self.export_file).pack(side="left", padx=5)
        ctk.CTkButton(bar, text="Sperren", fg_color="#7a1c1c", command=self.lock).pack(side="left", padx=5)


    def add_files(self):
        from tkinter import filedialog
        paths = filedialog.askopenfilenames()
        for p in paths:
            data = Path(p).read_bytes()
            self.vault_data[Path(p).name] = {
                "size": len(data),
                "imported": datetime.now().isoformat(),
                "sha256": sha256(data),
                "content": base64.b64encode(data).decode()
            }
            self.log(f"Datei hinzugefügt: {Path(p).name}")
        self.save_vault()
        self.refresh_list()

    def export_file(self):
        from tkinter import filedialog
        name = self.file_box.get("insert linestart", "insert lineend").split("|")[0].strip()
        if name not in self.vault_data:
            return
        target = filedialog.asksaveasfilename(initialfile=name)
        if target:
            Path(target).write_bytes(
                base64.b64decode(self.vault_data[name]["content"])
            )
            self.log(f"Datei exportiert: {name}")


    def save_vault(self):
        payload = json.dumps({
            "data": self.vault_data,
            "audit": self.audit_log
        }).encode()

        nonce = os.urandom(12)
        encrypted = AESGCM(self.key).encrypt(nonce, payload, None)
        VAULT_FILE.write_bytes(self.vault_salt + nonce + encrypted)

    def refresh_list(self):
        self.file_box.delete("1.0", "end")
        for name, meta in self.vault_data.items():
            self.file_box.insert(
                "end",
                f"{name} | {meta['size']} Bytes | {meta['imported']}\n"
            )


    def log(self, text: str):
        self.audit_log.append(
            f"{datetime.now().isoformat()} – {text}"
        )

    def check_timeout(self):
        if self.key and time.time() - self.last_activity > SESSION_TIMEOUT:
            self.lock()
        self.after(1000, self.check_timeout)

    def lock(self):
        self.save_vault()
        self.key = None
        self.show_login()


    def clear_container(self):
        for w in self.container.winfo_children():
            w.destroy()


if __name__ == "__main__":
    SecureVaultApp().mainloop()