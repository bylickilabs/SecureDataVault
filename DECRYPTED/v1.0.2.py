import os
import json
import time
import sqlite3
import base64
import hashlib
import hmac
import webbrowser
import io
from pathlib import Path
from datetime import datetime
from tkinter import filedialog

import customtkinter as ctk
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image

APP_NAME = "Secure Data Vault"
APP_VERSION = "1.0.2"
APP_COMPANY = "©Bylickilabs Software Solutions"
APP_AUTHOR = "©Thorsten Bylicki"
GITHUB_URL = "https://github.com/bylickilabs"

BASE_DIR = Path(__file__).parent
DB_FILE = BASE_DIR / "auth.db"
VAULT_FILE = BASE_DIR / "vault.vault"

SESSION_TIMEOUT = 300
PASSWORD_HASHER = PasswordHasher()

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
    chk = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, chk):
        raise ValueError("Integrity error")
    return AESGCM(key).decrypt(nonce, ct, None)

def init_db():
    with sqlite3.connect(DB_FILE) as db:
        db.execute("CREATE TABLE IF NOT EXISTS auth (id INTEGER PRIMARY KEY, password_hash TEXT)")
        db.commit()

def has_password():
    with sqlite3.connect(DB_FILE) as db:
        return db.execute("SELECT 1 FROM auth").fetchone() is not None

def store_password(pw):
    h = PASSWORD_HASHER.hash(pw)
    with sqlite3.connect(DB_FILE) as db:
        db.execute("DELETE FROM auth")
        db.execute("INSERT INTO auth(password_hash) VALUES (?)", (h,))
        db.commit()

def verify_password(pw):
    with sqlite3.connect(DB_FILE) as db:
        row = db.execute("SELECT password_hash FROM auth").fetchone()
        if not row:
            return False
        try:
            PASSWORD_HASHER.verify(row[0], pw)
            return True
        except:
            return False

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
        self.recycle_bin = {}
        self.audit_log = []

        self.last_activity = time.time()

        self.container = ctk.CTkFrame(self)
        self.container.pack(fill="both", expand=True)

        self.bind_all("<Any-KeyPress>", lambda e: self.touch())
        self.bind_all("<Any-Button>", lambda e: self.touch())

        self.show_login()
        self.after(1000, self.tick)

    def touch(self):
        self.last_activity = time.time()

    def show_login(self):
        self.clear_container()

        frame = ctk.CTkFrame(self.container)
        frame.pack(expand=True)

        ctk.CTkLabel(frame, text=APP_NAME, font=("Segoe UI", 26, "bold")).pack(pady=10)
        ctk.CTkLabel(frame, text=f"{APP_COMPANY} • {APP_AUTHOR}").pack()

        self.password_entry = ctk.CTkEntry(frame, show="*", width=320)
        self.password_entry.pack(pady=8)

        if not has_password():
            self.confirm_entry = ctk.CTkEntry(frame, show="*", width=320)
            self.confirm_entry.pack(pady=8)

        self.status = ctk.CTkLabel(frame, text="")
        self.status.pack()

        ctk.CTkButton(frame, text="Tresor öffnen", command=self.login).pack(pady=10)
        ctk.CTkButton(frame, text="GitHub", command=lambda: webbrowser.open(GITHUB_URL)).pack()

    def login(self):
        pw = self.password_entry.get().strip()
        if not pw:
            return

        if not has_password():
            if pw != self.confirm_entry.get():
                self.status.configure(text="Passwörter stimmen nicht überein")
                return
            store_password(pw)

        if not verify_password(pw):
            self.status.configure(text="Falsches Passwort")
            return

        if VAULT_FILE.exists():
            raw = VAULT_FILE.read_bytes()
            self.vault_salt = raw[:16]
            obj = json.loads(decrypt_block(raw[16:], derive_key(pw, self.vault_salt)))
            self.vault_data = obj.get("data", {})
            self.recycle_bin = obj.get("recycle", {})
            self.audit_log = obj.get("audit", [])
        else:
            self.vault_salt = os.urandom(16)

        self.key = derive_key(pw, self.vault_salt)

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

        bar = ctk.CTkFrame(self.container)
        bar.pack(pady=10)

        ctk.CTkButton(bar, text="Dateien", command=self.add_files).pack(side="left", padx=5)
        ctk.CTkButton(bar, text="Ordner", command=self.add_folder).pack(side="left", padx=5)
        ctk.CTkButton(bar, text="Vorschau", command=self.preview_selected).pack(side="left", padx=5)
        ctk.CTkButton(bar, text="Export", command=self.export_selected).pack(side="left", padx=5)
        ctk.CTkButton(bar, text="Löschen", command=self.delete_selected).pack(side="left", padx=5)
        ctk.CTkButton(bar, text="Sperren", fg_color="#7a1c1c", command=self.lock).pack(side="right", padx=5)

        self.countdown_label = ctk.CTkLabel(self.container, text="")
        self.countdown_label.pack()

        self.refresh_list()

    def refresh_list(self):
        f = self.search_entry.get().lower()
        self.file_box.delete("1.0", "end")
        for name, meta in self.vault_data.items():
            if f in name.lower():
                self.file_box.insert("end", f"{name} | {meta['size']} Bytes | {meta['imported']}\n")


    def add_blob(self, name, raw):
        sha = hashlib.sha256(raw).hexdigest()
        if any(v["sha256"] == sha for v in self.vault_data.values()):
            return

        self.vault_data[name] = {
            "size": len(raw),
            "imported": datetime.now().isoformat(),
            "sha256": sha,
            "content": base64.b64encode(raw).decode()
        }

        self.log(f"Datei hinzugefügt: {name}")

    def add_files(self):
        for p in filedialog.askopenfilenames():
            self.add_blob(Path(p).name, Path(p).read_bytes())
        self.save_vault()

    def add_folder(self):
        root = filedialog.askdirectory()
        if not root:
            return
        for r, _, files in os.walk(root):
            for f in files:
                p = Path(r) / f
                self.add_blob(p.name, p.read_bytes())
        self.save_vault()

    def selected_name(self):
        line = self.file_box.get("insert linestart", "insert lineend")
        return line.split("|")[0].strip()

    def preview_selected(self):
        name = self.selected_name()
        if name not in self.vault_data:
            return

        raw = base64.b64decode(self.vault_data[name]["content"])

        win = ctk.CTkToplevel(self)
        win.title(name)
        win.geometry("600x500")

        try:
            txt = raw.decode()
            box = ctk.CTkTextbox(win)
            box.pack(fill="both", expand=True)
            box.insert("end", txt)
            box.configure(state="disabled")
            return
        except:
            pass

        try:
            img = Image.open(io.BytesIO(raw))
            img.thumbnail((560,460))
            photo = ctk.CTkImage(light_image=img, dark_image=img, size=img.size)
            lbl = ctk.CTkLabel(win, image=photo, text="")
            lbl.image = photo
            lbl.pack(expand=True)
        except:
            ctk.CTkLabel(win, text="Keine Vorschau verfügbar").pack(pady=20)

    def export_selected(self):
        name = self.selected_name()
        if name not in self.vault_data:
            return

        tgt = filedialog.asksaveasfilename(initialfile=name)
        if tgt:
            Path(tgt).write_bytes(base64.b64decode(self.vault_data[name]["content"]))
            self.log(f"Exportiert: {name}")
            self.save_vault()

    def delete_selected(self):
        name = self.selected_name()
        if name in self.vault_data:
            self.recycle_bin[name] = self.vault_data[name]
            del self.vault_data[name]
            self.log(f"In Papierkorb: {name}")
            self.save_vault()

    def show_audit(self):
        win = ctk.CTkToplevel(self)
        win.geometry("700x500")
        box = ctk.CTkTextbox(win)
        box.pack(fill="both", expand=True)
        for a in self.audit_log:
            box.insert("end", a + "\n")

    def show_info(self):
        win = ctk.CTkToplevel(self)
        win.geometry("600x500")
        box = ctk.CTkTextbox(win)
        box.pack(fill="both", expand=True)
        box.insert("end", f"{APP_NAME}\nVersion {APP_VERSION}\n{APP_AUTHOR}\n{APP_COMPANY}")
        box.configure(state="disabled")

    def change_pw(self):
        win = ctk.CTkToplevel(self)
        win.geometry("350x220")
        e1 = ctk.CTkEntry(win, show="*")
        e2 = ctk.CTkEntry(win, show="*")
        e1.pack(pady=10)
        e2.pack(pady=10)

        def apply():
            if e1.get() != e2.get():
                return
            store_password(e1.get())
            self.vault_salt = os.urandom(16)
            self.key = derive_key(e1.get(), self.vault_salt)
            self.log("Passwort geändert")
            self.save_vault()
            win.destroy()

        ctk.CTkButton(win, text="Übernehmen", command=apply).pack()

    def log(self, txt):
        self.audit_log.append(f"{datetime.now().isoformat()} – {txt}")

    def save_vault(self):
        payload = json.dumps({
            "version": APP_VERSION,
            "data": self.vault_data,
            "recycle": self.recycle_bin,
            "audit": self.audit_log
        }).encode()

        VAULT_FILE.write_bytes(self.vault_salt + encrypt_block(payload, self.key))
        self.refresh_list()

    def tick(self):
        if self.key:
            r = SESSION_TIMEOUT - int(time.time() - self.last_activity)
            if r <= 0:
                self.lock()
            else:
                m,s = divmod(r,60)
                self.countdown_label.configure(text=f"Auto-Sperre in {m:02d}:{s:02d}")
        self.after(1000, self.tick)

    def lock(self):
        if self.key:
            self.save_vault()
        self.key = None
        self.show_login()


    def clear_container(self):
        for w in self.container.winfo_children():
            w.destroy()

if __name__ == "__main__":
    SecureVaultApp().mainloop()
