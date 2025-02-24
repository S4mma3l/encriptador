import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import json

import ttkthemes  # Importa la librería ttkthemes
from tkinter import ttk  # Importa ttk

class KeyManager:
    def __init__(self, master):
        self.master = master
        master.title("Gestor de Claves.pem")
        master.geometry("500x400")
        master.resizable(True, True)

        # Aplica el tema 'plastik'
        style = ttkthemes.ThemedStyle(master)
        style.set_theme("plastik")

        self.keys = {}
        self.load_keys()

        # Marco para la clave maestra
        master_key_frame = ttk.LabelFrame(master, text="Clave Maestra")
        master_key_frame.pack(padx=20, pady=20, fill="both", expand=True)
        ttk.Button(master_key_frame, text="Establecer Clave Maestra", command=self.set_master_key).pack(pady=10)  # Usa ttk.Button

        # Marco para cifrar/descifrar claves
        actions_frame = ttk.LabelFrame(master, text="Acciones")
        actions_frame.pack(padx=20, pady=10, fill="both", expand=True)
        ttk.Button(actions_frame, text="Cifrar Clave.pem", command=self.encrypt_key).pack(pady=10)  # Usa ttk.Button
        ttk.Button(actions_frame, text="Descifrar Clave.pem", command=self.decrypt_key).pack(pady=10)  # Usa ttk.Button
        ttk.Button(actions_frame, text="Mostrar Claves", command=self.show_keys).pack(pady=10)  # Usa ttk.Button


    def set_master_key(self):
        password = simpledialog.askstring("Clave Maestra", "Introduce la clave maestra:", show='*')
        if password:
            confirm_password = simpledialog.askstring("Confirmar Clave Maestra", "Confirma la clave maestra:", show='*')
            if password == confirm_password:
                self.master_password = password
                messagebox.showinfo("Clave Maestra", "Clave maestra establecida correctamente.")
            else:
                messagebox.showerror("Error", "Las contraseñas no coinciden.")
        else:
            messagebox.showerror("Error", "No se proporcionó ninguna contraseña.")

    def derive_key(self, password, salt=None):
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def encrypt_key(self):
        if not hasattr(self, 'master_password'):
            messagebox.showerror("Error", "Establece la clave maestra primero.")
            return

        file_path = filedialog.askopenfilename(title="Selecciona la clave .pem a cifrar")
        if file_path:
            try:
                with open(file_path, "rb") as file:
                    key_content = file.read()

                # Deriva la clave de cifrado y la sal de la contraseña maestra
                key, salt = self.derive_key(self.master_password)

                # Cifra la clave .pem con AES-GCM
                aesgcm = AESGCM(key)
                nonce = os.urandom(12)
                encrypted_key = aesgcm.encrypt(nonce, key_content, None)

                self.keys[os.path.basename(file_path)] = {
                    "encrypted_key": base64.b64encode(encrypted_key).decode(),
                    "nonce": base64.b64encode(nonce).decode(),
                    "salt": base64.b64encode(salt).decode()
                }
                self.save_keys()
                messagebox.showinfo("Éxito", "Clave cifrada y guardada.")
            except Exception as e:
                messagebox.showerror("Error", f"Error al cifrar la clave: {e}")

    def decrypt_key(self):
        if not hasattr(self, 'master_password'):
            messagebox.showerror("Error", "Establece la clave maestra primero.")
            return

        key_name = simpledialog.askstring("Descifrar Clave", "Introduce el nombre de la clave a descifrar:")
        if key_name and key_name in self.keys:
            try:
                # Solicita la contraseña maestra para derivar la clave de descifrado
                password = simpledialog.askstring("Contraseña Maestra", "Introduce la contraseña maestra:", show='*')
                if not password:
                    return

                # Deriva la clave de descifrado utilizando la sal almacenada
                salt = base64.b64decode(self.keys[key_name]["salt"])
                key = self.derive_key(password, salt)[0]  # Corrección: solo se necesita la clave, no la tupla

                # Descifra la clave .pem con AES-GCM
                aesgcm = AESGCM(key)
                nonce = base64.b64decode(self.keys[key_name]["nonce"])
                decrypted_key = aesgcm.decrypt(nonce, base64.b64decode(self.keys[key_name]["encrypted_key"]), None)

                file_path = filedialog.asksaveasfilename(defaultextension=".pem", title="Guardar clave descifrada como:")
                if file_path:
                    with open(file_path, "wb") as file:
                        file.write(decrypted_key)
                    messagebox.showinfo("Éxito", "Clave descifrada y guardada.")
            except Exception as e:
                messagebox.showerror("Error", f"Error al descifrar la clave: {e}")
        else:
            messagebox.showerror("Error", "Clave no encontrada.")

    def show_keys(self):
        if self.keys:
            key_list = "\n".join(self.keys.keys())
            messagebox.showinfo("Claves Cifradas", f"Claves cifradas guardadas:\n\n{key_list}")
        else:
            messagebox.showinfo("Claves Cifradas", "No hay claves cifradas guardadas.")

    def save_keys(self):
        with open("keys.json", "w") as file:
            json.dump(self.keys, file)

    def load_keys(self):
        if os.path.exists("keys.json"):
            with open("keys.json", "r") as file:
                self.keys = json.load(file)

root = tk.Tk()
KeyManager(root)
root.mainloop()