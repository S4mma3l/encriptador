import os
import shutil
import zipfile
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hmac
import tkinter as tk
from tkinter import filedialog
import json
import time

def generar_claves_rsa():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return private_pem, public_pem

def derivar_clave(contrasena, sal=None):
    if sal is None:
        sal = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=sal, iterations=100000, backend=default_backend())
    clave = kdf.derive(contrasena.encode())
    return clave, sal

def cifrar_aes(datos, clave, iv=None):
    if iv is None:
        iv = os.urandom(16)

    tamaño_bloque = algorithms.AES.block_size
    relleno = tamaño_bloque - (len(datos) % tamaño_bloque)
    datos += bytes([relleno] * relleno)

    cifrador = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend()).encryptor()
    datos_cifrados = cifrador.update(datos) + cifrador.finalize()
    return datos_cifrados, iv

def cifrar_rsa(datos, public_key):
    datos_cifrados = public_key.encrypt(datos, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return datos_cifrados

def hmac_datos(datos, clave):
    h = hmac.HMAC(clave, hashes.SHA256(), backend=default_backend())
    h.update(datos)
    return h.finalize()

def comprimir_carpeta(ruta_carpeta, ruta_zip):
    with zipfile.ZipFile(ruta_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archivo_zip: #nivel de compresión a 9.
        for carpeta_raiz, subcarpetas, archivos in os.walk(ruta_carpeta):
            for archivo in archivos:
                ruta_completa = os.path.join(carpeta_raiz, archivo)
                ruta_relativa = os.path.relpath(ruta_completa, ruta_carpeta)
                archivo_zip.write(ruta_completa, ruta_relativa)

def seleccionar_carpeta():
    root = tk.Tk()
    root.withdraw()
    ruta_carpeta = filedialog.askdirectory()
    return ruta_carpeta

# Ejemplo de uso:
ruta_carpeta_original = seleccionar_carpeta()

if ruta_carpeta_original:
    contrasena = input("Introduce una contraseña segura: ")
    ruta_zip_temporal = "carpeta_protegida.zip"
    ruta_zip_cifrado = "carpeta_protegida.encrypted"

    comprimir_carpeta(ruta_carpeta_original, ruta_zip_temporal)
    with open(ruta_zip_temporal, "rb") as archivo_zip:
        datos_zip = archivo_zip.read()
    os.remove(ruta_zip_temporal)

    clave_aes, sal = derivar_clave(contrasena)
    datos_cifrados_aes, iv = cifrar_aes(datos_zip, clave_aes)

    private_key_pem, public_key_pem = generar_claves_rsa()
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    clave_aes_cifrada_rsa = cifrar_rsa(clave_aes, public_key)

    hmac_val = hmac_datos(datos_cifrados_aes, clave_aes)

    datos_finales = {
        "iv": base64.b64encode(iv).decode(),
        "sal": base64.b64encode(sal).decode(),
        "clave_aes_cifrada": base64.b64encode(clave_aes_cifrada_rsa).decode(),
        "datos_cifrados": base64.b64encode(datos_cifrados_aes).decode(),
        "hmac": base64.b64encode(hmac_val).decode()
    }

    with open(ruta_zip_cifrado, "w") as archivo_cifrado:
        json.dump(datos_finales, archivo_cifrado)

    with open("private_key.pem", "wb") as private_file:
        private_file.write(private_key_pem)

    shutil.rmtree(ruta_carpeta_original)

    print(f"Carpeta '{ruta_carpeta_original}' comprimida y cifrada como '{ruta_zip_cifrado}'")