import os
import zipfile
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hmac
import tkinter as tk
from tkinter import filedialog
import json

def derivar_clave(contrasena, sal):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=sal, iterations=100000, backend=default_backend())
    clave = kdf.derive(contrasena.encode())
    return clave

def descifrar_aes(datos_cifrados, clave, iv):
    descifrador = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend()).decryptor()
    datos = descifrador.update(datos_cifrados) + descifrador.finalize()

    relleno = datos[-1]
    if relleno > 0 and relleno <= len(datos):
        datos = datos[:-relleno]

    return datos

def descifrar_rsa(datos_cifrados, private_key):
    datos = private_key.decrypt(datos_cifrados, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return datos

def hmac_datos(datos, clave):
    h = hmac.HMAC(clave, hashes.SHA256(), backend=default_backend())
    h.update(datos)
    return h.finalize()

def seleccionar_archivo(titulo):
    root = tk.Tk()
    root.withdraw()
    ruta_archivo = filedialog.askopenfilename(title=titulo)
    return ruta_archivo

# Ejemplo de uso:
ruta_zip_cifrado = seleccionar_archivo("Selecciona el archivo cifrado")
contrasena = input("Introduce la contraseña: ")
ruta_private_key = seleccionar_archivo("selecciona la llave privada")
ruta_carpeta_recuperada = "carpeta_recuperada"

if os.path.exists(ruta_zip_cifrado) and os.path.exists(ruta_private_key):
    with open(ruta_zip_cifrado, "r") as archivo_cifrado:
        datos_finales = json.load(archivo_cifrado)

    iv = base64.b64decode(datos_finales["iv"])
    sal = base64.b64decode(datos_finales["sal"])
    clave_aes_cifrada_rsa = base64.b64decode(datos_finales["clave_aes_cifrada"])
    datos_cifrados_aes = base64.b64decode(datos_finales["datos_cifrados"])
    hmac_val_cifrado = base64.b64decode(datos_finales["hmac"])

    with open(ruta_private_key, "rb") as key_file:
        private_key_pem = key_file.read()

    private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
    clave_aes = descifrar_rsa(clave_aes_cifrada_rsa, private_key)
    clave_derivada = derivar_clave(contrasena, sal)

    hmac_val_calculado = hmac_datos(datos_cifrados_aes, clave_derivada)

    if hmac_val_calculado == hmac_val_cifrado:
        datos_zip = descifrar_aes(datos_cifrados_aes, clave_derivada, iv)

        ruta_zip_desencriptado = "carpeta_desencriptada.zip"
        with open(ruta_zip_desencriptado, "wb") as archivo_zip:
            archivo_zip.write(datos_zip)

        with zipfile.ZipFile(ruta_zip_desencriptado, "r") as archivo_zip:
            archivo_zip.extractall(ruta_carpeta_recuperada)

        os.remove(ruta_zip_desencriptado)
        os.remove(ruta_zip_cifrado) # Elimina el archivo encriptado.
        os.remove(ruta_private_key) #Elimina la private key.

        print(f"Carpeta descifrada y recuperada en '{ruta_carpeta_recuperada}'")

    else:
        print("Error: La integridad de los datos no pudo ser verificada (HMAC mismatch).")

else:
    print("Archivo cifrado o llave privada no encontrados.")