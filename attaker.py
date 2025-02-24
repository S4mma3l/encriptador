import os
import zipfile
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hmac
import json
import itertools
import tkinter as tk
from tkinter import filedialog

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

def seleccionar_archivo_o_carpeta(titulo):
    root = tk.Tk()
    root.withdraw()
    ruta = filedialog.askopenfilename(title=titulo) or filedialog.askdirectory(title=titulo)
    return ruta

def ataque_diccionario(ruta_archivo_cifrado, ruta_private_key, diccionario):
    with open(ruta_archivo_cifrado, "r") as archivo_cifrado:
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

    with open(diccionario, "r", encoding="latin-1") as archivo_diccionario:
        for contrasena in archivo_diccionario:
            contrasena = contrasena.strip()
            clave_derivada = derivar_clave(contrasena, sal)
            hmac_val_calculado = hmac_datos(datos_cifrados_aes, clave_derivada)
            if hmac_val_calculado == hmac_val_cifrado:
                try:
                    datos_zip = descifrar_aes(datos_cifrados_aes, clave_derivada, iv)
                    ruta_zip_desencriptado = "carpeta_desencriptada_atacada.zip"
                    with open(ruta_zip_desencriptado, "wb") as archivo_zip:
                        archivo_zip.write(datos_zip)
                    with zipfile.ZipFile(ruta_zip_desencriptado, "r") as archivo_zip:
                        archivo_zip.extractall("carpeta_recuperada_atacada")
                    print(f"Contraseña encontrada: {contrasena}")
                    return True
                except:
                    print(f'Contraseña encontrada, pero falló la desencriptación. {contrasena}')
    return False

def ataque_fuerza_bruta(ruta_archivo_cifrado, ruta_private_key, longitud_maxima=6):
    caracteres = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+=-`~[]\{}|;':\",./<>?"
    for longitud in range(1, longitud_maxima + 1):
        for contrasena_tupla in itertools.product(caracteres, repeat=longitud):
            contrasena = "".join(contrasena_tupla)
            if ataque_diccionario(ruta_archivo_cifrado, ruta_private_key, [contrasena]):
                return True
    return False

# Ejemplo de uso:
ruta_archivo_cifrado = seleccionar_archivo("Introduce la ruta del archivo cifrado: ")
ruta_private_key = seleccionar_archivo("Introduce la ruta de la llave privada: ")
diccionario = seleccionar_archivo_o_carpeta("Selecciona diccionario o deja vacio")

if diccionario and os.path.exists(diccionario):
    if ataque_diccionario(ruta_archivo_cifrado, ruta_private_key, diccionario):
        print("Ataque de diccionario exitoso.")
    else:
        print("Ataque de diccionario fallido, intentando fuerza bruta...")
        if ataque_fuerza_bruta(ruta_archivo_cifrado, ruta_private_key):
            print("Ataque de fuerza bruta exitoso.")
        else:
            print("Ataque de fuerza bruta fallido.")
elif ataque_fuerza_bruta(ruta_archivo_cifrado, ruta_private_key):
    print('Ataque de fuerza bruta exitoso.')
else:
    print('Ataque fallido')