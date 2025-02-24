# Cifrador de Carpetas y Gestor de Claves

Este repositorio contiene dos programas en Python:

* **Cifrador de Carpetas:** Permite cifrar y comprimir carpetas, haciéndolas inaccesibles sin la clave de descifrado.
* **Gestor de Claves .pem:** Permite cifrar y descifrar claves privadas .pem utilizando una clave maestra.

## Cifrador de Carpetas

### Características

* Cifrado robusto utilizando AES-256 y RSA-4096.
* Compresión con `zipfile` para reducir el tamaño del archivo cifrado.
* Autenticación de mensajes con HMAC-SHA256 para garantizar la integridad de los datos.
* Interfaz gráfica simple con `tkinter` para seleccionar la carpeta a cifrar.

### Uso

1. Ejecutar `encriptador.py`.
2. Seleccionar la carpeta que se desea cifrar.
3. Introducir una contraseña segura.
4. El programa generará un archivo `carpeta_protegida.encrypted` y una clave `private_key.pem`.
5. Para descifrar, ejecutar `desencriptador.py` y seguir las instrucciones.

## Gestor de Claves .pem

### Características

* Cifrado de claves privadas .pem utilizando AES-256 en modo GCM.
* Derivación de claves con PBKDF2 para mayor seguridad.
* Interfaz gráfica moderna con `tkinter` y `ttkthemes`.

### Uso

1. Ejecutar `gestor.py`.
2. Establecer una clave maestra segura.
3. Cifrar claves .pem seleccionando el archivo y utilizando la clave maestra.
4. Descifrar claves .pem proporcionando el nombre del archivo cifrado y la clave maestra.

## Requisitos

* Python 3.6 o superior
* Las librerías listadas en `requirements.txt`

## Instalación

1. Clonar el repositorio: `git clone https://github.com/S4mma3l/encriptador.git`
2. Instalar las dependencias: `pip install -r requirements.txt`

## Seguridad

* Utiliza contraseñas fuertes y únicas para la clave maestra y el cifrado de carpetas.
* No compartas las claves privadas ni las contraseñas con nadie.
* Almacena las claves privadas cifradas y la clave maestra en un lugar seguro.

## Notas

* Este software se proporciona "tal cual", sin garantía de ningún tipo.
* Los autores no se hacen responsables de ningún daño o pérdida de datos que pueda resultar del uso de este software.