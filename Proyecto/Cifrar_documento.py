import base64
import hashlib
import PyPDF2
import docx
import csv
from PyPDF2 import PdfReader, PdfWriter
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

Ruta = "Proyecto/"

# Definimos las funciones para leer nuestros diferentes archivos
def leer_pdf(archivo_pdf):
    texto = ""
    with open(archivo_pdf, 'rb') as file:
        lector_pdf = PdfReader(file)
        for pagina in lector_pdf.pages:
            texto += pagina.extract_text()
    return texto

def leer_docx(archivo_docx):
    doc = docx.Document(archivo_docx)
    texto = "\n".join(parrafo.text for parrafo in doc.paragraphs)
    return texto

def leer_txt(archivo_txt):
    with open(archivo_txt, 'r', encoding='utf-8') as file:
        texto = file.read()
    return texto

def leer_csv(archivo_csv):
    texto = ""
    with open(archivo_csv, 'r', encoding='utf-8') as file:
        lector_csv = csv.reader(file)
        for fila in lector_csv:
            texto += ",".join(fila) + "\n"
    return texto

# Definimos una funcion para evaluar que clase de archivo es
def leer_archivo(ruta_archivo):
    if ruta_archivo.endswith('.pdf'):
        return leer_pdf(ruta_archivo)
    elif ruta_archivo.endswith('.docx'):
        return leer_docx(ruta_archivo)
    elif ruta_archivo.endswith('.txt'):
        return leer_txt(ruta_archivo)
    elif ruta_archivo.endswith('.csv'):
        return leer_csv(ruta_archivo)
    else:
        return "Formato de archivo no soportado."

def GenerarllaveAES(numbytes):
    key= get_random_bytes(numbytes)
    return key

def convb64(Contenido):
    contenido_codificado = base64.b64encode(Contenido)
    return contenido_codificado

# Funcion que guarda la llave de 3DES en base 64 dentro de un archivo
def Guardar_en_archivo(Contenido,Nombrearchivo):
    Contenido = convb64(Contenido)
    with open(Ruta+Nombrearchivo, 'wb') as archivo:
            archivo.write(Contenido)

def CifrarllaveAES(mensaje_bytes,public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    mensaje_cifrado = cipher_rsa.encrypt(mensaje_bytes)
    return mensaje_cifrado

def CifradoAES(key, mensaje):
    # Generar un nonce (Número Único de 12 bytes)
    nonce = get_random_bytes(12)
    # Crear un objeto de cifrado AES en modo GCM
    cifrador = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # Ciframos nuestro mensaje mediante el objeto de cifrado
    textocifrado, tag = cifrador.encrypt_and_digest(mensaje)
    # Regresamos el nonce, el archivo cifrado y el tag de autenticación
    return nonce + textocifrado + tag

# Importamos la llave 
with open(Ruta+'director_public.pem', 'rb') as f:
    public_key = RSA.import_key(f.read())

Nombre_archivo = input("Ingresa el nombre del archivo con extension: ")
contenido = leer_archivo(Ruta + Nombre_archivo)
print(contenido)
    
llave=GenerarllaveAES(16)
print("Llave original: ",llave)
llave_cifrada=CifrarllaveAES(llave,public_key)
print(llave_cifrada)

Guardar_en_archivo(llave_cifrada,"Llave_AESDirector.txt")

