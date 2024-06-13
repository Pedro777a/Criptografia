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
import json

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

def extraer_metadatos(archivo_pdf):
    with open(archivo_pdf, 'rb') as f:
        reader = PdfReader(f)
        metadatos = reader.metadata
    return dict(metadatos)

def CifradoAES_Archivo_conmetadatos(key, archivo_entrada, archivo_salida):
    # Generar un nonce (Número Único de 12 bytes)
    nonce = get_random_bytes(12)
    # Crear un objeto de cifrado AES en modo GCM
    cifrador = AES.new(key, AES.MODE_GCM, nonce=nonce)
    with open(Ruta+archivo_entrada, 'rb') as f:
        contenido = f.read()
    # Cifrar el contenido del archivo
    textocifrado, tag = cifrador.encrypt_and_digest(contenido)
    # Extraer metadatos del archivo PDF
    metadatos = extraer_metadatos(Ruta+Nombre_archivo)
    print(metadatos)
    metadatos_json = json.dumps(metadatos).encode('utf-8')
    print(metadatos_json)
    # Guardar el nonce, el archivo cifrado, el tag de autenticación y los metadatos en el archivo de salida
    with open(Ruta+archivo_salida, 'wb') as f:
        f.write(len(metadatos_json).to_bytes(4, byteorder='big'))
        f.write(metadatos_json)
        f.write(nonce + textocifrado + tag)

# Importamos la llave privada
with open(Ruta+'director_public.pem', 'rb') as f:
    public_key = RSA.import_key(f.read())

# Ingresamos nuestro archivo a cifrar
Nombre_archivo = input("Ingresa el nombre del archivo con extension: ")
contenido = leer_archivo(Ruta + Nombre_archivo)
print(contenido)

# Generamos la llave de AES
llave=GenerarllaveAES(16)
print("Llave original: ",llave)

# Ciframos la llave de AES con RSA y la llave publica
llave_cifrada=CifrarllaveAES(llave,public_key)
print(llave_cifrada)

# Guardamos la llave cifrada en un archivo .txt
Guardar_en_archivo(llave_cifrada,"Llave_AESDirector.txt")

# Ciframos nuestro documento y lo guardamos en un nuevo documento junto con sus metadatos
CifradoAES_Archivo_conmetadatos(llave, Nombre_archivo,'reporte_cifrado.pdf')
"""metadatos = extraer_metadatos(Ruta+"reporte_cifrado.pdf")
print(metadatos)
metadatos_json = json.dumps(metadatos).encode('utf-8')
print(metadatos_json)"""