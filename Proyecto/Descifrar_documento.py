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
    try:
        with open(archivo_txt, 'rb') as archivo:
            contenido = archivo.read()
        return contenido
    except IOError:
        print(f"No se pudo leer el archivo '{archivo_txt}'.")

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

def convb64(Contenido):
    contenido_codificado = base64.b64encode(Contenido)
    return contenido_codificado

# Funcion que guarda la llave de 3DES en base 64 dentro de un archivo
def Guardar_en_archivo(Contenido,Nombrearchivo):
    Contenido = convb64(Contenido)
    with open(Ruta+Nombrearchivo, 'wb') as archivo:
            archivo.write(Contenido)

def DescifrarllaveAES(mensaje_cifrado,private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    mensaje_descifrado = cipher_rsa.decrypt(mensaje_cifrado)
    return mensaje_descifrado

def DescifradoAES_Archivo(key, archivo_cifrado, archivo_salida):
    # Leer el contenido del archivo cifrado
    with open(Ruta+archivo_cifrado, 'rb') as f:
        contenido_cifrado = f.read()
    
    # Leer la longitud de los metadatos
    metadatos_len = int.from_bytes(contenido_cifrado[:4], byteorder='big')
    
    # Extraer los metadatos
    metadatos_json = contenido_cifrado[4:4 + metadatos_len]
    metadatos = json.loads(metadatos_json.decode('utf-8'))
    
    # Separar el nonce, el texto cifrado y el tag de autenticación
    nonce = contenido_cifrado[4 + metadatos_len:4 + metadatos_len + 12]
    tag = contenido_cifrado[-16:]
    textocifrado = contenido_cifrado[4 + metadatos_len + 12:-16]
    
    # Crear un objeto de descifrado AES en modo GCM
    cifrador = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    # Descifrar y verificar el contenido del archivo
    contenido = cifrador.decrypt_and_verify(textocifrado, tag)
    
    # Guardar el contenido descifrado en el archivo de salida
    with open(Ruta+archivo_salida, 'wb') as f:
        f.write(contenido)
    
    # Añadir los metadatos al archivo PDF descifrado
    with open(Ruta+archivo_salida, 'rb') as f:
        reader = PdfReader(f)
        writer = PdfWriter()
        writer.append_pages_from_reader(reader)
        writer.add_metadata(metadatos)
    
    with open(Ruta+archivo_salida, 'wb') as f:
        writer.write(f)

# Importamos la llave privada 
with open(Ruta+'administrador_private.pem', 'rb') as f:
    private_key = RSA.import_key(f.read())

# Leemos el contendio de la llave cifrada
Nombre_archivo="administrador_llave_AES_cifrada.bin"
#Nombre_archivo="reporte.pdf"
contenido = Ruta + Nombre_archivo
print(contenido)
#llave_cifrada=key=base64.b64decode(contenido)
#print(llave_cifrada) 
llave=DescifrarllaveAES(contenido,private_key)
print("Llave descifrada: ",llave)

DescifradoAES_Archivo(llave, 'reporte_cifrado.pdf', 'reporte_descifrado.pdf')