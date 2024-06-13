import base64
import hashlib
import PyPDF2
import docx
import csv
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from PyPDF2 import PdfReader, PdfWriter

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

def calcular_hash(Nombre_archivo):
    contenido = leer_archivo(Ruta + Nombre_archivo)
    print(contenido)

    hash_sha256 = hashlib.sha256()
    hash_sha256.update(contenido.encode('utf-8'))
    hash_hex256 = hash_sha256.hexdigest()

    print("Hash SHA-256:", hash_hex256)

    # Convertir el hash hexadecimal en bytes
    hash_bytes = hash_hex256.encode('utf-8')
    return hash_bytes

# Funcion que genera la firma del hash con la llave privada
def sign_hash(private_key_path, hash_data):
    with open(private_key_path, 'rb') as f:
        private_key = load_pem_private_key(
            f.read(),
            password=None
        )
    
    signature = private_key.sign(
        hash_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def Guardar_firma(input_pdf, output_pdf, signature, remitente):
    reader = PdfReader(input_pdf)
    writer = PdfWriter()
    
   # Copiar todas las páginas del lector al escritor
    for page in reader.pages:
        writer.add_page(page)
        
    # Copiar los metadatos existentes y agregar el nuevo metadato
    info_dict = reader.metadata
    new_info_dict = {**info_dict,remitente: signature.hex()}

    writer.add_metadata(new_info_dict)

    # Guardar el PDF con los metadatos actualizados
    with open(output_pdf, 'wb') as f:
        writer.write(f)

Nombre_archivo = input("Ingresa el nombre del archivo con extension: ")

hash_documento=calcular_hash(Nombre_archivo)

# Generamos la firma con la llave privada y nuestro hash del documento
firma = sign_hash(Ruta + "director_private.pem", hash_documento)

# Imprimimps la firma que es nuestro hash cifrado con la llave privada
print("ESTA ES MI FIRMA",firma)
print("ESTA ES MI FIRMA en hexadecimal",firma.hex())

# Guardamos nuestra firma en los metadatos de un nuevo documento 
Guardar_firma(Ruta+Nombre_archivo,Ruta+"Firma_doc.pdf",firma,'/firma_director')
print("Firma guardada dentro del documento ")