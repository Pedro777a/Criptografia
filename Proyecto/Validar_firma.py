import base64
import hashlib
import PyPDF2
import docx
import csv
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from PyPDF2 import PdfReader, PdfWriter

Ruta = "Proyecto/"

# Definimos las funciones para leer nuestros diferentes archivos
def leer_pdf(archivo_pdf):
    texto = ""
    with open(archivo_pdf, 'rb') as file:
        lector_pdf = PyPDF2.PdfReader(file)
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

# Funcion que calcula el hash de nuestro documento
def calcular_hash(ruta_archivo):
    contenido = leer_archivo(ruta_archivo)
    hash_sha256 = hashlib.sha256()
    hash_sha256.update(contenido.encode('utf-8')) 
    hash_hex256 = hash_sha256.hexdigest()

    print("Hash SHA-256:", hash_hex256)

    # Convertir el hash hexadecimal en bytes
    hash_bytes = hash_hex256.encode('utf-8')

    return hash_bytes

# FUncion para verificar la firma del documento con el hash del mismo
def verify_signature(public_key_path, file_path, signature):
    with open(public_key_path, 'rb') as f:
        public_key = load_pem_public_key(f.read())
    
    file_hash = calcular_hash(file_path)
    
    try:
        public_key.verify(
            signature,
            file_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

# Extraer la firma del documento firmado
def extract_signature_from_pdf(signed_pdf,remitente):
    reader = PdfReader(signed_pdf)
    metadata = reader.metadata
    print(metadata)
    signature_hex = metadata.get(remitente)
    return bytes.fromhex(signature_hex) if signature_hex else None

# Verificar la firma
Nombre=input("Ingrese el nombre del documento a verificar: ")
signed_pdf = Ruta+Nombre
extracted_signature = extract_signature_from_pdf(signed_pdf,'/firma_director')
print(extracted_signature)

if extracted_signature:
    is_valid = verify_signature(Ruta+"director_public.pem", signed_pdf, extracted_signature)
    print("Firma válida" if is_valid else "Firma no válida")
else:
    print("No se encontró la firma en el documento")
