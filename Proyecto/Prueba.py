import base64
import hashlib
import PyPDF2
import docx
import csv
from PyPDF2 import PdfReader, PdfWriter
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

Ruta = "Proyecto/"

# Funciones para leer diferentes tipos de archivos
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

# Leer el PDF con los metadatos
pdf_path = Ruta + 'Documento_firmado.pdf'
pdf_reader = PdfReader(pdf_path)

# Obtener el contenido del archivo PDF
contenido = leer_archivo(pdf_path)

# Cargar la clave pública para verificar la firma digital
with open(Ruta + 'director_public.pem', 'rb') as f:
    public_key = RSA.import_key(f.read())

# Obtener los metadatos
metadata = pdf_reader.metadata
print(metadata)

# Obtener la firma digital (hash cifrado) desde los metadatos
signature_b64 = metadata['/hash_director']
signature = base64.b64decode(signature_b64)

print(signature_b64)

# Generar el hash del contenido del documento
hash_obj = SHA256.new(contenido.encode('utf-8'))
print(hash_obj)

# Verificar la firma digital utilizando la clave pública
try:
    pkcs1_15.new(public_key).verify(hash_obj, signature_b64)
    print("La firma es válida y el documento no ha sido alterado.")
except (ValueError, TypeError):
    print("La firma no es válida o el documento ha sido alterado.")
