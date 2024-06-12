import base64
import hashlib
import PyPDF2
import docx
import csv
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
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

Nombre_archivo = input("Ingresa el nombre del archivo con extension: ")
contenido = leer_archivo(Ruta + Nombre_archivo)
print(contenido)

hash_sha256 = hashlib.sha256()
hash_sha256.update(contenido.encode('utf-8'))  # Asegurarse de actualizar el hash con el contenido
hash_hex256 = hash_sha256.hexdigest()

print("Hash SHA-256:", hash_hex256)

# Convertir el hash hexadecimal en bytes
hash_bytes = hash_hex256.encode('utf-8')

# Cargar las claves desde los archivos 
llave_privada = RSA.import_key(open(Ruta + "director_private.pem").read())

# Crear un cifrador RSA con la llave privada
cipher_rsa = PKCS1_OAEP.new(llave_privada)

# Crear un objeto lector y un objeto escritor
pdf_reader = PdfReader(Ruta + Nombre_archivo)
pdf_writer = PdfWriter()

# Copiar todas las páginas del lector al escritor
for page in pdf_reader.pages:
    pdf_writer.add_page(page)

ciphertext = cipher_rsa.encrypt(hash_bytes)

# Codificar el texto cifrado en base64 para almacenarlo como metadato
ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
print(ciphertext_b64)

# Copiar los metadatos existentes y agregar el nuevo metadato
info_dict = pdf_reader.metadata
new_info_dict = {**info_dict, '/hash_director': ciphertext_b64}

pdf_writer.add_metadata(new_info_dict)

# Guardar el PDF con los metadatos actualizados
with open(Ruta + "Documento_firmado.pdf", 'wb') as f:
    pdf_writer.write(f)

print("El nuevo texto cifrado se ha agregado como metadato al PDF.")
