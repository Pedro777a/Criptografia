import base64
import hashlib
import PyPDF2
import docx
import csv
from Crypto.Cipher import PKCS1_OAEP
from PyPDF2 import PdfReader, PdfWriter
from Crypto.PublicKey import RSA
import base64

Ruta="Proyecto/"

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

# Leer el PDF con los metadatos
pdf_path = Ruta+'Firma_doc.pdf'
pdf_reader = PdfReader(pdf_path)

contenido = leer_archivo(pdf_path)
#print(contenido)

# Cargar la clave pública para descifrar el hash cifrado
with open(Ruta + 'director_public.pem', 'rb') as f:
    public_key = RSA.import_key(f.read())
    
# Obtener los metadatos
metadata = pdf_reader.metadata

print(metadata)

cipher_rsa = PKCS1_OAEP.new(public_key)

# Obtener el hash cifrado desde los metadatos
ciphertext_b64_extracted = metadata['/hash_director']
ciphertext_extracted = base64.b64decode(ciphertext_b64_extracted)

# Descifrar el hash cifrado utilizando la llave pública
try:
    decrypted_hash = cipher_rsa.decrypt(ciphertext_extracted)
except ValueError:
    print("Error al descifrar el hash cifrado con la llave pública.")
    exit()

hash_sha256 = hashlib.sha256()
hash_sha256.update(contenido.encode('utf-8'))  # Asegurarse de actualizar el hash con el contenido
hash_hex256 = hash_sha256.hexdigest()

print("Hash SHA-256:", hash_hex256)

# Comparar los hashes
if decrypted_hash == generated_hash:
    print("La firma es válida y el documento no ha sido alterado.")
else:
    print("La firma no es válida o el documento ha sido alterado.")

"""# Cargar la clave privada para descifrar
with open(Ruta+'director_public.pem', 'rb') as f:
    llave_publica = RSA.import_key(f.read())

# Obtener la firma digital y el mensaje firmado de los metadatos
signature_b64 = metadata['/hash_director']

cipher_rsa = PKCS1_OAEP.new(llave_publica)

# Descifrar cada metadato cifrado
for key in metadata:
    if key.startswith('/hash_director') or key.startswith('/hash_supervisor'):
        ciphertext_b64_extracted = metadata[key]
        ciphertext_extracted = base64.b64decode(ciphertext_b64_extracted)
        plaintext_extracted = cipher_rsa.decrypt(ciphertext_extracted)
        print(f"{key[1:]} descifrado: {plaintext_extracted.decode('utf-8')}")
"""