import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

# 1. Cargar y hash del reporte (PDF)
def hash_pdf(file_path):
    with open(file_path, "rb") as f:
        pdf_data = f.read()
        hash_object = hashlib.sha256(pdf_data)
        return hash_object.digest()

# 2. Generar llaves RSA (Esto sería previamente hecho y compartir sólo las llaves públicas)
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Serializar llaves públicas
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# 3. Cifrar el hash con una llave pública
def encrypt_with_public_key(public_key, message):
    encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

# Rutas del archivo PDF y llaves públicas
pdf_path = "Proyecto/reporte.pdf"
director_public_key_path = "Proyecto/director_public_key.pem"
supervisor_public_key_path = "Proyecto/supervisor_public_key.pem"

# Hash del reporte PDF
pdf_hash = hash_pdf(pdf_path)

# Leer llaves públicas
with open(director_public_key_path, "rb") as key_file:
    director_public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

with open(supervisor_public_key_path, "rb") as key_file:
    supervisor_public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# Cifrar el hash con las llaves públicas
encrypted_hash_director = encrypt_with_public_key(director_public_key, pdf_hash)
encrypted_hash_supervisor = encrypt_with_public_key(supervisor_public_key, pdf_hash)

# Guardar los hashes cifrados en archivos
with open("encrypted_hash_director.bin", "wb") as f:
    f.write(encrypted_hash_director)

with open("encrypted_hash_supervisor.bin", "wb") as f:
    f.write(encrypted_hash_supervisor)

print("Hash del PDF cifrado con las llaves públicas del director y supervisor.")
