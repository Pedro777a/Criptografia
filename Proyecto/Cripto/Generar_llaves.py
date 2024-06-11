from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Función para generar llaves RSA
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Función para guardar la llave privada en un archivo
def save_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

# Función para guardar la llave pública en un archivo
def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

# Generar llaves para el director
director_private_key, director_public_key = generate_rsa_keys()
save_private_key(director_private_key, "director_private_key.pem")
save_public_key(director_public_key, "director_public_key.pem")

# Generar llaves para el supervisor
supervisor_private_key, supervisor_public_key = generate_rsa_keys()
save_private_key(supervisor_private_key, "supervisor_private_key.pem")
save_public_key(supervisor_public_key, "supervisor_public_key.pem")

print("Llaves generadas y guardadas en archivos.")
