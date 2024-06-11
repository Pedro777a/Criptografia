from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# Función para cargar la llave privada desde un archivo
def load_private_key(filename):
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

# Función para descifrar datos con una llave privada
def decrypt_with_private_key(private_key, encrypted_message):
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

# Rutas de las llaves privadas y los archivos cifrados
director_private_key_path = "Proyecto/director_private_key.pem"
supervisor_private_key_path = "Proyecto/supervisor_private_key.pem"
encrypted_hash_director_path = "Proyecto/encrypted_hash_director.bin"
encrypted_hash_supervisor_path = "Proyecto/encrypted_hash_supervisor.bin"

# Cargar llaves privadas
director_private_key = load_private_key(director_private_key_path)
supervisor_private_key = load_private_key(supervisor_private_key_path)

# Leer los hashes cifrados
with open(encrypted_hash_director_path, "rb") as f:
    encrypted_hash_director = f.read()

with open(encrypted_hash_supervisor_path, "rb") as f:
    encrypted_hash_supervisor = f.read()

# Descifrar los hashes
decrypted_hash_director = decrypt_with_private_key(director_private_key, encrypted_hash_director)
decrypted_hash_supervisor = decrypt_with_private_key(supervisor_private_key, encrypted_hash_supervisor)

# Mostrar los hashes descifrados
print("Hash descifrado por el director:", decrypted_hash_director.hex())
print("Hash descifrado por el supervisor:", decrypted_hash_supervisor.hex())
