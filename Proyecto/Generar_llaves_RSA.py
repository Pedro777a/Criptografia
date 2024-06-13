from Crypto.PublicKey import RSA

Ruta="Proyecto/"

# Funcion para generar llaves publicas y privadas de RSA
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Generar llaves para el director y el supervisor
director_private_key, director_public_key = generate_rsa_keys()
supervisor_private_key, supervisor_public_key = generate_rsa_keys()

# Guardar las llaves en archivos
with open(Ruta+"director_private.pem", "wb") as f:
    f.write(director_private_key)
with open(Ruta+"director_public.pem", "wb") as f:
    f.write(director_public_key)

with open(Ruta+"supervisor_private.pem", "wb") as f:
    f.write(supervisor_private_key)
with open(Ruta+"supervisor_public.pem", "wb") as f:
    f.write(supervisor_public_key)
