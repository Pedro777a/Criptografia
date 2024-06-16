import os
import json
import base64
import hashlib
import PyPDF2
import tkinter as tk
from tkinter import messagebox, filedialog
from PyPDF2 import PdfReader, PdfWriter
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

Ruta = "Proyecto/"

# Datos de ejemplo para los usuarios
usuarios = [
    {'username': 'prof', 'password': '1234', 'role': 'profesor', 'name': 'Profesor Uno'},
    {'username': 'director', 'password': '1234', 'role': 'director', 'name': 'Director Uno'},
    {'username': 'admin', 'password': '1234', 'role': 'administrador', 'name': 'Administrador Uno'},
]

# Funciones del backend del proyecto
def leer_pdf(archivo_pdf):
    texto = ""
    with open(archivo_pdf, 'rb') as file:
        lector_pdf = PdfReader(file)
        for pagina in lector_pdf.pages:
            texto += pagina.extract_text()
    return texto

def leer_archivo(ruta_archivo):
    if ruta_archivo.endswith('.pdf'):
        return leer_pdf(ruta_archivo)
    else:
        return "Formato de archivo no soportado."

def generar_o_cargar_rsa_keys(nombre_archivo_privado, nombre_archivo_publico):
    if not os.path.exists(Ruta + nombre_archivo_privado) or not os.path.exists(Ruta + nombre_archivo_publico):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        with open(Ruta + nombre_archivo_privado, "wb") as f:
            f.write(private_key)
        with open(Ruta + nombre_archivo_publico, "wb") as f:
            f.write(public_key)
        print(f"Llaves generadas y guardadas en {Ruta + nombre_archivo_privado} y {Ruta + nombre_archivo_publico}")
    else:
        print(f"Las llaves ya existen en {Ruta + nombre_archivo_privado} y {Ruta + nombre_archivo_publico}")

def calcular_hash(ruta_archivo):
    contenido = leer_archivo(ruta_archivo)
    print(contenido)

    hash_sha256 = hashlib.sha256()
    hash_sha256.update(contenido.encode('utf-8'))
    hash_hex256 = hash_sha256.hexdigest()

    print("Hash SHA-256:", hash_hex256)

    hash_bytes = hash_hex256.encode('utf-8')
    return hash_bytes

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

def guardar_firma(input_pdf, output_pdf, signature, remitente):
    reader = PdfReader(input_pdf)
    writer = PdfWriter()
    
    for page in reader.pages:
        writer.add_page(page)
        
    info_dict = reader.metadata
    new_info_dict = {**info_dict, remitente: signature.hex()}

    writer.add_metadata(new_info_dict)

    with open(output_pdf, 'wb') as f:
        writer.write(f)

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

def extract_signature_from_pdf(signed_pdf, remitente):
    reader = PdfReader(signed_pdf)
    metadata = reader.metadata
    print(metadata)
    signature_hex = metadata.get(remitente)
    return bytes.fromhex(signature_hex) if signature_hex else None

def GenerarllaveAES(numbytes):
    key= get_random_bytes(numbytes)
    return key

def convb64(Contenido):
    contenido_codificado = base64.b64encode(Contenido)
    return contenido_codificado

# Funcion que guarda la llave de AES en base 64 dentro de un archivo
def Guardar_en_archivo(Contenido,Nombrearchivo):
    Contenido = convb64(Contenido)
    with open(Ruta+Nombrearchivo, 'wb') as archivo:
            archivo.write(Contenido)

def CifrarllaveAES(mensaje_bytes,public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    mensaje_cifrado = cipher_rsa.encrypt(mensaje_bytes)
    return mensaje_cifrado

def extraer_metadatos(archivo_pdf):
    with open(archivo_pdf, 'rb') as f:
        reader = PdfReader(f)
        metadatos = reader.metadata
    return dict(metadatos)

def CifradoAES_Archivo_conmetadatos(key, archivo_entrada, archivo_salida):
    # Generar un nonce (Número Único de 12 bytes)
    nonce = get_random_bytes(12)
    # Crear un objeto de cifrado AES en modo GCM
    cifrador = AES.new(key, AES.MODE_GCM, nonce=nonce)
    with open(archivo_entrada, 'rb') as f:
        contenido = f.read()
    # Cifrar el contenido del archivo
    textocifrado, tag = cifrador.encrypt_and_digest(contenido)
    # Extraer metadatos del archivo PDF
    metadatos = extraer_metadatos(archivo_entrada)
    print(metadatos)
    metadatos_json = json.dumps(metadatos).encode('utf-8')
    print(metadatos_json)
    # Guardar el nonce, el archivo cifrado, el tag de autenticación y los metadatos en el archivo de salida
    with open(Ruta+archivo_salida, 'wb') as f:
        f.write(len(metadatos_json).to_bytes(4, byteorder='big'))
        f.write(metadatos_json)
        f.write(nonce + textocifrado + tag)

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

    print(f"Nonce: {nonce}")
    print(f"Tag: {tag}")
    print(f"Texto cifrado: {textocifrado}")
    print(f"Longitud del texto cifrado: {len(textocifrado)}")
    
    # Crear un objeto de descifrado AES en modo GCM
    cifrador = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    # Descifrar y verificar el contenido del archivo
    try:
        contenido = cifrador.decrypt_and_verify(textocifrado, tag)
    except ValueError as e:
        print(f"Error durante la verificación: {e}")
        raise e
    
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

def cifrar_archivo(rol_destinatario):
    llave_publica = Ruta + rol_destinatario + "_public.pem"
    if 'archivo_seleccionado' not in globals():
        messagebox.showwarning("Advertencia", "Primero debe subir un reporte.")
        return
    nombre_archivo = os.path.basename(archivo_seleccionado)
    key = GenerarllaveAES(32)
    with open(llave_publica, 'rb') as f:
        public_key = RSA.import_key(f.read())
    mensaje_cifrado = CifrarllaveAES(key, public_key)
    Guardar_en_archivo(mensaje_cifrado, rol_destinatario+"_llave_AES_cifrada.bin")
    CifradoAES_Archivo_conmetadatos(key, archivo_seleccionado, "documento_cifrado.pdf")
    print("El documento ha sido cifrado y la llave ha sido guardada.")

def Descifrar_archivo(user):
    llave_privada = Ruta + user['role'] + "_private.pem"
    if 'archivo_seleccionado' not in globals():
        messagebox.showwarning("Advertencia", "Primero debe subir un reporte.")
        return
    nombre_archivo = os.path.basename(archivo_seleccionado)
    ruta_llave_aes_cifrada = Ruta + user['role'] + "_llave_AES_cifrada.bin"

    with open(llave_privada, 'rb') as f:
        private_key = RSA.import_key(f.read())

    with open(ruta_llave_aes_cifrada, 'rb') as f:
        mensaje_cifrado = f.read()

    print(mensaje_cifrado)
    llave_cifrada=key=base64.b64decode(mensaje_cifrado)
    key = DescifrarllaveAES(llave_cifrada, private_key)
    print(f"Descifre la llave: {key}")
    DescifradoAES_Archivo(key, nombre_archivo, "documento_descifrado.pdf")
    messagebox.showinfo("Éxito", "El documento ha sido descifrado correctamente.")
    """except Exception as e:
        messagebox.showerror("Error", f"Error al descifrar el documento: {e}")
"""
def iniciar_sesion():
    usuario = entry_usuario.get()
    contrasena = entry_contrasena.get()
    for user in usuarios:
        if usuario == user['username'] and contrasena == user['password']:
            generar_o_cargar_rsa_keys(f"{user['role']}_private.pem", f"{user['role']}_public.pem")
            ventana_login.destroy()
            abrir_ventana_principal(user)
            return
    messagebox.showerror("Error", "Usuario o contraseña incorrectos")

def cerrar_sesion(ventana):
    ventana.destroy()
    crear_ventana_login()

def volver_menu(ventana, ventana_principal):
    ventana.destroy()
    ventana_principal.deiconify()

def subir_reporte():
    file_path = filedialog.askopenfilename(initialdir=Ruta)
    if file_path:
        print("Archivo seleccionado:", file_path)
        global archivo_seleccionado
        archivo_seleccionado = file_path
    else:
        print("No se seleccionó ningún archivo")

def firmar_documento(user):
    llave_privada = Ruta + user['role'] + "_private.pem"
    if 'archivo_seleccionado' not in globals():
        messagebox.showwarning("Advertencia", "Primero debe subir un reporte.")
        return
    nombre_archivo = os.path.basename(archivo_seleccionado)
    hash_documento = calcular_hash(archivo_seleccionado)
    firma = sign_hash(llave_privada, hash_documento)
    print("ESTA ES MI FIRMA", firma)
    print("ESTA ES MI FIRMA en hexadecimal", firma.hex())
    guardar_firma(archivo_seleccionado, Ruta + "Firma_doc.pdf", firma, '/firma_' + user['role'])
    print("Firma guardada dentro del documento Firma_doc.pdf")

def abrir_ventana_firmar(user, ventana_principal):
    ventana_principal.withdraw()
    ventana_firmar = tk.Tk()
    ventana_firmar.title("Firmar Reporte")

    ancho_ventana = 400
    alto_ventana = 300
    x_ventana = (ventana_firmar.winfo_screenwidth() // 2) - (ancho_ventana // 2)
    y_ventana = (ventana_firmar.winfo_screenheight() // 2) - (alto_ventana // 2)
    ventana_firmar.geometry(f"{ancho_ventana}x{alto_ventana}+{x_ventana}+{y_ventana}")

    frame_botones = tk.Frame(ventana_firmar)
    frame_botones.pack(pady=20)

    tk.Button(frame_botones, text="Subir Reporte", font=("Helvetica", 12), command=subir_reporte).grid(row=0, column=0, padx=10, pady=10)
    tk.Button(frame_botones, text="Firmar Documento", font=("Helvetica", 12), command=lambda: firmar_documento(user)).grid(row=1, column=0, columnspan=2, pady=10)
    tk.Button(ventana_firmar, text="Volver a Menu", font=("Helvetica", 12), command=lambda: volver_menu(ventana_firmar, ventana_principal)).pack(side=tk.BOTTOM, pady=20)

    ventana_firmar.mainloop()

def abrir_ventana_cifrar(user, ventana_principal):
    ventana_principal.withdraw()
    ventana_cifrar = tk.Tk()
    ventana_cifrar.title("Cifrar Reporte")

    ancho_ventana = 400
    alto_ventana = 350
    x_ventana = (ventana_cifrar.winfo_screenwidth() // 2) - (ancho_ventana // 2)
    y_ventana = (ventana_cifrar.winfo_screenheight() // 2) - (alto_ventana // 2)
    ventana_cifrar.geometry(f"{ancho_ventana}x{alto_ventana}+{x_ventana}+{y_ventana}")

    # Etiqueta y desplegable para seleccionar el rol
    label_rol = tk.Label(ventana_cifrar, text="Selecciona el rol del destinatario:")
    label_rol.pack(pady=10)

    roles = [user['role'] for user in usuarios]
    variable_rol = tk.StringVar(ventana_cifrar)
    variable_rol.set(roles[0])  # Valor por defecto
    dropdown_rol = tk.OptionMenu(ventana_cifrar, variable_rol, *roles)
    dropdown_rol.pack(pady=10)

    frame_botones = tk.Frame(ventana_cifrar)
    frame_botones.pack(pady=20)

    tk.Button(frame_botones, text="Subir Reporte", font=("Helvetica", 12), command=subir_reporte).grid(row=0, column=0, padx=10, pady=10)
    tk.Button(frame_botones, text="Cifrar Documento", font=("Helvetica", 12), command=lambda: cifrar_archivo(variable_rol.get())).grid(row=1, column=0, columnspan=2, pady=10)
    tk.Button(ventana_cifrar, text="Volver a Menu", font=("Helvetica", 12), command=lambda: volver_menu(ventana_cifrar, ventana_principal)).pack(side=tk.BOTTOM, pady=20)

    ventana_cifrar.mainloop()

def abrir_ventana_validar_firma(user, ventana_principal):
    ventana_principal.withdraw()
    ventana_validar = tk.Tk()
    ventana_validar.title("Validar Firma")

    ancho_ventana = 400
    alto_ventana = 300
    x_ventana = (ventana_validar.winfo_screenwidth() // 2) - (ancho_ventana // 2)
    y_ventana = (ventana_validar.winfo_screenheight() // 2) - (alto_ventana // 2)
    ventana_validar.geometry(f"{ancho_ventana}x{alto_ventana}+{x_ventana}+{y_ventana}")

    frame_botones = tk.Frame(ventana_validar)
    frame_botones.pack(pady=20)

    tk.Button(frame_botones, text="Subir Documento", font=("Helvetica", 12), command=subir_reporte).pack(pady=10)

    tk.Label(frame_botones, text="Seleccionar Rol", font=("Helvetica", 12)).pack(pady=10)
    rol_seleccionado = tk.StringVar(frame_botones)
    roles = ["profesor", "director", "administrador"]
    rol_menu = tk.OptionMenu(frame_botones, rol_seleccionado, *roles)
    rol_menu.pack(pady=10)

    def validar_firma():
        if 'archivo_seleccionado' not in globals():
            messagebox.showwarning("Advertencia", "Primero debe subir un documento.")
            return
        if not rol_seleccionado.get():
            messagebox.showwarning("Advertencia", "Debe seleccionar un rol.")
            return
        remitente = "/firma_" + rol_seleccionado.get()
        signature = extract_signature_from_pdf(archivo_seleccionado, remitente)
        if not signature:
            messagebox.showwarning("Advertencia", f"No se encontró una firma de {rol_seleccionado.get()} en el documento.")
            return
        public_key_path = Ruta + rol_seleccionado.get() + "_public.pem"
        if verify_signature(public_key_path, archivo_seleccionado, signature):
            messagebox.showinfo("Éxito", "La firma es válida.")
        else:
            messagebox.showerror("Error", "La firma no es válida.")

    tk.Button(frame_botones, text="Validar Firma", font=("Helvetica", 12), command=validar_firma).pack(pady=10)
    tk.Button(ventana_validar, text="Volver a Menu", font=("Helvetica", 12), command=lambda: volver_menu(ventana_validar, ventana_principal)).pack(side=tk.BOTTOM, pady=20)

    ventana_validar.mainloop()

def abrir_ventana_descifrar(user, ventana_principal):
    ventana_principal.withdraw()
    ventana_descifrar = tk.Tk()
    ventana_descifrar.title("Descifrar Reporte")

    ancho_ventana = 400
    alto_ventana = 300
    x_ventana = (ventana_descifrar.winfo_screenwidth() // 2) - (ancho_ventana // 2)
    y_ventana = (ventana_descifrar.winfo_screenheight() // 2) - (alto_ventana // 2)
    ventana_descifrar.geometry(f"{ancho_ventana}x{alto_ventana}+{x_ventana}+{y_ventana}")

    frame_botones = tk.Frame(ventana_descifrar)
    frame_botones.pack(pady=20)

    tk.Button(frame_botones, text="Subir Reporte", font=("Helvetica", 12), command=subir_reporte).pack(pady=10)
    tk.Button(frame_botones, text="Descifrar Documento", font=("Helvetica", 12), command=lambda: Descifrar_archivo(user)).pack(pady=10)
    tk.Button(ventana_descifrar, text="Volver a Menu", font=("Helvetica", 12), command=lambda: volver_menu(ventana_descifrar, ventana_principal)).pack(side=tk.BOTTOM, pady=20)

    ventana_descifrar.mainloop()

def abrir_ventana_principal(user):
    ventana_principal = tk.Tk()
    ventana_principal.title(f"Ventana de {user['role'].capitalize()}")

    ancho_ventana = 600
    alto_ventana = 400
    x_ventana = (ventana_principal.winfo_screenwidth() // 2) - (ancho_ventana // 2)
    y_ventana = (ventana_principal.winfo_screenheight() // 2) - (alto_ventana // 2)
    ventana_principal.geometry(f"{ancho_ventana}x{alto_ventana}+{x_ventana}+{y_ventana}")

    tk.Label(ventana_principal, text=f"Bienvenido, {user['name']}!", font=("Helvetica", 14)).pack(pady=10)

    frame_botones = tk.Frame(ventana_principal)
    frame_botones.pack(pady=20)

    def crear_boton(frame, texto, command=None):
        boton = tk.Button(frame, text=texto, font=("Helvetica", 12), command=command)
        boton.pack(side=tk.LEFT, padx=10, pady=5)
        return boton

    botones = []
    if user['role'] == 'profesor':
        botones = [("Generar reporte", None), ("Firmar reporte", lambda: abrir_ventana_firmar(user, ventana_principal)), ("Cifrar reporte", lambda: abrir_ventana_cifrar(user, ventana_principal))]
    elif user['role'] == 'director':
        botones = [("Generar reporte", None), ("Firmar reporte", lambda: abrir_ventana_firmar(user, ventana_principal)), 
                   ("Cifrar reporte", lambda: abrir_ventana_cifrar(user, ventana_principal)), ("Validar firma", lambda: abrir_ventana_validar_firma(user, ventana_principal)), ("Descifrar reporte", lambda: abrir_ventana_descifrar(user, ventana_principal))]
    elif user['role'] == 'administrador':
        botones = [("Generar reporte", None), ("Firmar reporte", lambda: abrir_ventana_firmar(user, ventana_principal)), 
                   ("Cifrar reporte", lambda: abrir_ventana_cifrar(user, ventana_principal)), ("Validar firma", lambda: abrir_ventana_validar_firma(user, ventana_principal)), ("Descifrar reporte", lambda: abrir_ventana_descifrar(user, ventana_principal))]

    for i, (texto, cmd) in enumerate(botones):
        if i < 3:
            crear_boton(frame_botones, texto, cmd)
        else:
            if i == 3:
                frame_botones2 = tk.Frame(ventana_principal)
                frame_botones2.pack(pady=5)
            crear_boton(frame_botones2, texto, cmd)

    tk.Button(ventana_principal, text="Cerrar Sesión", font=("Helvetica", 12), command=lambda: cerrar_sesion(ventana_principal)).pack(side=tk.BOTTOM, pady=20)

    ventana_principal.mainloop()

def crear_ventana_login():
    global ventana_login
    ventana_login = tk.Tk()
    ventana_login.title("Inicio de Sesión")

    ancho_ventana = 400
    alto_ventana = 250
    x_ventana = (ventana_login.winfo_screenwidth() // 2) - (ancho_ventana // 2)
    y_ventana = (ventana_login.winfo_screenheight() // 2) - (alto_ventana // 2)
    ventana_login.geometry(f"{ancho_ventana}x{alto_ventana}+{x_ventana}+{y_ventana}")

    frame_login = tk.Frame(ventana_login)
    frame_login.pack(pady=20)

    tk.Label(frame_login, text="Usuario", font=("Helvetica", 12)).grid(row=0, column=0, padx=10, pady=10)
    global entry_usuario
    entry_usuario = tk.Entry(frame_login, font=("Helvetica", 12))
    entry_usuario.grid(row=0, column=1, padx=10, pady=10)

    tk.Label(frame_login, text="Contraseña", font=("Helvetica", 12)).grid(row=1, column=0, padx=10, pady=10)
    global entry_contrasena
    entry_contrasena = tk.Entry(frame_login, show='*', font=("Helvetica", 12))
    entry_contrasena.grid(row=1, column=1, padx=10, pady=10)

    tk.Button(frame_login, text="Iniciar Sesión", command=iniciar_sesion, font=("Helvetica", 12)).grid(row=2, columnspan=2, pady=10)

    ventana_login.mainloop()

crear_ventana_login()
