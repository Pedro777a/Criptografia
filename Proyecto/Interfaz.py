import os
import json
import base64
import hashlib
import PyPDF2
import tkinter as tk
from tkinter import messagebox, filedialog
from PIL import Image, ImageTk
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
# Funcion que nos permite leer pdf
def leer_pdf(archivo_pdf):
    texto = ""
    with open(archivo_pdf, 'rb') as file:
        lector_pdf = PdfReader(file)
        for pagina in lector_pdf.pages:
            texto += pagina.extract_text()
    return texto

# Funcion que lee el archivo de acuerdo con su extension
def leer_archivo(ruta_archivo):
    if ruta_archivo.endswith('.pdf'):
        return leer_pdf(ruta_archivo)
    else:
        return "Formato de archivo no soportado."

# Funcion que genera o carga las llaves RSA para cada usuario
def generar_o_cargar_rsa_keys(nombre_archivo_privado, nombre_archivo_publico):
    print("---Generar o cargar claves RSA---")
    if not os.path.exists(Ruta + nombre_archivo_privado) or not os.path.exists(Ruta + nombre_archivo_publico):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        with open(Ruta + nombre_archivo_privado, "wb") as f:
            f.write(private_key)
        with open(Ruta + nombre_archivo_publico, "wb") as f:
            f.write(public_key)
        print(f"Llaves generadas y guardadas en {Ruta + nombre_archivo_privado} y {Ruta + nombre_archivo_publico}\n")
    else:
        print(f"Las llaves ya existen en {Ruta + nombre_archivo_privado} y {Ruta + nombre_archivo_publico}\n")

# Funcion que calcula el Hash de un archivo con SHA-256
def calcular_hash(ruta_archivo):
    contenido = leer_archivo(ruta_archivo)

    hash_sha256 = hashlib.sha256()
    hash_sha256.update(contenido.encode('utf-8'))
    hash_hex256 = hash_sha256.hexdigest()

    print("Hash SHA-256:", hash_hex256)

    hash_bytes = hash_hex256.encode('utf-8')
    return hash_bytes

# Funcion que crea una firma con la llave privada de nuestro destinatario 
# y el hash de un archivo
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

# Funcion que guarda una firma dentro de los metadatos de un archivo
# Con el rol de quien lo firma
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

# Funcion que verifica una firma de con la llave publica de las llaves RSA
def verify_signature(public_key_path, file_path, signature):
    with open(public_key_path, 'rb') as f:
        public_key = load_pem_public_key(f.read())
    
    file_hash = calcular_hash(file_path)
    print("Hash calculado con exito")
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

# Funcion que extrae la firma de los metadatos de un archivo
def extract_signature_from_pdf(signed_pdf, remitente):
    reader = PdfReader(signed_pdf)
    metadata = reader.metadata
    print(f"Metadatos del archivo: {metadata}")
    signature_hex = metadata.get(remitente)
    return bytes.fromhex(signature_hex) if signature_hex else None

# Funcion que genera la llave de AES para cifrar un archivo
def GenerarllaveAES(numbytes):
    key= get_random_bytes(numbytes)
    return key

# Funcion que convierte un texto binario a base 64
def convb64(Contenido):
    contenido_codificado = base64.b64encode(Contenido)
    return contenido_codificado

# Funcion que guarda la llave de AES en base 64 dentro de un archivo
def Guardar_en_archivo(Contenido,Nombrearchivo):
    Contenido = convb64(Contenido)
    with open(Ruta+Nombrearchivo, 'wb') as archivo:
            archivo.write(Contenido)

# Funcion que realiza el key wrapping de una llave de AES con una llave publica
def CifrarllaveAES(mensaje_bytes,public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    mensaje_cifrado = cipher_rsa.encrypt(mensaje_bytes)
    print("Llave de AES cifrada con RSA")
    return mensaje_cifrado

# Funcon que extrae los metadatos de un archivo
def extraer_metadatos(archivo_pdf):
    with open(archivo_pdf, 'rb') as f:
        reader = PdfReader(f)
        metadatos = reader.metadata
    return dict(metadatos)

# Fucnion que realiza el cifrado de AES de un archivo 
# Y tambien ingresa los metadatos del archivo orignal al archivo cifrado
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
    print(f"Metadatos del archivo original: {metadatos}")
    metadatos_json = json.dumps(metadatos).encode('utf-8')
    print("Metadatos agregados al archvio cifrado correctamente")
    # Guardar el nonce, el archivo cifrado, el tag de autenticación y los metadatos en el archivo de salida
    with open(Ruta+archivo_salida, 'wb') as f:
        f.write(len(metadatos_json).to_bytes(4, byteorder='big'))
        f.write(metadatos_json)
        f.write(nonce + textocifrado + tag)

# Funcion que descifra la llave de AES con la llave privada
def DescifrarllaveAES(mensaje_cifrado,private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    mensaje_descifrado = cipher_rsa.decrypt(mensaje_cifrado)
    return mensaje_descifrado

# Funcion que descifra AES de un archivo conservando sus metadatos
def DescifradoAES_Archivo(key, archivo_cifrado, archivo_salida):
    # Leer el contenido del archivo cifrado
    with open(Ruta+archivo_cifrado, 'rb') as f:
        contenido_cifrado = f.read()
    
    # Leer la longitud de los metadatos
    metadatos_len = int.from_bytes(contenido_cifrado[:4], byteorder='big')

    # Extraer los metadatos
    metadatos_json = contenido_cifrado[4:4 + metadatos_len]
    metadatos = json.loads(metadatos_json.decode('utf-8'))
    print(f"Metadatos del archivo cifrado extraidos: {metadatos}")
    # Separar el nonce, el texto cifrado y el tag de autenticación
    nonce = contenido_cifrado[4 + metadatos_len:4 + metadatos_len + 12]
    tag = contenido_cifrado[-16:]
    textocifrado = contenido_cifrado[4 + metadatos_len + 12:-16]
    
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

# Funcion que muestra el flujo del cifrado de archivos 
def cifrar_archivo(rol_destinatario):
    print("---Cifrar documento---")
    llave_publica = Ruta + rol_destinatario + "_public.pem"
    if 'archivo_seleccionado' not in globals():
        messagebox.showwarning("Advertencia", "Primero debe subir un reporte.")
        return
    nombre_archivo = os.path.basename(archivo_seleccionado)
    key = GenerarllaveAES(32)
    print(f"Llave de AES generada correctamente: {key.hex()}")
    with open(llave_publica, 'rb') as f:
        public_key = RSA.import_key(f.read())
    mensaje_cifrado = CifrarllaveAES(key, public_key)
    Guardar_en_archivo(mensaje_cifrado, rol_destinatario+"_llave_AES_cifrada.bin")
    print(f"Llave cifrada guardada en: {Ruta+rol_destinatario+"_llave_AES_cifrada.bin"}")
    CifradoAES_Archivo_conmetadatos(key, archivo_seleccionado, rol_destinatario+"_documento_cifrado.pdf")
    print(f"Documento cifrado correctamente y guardado en: {Ruta+rol_destinatario+"_documento_cifrado.pdf"}\n")
    messagebox.showinfo("Éxito", "El documento ha sido cifrado correctamente.")


# Funcion que muestra el flujo de descifrado de archivos
def Descifrar_archivo(user):
    print("---Descifrar archivo---")
    llave_privada = Ruta + user['role'] + "_private.pem"
    if 'archivo_seleccionado' not in globals():
        messagebox.showwarning("Advertencia", "Primero debe subir un reporte.")
        return
    nombre_archivo = os.path.basename(archivo_seleccionado)
    ruta_llave_aes_cifrada = Ruta + user['role'] + "_llave_AES_cifrada.bin"
    with open(llave_privada, 'rb') as f:
        private_key = RSA.import_key(f.read())
    print(f"Llave privada de {user['role']} cargada con exito")
    with open(ruta_llave_aes_cifrada, 'rb') as f:
        mensaje_cifrado = f.read()
    print("Llave cifrada cargada con exito")
    try:
        llave_cifrada=key=base64.b64decode(mensaje_cifrado)
        print(f"Llave cifrada: {llave_cifrada}")
        key = DescifrarllaveAES(llave_cifrada, private_key)
        print(f"Llave descifrada: {key.hex()}")
        DescifradoAES_Archivo(key, nombre_archivo, user['role']+"_documento_descifrado.pdf")
        print(f"Documento descifrado correctamente y guardado en {Ruta+user['role']+"_documento_descifrado.pdf"}")
        messagebox.showinfo("Éxito", "El documento ha sido descifrado correctamente.")
    except Exception as e:
        messagebox.showerror("Error", f"Error al descifrar el documento: {e}")

# Funcion para el inicio de sesion de usuarios
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

# Funcion para el cerrar sesion de los usuarios
def cerrar_sesion(ventana):
    ventana.destroy()
    crear_ventana_login()

# Funcion para regresar al menu
def volver_menu(ventana, ventana_principal):
    ventana.destroy()
    ventana_principal.deiconify()

# Funcion que nos permite subir un archivo con el explorador de archivos
def subir_reporte():
    file_path = filedialog.askopenfilename(initialdir=Ruta)
    if file_path:
        print("Archivo seleccionado:", file_path)
        global archivo_seleccionado
        archivo_seleccionado = file_path
    else:
        print("No se seleccionó ningún archivo")

# Funcion que nos muestra el flujo de firma de documento
def firmar_documento(user):
    print("---Firmar documento---")
    llave_privada = Ruta + user['role'] + "_private.pem"
    print(f"Llave privada: {llave_privada} cargada exitosamente")
    if 'archivo_seleccionado' not in globals():
        messagebox.showwarning("Advertencia", "Primero debe subir un reporte.")
        return
    nombre_archivo = os.path.basename(archivo_seleccionado)
    hash_documento = calcular_hash(archivo_seleccionado)
    firma = sign_hash(llave_privada, hash_documento)
    print("Firma del documento: ", firma)
    print("Firma hexadecimal del documento: ", firma.hex())
    guardar_firma(archivo_seleccionado, Ruta + "Firma_doc.pdf", firma, '/firma_' + user['role'])
    print("Firma guardada en los metadatos del documento Firma_doc.pdf")
    messagebox.showinfo("Éxito", "El documento ha sido firmado correctamente.")

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
        print("---Validar firma---")
        if 'archivo_seleccionado' not in globals():
            messagebox.showwarning("Advertencia", "Primero debe subir un documento.")
            return
        if not rol_seleccionado.get():
            messagebox.showwarning("Advertencia", "Debe seleccionar un rol.")
            return
        remitente = "/firma_" + rol_seleccionado.get()
        signature = extract_signature_from_pdf(archivo_seleccionado, remitente)
        print(f"Firma cargada con exito: {signature}")
        if not signature:
            messagebox.showwarning("Advertencia", f"No se encontró una firma de {rol_seleccionado.get()} en el documento.")
            return
        public_key_path = Ruta + rol_seleccionado.get() + "_public.pem"
        print(f"Llave publica de {rol_seleccionado.get()} cargada con exito")
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
        botones = [("Firmar reporte", lambda: abrir_ventana_firmar(user, ventana_principal)), ("Cifrar reporte", lambda: abrir_ventana_cifrar(user, ventana_principal)), ("Descifrar reporte", lambda: abrir_ventana_descifrar(user, ventana_principal))]
    elif user['role'] == 'director':
        botones = [("Firmar reporte", lambda: abrir_ventana_firmar(user, ventana_principal)), 
                   ("Cifrar reporte", lambda: abrir_ventana_cifrar(user, ventana_principal)), ("Validar firma", lambda: abrir_ventana_validar_firma(user, ventana_principal)), ("Descifrar reporte", lambda: abrir_ventana_descifrar(user, ventana_principal))]
    elif user['role'] == 'administrador':
        botones = [("Firmar reporte", lambda: abrir_ventana_firmar(user, ventana_principal)), 
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
    ventana_login.title("INICIO DE SESION ")

    ancho_ventana = 800
    alto_ventana = 400
    x_ventana = (ventana_login.winfo_screenwidth() // 2) - (ancho_ventana // 2)
    y_ventana = (ventana_login.winfo_screenheight() // 2) - (alto_ventana // 2)
    ventana_login.geometry(f"{ancho_ventana}x{alto_ventana}+{x_ventana}+{y_ventana}")

    # Crear frame para la imagen a la izquierda
    frame_imagen = tk.Frame(ventana_login, bg="#007BFF")
    frame_imagen.pack(side="left", fill="both", expand=True)

    # Cargar la imagen y agregarla al frame
    img_path = r"C:\Users\Pedro Cruz\Documents\GitHub\Criptografia\Proyecto\imagenes\OIP.png"
    print(f"Ruta de la imagen: {img_path}")  # Instrucción de depuración para verificar la ruta

    # Verificar si el archivo existe
    if not os.path.isfile(img_path):
        print(f"El archivo no existe en la ruta especificada: {img_path}")
        return

    img = Image.open(img_path)
    img = img.resize((400, 400), Image.Resampling.LANCZOS)  # Ajuste aquí
    img_tk = ImageTk.PhotoImage(img)
    label_img = tk.Label(frame_imagen, image=img_tk, bg="#007BFF")
    label_img.image = img_tk
    label_img.pack(expand=True)

    # Crear frame para los campos de login a la derecha
    frame_login = tk.Frame(ventana_login, bg="white")
    frame_login.pack(side="right", fill="both", expand=True)

    tk.Label(frame_login, text="Inicio de sesión", font=("Helvetica", 18), bg="white").pack(pady=20)
    tk.Label(frame_login, text="Usuario", font=("Helvetica", 12), bg="white").pack(pady=10)
    global entry_usuario
    entry_usuario = tk.Entry(frame_login, font=("Helvetica", 12))
    entry_usuario.pack(pady=10)

    tk.Label(frame_login, text="Contraseña", font=("Helvetica", 12), bg="white").pack(pady=10)
    global entry_contrasena
    entry_contrasena = tk.Entry(frame_login, show='*', font=("Helvetica", 12))
    entry_contrasena.pack(pady=10)

    tk.Button(frame_login, text="Iniciar sesión", command=iniciar_sesion, font=("Helvetica", 12), bg="#007BFF", fg="white").pack(pady=20)

    ventana_login.mainloop()

crear_ventana_login()