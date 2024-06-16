import os
import tkinter as tk
from tkinter import messagebox, filedialog
from Crypto.PublicKey import RSA

Ruta="Proyecto/"

# Datos de ejemplo para los usuarios
usuarios = [
    {'username': 'prof1', 'password': '1234', 'role': 'profesor', 'name': 'Profesor Uno'},
    {'username': 'director1', 'password': '1234', 'role': 'director', 'name': 'Director Uno'},
    {'username': 'admin1', 'password': '1234', 'role': 'administrador', 'name': 'Administrador Uno'},
]

# Función para generar llaves públicas y privadas de RSA si no existen
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

# Función para verificar las credenciales e iniciar sesión
def iniciar_sesion():
    usuario = entry_usuario.get()
    contrasena = entry_contrasena.get()
    for user in usuarios:
        if usuario == user['username'] and contrasena == user['password']:
            # Generar o cargar las llaves al iniciar sesión
            generar_o_cargar_rsa_keys(f"{user['role']}_private.pem", f"{user['role']}_public.pem")
            ventana_login.destroy()
            abrir_ventana_principal(user)
            return
    messagebox.showerror("Error", "Usuario o contraseña incorrectos")

# Función para cerrar sesión y volver a la ventana de inicio de sesión
def cerrar_sesion(ventana):
    ventana.destroy()
    crear_ventana_login()

# Función para volver al menú anterior
def volver_menu(ventana, ventana_principal):
    ventana.destroy()
    ventana_principal.deiconify()

def subir_reporte():
    file_path = filedialog.askopenfilename(initialdir=Ruta)
    if file_path:
        print("Archivo seleccionado:", file_path)
        # Guardar la ruta del archivo en una variable global si es necesario
        global archivo_seleccionado
        archivo_seleccionado = file_path
    else:
        print("No se seleccionó ningún archivo")

# Función para abrir la ventana de firmar reporte
def abrir_ventana_firmar(user, ventana_principal):
    ventana_principal.withdraw()
    ventana_firmar = tk.Tk()
    ventana_firmar.title("Firmar Reporte")

    # Centrar la ventana
    ancho_ventana = 400
    alto_ventana = 300
    x_ventana = (ventana_firmar.winfo_screenwidth() // 2) - (ancho_ventana // 2)
    y_ventana = (ventana_firmar.winfo_screenheight() // 2) - (alto_ventana // 2)
    ventana_firmar.geometry(f"{ancho_ventana}x{alto_ventana}+{x_ventana}+{y_ventana}")

    # Marco para los botones
    frame_botones = tk.Frame(ventana_firmar)
    frame_botones.pack(pady=20)

    # Botones
    tk.Button(frame_botones, text="Subir Reporte", font=("Helvetica", 12), command=subir_reporte).grid(row=0, column=0, padx=10, pady=10)
    tk.Button(frame_botones, text="Subir Llave", font=("Helvetica", 12)).grid(row=0, column=1, padx=10, pady=10)
    tk.Button(frame_botones, text="Firmar Documento", font=("Helvetica", 12)).grid(row=1, column=0, columnspan=2, pady=10)
    tk.Button(ventana_firmar, text="Volver a Menu", font=("Helvetica", 12), command=lambda: volver_menu(ventana_firmar, ventana_principal)).pack(side=tk.BOTTOM, pady=20)

    ventana_firmar.mainloop()

# Función para abrir la ventana de cifrar reporte
def abrir_ventana_cifrar(user, ventana_principal):
    ventana_principal.withdraw()
    ventana_cifrar = tk.Tk()
    ventana_cifrar.title("Cifrar Reporte")

    # Centrar la ventana
    ancho_ventana = 400
    alto_ventana = 250
    x_ventana = (ventana_cifrar.winfo_screenwidth() // 2) - (ancho_ventana // 2)
    y_ventana = (ventana_cifrar.winfo_screenheight() // 2) - (alto_ventana // 2)
    ventana_cifrar.geometry(f"{ancho_ventana}x{alto_ventana}+{x_ventana}+{y_ventana}")

    # Marco para los botones
    frame_botones = tk.Frame(ventana_cifrar)
    frame_botones.pack(pady=20)

    # Botones
    tk.Button(frame_botones, text="Subir Reporte", font=("Helvetica", 12), command=subir_reporte).grid(row=0, column=0, padx=10, pady=10)
    tk.Button(ventana_cifrar, text="Volver a Menu", font=("Helvetica", 12), command=lambda: volver_menu(ventana_cifrar, ventana_principal)).pack(side=tk.BOTTOM, pady=20)

    ventana_cifrar.mainloop()

# Función para abrir la ventana correspondiente al rol
def abrir_ventana_principal(user):
    ventana_principal = tk.Tk()
    ventana_principal.title(f"Ventana de {user['role'].capitalize()}")

    # Centrar la ventana
    ancho_ventana = 600
    alto_ventana = 400
    x_ventana = (ventana_principal.winfo_screenwidth() // 2) - (ancho_ventana // 2)
    y_ventana = (ventana_principal.winfo_screenheight() // 2) - (alto_ventana // 2)
    ventana_principal.geometry(f"{ancho_ventana}x{alto_ventana}+{x_ventana}+{y_ventana}")

    # Mensaje de bienvenida
    tk.Label(ventana_principal, text=f"Bienvenido, {user['name']}!", font=("Helvetica", 14)).pack(pady=10)

    # Marco para centrar los botones
    frame_botones = tk.Frame(ventana_principal)
    frame_botones.pack(pady=20)

    # Función para crear botones con espaciado horizontal
    def crear_boton(frame, texto, command=None):
        boton = tk.Button(frame, text=texto, font=("Helvetica", 12), command=command)
        boton.pack(side=tk.LEFT, padx=10, pady=5)
        return boton

    # Botones específicos según el rol
    botones = []
    if user['role'] == 'profesor':
        botones = [("Generar reporte", None), ("Firmar reporte", lambda: abrir_ventana_firmar(user, ventana_principal)), ("Cifrar reporte", lambda: abrir_ventana_cifrar(user, ventana_principal))]
    elif user['role'] == 'director':
        botones = [("Generar reporte", None), ("Firmar reporte", lambda: abrir_ventana_firmar(user, ventana_principal)), 
                   ("Cifrar reporte", lambda: abrir_ventana_cifrar(user, ventana_principal)), ("Validar firma", None), ("Descifrar reporte", None)]
    elif user['role'] == 'administrador':
        botones = [("Generar reporte", None), ("Firmar reporte", lambda: abrir_ventana_firmar(user, ventana_principal)), 
                   ("Cifrar reporte", lambda: abrir_ventana_cifrar(user, ventana_principal)), ("Validar firma", None), ("Descifrar reporte", None)]

    # Crear botones en dos filas si hay más de tres botones
    for i, (texto, cmd) in enumerate(botones):
        if i < 3:
            crear_boton(frame_botones, texto, cmd)
        else:
            if i == 3:
                frame_botones2 = tk.Frame(ventana_principal)
                frame_botones2.pack(pady=5)
            crear_boton(frame_botones2, texto, cmd)

    # Botón para cerrar sesión
    tk.Button(ventana_principal, text="Cerrar Sesión", font=("Helvetica", 12), command=lambda: cerrar_sesion(ventana_principal)).pack(side=tk.BOTTOM, pady=20)

    ventana_principal.mainloop()

# Función para crear la ventana de inicio de sesión
def crear_ventana_login():
    global ventana_login
    ventana_login = tk.Tk()
    ventana_login.title("Inicio de Sesión")

    # Centrar la ventana
    ancho_ventana = 400
    alto_ventana = 250
    x_ventana = (ventana_login.winfo_screenwidth() // 2) - (ancho_ventana // 2)
    y_ventana = (ventana_login.winfo_screenheight() // 2) - (alto_ventana // 2)
    ventana_login.geometry(f"{ancho_ventana}x{alto_ventana}+{x_ventana}+{y_ventana}")

    # Marco para centrar los widgets
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

# Iniciar la aplicación
crear_ventana_login()
