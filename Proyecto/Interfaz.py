import tkinter as tk
from tkinter import messagebox

# Datos de ejemplo para los usuarios
usuarios = [
    {'username': 'prof1', 'password': '1234', 'role': 'profesor', 'name': 'Profesor Uno'},
    {'username': 'director1', 'password': '1234', 'role': 'director', 'name': 'Director Uno'},
    {'username': 'admin1', 'password': '1234', 'role': 'administrador', 'name': 'Administrador Uno'},
]

# Función para verificar las credenciales e iniciar sesión
def iniciar_sesion():
    usuario = entry_usuario.get()
    contrasena = entry_contrasena.get()
    for user in usuarios:
        if usuario == user['username'] and contrasena == user['password']:
            ventana_login.destroy()
            abrir_ventana_principal(user)
            return
    messagebox.showerror("Error", "Usuario o contraseña incorrectos")

# Función para cerrar sesión y volver a la ventana de inicio de sesión
def cerrar_sesion(ventana_principal):
    ventana_principal.destroy()
    crear_ventana_login()

# Función para abrir la ventana correspondiente al rol
def abrir_ventana_principal(user):
    ventana_principal = tk.Tk()
    ventana_principal.title(f"Ventana de {user['role'].capitalize()}")
    ventana_principal.geometry("300x300")

    # Mensaje de bienvenida
    tk.Label(ventana_principal, text=f"Bienvenido, {user['name']}!", font=("Helvetica", 14)).pack(pady=10)

    # Botones específicos según el rol
    if user['role'] == 'profesor':
        tk.Button(ventana_principal, text="Generar reporte", font=("Helvetica", 12)).pack(pady=5)
        tk.Button(ventana_principal, text="Firmar reporte", font=("Helvetica", 12)).pack(pady=5)
        tk.Button(ventana_principal, text="Cifrar reporte", font=("Helvetica", 12)).pack(pady=5)
    elif user['role'] == 'director':
        tk.Button(ventana_principal, text="Generar reporte", font=("Helvetica", 12)).pack(pady=5)
        tk.Button(ventana_principal, text="Firmar reporte", font=("Helvetica", 12)).pack(pady=5)
        tk.Button(ventana_principal, text="Cifrar reporte", font=("Helvetica", 12)).pack(pady=5)
        tk.Button(ventana_principal, text="Validar firma", font=("Helvetica", 12)).pack(pady=5)
        tk.Button(ventana_principal, text="Descifrar reporte", font=("Helvetica", 12)).pack(pady=5)
    elif user['role'] == 'administrador':
        tk.Button(ventana_principal, text="Generar reporte", font=("Helvetica", 12)).pack(pady=5)
        tk.Button(ventana_principal, text="Firmar reporte", font=("Helvetica", 12)).pack(pady=5)
        tk.Button(ventana_principal, text="Cifrar reporte", font=("Helvetica", 12)).pack(pady=5)
        tk.Button(ventana_principal, text="Validar firma", font=("Helvetica", 12)).pack(pady=5)
        tk.Button(ventana_principal, text="Descifrar reporte", font=("Helvetica", 12)).pack(pady=5)

    # Botón para cerrar sesión
    tk.Button(ventana_principal, text="Cerrar Sesión", font=("Helvetica", 12), command=lambda: cerrar_sesion(ventana_principal)).pack(pady=20)

    ventana_principal.mainloop()

# Función para crear la ventana de inicio de sesión
def crear_ventana_login():
    global ventana_login
    ventana_login = tk.Tk()
    ventana_login.title("Inicio de Sesión")
    ventana_login.geometry("400x250")

    tk.Label(ventana_login, text="Usuario", font=("Helvetica", 12)).grid(row=0, column=0, padx=10, pady=10)
    global entry_usuario
    entry_usuario = tk.Entry(ventana_login, font=("Helvetica", 12))
    entry_usuario.grid(row=0, column=1, padx=10, pady=10)

    tk.Label(ventana_login, text="Contraseña", font=("Helvetica", 12)).grid(row=1, column=0, padx=10, pady=10)
    global entry_contrasena
    entry_contrasena = tk.Entry(ventana_login, show='*', font=("Helvetica", 12))
    entry_contrasena.grid(row=1, column=1, padx=10, pady=10)

    tk.Button(ventana_login, text="Iniciar Sesión", command=iniciar_sesion, font=("Helvetica", 12)).grid(row=2, columnspan=2, pady=10)

    ventana_login.mainloop()

# Iniciar la aplicación
crear_ventana_login()
