"""
  Algoritmo Cifrado AES
  Instituto Polit�cnico Nacional
  ESCOM
  Alvarado Romero Luis Manuel   
  Materia: Ciptografia
  Grupo: 6CM3
"""
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

Ruta = "Practica6/"

# Funcion que genera la llave de Cifrado
def GenerarllaveAES(numbytes):
    key= get_random_bytes(numbytes)
    print(f"\nLlave generada: {key}") 
    return key

# Funcion que nos permite leer un archivo
def leer_archivo(nombre_archivo):
    try:
        with open(Ruta+nombre_archivo, 'rb') as archivo:
            contenido = archivo.read()
        return contenido
    except IOError:
        print(f"No se pudo leer el archivo '{nombre_archivo}'.")

# Funcion que convierte un contenido a base 64 para lectura en pantalla
def convb64(Contenido):
    contenido_codificado = base64.b64encode(Contenido)
    return contenido_codificado

# Funcion que guarda la llave de 3DES en base 64 dentro de un archivo
def Guardar_en_archivo(Contenido,Nombrearchivo):
    Contenido= convb64(Contenido)
    with open(Ruta+Nombrearchivo, 'wb') as archivo:
            archivo.write(Contenido)

# Funcion que cifra un archivo mediante 3DES
def CifradoAES(key, mensaje):
    # Generar un IV (Vector de Inicialización) aleatorio
    iv = get_random_bytes(16)
    # Crear un objeto de cifrado AES en modo CBC
    cifrador = AES.new(key, AES.MODE_CBC, iv)
    # Rellenamos el texto mediante el tamaño del bloque de AES 
    texto_rellenado = pad(mensaje, AES.block_size)
    # Ciframos nuestro mensaje mediante el objeto de cifrado
    textocifrado = cifrador.encrypt(texto_rellenado)
    # Regresamos el archivo cifrado junto con el vector de inicializacion al principio
    return iv+textocifrado

# Funcion que descifra un archivo mediante 3DES
def DescifradoAES(key, mensaje):
    # Extraer el IV de los primeros 16 bytes
    iv = mensaje[:16]    
    # Extraer los datos cifrados
    datos_cifrado = mensaje[16:]
    # Creamos el objeto cifrador con el modo de operacion la llave y el IV
    cifrador =  AES.new(key, AES.MODE_CBC, iv)
    # Desciframos el mensaje con el objeto cifrador
    texto_descifrado = cifrador.decrypt(datos_cifrado)
    # Le quitamos el texto de relleno con la herramienta unpad
    mensaje = unpad(texto_descifrado, AES.block_size)
    return mensaje

def opcion_1():
    print("Seleccionaste Generar llave de AES")
    while True:
        tam=input("Ingresa el tamaño de llave en bytes: ")
        tam=int(tam)
        if(tam>32 or tam<16 or tam%8!=0):
            print("No es un tamaño de llave valida")
        else: 
            break
    key=GenerarllaveAES(int(tam))
    Guardar_en_archivo(key,"Llave.txt")
    print("La llave de cifrado se guardo en el archivo Llave.txt")

def opcion_2():
    print("Seleccionaste cifrar archivo")
    Nombrearchivo=(input("Ingrese el nombre del archivo a cifrar: "))
    Contenido=leer_archivo(Nombrearchivo)
    print(f"El archivo contiene: \n{Contenido}")
    Nombre=input("Ingresa el nombre del archivo de la llave con extension: ")
    key=leer_archivo(Nombre)
    key=base64.b64decode(key)    
    print(f"Llave de cifrado: {key}")
    Mensajecifrado=CifradoAES(key,Contenido)
    print(f"\nTexto cifrado:\n {Mensajecifrado}")
    Guardar_en_archivo(Mensajecifrado,"ArchivoCifrado.txt")
    print("El archivo cifrado se guardo como ArchivoCifrado.txt")    
    
def opcion_3():
    print("Seleccionaste descifrar archivo")
    Nombre=(input("Ingrese el nombre del archivo a descifrar: "))
    Contenido=leer_archivo(Nombre)
    Mensajecifrado=base64.b64decode(Contenido)
    Nombre=input("Ingresa el nombre del archivo de la llave con extension: ")
    key=leer_archivo(Nombre)
    key=base64.b64decode(key)
    print(f"Llave original: {key}")
    print(f"\nEl archivo cifrado es: \n{Contenido}")
    Mensaje=DescifradoAES(key,Mensajecifrado)
    print(f"\nEl archivo descifrado es: \n{Mensaje}")
    with open(Ruta+"ArchivoDescifrado.txt", 'wb') as archivo:
            archivo.write(Mensaje)
    print("El archivo descifrado se guardo como ArchivoDescifrado.txt")
    
def salir():
    print("Saliendo del programa...")
    exit()

def main():
    opciones = {
        '1': opcion_1,
        '2': opcion_2,
        '3': opcion_3,
        '4': salir
    }

    while True:
        print("\n Menú:")
        print("1. Generar llave AES")
        print("2. Cifrar archivo")
        print("3. Descifrar archivo")
        print("4. Salir\n")
        seleccion = input("Selecciona una opción: ")

        if seleccion in opciones:
            opciones[seleccion]()
        else:
            print("Opción no válida. Por favor, selecciona una opción del menú.")

if __name__ == "__main__":
    main()