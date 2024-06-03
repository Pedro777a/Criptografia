"""
  Algoritmo Cifrado 3DES
  Instituto Polit�cnico Nacional
  ESCOM
  Alvarado Romero Luis Manuel   
  Materia: Ciptografia
  Grupo: 6CM3
"""
import base64
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

Ruta = "Practica4/"

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

# Funcion que genera la llave de 3DES
def GenerarllaveDES(numbytes):
    key= get_random_bytes(numbytes)
    print(f"\nLlave generada: {key}") 
    return key

# Funcion que guarda la llave de 3DES en base 64 dentro de un archivo
def Guardar_en_archivo(Contenido,Nombrearchivo):
    Contenido= convb64(Contenido)
    with open(Ruta+Nombrearchivo, 'wb') as archivo:
            archivo.write(Contenido)

# Funcion que cifra un archivo mediante 3DES
def Cifrado3DES(key, mensaje):
    cifrador = DES3.new(key, DES3.MODE_ECB)
    texto_rellenado = pad(mensaje, DES3.block_size)
    textocifrado = cifrador.encrypt(texto_rellenado)
    return textocifrado

# Funcion que descifra un archivo mediante 3DES
def Descifrado3DES(key, mensaje):
    cifrador = DES3.new(key, DES3.MODE_ECB)
    texto_descifrado = cifrador.decrypt(mensaje)
    mensaje = unpad(texto_descifrado, DES3.block_size)
    return mensaje


def opcion_1():
    print("Seleccionaste cifrar archivo")
    Nombrearchivo=(input("Ingrese el nombre del archivo: "))
    Contenido=leer_archivo(Nombrearchivo)
    print(f"El archivo contiene: \n{Contenido}")
    res=input("\n¿Tienes algun archvio de llave? ")
    if(res=="si"):
        Nombre=input("Ingresa el nombre de tu archivo con extension: ")
        key=leer_archivo(Nombre)
        key=base64.b64decode(key)
    else:
        key=GenerarllaveDES(24)
    Guardar_en_archivo(key,"Llave.txt")
    print(f"Llave de cifrado: {key}")
    Mensajecifrado=Cifrado3DES(key,Contenido)
    print(f"\nTexto cifrado:\n {Mensajecifrado}")
    Guardar_en_archivo(Mensajecifrado,"ArchivoCifrado.txt")
    
    
def opcion_2():
    print("Seleccionaste descifrar archivo")
    Contenido=leer_archivo("ArchivoCifrado.txt")
    Mensajecifrado=base64.b64decode(Contenido)
    key=leer_archivo("Llave.txt")
    key= base64.b64decode(key)
    print(f"Llave original: {key}")
    print(f"\nEl archivo cifrado es: \n{Contenido}")
    Mensaje=Descifrado3DES(key,Mensajecifrado)
    print(f"\nEl archivo descifrado es: \n{Mensaje}")
    with open(Ruta+"ArchivoDescifrado.txt", 'wb') as archivo:
            archivo.write(Mensaje)

def salir():
    print("Saliendo del programa...")
    exit()

def main():
    opciones = {
        '1': opcion_1,
        '2': opcion_2,
        '3': salir
    }

    while True:
        print("\n Menú:")
        print("1.Cifrar archivo")
        print("2.Descifrar archivo")
        print("3. Salir\n")
        seleccion = input("Selecciona una opción: ")

        if seleccion in opciones:
            opciones[seleccion]()
        else:
            print("Opción no válida. Por favor, selecciona una opción del menú.")

if __name__ == "__main__":
    main()