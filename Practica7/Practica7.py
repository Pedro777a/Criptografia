"""
  Algoritmo Funciones Hash criptograficas
  Instituto Polit�cnico Nacional
  ESCOM
  Alvarado Romero Luis Manuel   
  Materia: Ciptografia
  Grupo: 6CM3
"""
import base64
import hashlib
import PyPDF2
import docx
import csv

Ruta = "Practica7/"

# Definimos las funciones para leer nuestros diferentes archivos
def leer_pdf(archivo_pdf):
    texto = ""
    with open(archivo_pdf, 'rb') as file:
        lector_pdf = PyPDF2.PdfReader(file)
        for pagina in lector_pdf.pages:
            texto += pagina.extract_text()
    return texto

def leer_docx(archivo_docx):
    doc = docx.Document(archivo_docx)
    texto = "\n".join(parrafo.text for parrafo in doc.paragraphs)
    return texto

def leer_txt(archivo_txt):
    with open(archivo_txt, 'r', encoding='utf-8') as file:
        texto = file.read()
    return texto

def leer_csv(archivo_csv):
    texto = ""
    with open(archivo_csv, 'r', encoding='utf-8') as file:
        lector_csv = csv.reader(file)
        for fila in lector_csv:
            texto += ",".join(fila) + "\n"
    return texto

# Definimos una funcion para evaluar que clase de archivo es
def leer_archivo(ruta_archivo):
    if ruta_archivo.endswith('.pdf'):
        return leer_pdf(ruta_archivo)
    elif ruta_archivo.endswith('.docx'):
        return leer_docx(ruta_archivo)
    elif ruta_archivo.endswith('.txt'):
        return leer_txt(ruta_archivo)
    elif ruta_archivo.endswith('.csv'):
        return leer_csv(ruta_archivo)
    else:
        return "Formato de archivo no soportado."

Nombre_archivo=input("Ingresa el nombre del archivo con extension: ")
contenido = leer_archivo(Ruta+Nombre_archivo)
print(contenido)

# Crear un objeto hash SHA-224
hash_sha224 = hashlib.sha224()

hash_sha256 = hashlib.sha256()

hash_sha384 = hashlib.sha384()

# Actualizar el objeto hash con la cadena de texto codificada en bytes
hash_sha224.update(contenido.encode('utf-8'))

hash_sha256.update(contenido.encode('utf-8'))

hash_sha384.update(contenido.encode('utf-8'))

# Obtener el valor del hash en formato hexadecimal
hash_hex224 = hash_sha224.hexdigest()

hash_hex256 = hash_sha256.hexdigest()

hash_hex384 = hash_sha384.hexdigest()

# Imprimimos la cadena de salida de la funcion Hash
print("Hash SHA-224:", hash_hex224)

print("Hash SHA-256:", hash_hex256)

print("Hash SHA-384:", hash_hex384)

"""
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
    main()"""