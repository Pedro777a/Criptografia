"""
  Algoritmo de Product Cipher
  Instituto Polit�cnico Nacional
  ESCOM
  Alvarado Romero Luis Manuel   
  Materia: Ciptografia
  Grupo: 6CM3
"""
import random
import math
import pickle

# Creas un diccionario con las 27 letras
# Llenas la matriz
# Tomas los indices de fila columna 
# Sacas la correlacion de palabra digito con un diccionario
# Devuelves el mensaje 
DiccionarioIngles=['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
Renglon_cifrado=['A','D','F','G','V','X']
Ruta="Practica3/"

# Funcion que nos permite leer un archivo
def leer_archivo(nombre_archivo):
    try:
        with open(Ruta+nombre_archivo, 'r') as archivo:
            contenido = archivo.read()
        return contenido
    except IOError:
        print(f"No se pudo leer el archivo '{nombre_archivo}'.")

# Funcion que nos permite imprimir una matriz de forma cuadrada
def imprimir_matriz_cuadrada(matriz):
    # Encontrar el número máximo de dígitos en cualquier elemento de la matriz
    max_longitud = max(max(len(str(elemento)) for elemento in fila) for fila in matriz)
    # Imprimir la matriz
    for fila in matriz:
        for elemento in fila:
            # Formatear cada elemento para que tenga el mismo ancho
            print(f'{elemento:{max_longitud}}', end=' ')
        print()  # Imprimir una nueva línea después de cada fila

# Funcion que llena nuestra matriz de sustitucion de manera aleatoria usando el diccionario
def MatizAleatoria(Diccionario):
    # Inicializar la matriz con espacios en blanco
    Matriz = [['x'] * 6 for _ in range(6)]
    random.shuffle(Diccionario)
    indice=0
    for i in range (6):
        for j in range(6):
            Matriz[i][j]=Diccionario[indice]
            indice+=1
    return Matriz

# Funcion que busca la correspondencia del mensaje dentro de la matriz
def BuscarCorrespondencia(Matriz,Mensaje):
    MensajeDigito=[]
    for i in Mensaje:
        for j in range(len(Matriz)):
             for k in range(len(Matriz[j])):
                if Matriz[j][k]==i:
                    MensajeDigito.append(j)
                    MensajeDigito.append(k)
    return MensajeDigito

# Funcion que convierte nuestros indices a las letras usando nuestro renglon de sustitucion
def ConvDig(Mensajedigito):
    Mensaje=[]
    for i in Mensajedigito:
        Mensaje.append(Renglon_cifrado[i])
    return Mensaje

# Funcion que nos permite pasar el mensasje en palabras a digitod para nuestros indices de matriz
def ConvPal(MensajeCar):
    Mensaje=[]
    for i in MensajeCar:
        for j in range(len(Renglon_cifrado)):
            if(i==Renglon_cifrado[j]):
                Mensaje.append(j)
    return Mensaje

# Funcion que nos permite usar nuestro indices del mensaje para encontrar el mensaje original
def EncontrarCorrespondencia(MensajeDigito,MatrizCorrespondencia):
    Mensaje=[]
    for i in range(0,len(MensajeDigito)-1,2):
        j=MensajeDigito[i]
        k=MensajeDigito[i+1]
        Mensaje.append(MatrizCorrespondencia[j][k])
    return Mensaje

# Encontramos la permutacion de nuestra palabra clave
def EncontrarPermutacion(palabra):
    Permutacion = []
    letras_unicas = sorted(set(palabra), key=palabra.index)
    letras_alfabeticas = sorted(letras_unicas)
    diccionario_letras = {letra: i+1 for i, letra in enumerate(letras_alfabeticas)}
    
    for letra in palabra.lower():
        if letra.isalpha():
            Permutacion.append(diccionario_letras[letra])
    
    # Restar 1 al final a todos los valores del arreglo
    Permutacion = [num - 1 for num in Permutacion]
    
    return Permutacion

# Funcion que crea una matriz a partide del mensaje que le pasamos 
def partir_mensaje_en_matriz(mensaje, n):
    # Calcular el número de filas necesarias en base a la longitud del mensaje sin espacios
    num_caracteres = len(mensaje)
    num_filas = math.ceil(num_caracteres / n)

    # Crear la matriz con el mensaje
    matriz = [[''] * n for _ in range(num_filas)]

    # Llenar la matriz con el mensaje sin espacios
    indice_mensaje = 0
    for i in range(num_filas):
        for j in range(n):
            if indice_mensaje < num_caracteres:
                matriz[i][j] = mensaje[indice_mensaje]
                indice_mensaje += 1
            else:
                matriz[i][j] = random.choice('abcdefghijklmnopqrstuvwxyz')

    return matriz

# Funcion que reconstruye la matriz de nuestro mensaje cifrado
def ReconstruirMatriz(mensaje, n, Permutacion):
    # Calcular el número de filas necesarias en base a la longitud del mensaje sin espacios
    num_caracteres = len(mensaje)
    num_filas = math.ceil(num_caracteres / n)

    # Crear la matriz con el mensaje
    matriz = [[''] * n for _ in range(num_filas)]

    # Llenar la matriz con el mensaje sin espacios
    indice_mensaje = 0
    indice_real=0
    for i in range(0,n):
        for j in Permutacion:          
            if(i==j):
                for k in range(num_filas):
                    if indice_mensaje < num_caracteres:
                        matriz[k][indice_real] = mensaje[indice_mensaje]
                        indice_mensaje += 1
                    else:
                        matriz[i][j] = random.choice('abcdefghijklmnopqrstuvwxyz')
            indice_real=indice_real+1
        indice_real=0
    return matriz

# Funcion que lee el mensaje original desde la matriz de nuestro mensaje
def LeeMensaje(Matriz):
    MensajeCar=[]
    for j in range(len(Matriz)):
        for k in range(len(Matriz[j])):
            MensajeCar.append(Matriz[j][k])
    return MensajeCar

# Leemos los elementos de las columnas de nuestra matriz para realizar un mensaje cifrado
def Recuperarelementos(matriz, indices):
    mensaje=[]
    for i in range(0,len(indices)):
        r=0
        for j in indices:
            if(i==j):
                if(r<len(indices)-1):
                    columna = list(zip(*matriz))[r]
                    mensaje.extend(columna)
                else:
                    columna = list(zip(*matriz))[r]
                    mensaje.extend(columna)
            r=r+1
    return mensaje

def ProductCipher(Mensaje,Palabra,matriz):
    MensajeDigito=BuscarCorrespondencia(matriz,Mensaje)
    print(f"\nMensaje a digito: {MensajeDigito}\n")
    Mensaje=ConvDig(MensajeDigito)
    print(f"\nMensaje sustituido: {Mensaje}\n")
    Permutacion=EncontrarPermutacion(Palabra)
    print(f"La permutacion de nuestra palabra es: {Permutacion}")
    NMatriz=partir_mensaje_en_matriz(Mensaje,len(Permutacion))
    print(f"La matriz de nuestro mensaje es:")
    imprimir_matriz_cuadrada(NMatriz)
    MensajeCifrado=Recuperarelementos(NMatriz, Permutacion)
    return MensajeCifrado

def DescifraProductCipher(MensajeCifrado, Palabra, Matrizcorrespondencia):
    Mensaje=[]
    Permutacion=EncontrarPermutacion(Palabra)
    print("La matriz de correspondencia es: \n")
    imprimir_matriz_cuadrada(Matrizcorrespondencia)
    print(f"\nLa palabra clave es: {Palabra}")
    print(f"La permutacion de nuestra palabra es: {Permutacion}")
    Matriz=ReconstruirMatriz(MensajeCifrado,len(Permutacion),Permutacion)
    print(f"\nLa matriz de nuestro mensaje es:")
    imprimir_matriz_cuadrada(Matriz)
    MensajeCaract=LeeMensaje(Matriz)
    print(f"\nEl mensaje a caracter es: {MensajeCaract}")
    Mensajedig=ConvPal(MensajeCaract)
    print(f"\nEl mensaje a digito es: {Mensajedig}")
    Mensaje=EncontrarCorrespondencia(Mensajedig,Matrizcorrespondencia)
    #Mensaje=''.join(Mensaje)
    print(f"\nEl mensaje descifrado es: {Mensaje}") 
    return Mensaje

def opcion_1():
    PalabraClave=input("Ingrese la palabra clave del cifrado: ")
    Mensaje=input("Ingrese el mensaje a cifrar: ")
    PalabraClave=PalabraClave.lower()
    Mensaje=Mensaje.lower()
    matriz=MatizAleatoria(DiccionarioIngles)
    print("Matriz de Susitucion: \n")
    imprimir_matriz_cuadrada(matriz)
    MensajeCifrado=ProductCipher(Mensaje,PalabraClave,matriz)
    print(f"\nEl mensaje cifrado es:{MensajeCifrado} \n")
    with open(Ruta+'palabraclave.pkl', 'wb') as f:
            pickle.dump(PalabraClave, f)
    with open(Ruta+'mensaje_cifrado.pkl', 'wb') as f:
            pickle.dump(MensajeCifrado, f)
    with open(Ruta+'matriz_correspondencia.pkl', 'wb') as f:
            pickle.dump(matriz, f)
    with open(Ruta+"Archivocifrado.txt", 'w+') as archivo:
            archivo.write("".join(MensajeCifrado))
    
def opcion_2():
    try:
        # Cargamos la palabra y el mensaje
        with open(Ruta+'palabraclave.pkl', 'rb') as f:
            PalabraClave=pickle.load(f)
        with open(Ruta+'matriz_correspondencia.pkl', 'rb') as f:
            matriz=pickle.load(f)
        """with open(Ruta+'mensaje_cifrado.pkl', 'rb') as f:
            MensajeCifrado=pickle.load(f)"""
        print("Datos cargados desde archivos pickle. \n")
        MensajeCifrado=leer_archivo("Archivocifrado.txt")
        print(f"El mensaje cifrado es: {MensajeCifrado}\n")
        DescifraProductCipher(MensajeCifrado,PalabraClave,matriz)
    except FileNotFoundError:
        print("Archivos no encontrados")

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
        print("1. Cifrado de product cipher")
        print("2. Descifrado product cipher")
        print("3. Salir\n")
        seleccion = input("Selecciona una opción: ")

        if seleccion in opciones:
            opciones[seleccion]()
        else:
            print("Opción no válida. Por favor, selecciona una opción del menú.")

if __name__ == "__main__":
    main()