"""
  Algoritmo de multiplicative inverse
  Instituto Polit�cnico Nacional
  ESCOM
  Alvarado Romero Luis Manuel   
  Materia: Ciptografia
  Grupo: 6CM3
"""
import random
import math
import string

# Calculamos el maximo comun divisor
def gcd(a,b):
    while b!=0:
        a, b = b, a%b
    return a

# Define si un numero es cooprimo de otro numero
def es_coprimo(num,tam):
    # Evaluamos si a es coopimo de n
    if(gcd(num,tam)==1):
        return True

# Definimmos una nueva funcion basada en el algoritmo extendido de euclides
def Xgcd(a,n):
    u,v=a,n
    x1=1 
    x2=0
    while u!=1:
        q=math.floor(v/u)
        r=v-q*u
        x=x2-q*x1
        v=u
        u=r
        x2=x1
        x1=x
    res = x1%n
    return(res)

# Listamos los elementos de Z* junto con sus inversos
def Listarelem(n):
    ZEs=[]
    Inversos=[]
    for i in range(1,n):
        if es_coprimo(i,n)==True:
            ZEs.append(i)
            Inversos.append(Xgcd(i,n))
    return ZEs, Inversos

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

# Generamos una matriz con nuestro mensaje a encriptar basado en la longitud de nuestro mensaje
def partir_mensaje_en_matriz(mensaje, n):
    # Eliminar los espacios del mensaje
    mensaje_sin_espacios = mensaje.replace(" ", "")
    
    # Calcular el número de filas y columnas necesarias en base a la longitud del mensaje sin espacios
    num_caracteres = len(mensaje_sin_espacios)
    num_filas = math.ceil(num_caracteres / n)
    
    # Inicializar la matriz con espacios en blanco
    matriz = [[''] * n for _ in range(num_filas)]
    
    # Inicializar variables para los índices de fila y columna
    fila_inicio, fila_fin = 0, num_filas - 1
    columna_inicio, columna_fin = 0, n - 1
    
    indice_mensaje = 0
    while fila_inicio <= fila_fin and columna_inicio <= columna_fin:
        # Llenar la fila superior de izquierda a derecha
        for j in range(columna_inicio, columna_fin + 1):
            if indice_mensaje < num_caracteres:
                matriz[fila_inicio][j] = mensaje_sin_espacios[indice_mensaje]
                indice_mensaje += 1
            else:
                matriz[fila_inicio][j] = random.choice(string.ascii_lowercase)
        
        fila_inicio += 1
        
        # Llenar la columna derecha de arriba hacia abajo
        for i in range(fila_inicio, fila_fin + 1):
            if indice_mensaje < num_caracteres:
                matriz[i][columna_fin] = mensaje_sin_espacios[indice_mensaje]
                indice_mensaje += 1
            else:
                matriz[i][columna_fin] = random.choice(string.ascii_lowercase)
        
        columna_fin -= 1
        
        # Llenar la fila inferior de derecha a izquierda
        if fila_inicio <= fila_fin:
            for j in range(columna_fin, columna_inicio - 1, -1):
                if indice_mensaje < num_caracteres:
                    matriz[fila_fin][j] = mensaje_sin_espacios[indice_mensaje]
                    indice_mensaje += 1
                else:
                    matriz[fila_fin][j] = random.choice(string.ascii_lowercase)
            
            fila_fin -= 1
        
        # Llenar la columna izquierda de abajo hacia arriba
        if columna_inicio <= columna_fin:
            for i in range(fila_fin, fila_inicio - 1, -1):
                if indice_mensaje < num_caracteres:
                    matriz[i][columna_inicio] = mensaje_sin_espacios[indice_mensaje]
                    indice_mensaje += 1
                else:
                    matriz[i][columna_inicio] = random.choice(string.ascii_lowercase)
            
            columna_inicio += 1
    
    return matriz

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

def imprimir_matriz_cuadrada(matriz):
    # Encontrar el número máximo de dígitos en cualquier elemento de la matriz
    max_longitud = max(max(len(str(elemento)) for elemento in fila) for fila in matriz)
    # Imprimir la matriz
    for fila in matriz:
        for elemento in fila:
            # Formatear cada elemento para que tenga el mismo ancho
            print(f'{elemento:{max_longitud}}', end=' ')
        print()  # Imprimir una nueva línea después de cada fila

# Funcion que realiza el cifrado de trasposicion con la tecnica Scrambling
def Transpositioncipher(Palabra,Mensaje):
    Permutacion=EncontrarPermutacion(Palabra)
    print(f"La permutacion de nuestra palabra es: {Permutacion}")
    n=len(Palabra)
    Matriz=partir_mensaje_en_matriz(Mensaje, n)
    print(f"La matriz de nuestro mensaje es: \n")
    imprimir_matriz_cuadrada(Matriz)
    MensajeCifrado=Recuperarelementos(Matriz, Permutacion)
    return (MensajeCifrado)

def Descifrado(Palabra,MensajeCifrado):
    
    return Mensaje

def opcion_1():
    # Ejercicio 1
    a=int(input("Ingrese el numero para calular inverso: "))
    n=int(input("Ingrese el modulo: "))
    if (es_coprimo(a,n)==True):
        res=Xgcd(a,n)
        print(f"{a}^-1 mod {n}: {res}")
    else:
        print("Esta operacion modular no contiene inverso \n")
    
def opcion_2():
    # Ejericio 2
    tam=int(input("Ingrese el tamaño del diccionario:"))
    Dic, Inversos=Listarelem(tam)
    print(f"Z*={Dic} \n")
    print(f"Inversos={Inversos} \n")

def opcion_3():
    # Ejercicio 3
    PalabraClave=input("Ingrese la palabra clave del cifrado:")
    Mensaje=input("Ingrese el mensaje a cifrar:")
    MensajeCifrado=Transpositioncipher(PalabraClave,Mensaje)
    print(f"\nMensaje cifrado={MensajeCifrado} \n")

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
        print("1. Encontrar el inverso multiplicativo")
        print("2. Encontrar los elementos de Z* y sus negativos")
        print("3. Cifrado por trasposicion con scrambling word")
        print("4. Salir\n")
        seleccion = input("Selecciona una opción: ")

        if seleccion in opciones:
            opciones[seleccion]()
        else:
            print("Opción no válida. Por favor, selecciona una opción del menú.")

if __name__ == "__main__":
    main()