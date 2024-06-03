"""
  Algoritmo de cifrado afin
  Instituto Polit�cnico Nacional
  ESCOM
  Alvarado Romero Luis Manuel   
  Materia: Ciptografia
  Grupo: 6CM3
"""
import random
import math
import pickle

A = [chr(i) for i in range(32, 127)]
Ruta = "Practica1/"

# Funcion para obtener el numero de elementos en un alfabeto
def Numelem(Diccionario):
    numelem=[]
    j=0
    for i in Diccionario:
        numelem.append(j)
        j=j+1
    return numelem

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

# Genera una llave valida de nuestro diccionario
def Findkey(n):
    while True:
        # Generar los numeros random de a y b
        a= random.randint(1,n-1)
        b= random.randint(0,n-1)
        if es_coprimo(a,n)==True:
            print(f"La llave es: K({a},{b})")
            return a, b
            break

# Busca por fuerza bruta el inverso multiplicativo de un numero en nuestro diccionario
def InversoMulti(n,num):
    flag = 0
    for i in range (1,n):
        if((num*i)%n==1):
            print(f"Su inverso multiplicativo es: {i}")
            flag=1
            return i
    if (flag==0):
        print(f"-1")
        return -1

# Verificamos si los elementos en la palabra se encuentran en nuestro diccionario
def Verificarpalabra(Palabra,Diccionario):
    for i in Palabra:
        if i not in Diccionario:
            print("El mensaje no cuenta con los caracteres en el ASCII")
            return False 
    return True

# Funcion que realiza el cifrado afin
def Cifrado(mensaje,Diccionario,a,b):
    MensajeCifrado=[]
    ElemDic=Numelem(Diccionario)
    for i in mensaje:
        for j in ElemDic:
            if i==Diccionario[j]:
                num=j
                Cnum=((num*a)+b)
                Cnum=Cnum%len(ElemDic)
                Cif=Diccionario[Cnum]
                MensajeCifrado.append(Cif)
            
    print(MensajeCifrado)
    return MensajeCifrado

# Funcion que reliza el descifrado de nuestro mensaje
def Descifrado(mensaje,Diccionario,a,b):
    Mensajedescifrado=[]
    ElemDic=Numelem(Diccionario)
    an=InversoMulti(len(Diccionario),a)
    for i in mensaje:
        for j in ElemDic:
            if i==Diccionario[j]:
                num=j
                Cnum=((num-b)*an)
                Cnum=Cnum%len(ElemDic)
                Cif=Diccionario[Cnum]
                Mensajedescifrado.append(Cif)
            
    print(Mensajedescifrado)
    return Mensajedescifrado

# Funcion que lista los elementos que cumplen con ser coprimos
def NuevoDic(tam):
    NDiccionario=[]
    for i in range(1,tam):
        if es_coprimo(i,tam)==True:
            NDiccionario.append(i)
    return NDiccionario


# Funcion que encuentra todas las llaves validas en un diccionario
def Llavesvalidas(tam,NombreArchivo):
    try:
        with open(NombreArchivo, 'w+') as archivo:
            Elementos=NuevoDic(tam)
            for i in Elementos:
                a=InversoMulti(tam,i)
                for j in range(0,tam):
                    archivo.write(f"Llave {i,j}, Inverso: {a} \n")
    except IOError:
        print(f"No se pudo escribir en el archivo '{NombreArchivo}'.")

# Funcion que nos permite leer un archivo
def leer_archivo(nombre_archivo):
    try:
        with open(Ruta+nombre_archivo, 'r') as archivo:
            contenido = archivo.read()
        return contenido
    except IOError:
        print(f"No se pudo leer el archivo '{nombre_archivo}'.")

def opcion_1():
    # Ejercicio 1: 
    print("Seleccionaste la opción de encontrar llave valida. \n")
    n=int(input("Ingrese el tamaño del alfabeto: "))
    a,b=Findkey(n)

def opcion_2():
    # Ejercicio 2:
    print("Seleccionaste la opción de encontrar el inverso multiplicativo. \n")
    n=int(input("Ingrese el tamaño del alfabeto: "))
    num=int(input("Ingrese el numero que desea conocer su inverso: "))
    if(num>0 & num<n):
        InversoMulti(n,num)
    else: 
        print("Ingrese un numero valido")

def opcion_3():
    # Ejercicio 3:
    print("Seleccionaste la opción de cifrar un mensaje. \n")
    print(f"A={A}\n")    
    mensaje=input("Ingrese el mensaje que desea cifrar: ")
    while True: 
        a=int(input("Ingrese el primer elmento de la llave: "))
        if(es_coprimo(a,len(A))):
            break
        print("Clave no valida\n")
    while True: 
        b=int(input("Ingrese el segundo elemento de la llave: "))
        if(0 <= b < len(A)):
            break
        print("Clave no valida\n")
    with open(Ruta+'a_mensaje.pkl', 'wb') as f:
            pickle.dump(a, f)
    with open(Ruta+'b_mensaje.pkl', 'wb') as f:
            pickle.dump(b, f)
    if Verificarpalabra(mensaje, A)==True:
        MensajeCifrado=Cifrado(mensaje,A,a,b)
        with open(Ruta+"Mensajecifrado.txt", 'w+') as archivo:
            archivo.write("".join(MensajeCifrado))
    else:
        print("Intente con otro mensaje")

def opcion_4():
    print("Seleccionaste la opción descifrar un mensaje. \n")
    # Ejercicio 4:
    try:
        # Cargamos la llave
        with open(Ruta+'a_mensaje.pkl', 'rb') as f:
            a=pickle.load(f)
        with open(Ruta+'b_mensaje.pkl', 'rb') as f:
            b=pickle.load(f)
        print("Datos cargados desde archivos pickle. \n")
        MensajeCifrado=leer_archivo("Mensajecifrado.txt")
        print(f"El mensaje cifrado es: {MensajeCifrado}")
        print(f"La llave es: {a,b}")
        mensajeDescifrado=Descifrado(MensajeCifrado,A,a,b)
    except FileNotFoundError:
        print("Llave no encontrada")

def opcion_5():
    # Ejercicio 5a
    print("Seleccionaste la de encontrar las llaves validas. \n")
    n=int(input("Ingrese el tamaño del alfabeto: "))
    Llavesvalidas(n,"Llaves_validas.txt")

def opcion_6():
    # Ejercicio 5b
    print("Seleccionaste la opción de cifrar un archivo. \n")
    Nombrearchivo=(input("Ingrese el nombre del archivo: "))
    while True: 
        a=int(input("Ingrese el primer elmento de la llave: "))
        if(es_coprimo(a,len(A))):
            break
        print("Clave no valida\n")
    while True: 
        b=int(input("Ingrese el segundo elemento de la llave: "))
        if(0 <= b < len(A)):
            break
        print("Clave no valida\n")
    Contenido=leer_archivo(Nombrearchivo)
    print(f"El contenido del archivo es: \n{Contenido} \n")
    with open(Ruta+'a_archivo.pkl', 'wb') as f:
            pickle.dump(a, f)
    with open(Ruta+'b_archivo.pkl', 'wb') as f:
            pickle.dump(b, f)
    MensajeCifrado=Cifrado(Contenido,A,a,b)
    with open(Ruta+"Archivocifrado.txt", 'w+') as archivo:
            archivo.write("".join(MensajeCifrado))
        
def opcion_7():
    # Ejercicio 5c
    print("Seleccionaste la opción descifrar un archivo. \n")
    try:
        # Cargamos la llave
        with open('a_archivo.pkl', 'rb') as f:
            a=pickle.load(f)
        with open('b_archivo.pkl', 'rb') as f:
            b=pickle.load(f)
        print("Datos cargados desde archivos pickle. \n")
        Nombrearchivo=(input("Ingrese el nombre del archivo: "))
        MensajeCifrado=leer_archivo(Nombrearchivo)
        print(f"El mensaje cifrado es: {MensajeCifrado}")
        print(f"La llave es: {a,b}")
        mensajeDescifrado=Descifrado(MensajeCifrado,A,a,b)
    except FileNotFoundError:
        print("Llave no encontrada")

def salir():
    print("Saliendo del programa...")
    exit()

def main():
    
    opciones = {
        '1': opcion_1,
        '2': opcion_2,
        '3': opcion_3,
        '4': opcion_4,
        '5': opcion_5,
        '6': opcion_6,
        '7': opcion_7,
        '8': salir
    }

    while True:
        print("\n Menú:")
        print("1. Encontrar una llave")
        print("2. Encontrar el inverso multiplicativo de un numero")
        print("3. Cifrar un mensaje")
        print("4. Descifrar el mensaje")
        print("5. Encontrar las llaves validas en un alfabeto")
        print("6. Cifrar un archivo")
        print("7. Descifrar un archivo")
        print("8. Salir\n")
        seleccion = input("Selecciona una opción: ")

        if seleccion in opciones:
            opciones[seleccion]()
        else:
            print("Opción no válida. Por favor, selecciona una opción del menú.")

    # Ejercicio 5c
    mensajeDescifrado=Descifrado(mensajeCifrado,A,a,b)

if __name__ == "__main__":
    main()
