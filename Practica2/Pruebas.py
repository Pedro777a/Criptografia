def LeerMatrizConOrden(matriz, indices_orden):
    mensaje = []

    # Convertir la matriz de caracteres a una lista de listas
    matriz_lista = [list(fila) for fila in matriz]

    # Verificar que los índices de orden estén dentro del rango válido
    max_indice = len(matriz_lista[0]) - 1
    for indice in indices_orden:
        if indice < 0 or indice > max_indice:
            print(f"Índice {indice} fuera de rango para la matriz.")
            return []

    # Transponer la matriz según el orden dado por los índices
    matriz_transpuesta = [matriz_lista[indice] for indice in indices_orden]

    # Recorrer las columnas transpuestas y agregarlas al mensaje
    for columna in zip(*matriz_transpuesta):
        mensaje.extend(columna)

    return mensaje

# Ejemplo de uso:
matriz_input = [
    ['a', 'b', 'c', 'd'],
    ['e', 'f', 'g', 'h'],
    ['i', 'j', 'k', 'l']
]
indices_orden_input = [2, 1, 0]  # Se eliminó el índice 3

mensaje_obtenido = LeerMatrizConOrden(matriz_input, indices_orden_input)
print("Mensaje obtenido:", mensaje_obtenido)
