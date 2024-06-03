matriz = [
    [1, 2, 3, 2],
    [4, 5, 6, 3],
    [7, 8, 9, 5],
    [3, 4, 5, 6]
]

# Utilizando zip para transponer la matriz y acceder a la columna 1

#print(columna_1)  # Output: (1, 4, 7)

arreglo=[2, 0, 3, 1]

for i in range(0,len(arreglo)):
    r=0
    for j in arreglo:
        print(j)
        if(i==j):
            print(f"{j} Aqui somos iguales y r vale{r}")
            if(r<len(arreglo)-1):
                columna_1 = list(zip(*matriz))[r]
            else:
                columna_1 = list(zip(*matriz))[r]
            print(columna_1)
        r=r+1