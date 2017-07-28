#!/usr/bin/env python
import math
from operator import itemgetter
from scipy import stats
import sys

def calcularMedia(data):
    return (sum(x for x in data)/len(data))

def calcularDesvio(data, media):
    resul = sum((x - media)**2 for x in data)

    return (resul/(len(data)-1))**0.5

#Toma un arreglo de valores y avisa si quita un outlier, no dice nada en caso contrario
def quitarOutliers(datos):
    hayOutliers = True
    outliers = []
    #Cicla hasta que no queden outlier por sacar.
    while hayOutliers:
        cantDatos = len(datos)

        min_ = min(datos)
        max_ = max(datos)

        media = calcularMedia(datos)
        desvio = calcularDesvio(datos, media)

        valorAbsolutoMin = abs(min_ - media)
        valorAbsolutoMax = abs(max_ - media)

        t_a2 = stats.t.ppf(1-(0.05/2.),cantDatos-2)
        tau = (t_a2*(cantDatos-1))/(math.sqrt(cantDatos)*math.sqrt(cantDatos-2+t_a2**2))
        tS = tau*desvio

        if valorAbsolutoMax > valorAbsolutoMin:
            if valorAbsolutoMax > tS:
                #Este es el caso en el que tengo que quitar el elemento
                for i in range(0,cantDatos):
                    if datos[i] == max_:
                        outliers.append(datos[i])
                        datos.pop(i)
                        break
            else:
                hayOutliers = False
        else:
            if valorAbsolutoMin > tS:
                #Este es el caso en el que tengo que quitar el elemento
                for i in range(0,cantDatos):
                    if datos[i] == min_:
                        outliers.append(datos[i])
                        datos.pop(i)
                        break
            else:
                hayOutliers = False
    return outliers

if __name__ == "__main__":
    dat = [0.65, 1.52, 223.81, 16.48, 41.17, -1.79, 4.04, -3.58, 101.59, 6.17, -0.19, 41.03, -46.96]

    outliers = quitarOutliers(dat)
    print outliers
