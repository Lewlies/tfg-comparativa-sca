#!/usr/bin/env python3
# Une los canonical-comparison.csv del corpus. Uso: python3 agregar_resultados.py [corpus]

import csv
import glob
import os
import sys

corpus = sys.argv[1] if len(sys.argv) > 1 else "."
os.chdir(corpus)

filas = []
cabecera = None
repos = set()

for ruta in sorted(glob.glob("*/*/results/*/*-canonical-comparison.csv")):
    categoria, ecosistema, _, repo = ruta.split("/")[:4]
    with open(ruta, newline="", encoding="utf-8") as f:
        contenido = list(csv.reader(f))
    if not contenido:
        continue
    if cabecera is None:
        cabecera = contenido[0]
        filas.append(["categoria", "ecosistema", "repo"] + cabecera)
    repos.add((categoria, ecosistema, repo))
    datos = contenido[1:]
    # fila vacia para no perder los repos sin vulnerabilidades
    if not datos:
        filas.append([categoria, ecosistema, repo] + [""] * len(cabecera))
    for d in datos:
        filas.append([categoria, ecosistema, repo] + d)

with open("resultados_consolidados.csv", "w", newline="", encoding="utf-8") as f:
    csv.writer(f).writerows(filas)

print(f"Escritas {len(filas) - 1} filas en resultados_consolidados.csv")
print(f"Repositorios distintos: {len(repos)}")
