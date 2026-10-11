#!/usr/bin/env python3
# Genera ql/MapaGenerado.qll a partir de la cache de ranking_paquetes.py

import argparse
import csv
import datetime
import json
import os
import re
import sys
from collections import defaultdict

JACKSON = {"com.fasterxml.jackson.core:jackson-databind", "tools.jackson.core:jackson-databind"}

JACKSON_TIPOS = [
    "com.fasterxml.jackson.databind.ObjectMapper",
    "com.fasterxml.jackson.databind.ObjectReader",
    "tools.jackson.databind.ObjectMapper",
    "tools.jackson.databind.ObjectReader",
]
JACKSON_METODOS = [
    "readValue", "readValues", "readTree", "convertValue", "treeToValue",
    "enableDefaultTyping", "activateDefaultTyping",
]
JACKSON_NOTA = ("asignado por regla de paquete (jackson-databind). La familia de "
                "gadgets exige tipado por defecto activo y entrada no confiable; "
                "la de denegacion de servicio solo entrada no confiable")

MOTIVO_SPRING = ("Vulnerabilidad del framework Spring. La dispara el propio framework "
                 "al atender una peticion, enlazar datos, resolver rutas o cargar "
                 "configuracion, no una llamada explicita de la aplicacion. "
                 "Asignado por regla de paquete.")
MOTIVO_SPEL = ("Spring Expression Language. Explotable si se evaluan expresiones "
               "con entrada no confiable; en la mayoria de aplicaciones las evalua el "
               "propio framework (anotaciones, seguridad, rutas), por eso se clasifica "
               "sin simbolo de aplicacion, con la salvedad de que una aplicacion que "
               "invoque SpelExpressionParser directamente si tendria punto de contacto. "
               "Asignado por regla de paquete.")
MOTIVO_TOMCAT = ("Vulnerabilidad del contenedor de servlets Apache Tomcat. La dispara el "
                 "servidor al procesar el protocolo, las sesiones o su configuracion, "
                 "sin intervencion del codigo de la aplicacion. Asignado por regla de paquete.")
MOTIVO_AMBOS = ("Vulnerabilidad que OSV asocia a la vez a Spring y a Tomcat. Pertenece a "
                "la capa de framework o contenedor, no a una API invocada por la "
                "aplicacion. Asignado por regla de paquete.")


def familia(paquete):
    grupo, _, artefacto = paquete.partition(":")
    if paquete in JACKSON:
        return "jackson"
    if grupo == "org.springframework" and artefacto == "spring-expression":
        return "spel"
    if grupo.startswith("org.springframework"):
        return "spring"
    if grupo == "org.apache.tomcat" or grupo.startswith("org.apache.tomcat."):
        return "tomcat"
    return None


def clasificar(paquetes):
    familias = {familia(p) for p in paquetes} - {None}
    if not familias:
        return None
    if "jackson" in familias:
        return "jackson"
    spring = familias & {"spring", "spel"}
    if spring and "tomcat" in familias:
        return "ambos"
    if familias == {"spel"}:
        return "spel"
    if spring:
        return "spring"
    return "tomcat"


def lista_ql(valores):
    return "[" + ", ".join(f'"{v}"' for v in valores) + "]"


def envolver(cves, ancho=4):
    filas = [cves[i:i + ancho] for i in range(0, len(cves), ancho)]
    return "[\n    " + ",\n    ".join(", ".join(f'"{c}"' for c in fila) for fila in filas) + "\n  ]"


def main():
    base = os.path.expanduser("~")
    ql = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ql")
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", default=f"{base}/alcanzabilidad-resultados/cve_a_paquete_cache_v2.json")
    ap.add_argument("--manual", default=f"{ql}/Alcanzabilidad.qll")
    ap.add_argument("--dataset", default=f"{base}/corpus/resultados_enriquecidos_v2.csv")
    ap.add_argument("--salida", default=f"{ql}/MapaGenerado.qll")
    args = ap.parse_args()

    if not os.path.isfile(args.cache):
        sys.exit(f"no encuentro la cache en {args.cache}. Corre antes ranking_paquetes.py")
    with open(args.cache, encoding="utf-8") as f:
        cache = json.load(f)

    if not any(cache.values()):
        sys.exit("la cache no contiene ningun paquete Maven, regenerala con ranking_paquetes.py")

    manuales = set()
    if os.path.isfile(args.manual):
        with open(args.manual, encoding="utf-8") as f:
            manuales = set(re.findall(r'"(CVE-\d{4}-\d+)"', f.read()))
    print(f"{len(manuales)} CVE ya estan en el mapa manual y se excluyen")

    grupos = defaultdict(list)
    for cve, paquetes in sorted(cache.items()):
        if cve in manuales or not paquetes:
            continue
        clase = clasificar(paquetes)
        if clase:
            grupos[clase].append(cve)

    hoy = datetime.date.today().isoformat()
    lineas = [
        f"// Generado por generar_mapa.py el {hoy}",
        "",
        "predicate simboloGenerado(string cve, string tipo, string metodo, string nota) {",
    ]
    if grupos["jackson"]:
        lineas += [
            f"  cve = {envolver(grupos['jackson'])} and",
            f"  tipo = {lista_ql(JACKSON_TIPOS)} and",
            f"  metodo = {lista_ql(JACKSON_METODOS)} and",
            f'  nota = "{JACKSON_NOTA}"',
        ]
    else:
        lineas.append("  none()")
    lineas += ["}", "", "predicate sinSimboloGenerado(string cve, string componente, string motivo) {"]

    bloques = []
    for clase, componente, motivo in [
        ("spring", "Spring Framework", MOTIVO_SPRING),
        ("spel", "Spring Expression Language", MOTIVO_SPEL),
        ("tomcat", "Apache Tomcat", MOTIVO_TOMCAT),
        ("ambos", "Spring y Tomcat", MOTIVO_AMBOS),
    ]:
        if grupos[clase]:
            bloques.append(
                f"  cve = {envolver(grupos[clase])} and\n"
                f'  componente = "{componente}" and\n'
                f'  motivo = "{motivo}"'
            )
    lineas.append("\n  or\n".join(bloques) if bloques else "  none()")
    lineas += ["}", ""]

    with open(args.salida, "w", encoding="utf-8") as f:
        f.write("\n".join(lineas))

    pares = defaultdict(set)
    if os.path.isfile(args.dataset):
        clase_de = {c: k for k, lista in grupos.items() for c in lista}
        with open(args.dataset, newline="", encoding="utf-8") as f:
            for fila in csv.DictReader(f):
                if fila.get("ecosistema") != "maven":
                    continue
                for cve in (fila.get("cve_ids") or "").split(";"):
                    cve = cve.strip()
                    if cve in clase_de:
                        pares[clase_de[cve]].add((fila.get("repo", ""), cve))

    print()
    print("=" * 62)
    print("  MAPA GENERADO POR REGLA DE PAQUETE")
    print("=" * 62)
    etiquetas = [("jackson", "jackson-databind, con simbolo"),
                 ("spring", "Spring, sin simbolo"),
                 ("spel", "Spring Expression Language, sin simbolo"),
                 ("tomcat", "Tomcat, sin simbolo"),
                 ("ambos", "Spring y Tomcat a la vez, sin simbolo")]
    total_cves = total_pares = 0
    for clase, texto in etiquetas:
        n = len(grupos[clase])
        p = len(pares[clase])
        total_cves += n
        total_pares += p
        print(f"  {texto:<42} {n:4d} CVE  {p:4d} pares")
    print(f"  {'total':<42} {total_cves:4d} CVE  {total_pares:4d} pares")
    print()
    print(f"  escrito en {args.salida}")
    print("  siguiente paso, relanzar el censo con el mapa ampliado")

if __name__ == "__main__":
    main()
