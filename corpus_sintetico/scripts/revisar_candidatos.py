#!/usr/bin/env python3
# Revisa los CANDIDATO_FP de puntuacion_extras.csv contra los rangos de osv.dev. Uso: python3 revisar_candidatos.py [--solo-test]

import argparse
import collections
import csv
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request


def clave(v):
    piezas = [p for p in re.split(r"[.\-_+]", (v or "").strip()) if p != ""]
    return [int(p) if p.isdigit() else p.lower() for p in piezas]


# el texto ordena antes que un numero (2.0-beta9 < 2.0)
def cmp_ver(a, b):
    ka, kb = clave(a), clave(b)
    for i in range(max(len(ka), len(kb))):
        if i >= len(ka):
            return -1 if isinstance(kb[i], int) else 1
        if i >= len(kb):
            return 1 if isinstance(ka[i], int) else -1
        x, y = ka[i], kb[i]
        if isinstance(x, int) and isinstance(y, int):
            if x != y:
                return -1 if x < y else 1
        elif isinstance(x, int):
            return 1
        elif isinstance(y, int):
            return -1
        elif x != y:
            return -1 if x < y else 1
    return 0


def en_rango(ver, rango):
    afectado = False
    for ev in rango.get("events", []):
        if "introduced" in ev:
            intro = ev["introduced"]
            if intro == "0" or cmp_ver(ver, intro) >= 0:
                afectado = True
        elif "fixed" in ev:
            if cmp_ver(ver, ev["fixed"]) >= 0:
                afectado = False
        elif "last_affected" in ev:
            if cmp_ver(ver, ev["last_affected"]) > 0:
                afectado = False
    return afectado


def norm_pkg(n):
    n = (n or "").strip().lower()
    for sep in (":", "/"):
        if sep in n:
            n = n.rsplit(sep, 1)[-1]
    return n


# los registros CVE de osv.dev no suelen traer el paquete, por eso SIN_PAQUETE
def evaluar(ver, paquete, datos_osv):
    objetivo = norm_pkg(paquete)
    visto = []
    for af in datos_osv.get("affected", []) or []:
        nombre = ((af.get("package") or {}).get("name") or "")
        if not nombre:
            continue
        if norm_pkg(nombre) != objetivo and objetivo not in nombre.lower():
            continue
        visto.append(nombre)
        if ver and ver in (af.get("versions") or []):
            return "AFECTADA", f"{nombre} lista {ver} explicitamente"
        for rg in af.get("ranges", []) or []:
            if ver and en_rango(ver, rg):
                return "AFECTADA", f"{nombre} rango {rg.get('events')}"
    if not visto:
        return "SIN_PAQUETE", "el registro no trae datos de paquete por ecosistema"
    return "NO_AFECTADA", f"{visto[0]} afectado, pero {ver} queda fuera de sus rangos"


# casos de respuesta conocida para comprobar el comparador antes de usarlo
LOG4J_45046 = {"affected": [{
    "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
    "ranges": [{"type": "ECOSYSTEM", "events": [
        {"introduced": "2.0-beta9"}, {"fixed": "2.12.2"},
        {"introduced": "2.13.0"}, {"fixed": "2.16.0"}]}]}]}

URLLIB3_33503 = {"affected": [{
    "package": {"ecosystem": "PyPI", "name": "urllib3"},
    "ranges": [{"type": "ECOSYSTEM", "events": [
        {"introduced": "0"}, {"fixed": "1.26.5"}]}]}]}

PYYAML_14343 = {"affected": [{
    "package": {"ecosystem": "PyPI", "name": "PyYAML"},
    "ranges": [{"type": "ECOSYSTEM", "events": [
        {"introduced": "0"}, {"fixed": "5.4"}]}]}]}

SNAKEYAML_38749 = {"affected": [{
    "package": {"ecosystem": "Maven", "name": "org.yaml:snakeyaml"},
    "ranges": [{"type": "ECOSYSTEM", "events": [
        {"introduced": "0"}, {"fixed": "1.31"}]}]}]}

NVD_SIN_PAQUETE = {"summary": "Apache Log4j Core", "affected": [
    {"package": {"ecosystem": "", "name": ""}, "ranges": []}]}

CASOS = [
    ("log4j-core 2.14.1 / CVE-2021-45046", LOG4J_45046, "log4j-core", "2.14.1", "AFECTADA"),
    ("log4j-core 2.12.1 / CVE-2021-45046", LOG4J_45046, "log4j-core", "2.12.1", "AFECTADA"),
    ("log4j-core 2.12.2 ya parcheada",     LOG4J_45046, "log4j-core", "2.12.2", "NO_AFECTADA"),
    ("log4j-core 2.17.0 ya parcheada",     LOG4J_45046, "log4j-core", "2.17.0", "NO_AFECTADA"),
    ("urllib3 1.26.4 / CVE-2021-33503",    URLLIB3_33503, "urllib3", "1.26.4", "AFECTADA"),
    ("urllib3 1.26.5 ya parcheada",        URLLIB3_33503, "urllib3", "1.26.5", "NO_AFECTADA"),
    ("PyYAML 5.3.1 / CVE-2020-14343",      PYYAML_14343, "pyyaml", "5.3.1", "AFECTADA"),
    ("snakeyaml 1.23 / CVE-2022-38749",    SNAKEYAML_38749, "snakeyaml", "1.23", "AFECTADA"),
    ("registro NVD sin datos de paquete",  NVD_SIN_PAQUETE, "log4j-core", "2.14.1", "SIN_PAQUETE"),
]


def autocomprobar():
    print("Autocomprobacion del comparador de versiones")
    fallos = 0
    for etiqueta, datos, pkg, ver, esperado in CASOS:
        obtenido, _ = evaluar(ver, pkg, datos)
        ok = obtenido == esperado
        fallos += 0 if ok else 1
        print(f"  {'ok   ' if ok else 'FALLA'}  {etiqueta:<38}"
              f"esperado={esperado:<12}obtenido={obtenido}")
    print()
    if fallos:
        print(f"{fallos} casos fallan, no se sigue")
        return False
    print(f"{len(CASOS)} casos correctos\n")
    return True


def forma_osv(vid):
    v = vid.strip()
    return "GHSA-" + v[5:].lower() if v.upper().startswith("GHSA-") else v.upper()


# agrupa por alias igual que canonicalize_sca.py
def agrupar(filas):
    padre = {}

    def find(x):
        padre.setdefault(x, x)
        while padre[x] != x:
            padre[x] = padre[padre[x]]
            x = padre[x]
        return x

    for r in filas:
        ids = [i for i in (r.get("ids") or "").split("|") if i]
        for i in ids[1:]:
            a, b = find(ids[0]), find(i)
            if a != b:
                padre[a] = b

    g = collections.defaultdict(lambda: {"ids": set(), "herr": set(),
                                         "pkg": set(), "ver": set(), "repos": set()})
    for r in filas:
        ids = [i for i in (r.get("ids") or "").split("|") if i]
        if not ids:
            continue
        k = find(ids[0])
        g[k]["ids"].update(ids)
        g[k]["herr"].add(r.get("herramienta", "?"))
        g[k]["repos"].add(r.get("repo", "?"))
        if (r.get("paquete") or "").strip():
            g[k]["pkg"].add(r["paquete"].strip())
        if (r.get("version") or "").strip():
            g[k]["ver"].add(r["version"].strip())
    return g


# GHSA y PYSEC primero porque son los que traen los rangos
def ids_ordenados(ids):
    up = lambda p: [i for i in ids if i.upper().startswith(p)]
    prim = up("GHSA-") + up("PYSEC-")
    cve = up("CVE-")
    return prim + [i for i in ids if i not in prim + cve] + cve


def consultar(vid, cache):
    if vid in cache:
        return cache[vid]
    try:
        with urllib.request.urlopen(
                f"https://api.osv.dev/v1/vulns/{forma_osv(vid)}", timeout=25) as r:
            cache[vid] = json.load(r)
    except Exception as e:
        cache[vid] = {"__error__": f"{type(e).__name__} {getattr(e, 'code', '')}"}
    time.sleep(0.15)
    return cache[vid]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--extras", default=os.path.expanduser(
        "~/corpus-sintetico/puntuacion/puntuacion_extras.csv"))
    ap.add_argument("--salida", default=os.path.expanduser(
        "~/corpus-sintetico/puntuacion/revision_candidatos.csv"))
    ap.add_argument("--solo-test", action="store_true")
    args = ap.parse_args()

    if not autocomprobar():
        sys.exit(1)
    if args.solo_test:
        return

    filas = [r for r in csv.DictReader(open(args.extras, encoding="utf-8"))
             if (r.get("clasificacion") or "").upper().startswith("CANDIDATO")]
    g = agrupar(filas)
    print(f"{len(filas)} filas CANDIDATO_FP  ->  {len(g)} vulnerabilidades distintas")
    print("Consultando osv.dev\n")

    cache, resultados = {}, []
    for v in g.values():
        ids = sorted(v["ids"])
        etiqueta = next((i for i in ids if i.upper().startswith("CVE-")), ids[0])
        pkg = sorted(v["pkg"])[0] if v["pkg"] else ""
        ver = sorted(v["ver"], key=clave)[0] if v["ver"] else ""
        herr = ";".join(sorted(v["herr"]))
        repos = ";".join(sorted(v["repos"]))

        if not pkg or not ver:
            resultados.append([etiqueta, pkg, ver, "SIN_DATOS", "",
                               "el informe de la herramienta no trae paquete o version",
                               herr, repos, ""])
            continue

        veredicto, motivo, quien, resumen, errores = "SIN_DATOS_OSV", \
            "ningun identificador del grupo trae datos de paquete", "", "", []
        for vid in ids_ordenados(ids):
            d = consultar(vid, cache)
            if "__error__" in d:
                errores.append(f"{vid} {d['__error__']}")
                continue
            estado, expl = evaluar(ver, pkg, d)
            resumen = resumen or (d.get("summary") or "").replace("\n", " ")
            if estado in ("AFECTADA", "NO_AFECTADA"):
                veredicto = "RUIDO_REAL" if estado == "AFECTADA" else "REVISAR_A_MANO"
                motivo, quien = expl, vid
                break
        if veredicto == "SIN_DATOS_OSV" and errores:
            veredicto, motivo = "ERROR_CONSULTA", "; ".join(errores[:3])

        resultados.append([etiqueta, pkg, ver, veredicto, quien, motivo,
                           herr, repos, resumen])

    orden = {"REVISAR_A_MANO": 0, "SIN_DATOS_OSV": 1, "SIN_DATOS": 2,
             "ERROR_CONSULTA": 3, "RUIDO_REAL": 4}
    resultados.sort(key=lambda x: (orden[x[3]], x[0]))

    campos = ["id", "paquete", "version", "veredicto", "resuelto_via", "motivo",
              "herramientas", "repos", "resumen_osv"]
    with open(args.salida, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(campos)
        w.writerows(resultados)

    for r in resultados:
        print(f"{r[3]:<16}{r[0]:<20}{r[1]}@{r[2]}")
        print(f"{'':<16}{r[5][:94]}")
        print(f"{'':<16}via {r[4] or 'ninguno'}   reportado por {r[6]}")
    print()
    c = collections.Counter(r[3] for r in resultados)
    for k in ("RUIDO_REAL", "REVISAR_A_MANO", "SIN_DATOS_OSV", "SIN_DATOS", "ERROR_CONSULTA"):
        if c.get(k):
            print(f"  {k:<18}{c[k]}")
    print(f"\nDetalle en {args.salida}")


if __name__ == "__main__":
    main()
