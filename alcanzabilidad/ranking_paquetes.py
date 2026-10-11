#!/usr/bin/env python3
# Ranking de paquetes Maven por numero de pares repo-CVE

import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict

OSV = "https://api.osv.dev/v1/vulns/"


def cargar_pares(dataset, ecosistema):
    pares = set()
    id_consulta = {}
    with open(dataset, newline="", encoding="utf-8") as f:
        for fila in csv.DictReader(f):
            if fila.get("ecosistema") != ecosistema:
                continue
            repo = fila.get("repo", "")
            miembros = [m.strip() for m in (fila.get("cluster_members") or "").split(";")]
            # el registro GHSA trae el paquete Maven, el CVE no siempre
            ghsa = next((m for m in miembros if m.startswith("GHSA-")), None)
            for trozo in (fila.get("cve_ids") or "").split(";"):
                trozo = trozo.strip()
                if trozo.startswith("CVE-"):
                    pares.add((repo, trozo))
                    if ghsa and trozo not in id_consulta:
                        id_consulta[trozo] = ghsa
    return sorted(pares), id_consulta


def consultar_osv(cve, ident, cache, contadores):
    if cve in cache:
        contadores["cache"] += 1
        return cache[cve], "cache"

    try:
        req = urllib.request.Request(OSV + ident, headers={"User-Agent": "tfg-sca/1.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            datos = json.load(r)
        paquetes = sorted({
            a["package"]["name"]
            for a in datos.get("affected", [])
            if a.get("package", {}).get("ecosystem") == "Maven" and a.get("package", {}).get("name")
        })
        estado = "ok" if paquetes else "vacio"
        cache[cve] = paquetes
        contadores[estado] += 1
        return paquetes, estado
    except urllib.error.HTTPError as e:
        estado = "404" if e.code == 404 else "error"
    except Exception:
        estado = "error"

    contadores[estado] += 1
    return [], estado


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=os.path.expanduser("~/corpus/resultados_enriquecidos_v2.csv"))
    ap.add_argument("--salida", default=os.path.expanduser("~/alcanzabilidad-resultados"))
    ap.add_argument("--ecosistema", default="maven")
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--pausa", type=float, default=0.15, help="segundos entre consultas a OSV")
    args = ap.parse_args()

    if not os.path.isfile(args.dataset):
        sys.exit(f"no encuentro el dataset en {args.dataset}")
    os.makedirs(args.salida, exist_ok=True)

    ruta_cache = os.path.join(args.salida, "cve_a_paquete_cache_v2.json")
    cache = {}
    if os.path.isfile(ruta_cache):
        with open(ruta_cache, encoding="utf-8") as f:
            cache = json.load(f)
        print(f"cache con {len(cache)} vulnerabilidades ya resueltas")

    pares, id_consulta = cargar_pares(args.dataset, args.ecosistema)
    cves = sorted({c for _, c in pares})
    con_ghsa = sum(1 for c in cves if c in id_consulta)
    print(f"{len(pares)} pares repo-vulnerabilidad, {len(cves)} CVE distintos")
    print(f"{con_ghsa} tienen GHSA en cluster_members, {len(cves) - con_ghsa} solo CVE")

    nuevos = [c for c in cves if c not in cache]
    print(f"{len(nuevos)} por consultar a OSV, unos {int(len(nuevos) * (args.pausa + 0.3) / 60) + 1} minutos\n")

    contadores = defaultdict(int)
    for i, cve in enumerate(nuevos, 1):
        consultar_osv(cve, id_consulta.get(cve, cve), cache, contadores)
        if i % 50 == 0 or i == len(nuevos):
            print(f"  {i}/{len(nuevos)}   ok={contadores['ok']} "
                  f"vacio={contadores['vacio']} 404={contadores['404']} error={contadores['error']}")
            with open(ruta_cache, "w", encoding="utf-8") as f:
                json.dump(cache, f, indent=1, sort_keys=True)
        time.sleep(args.pausa)

    with open(ruta_cache, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=1, sort_keys=True)

    consultadas = contadores["ok"] + contadores["vacio"] + contadores["404"] + contadores["error"]
    if consultadas:
        fallos = contadores["404"] + contadores["error"]
        if fallos > 0.2 * consultadas:
            sys.exit(f"\n{fallos} de {consultadas} consultas a OSV fallaron, revisa la red")
        if contadores["ok"] == 0:
            sys.exit(f"\nninguna de las {consultadas} consultas devolvio un paquete Maven")

    pares_por_paquete = defaultdict(set)
    cves_por_paquete = defaultdict(set)
    repos_por_paquete = defaultdict(set)
    sin_paquete = set()

    for repo, cve in pares:
        paquetes = cache.get(cve, [])
        if not paquetes:
            sin_paquete.add(cve)
            continue
        for p in paquetes:
            pares_por_paquete[p].add((repo, cve))
            cves_por_paquete[p].add(cve)
            repos_por_paquete[p].add(repo)

    ranking = sorted(pares_por_paquete.items(), key=lambda kv: (-len(kv[1]), kv[0]))

    ruta_csv = os.path.join(args.salida, f"ranking_paquetes_{args.ecosistema}.csv")
    total_pares = len(pares)
    acumulado = 0
    cubiertos = set()
    with open(ruta_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["posicion", "paquete", "pares_repo_cve", "cves_distintos", "repos",
                    "pares_acumulados_unicos", "pct_acumulado", "cves"])
        for pos, (paq, conjunto) in enumerate(ranking, 1):
            cubiertos |= conjunto
            acumulado = len(cubiertos)
            w.writerow([pos, paq, len(conjunto), len(cves_por_paquete[paq]),
                        len(repos_por_paquete[paq]), acumulado,
                        f"{100.0 * acumulado / total_pares:.1f}",
                        " ".join(sorted(cves_por_paquete[paq]))])

    cubiertos = set()
    hitos = {}
    for pos, (paq, conjunto) in enumerate(ranking, 1):
        cubiertos |= conjunto
        pct = 100.0 * len(cubiertos) / total_pares
        for objetivo in (25, 50, 75, 90):
            if objetivo not in hitos and pct >= objetivo:
                hitos[objetivo] = pos

    print("\n" + "=" * 62)
    print("  CONCENTRACION DE VULNERABILIDADES POR COMPONENTE")
    print("=" * 62)
    print(f"  pares repo-vulnerabilidad ......... {total_pares}")
    print(f"  CVE distintos .................... {len(cves)}")
    print(f"  CVE resueltos a paquete .......... {len(cves) - len(sin_paquete)}")
    print(f"  CVE sin paquete Maven en OSV ..... {len(sin_paquete)}")
    print(f"  paquetes Maven distintos ......... {len(ranking)}")
    if consultadas:
        print(f"  consultas  ok={contadores['ok']}  vacio={contadores['vacio']}  "
              f"404={contadores['404']}  error={contadores['error']}")
    print()
    print("  paquetes necesarios para cubrir")
    for objetivo in (25, 50, 75, 90):
        n = hitos.get(objetivo)
        print(f"    el {objetivo}% de los pares ......... {n if n else 'no se alcanza'}")
    print()
    print(f"  top {args.top} por pares repo-vulnerabilidad")
    for pos, (paq, conjunto) in enumerate(ranking[: args.top], 1):
        print(f"   {pos:3d}. {paq:<52} {len(conjunto):4d} pares  "
              f"{len(cves_por_paquete[paq]):3d} CVE  {len(repos_por_paquete[paq]):2d} repos")

    print()
    print(f"  ranking completo en {ruta_csv}")

if __name__ == "__main__":
    main()
