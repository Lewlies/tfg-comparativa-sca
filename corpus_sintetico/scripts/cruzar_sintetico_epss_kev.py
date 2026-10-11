#!/usr/bin/env python3
# Agrega los resultados del corpus sintetico y los cruza con EPSS y KEV

import argparse
import csv
import glob
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
RE_NOCVE = re.compile(r"(?:GHSA(?:-[0-9a-z]{4}){3}|PYSEC-\d{4}-\d+)", re.IGNORECASE)


def agregar(corpus):
    filas, cabecera, repos = [], None, set()
    patron = str(corpus / "*" / "*" / "results" / "*" / "*-canonical-comparison.csv")
    for ruta in sorted(glob.glob(patron)):
        partes = Path(ruta).parts
        dimension, eco, repo = partes[-5], partes[-4], partes[-2]
        with open(ruta, newline="", encoding="utf-8") as f:
            todas = list(csv.reader(f))
        if not todas:
            continue
        if cabecera is None:
            cabecera = todas[0]
        repos.add(repo)
        datos = todas[1:]
        if not datos:
            filas.append([dimension, eco, repo] + [""] * len(cabecera))
        else:
            for r in datos:
                filas.append([dimension, eco, repo] + r)
    if cabecera is None:
        sys.exit(f"No encuentro ningun *-canonical-comparison.csv bajo {corpus}")
    return ["dimension", "ecosistema", "repo"] + cabecera, filas, repos


def forma_osv(vid):
    v = vid.strip()
    if v.upper().startswith("GHSA-"):
        return "GHSA-" + v[5:].lower()
    return v.upper()


def resolver_alias(ids, cache_path, sin_red):
    cache = {}
    if cache_path.is_file():
        try:
            cache = json.load(open(cache_path, encoding="utf-8"))
        except json.JSONDecodeError:
            cache = {}

    faltan = sorted(i for i in ids if i not in cache)
    if faltan and sin_red:
        print(f"  {len(faltan)} IDs sin resolver y --sin-red activo, se dejan vacios")
    elif faltan:
        print(f"  consultando osv.dev para {len(faltan)} IDs sin CVE directo")
        for n, vid in enumerate(faltan, 1):
            try:
                with urllib.request.urlopen(
                        f"https://api.osv.dev/v1/vulns/{forma_osv(vid)}", timeout=20) as r:
                    datos = json.load(r)
                cves = [a.upper() for a in (datos.get("aliases") or [])
                        if RE_CVE.fullmatch(a)]
                cache[vid] = sorted(set(cves))
            except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
                codigo = getattr(e, "code", "")
                print(f"    aviso: {vid} no resuelto ({type(e).__name__} {codigo})")
                continue
            if n % 20 == 0:
                print(f"    {n}/{len(faltan)}")
            time.sleep(0.15)
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=1, sort_keys=True)
        print(f"  cache guardada en {cache_path}")
    return cache


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=os.path.expanduser("~/corpus-sintetico"))
    ap.add_argument("--epss", default=os.path.expanduser("~/corpus/epss_scores-current.csv"))
    ap.add_argument("--kev", default=os.path.expanduser("~/corpus/kev.json"))
    ap.add_argument("--sin-red", action="store_true")
    args = ap.parse_args()

    corpus = Path(os.path.expanduser(args.corpus))
    cache_path = corpus / "ghsa_sin_cve_sintetico.json"

    cabecera, filas, repos = agregar(corpus)
    cons = corpus / "resultados_consolidados_sintetico.csv"
    with open(cons, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(cabecera); w.writerows(filas)
    print(f"Consolidado: {cons}  ({len(filas)} filas, {len(repos)} repos)")
    if len(repos) != 12:
        print(f"  AVISO: esperaba 12 repos y hay {len(repos)}. Revisa antes de seguir.")
    print()

    idx = {c: i for i, c in enumerate(cabecera)}
    col_miembros = idx.get("cluster_members")
    if col_miembros is None:
        sys.exit(f"No hay columna cluster_members. Cabecera: {cabecera}")

    sin_cve = set()
    for fila in filas:
        miembros = fila[col_miembros] or ""
        if not RE_CVE.search(miembros):
            sin_cve.update(i.upper() for i in RE_NOCVE.findall(miembros))
    print(f"IDs sin CVE directo que hay que resolver: {len(sin_cve)}")
    mapa = resolver_alias(sin_cve, cache_path, args.sin_red)
    print()

    epss = {}
    with open(args.epss, encoding="utf-8") as f:
        lineas = [l for l in f if not l.lstrip().startswith("#")]
    for r in csv.DictReader(lineas):
        c = (r.get("cve") or "").strip().upper()
        if c:
            epss[c] = (r.get("epss", ""), r.get("percentile", ""))
    kev = {}
    for v in json.load(open(args.kev, encoding="utf-8")).get("vulnerabilities", []):
        c = (v.get("cveID") or "").strip().upper()
        if c:
            kev[c] = v.get("dateAdded", "")
    print(f"CVE con EPSS: {len(epss)}   CVE en KEV: {len(kev)}")
    print()

    salida, n_kev, n_epss, n_cve = [], 0, 0, 0
    for fila in filas:
        miembros = fila[col_miembros] or ""
        directos = {c.upper() for c in RE_CVE.findall(miembros)}
        resueltos = set()
        for i in RE_NOCVE.findall(miembros):
            resueltos.update(mapa.get(i.upper(), []))
        resueltos -= directos
        todos = sorted(directos | resueltos)
        if todos:
            n_cve += 1

        fuente = ("directo+alias_resuelto" if directos and resueltos
                  else "directo" if directos
                  else "alias_resuelto" if resueltos else "")

        cand = [(c, epss[c]) for c in todos if c in epss]
        score = pct = ""
        if cand:
            def num(x):
                try:
                    return float(x[1][0])
                except (TypeError, ValueError):
                    return -1.0
            score, pct = max(cand, key=num)[1]
            n_epss += 1

        kcves = [c for c in todos if c in kev]
        if kcves:
            n_kev += 1

        salida.append(fila + [";".join(todos), fuente, score, pct,
                              "True" if kcves else "False", ";".join(kcves),
                              ";".join(sorted({kev[c] for c in kcves if kev.get(c)}))])

    campos = cabecera + ["cve_ids", "cve_fuente", "epss_score", "epss_percentile",
                         "en_kev", "kev_cves", "kev_date_added"]
    enr = corpus / "resultados_enriquecidos_sintetico.csv"
    with open(enr, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(campos); w.writerows(salida)

    print(f"Enriquecido: {enr}  ({len(salida)} filas)")
    print(f"  con al menos un CVE: {n_cve}")
    print(f"  con score EPSS:      {n_epss}")
    print(f"  en CISA KEV:         {n_kev}")
    print()

    if n_kev:
        print("=== Clusters del sintetico en KEV ===")
        ic = {c: i for i, c in enumerate(campos)}
        for r in salida:
            if r[ic["en_kev"]] == "True":
                print(f"  {r[ic['repo']]:<34}{r[ic['kev_cves']]:<20}"
                      f"EPSS={r[ic['epss_score']]:<10}{r[ic['tools_found']] if 'tools_found' in ic else ''}")

if __name__ == "__main__":
    main()
