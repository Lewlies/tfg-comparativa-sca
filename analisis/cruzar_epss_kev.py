#!/usr/bin/env python3
# Cruza resultados_consolidados.csv con EPSS y KEV. Se ejecuta desde la raiz del corpus

import csv
import json
import re
import sys
import time
import gzip
import shutil
import urllib.request
from pathlib import Path

DIR = Path(".")
CONSOLIDADO = DIR / "resultados_consolidados.csv"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_GZ = DIR / "epss_scores-current.csv.gz"
EPSS_CSV = DIR / "epss_scores-current.csv"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_JSON = DIR / "kev.json"
GHSA_CACHE = DIR / "ghsa_sin_cve_verificacion.json"
SALIDA = DIR / "resultados_enriquecidos_v2.csv"

OSV_API_URL = "https://api.osv.dev/v1/vulns/{}"
OSV_REQUEST_DELAY = 0.15

CVE_RE = re.compile(r"CVE-\d{4}-\d+")
GHSA_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}")


def descargar_epss():
    print(f"[epss] descargando {EPSS_URL}")
    urllib.request.urlretrieve(EPSS_URL, EPSS_GZ)
    with gzip.open(EPSS_GZ, "rb") as f_in, open(EPSS_CSV, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)
    epss = {}
    with open(EPSS_CSV, newline="", encoding="utf-8") as f:
        # la primera linea es la version del modelo
        next(f)
        for row in csv.DictReader(f):
            epss[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
    print(f"[epss] cargado: {len(epss)} CVEs")
    return epss


def descargar_kev():
    print(f"[kev] descargando {KEV_URL}")
    req = urllib.request.Request(KEV_URL, headers={"User-Agent": "TFG-SCA-comparativa/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    with open(KEV_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f)
    kev = {v["cveID"]: v.get("dateAdded", "") for v in data["vulnerabilities"]}
    print(f"[kev] cargado: {len(kev)} CVEs (catalogVersion={data['catalogVersion']})")
    return kev


def cargar_cache_ghsa():
    if GHSA_CACHE.exists():
        with open(GHSA_CACHE, encoding="utf-8") as f:
            data = json.load(f)
        mapeo = {g: cves for g, cves in data.get("encontrados", [])}
        sin_cve = set(data.get("sin_cve_ids", []))
        return mapeo, sin_cve
    return {}, set()


def guardar_cache_ghsa(mapeo, sin_cve):
    data = {
        "encontrados": [[g, cves] for g, cves in sorted(mapeo.items())],
        "sin_cve_confirmado": len(sin_cve),
        "sin_cve_ids": sorted(sin_cve),
    }
    with open(GHSA_CACHE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def resolver_ghsa(ghsa_ids, mapeo_cache, sin_cve_cache):
    pendientes = sorted(g for g in ghsa_ids if g not in mapeo_cache and g not in sin_cve_cache)
    if not pendientes:
        print(f"[ghsa] {len(ghsa_ids)} GHSA unicos, todos ya resueltos en cache")
        return mapeo_cache, sin_cve_cache

    print(f"[ghsa] {len(ghsa_ids)} GHSA unicos, {len(pendientes)} nuevos por consultar en OSV")
    for i, ghsa in enumerate(pendientes, 1):
        try:
            req = urllib.request.Request(
                OSV_API_URL.format(ghsa),
                headers={"User-Agent": "TFG-SCA-comparativa/1.0"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
            cves = [a for a in data.get("aliases", []) or [] if a.startswith("CVE-")]
            if cves:
                mapeo_cache[ghsa] = cves
            else:
                sin_cve_cache.add(ghsa)
        except Exception as e:
            print(f"  [error] {ghsa}: {e}", file=sys.stderr)
        if i % 100 == 0:
            print(f"  ...{i}/{len(pendientes)} consultados")
        time.sleep(OSV_REQUEST_DELAY)

    guardar_cache_ghsa(mapeo_cache, sin_cve_cache)
    print(f"[ghsa] resueltos con CVE: {len(mapeo_cache)}, confirmados sin CVE: {len(sin_cve_cache)}")
    return mapeo_cache, sin_cve_cache


def main():
    if not CONSOLIDADO.exists():
        sys.exit(f"[error] no existe {CONSOLIDADO} -- generalo primero agregando los "
                  f"*-canonical-comparison.csv de cada repo")

    epss = descargar_epss()
    kev = descargar_kev()

    ghsa_a_resolver = set()
    with open(CONSOLIDADO, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            members = row.get("cluster_members", "") or ""
            if not CVE_RE.search(members):
                ghsa_a_resolver.update(GHSA_RE.findall(members))

    mapeo_cache, sin_cve_cache = cargar_cache_ghsa()
    ghsa_to_cve, _ = resolver_ghsa(ghsa_a_resolver, mapeo_cache, sin_cve_cache)

    rows_out = []
    n_con_cve = n_con_epss = n_en_kev = 0

    with open(CONSOLIDADO, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames + [
            "cve_ids", "cve_fuente", "epss_score", "epss_percentile",
            "en_kev", "kev_cves", "kev_date_added",
        ]
        for row in reader:
            members = row.get("cluster_members", "") or ""
            cves_directos = set(CVE_RE.findall(members))
            cves_via_ghsa = set()
            for g in GHSA_RE.findall(members):
                cves_via_ghsa.update(ghsa_to_cve.get(g, []))

            cves = cves_directos | cves_via_ghsa
            if cves_directos and cves_via_ghsa:
                fuente = "directo+ghsa_resuelto"
            elif cves_directos:
                fuente = "directo"
            elif cves_via_ghsa:
                fuente = "ghsa_resuelto"
            else:
                fuente = ""

            epss_score = epss_percentile = ""
            en_kev = "false"
            kev_cves = kev_date_added = ""

            if cves:
                n_con_cve += 1
                puntuados = [(c, *epss[c]) for c in cves if c in epss]
                if puntuados:
                    n_con_epss += 1
                    # EPSS mas alto del cluster
                    mejor = max(puntuados, key=lambda t: t[1])
                    epss_score = f"{mejor[1]:.5f}"
                    epss_percentile = f"{mejor[2]:.5f}"
                kev_hits = [c for c in cves if c in kev]
                if kev_hits:
                    n_en_kev += 1
                    en_kev = "true"
                    kev_cves = ";".join(kev_hits)
                    kev_date_added = ";".join(kev[c] for c in kev_hits)

            row["cve_ids"] = ";".join(sorted(cves))
            row["cve_fuente"] = fuente
            row["epss_score"] = epss_score
            row["epss_percentile"] = epss_percentile
            row["en_kev"] = en_kev
            row["kev_cves"] = kev_cves
            row["kev_date_added"] = kev_date_added
            rows_out.append(row)

    with open(SALIDA, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows_out)

    print()
    print(f"Total clusters: {len(rows_out)}")
    print(f"Con >=1 CVE (directo o via GHSA): {n_con_cve}")
    print(f"Con score EPSS: {n_con_epss}")
    print(f"Con >=1 CVE en CISA KEV: {n_en_kev}")
    print(f"Escrito: {SALIDA}")

if __name__ == "__main__":
    main()
