#!/usr/bin/env python3
# Agrupa los IDs de las cuatro herramientas por alias de OSV

import argparse
import json
import sys
import time
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

OSV_API_URL = "https://api.osv.dev/v1/vulns/{}"
REQUEST_TIMEOUT = 15
REQUEST_DELAY = 0.05


def extract_trivy(path):
    data = json.loads(Path(path).read_text())
    ids = set()
    for result in data.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            vid = vuln.get("VulnerabilityID")
            if vid:
                ids.add(vid)
    return ids


def extract_grype(path):
    data = json.loads(Path(path).read_text())
    ids = set()
    for match in data.get("matches", []) or []:
        vid = (match.get("vulnerability") or {}).get("id")
        if vid:
            ids.add(vid)
    return ids


def extract_osv_scanner(path):
    data = json.loads(Path(path).read_text())
    ids = set()
    for result in data.get("results", []) or []:
        for pkg in result.get("packages", []) or []:
            for vuln in pkg.get("vulnerabilities", []) or []:
                vid = vuln.get("id")
                if vid:
                    ids.add(vid)
    return ids


def extract_dependency_check(path):
    data = json.loads(Path(path).read_text())
    ids = set()
    for dep in data.get("dependencies", []) or []:
        for vuln in dep.get("vulnerabilities", []) or []:
            vid = vuln.get("name")
            if vid:
                ids.add(vid)
    return ids

EXTRACTORS = {
    "trivy": extract_trivy,
    "grype": extract_grype,
    "osv-scanner": extract_osv_scanner,
    "dependency-check": extract_dependency_check,
}


def load_cache(cache_path):
    if cache_path.exists():
        try:
            return json.loads(cache_path.read_text())
        except json.JSONDecodeError:
            print(f"[warn] cache corrupta en {cache_path}, empezando de cero", file=sys.stderr)
    return {}


def save_cache(cache, cache_path):
    cache_path.write_text(json.dumps(cache, indent=2, sort_keys=True))


def get_aliases(vid, cache, retries=3):
    if vid in cache:
        return set(cache[vid])

    # texto libre en vez de un ID
    if any(c.isspace() for c in vid) or len(vid) > 100:
        aliases = {vid}
        cache[vid] = sorted(aliases)
        return aliases
    url = OSV_API_URL.format(vid)
    aliases = {vid}
    for attempt in range(retries):
        try:
            req = Request(url, headers={"User-Agent": "TFG-SCA-comparativa/1.0"})
            with urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                data = json.loads(resp.read())
            aliases |= set(data.get("aliases", []))
            if data.get("id"):
                aliases.add(data["id"])
            break
        except HTTPError as e:
            if e.code == 404:
                break
            if e.code == 429 and attempt < retries - 1:
                time.sleep(2 ** attempt)
                continue
            print(f"[warn] HTTP {e.code} para {vid}", file=sys.stderr)
            break
        except URLError as e:
            if attempt < retries - 1:
                time.sleep(1 + attempt)
                continue
            print(f"[warn] error de red para {vid}: {e}", file=sys.stderr)
            break

    cache[vid] = sorted(aliases)
    return aliases


class UnionFind:
    def __init__(self):
        self.parent = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def main():
    parser = argparse.ArgumentParser(
        description="Canonicaliza y compara hallazgos de vulnerabilidades entre herramientas SCA vía alias de OSV."
    )
    parser.add_argument("--trivy", help="ruta al JSON de salida de trivy fs")
    parser.add_argument("--grype", help="ruta al JSON de salida de grype")
    parser.add_argument("--osv-scanner", help="ruta al JSON de salida de osv-scanner")
    parser.add_argument("--dependency-check", help="ruta al dependency-check-report.json")
    parser.add_argument("--repo-name", default="repo", help="nombre identificador del repo para los reportes")
    parser.add_argument("--out-dir", default=".", help="directorio donde guardar cache y CSV de salida")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    tool_files = {
        "trivy": args.trivy,
        "grype": args.grype,
        "osv-scanner": args.osv_scanner,
        "dependency-check": args.dependency_check,
    }
    tool_files = {k: v for k, v in tool_files.items() if v}
    if not tool_files:
        parser.error("Pasa al menos un archivo de resultados (--trivy, --grype, --osv-scanner, --dependency-check)")

    tool_ids = {}
    for tool, path in tool_files.items():
        if not Path(path).exists():
            print(f"[warn] No existe el archivo para {tool}: {path} -- se trata como 0 IDs (posible limitacion de la herramienta para este repo)", file=sys.stderr)
            tool_ids[tool] = set()
            continue
        try:
            ids = EXTRACTORS[tool](path)
        except json.JSONDecodeError as e:
            print(f"[warn] JSON invalido/vacio para {tool} en {path} ({e}) -- se trata como 0 IDs (posible fallo transitorio de la herramienta para este repo)", file=sys.stderr)
            ids = set()
        tool_ids[tool] = ids
        print(f"{tool}: {len(ids)} IDs extraídos de {path}")

    all_ids = set()
    for ids in tool_ids.values():
        all_ids |= ids

    cache_path = out_dir / "osv_alias_cache.json"
    cache = load_cache(cache_path)

    print(f"\nResolviendo alias vía OSV API para {len(all_ids)} IDs únicos...")
    uf = UnionFind()
    for i, vid in enumerate(sorted(all_ids), 1):
        aliases = get_aliases(vid, cache)
        for a in aliases:
            uf.union(vid, a)
        if vid not in cache:
            time.sleep(REQUEST_DELAY)
        if i % 10 == 0 or i == len(all_ids):
            print(f"  {i}/{len(all_ids)}")
            save_cache(cache, cache_path)
    save_cache(cache, cache_path)

    clusters = {}
    for vid in all_ids:
        root = uf.find(vid)
        clusters.setdefault(root, set()).add(vid)

    cluster_tools = {}
    for root, members in clusters.items():
        found_by = {tool for tool, ids in tool_ids.items() if members & ids}
        cluster_tools[root] = found_by

    n_canonical = len(clusters)

    print(f"\n=== Resultado para {args.repo_name} ===")
    print(f"Vulnerabilidades canónicas (clusters únicos tras resolver alias): {n_canonical}\n")

    print(f"{'Herramienta':<20}{'IDs crudos':<14}{'Vulns canónicas':<18}")
    for tool, ids in tool_ids.items():
        canon_count = len({uf.find(vid) for vid in ids})
        print(f"{tool:<20}{len(ids):<14}{canon_count:<18}")

    tools_list = list(tool_ids.keys())
    if len(tools_list) > 1:
        print("\nSolapamiento canónico (vulnerabilidades compartidas entre pares):")
        header = "".ljust(20) + "".join(t[:16].ljust(18) for t in tools_list)
        print(header)
        for t1 in tools_list:
            row = t1.ljust(20)
            for t2 in tools_list:
                shared = sum(1 for tools in cluster_tools.values() if t1 in tools and t2 in tools)
                row += str(shared).ljust(18)
            print(row)

        print("\nHallazgos exclusivos (detectados por una sola herramienta):")
        for tool in tools_list:
            exclusive = sum(1 for tools in cluster_tools.values() if tools == {tool})
            print(f"  {tool}: {exclusive}")

        detected_by_all = sum(1 for tools in cluster_tools.values() if tools == set(tools_list))
        print(f"\nDetectadas por TODAS las herramientas presentes: {detected_by_all}")

    out_csv = out_dir / f"{args.repo_name}-canonical-comparison.csv"
    with open(out_csv, "w") as f:
        f.write("cluster_members,tools_found,n_tools\n")
        for root, members in sorted(clusters.items(), key=lambda kv: -len(cluster_tools[kv[0]])):
            tools_found = cluster_tools[root]
            members_str = ";".join(sorted(members))
            tools_str = ";".join(sorted(tools_found))
            f.write(f'"{members_str}","{tools_str}",{len(tools_found)}\n')

    print(f"\nDetalle completo guardado en: {out_csv}")
    print(f"Cache de alias guardada en: {cache_path}")

if __name__ == "__main__":
    main()
