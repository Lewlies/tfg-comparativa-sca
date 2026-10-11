#!/usr/bin/env python3
# Descarga el corpus real en los SHA del manifiesto. Uso: python3 reproducir_corpus.py --dest ~/corpus

import argparse
import csv
import shutil
import subprocess
import sys
from pathlib import Path


def git(*args, cwd=None):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


def descargar_en_sha(url, sha, destino):
    destino.mkdir(parents=True, exist_ok=True)
    for paso in (
        ("init", "-q"),
        ("remote", "add", "origin", url),
        # GitHub permite hacer fetch de un SHA concreto
        ("fetch", "-q", "--depth", "1", "origin", sha),
        ("checkout", "-q", "--detach", "FETCH_HEAD"),
    ):
        r = git(*paso, cwd=destino)
        if r.returncode != 0:
            return False, (r.stderr.strip().splitlines() or ["error desconocido"])[-1]
    actual = git("rev-parse", "HEAD", cwd=destino).stdout.strip()
    if actual != sha:
        return False, f"el HEAD descargado ({actual[:8]}) no coincide con el SHA del manifiesto"
    return True, "ok"


def main():
    p = argparse.ArgumentParser(description="Descarga el corpus real del TFG en los commits registrados.")
    p.add_argument("--dest", required=True, help="carpeta destino del corpus")
    p.add_argument("--manifest", default=str(Path(__file__).resolve().parent / "corpus_manifest.csv"),
                   help="ruta a corpus_manifest.csv (por defecto, el que esta junto a este script)")
    p.add_argument("--force", action="store_true", help="vuelve a descargar los repositorios que ya existan")
    args = p.parse_args()

    if shutil.which("git") is None:
        sys.exit("ERROR: no se encuentra git en el PATH")

    dest = Path(args.dest).expanduser().resolve()
    dest.mkdir(parents=True, exist_ok=True)
    with open(args.manifest, newline="", encoding="utf-8") as f:
        filas = list(csv.DictReader(f))

    fallos = []
    for i, fila in enumerate(filas, 1):
        objetivo = dest / fila["categoria"] / fila["ecosistema"] / fila["repo"]
        etiqueta = f"[{i}/{len(filas)}] {fila['categoria']}/{fila['ecosistema']}/{fila['repo']}"
        if objetivo.exists() and any(objetivo.iterdir()):
            if not args.force:
                print(f"{etiqueta} ya existe, se omite (usa --force)")
                continue
            shutil.rmtree(objetivo)
        ok, msg = descargar_en_sha(fila["url"], fila["commit_sha"], objetivo)
        print(f"{etiqueta} {'OK ' + fila['commit_sha'][:8] if ok else 'FALLO (' + msg + ')'}")
        if not ok:
            fallos.append((fila["repo"], msg))

    shutil.copyfile(args.manifest, dest / "corpus_manifest.csv")
    print(f"\nDescargados correctamente: {len(filas) - len(fallos)}/{len(filas)}")
    for repo, msg in fallos:
        print(f"  - {repo}: {msg}")
    sys.exit(1 if fallos else 0)

if __name__ == "__main__":
    main()
