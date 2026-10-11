#!/usr/bin/env bash
# Copia los 12 repos sinteticos a ~/corpus-sintetico con la estructura del corpus real. Uso: bash montar_corpus_sintetico.sh [destino]

set -euo pipefail

ORIGEN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DESTINO="${1:-$HOME/corpus-sintetico}"
MANIFIESTO="$DESTINO/corpus_manifest.csv"
mkdir -p "$DESTINO"

ECOS=(npm pypi maven)
DIMS=(mixed boundary-vulnerable boundary-patched control)

echo "categoria,ecosistema,repo,url,commit_sha,fecha_descarga,modo_clonado" > "$MANIFIESTO.tmp"
for dim in "${DIMS[@]}"; do
  for eco in "${ECOS[@]}"; do
    repo="synthetic-$eco-$dim"
    dir="$DESTINO/$dim/$eco/$repo"
    rm -rf "$dir"
    mkdir -p "$dir"
    cp -r "$ORIGEN/$eco/$dim/." "$dir/"
    # scan_repo.sh necesita un repositorio git para registrar el commit
    git -C "$dir" init -q
    git -C "$dir" add .
    git -C "$dir" -c user.name=tfg -c user.email=tfg@localhost commit -q -m "$repo"
    sha=$(git -C "$dir" rev-parse HEAD)
    echo "$dim,$eco,$repo,$dir,$sha,$(date +%Y-%m-%d),local" >> "$MANIFIESTO.tmp"
    echo "  $repo"
  done
done
mv "$MANIFIESTO.tmp" "$MANIFIESTO"
echo "Corpus sintetico en $DESTINO"
