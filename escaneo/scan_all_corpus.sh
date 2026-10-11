#!/usr/bin/env bash
# Escanea todos los repos de corpus_manifest.csv. Uso: ./scan_all_corpus.sh [corpus] [--force]

set -uo pipefail

CORPUS_DIR="$HOME/corpus"
FORCE=0

for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        *) CORPUS_DIR="$arg" ;;
    esac
done

case "$CORPUS_DIR" in
    /*) : ;;
    *) CORPUS_DIR="$PWD/$CORPUS_DIR" ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN_REPO="$SCRIPT_DIR/scan_repo.sh"
MANIFEST="$CORPUS_DIR/corpus_manifest.csv"
MASTER_TIMINGS="$CORPUS_DIR/results_master_timings.csv"
ERROR_LOG="$CORPUS_DIR/scan_all_errors.log"

if [ ! -f "$SCAN_REPO" ]; then
    echo "[error] no se encuentra scan_repo.sh en $SCRIPT_DIR" >&2
    exit 1
fi
chmod +x "$SCAN_REPO" 2>/dev/null || true

if [ ! -d "$CORPUS_DIR" ]; then
    echo "[error] no existe el directorio de corpus: $CORPUS_DIR" >&2
    echo "        corre primero reproducir_corpus.py --dest $CORPUS_DIR o pasa la ruta correcta como primer argumento" >&2
    exit 1
fi

: > "$ERROR_LOG"
echo "categoria,ecosistema,repo,herramienta,segundos,exit_code" > "$MASTER_TIMINGS"

REPO_LIST_FILE="$(mktemp)"
trap 'rm -f "$REPO_LIST_FILE"' EXIT

if [ -f "$MANIFEST" ]; then
    echo "[info] usando manifiesto: $MANIFEST"
    tail -n +2 "$MANIFEST" | while IFS=',' read -r categoria ecosistema repo url _resto; do
        [ -z "$repo" ] && continue
        printf '%s|%s|%s|%s\n' "$categoria" "$ecosistema" "$repo" "$url" >> "$REPO_LIST_FILE"
    done
else
    echo "[warn] no se encontro $MANIFEST, descubriendo repos recorriendo carpetas..."
    while IFS= read -r -d '' gitdir; do
        repodir="$(dirname "$gitdir")"
        repo="$(basename "$repodir")"
        ecosistema="$(basename "$(dirname "$repodir")")"
        categoria="$(basename "$(dirname "$(dirname "$repodir")")")"
        url="$(git -C "$repodir" remote get-url origin 2>/dev/null || echo "")"
        printf '%s|%s|%s|%s\n' "$categoria" "$ecosistema" "$repo" "$url" >> "$REPO_LIST_FILE"
    done < <(find "$CORPUS_DIR" -mindepth 4 -maxdepth 4 -type d -name .git -print0 2>/dev/null)
fi

TOTAL=$(wc -l < "$REPO_LIST_FILE" | tr -d ' ')
if [ "$TOTAL" -eq 0 ]; then
    echo "[error] no se encontro ningun repositorio en $CORPUS_DIR (ni manifiesto ni carpetas .git de 3 niveles de profundidad)" >&2
    exit 1
fi

echo "[info] $TOTAL repositorios a procesar (directorio-corpus: $CORPUS_DIR)"
[ "$FORCE" -eq 1 ] && echo "[info] --force activo: se re-escanearan tambien los repos que ya tuvieran resultados"
echo ""

if [ -z "${NVD_API_KEY:-}" ]; then
    echo "[warn] NVD_API_KEY no esta definida; Dependency-Check puede fallar por rate limit en varios de los $TOTAL repos"
    echo ""
fi

i=0
BATCH_START=$(date +%s)

while IFS='|' read -r categoria ecosistema repo url; do
    i=$((i + 1))
    PARENT_DIR="$CORPUS_DIR/$categoria/$ecosistema"
    RESULTS_DIR="$PARENT_DIR/results/$repo"
    SUMMARY_FILE="$RESULTS_DIR/${repo}-summary.txt"
    echo "[$i/$TOTAL] $categoria/$ecosistema/$repo"

    # solo mira que exista el summary
    if [ "$FORCE" -eq 0 ] && [ -f "$SUMMARY_FILE" ]; then
        echo "[info] ya tiene resultados en $RESULTS_DIR, se omite (usa --force para re-escanear)"
        echo ""
        continue
    fi

    if [ -z "$url" ]; then
        echo "[warn] no se pudo determinar la URL de origen de $repo; si la carpeta todavia no existe, el clonado va a fallar"
    fi

    if "$SCAN_REPO" "$url" "$repo" "$PARENT_DIR"; then
        :
    else
        echo "[FALLO] $categoria/$ecosistema/$repo (ver arriba para el detalle)" | tee -a "$ERROR_LOG"
    fi

    TIMING_FILE="$RESULTS_DIR/${repo}-timings.csv"
    if [ -f "$TIMING_FILE" ]; then
        tail -n +2 "$TIMING_FILE" | while IFS=',' read -r herramienta segundos exit_code; do
            printf '%s,%s,%s,%s,%s,%s\n' "$categoria" "$ecosistema" "$repo" "$herramienta" "$segundos" "$exit_code" >> "$MASTER_TIMINGS"
        done
    else
        echo "[warn] no se genero $TIMING_FILE para $repo (¿fallo antes de llegar a medir tiempos?)" | tee -a "$ERROR_LOG"
    fi

    echo ""
done < "$REPO_LIST_FILE"

BATCH_END=$(date +%s)
BATCH_ELAPSED=$((BATCH_END - BATCH_START))
echo "[done] corpus procesado en $((BATCH_ELAPSED / 60)) min $((BATCH_ELAPSED % 60)) s"
echo ""
echo "Tiempos por herramienta y repo guardados en: $MASTER_TIMINGS"
echo ""

if [ -s "$ERROR_LOG" ]; then
    echo "[atencion] hubo fallos en algunos repos, ver $ERROR_LOG:"
    cat "$ERROR_LOG"
else
    echo "[ok] sin fallos registrados"
fi

echo ""
echo "--- Resumen de tiempos (segundos) por herramienta y repo ---"
if command -v column >/dev/null 2>&1; then
    { echo "categoria,ecosistema,repo,herramienta,segundos,exit_code"; tail -n +2 "$MASTER_TIMINGS"; } | column -t -s ','
else
    cat "$MASTER_TIMINGS"
fi
