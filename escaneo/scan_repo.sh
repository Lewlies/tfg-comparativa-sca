#!/usr/bin/env bash
# Escanea un repo con las cuatro herramientas SCA y Syft. Uso: ./scan_repo.sh <git-url> <nombre> [corpus]

set -uo pipefail

if [ $# -lt 2 ]; then
    echo "Uso: $0 <git-url> <nombre-repo> [directorio-corpus]"
    exit 1
fi

REPO_URL="$1"
REPO_NAME="$2"
CORPUS_DIR="${3:-$HOME/corpus}"

case "$CORPUS_DIR" in
    /*) : ;;
    *) CORPUS_DIR="$PWD/$CORPUS_DIR" ;;
esac
REPO_DIR="$CORPUS_DIR/$REPO_NAME"
RESULTS_DIR="$CORPUS_DIR/results/$REPO_NAME"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CANONICALIZE_SCRIPT="$SCRIPT_DIR/canonicalize_sca.py"
TIMING_FILE="$RESULTS_DIR/${REPO_NAME}-timings.csv"

mkdir -p "$RESULTS_DIR"
echo "herramienta,segundos,exit_code" > "$TIMING_FILE"

log_timing() {
    printf '%s,%s,%s\n' "$1" "$2" "$3" >> "$TIMING_FILE"
    printf '[tiempo] %s: %ds (exit=%s)\n' "$1" "$2" "$3"
}

echo "=== $REPO_NAME ==="

if [ -d "$REPO_DIR" ]; then
    echo "[info] $REPO_DIR ya existe, se reutiliza el checkout actual (no se vuelve a clonar)"
else
    echo "[info] clonando $REPO_URL ..."
    if ! git clone "$REPO_URL" "$REPO_DIR"; then
        echo "[error] fallo el clonado de $REPO_URL -- no se va a escanear $REPO_NAME" >&2
        exit 2
    fi
fi

if ! cd "$REPO_DIR"; then
    echo "[error] no se pudo entrar en $REPO_DIR -- no se va a escanear $REPO_NAME" >&2
    exit 3
fi

COMMIT=$(git rev-parse HEAD)
if [ -z "$COMMIT" ]; then
    echo "[error] $REPO_DIR no parece un repositorio git valido (no se pudo resolver HEAD) -- no se va a escanear $REPO_NAME" >&2
    exit 4
fi
echo "$COMMIT" > "$RESULTS_DIR/commit.txt"
echo "[info] commit fijado: $COMMIT (guardado en $RESULTS_DIR/commit.txt)"

TOTAL_SECONDS=0

echo ""
echo "[1/5] OSV-Scanner..."
t0=$(date +%s)
# --no-ignore para no saltarse lockfiles de .gitignore
osv-scanner scan -r . --no-resolve --no-ignore --format json > "$RESULTS_DIR/${REPO_NAME}-osv.json"
ec=$?
elapsed=$(( $(date +%s) - t0 ))
TOTAL_SECONDS=$((TOTAL_SECONDS + elapsed))
log_timing "osv-scanner" "$elapsed" "$ec"

echo ""
# Maven Central da 429 a Trivy: se precachea ~/.m2 y se bajan con curl los .pom que falten
if [ -f pom.xml ]; then
  echo "[precacheo] mvn dependency:go-offline..."
  mvn -q dependency:go-offline -fn 2>/dev/null || true
fi
echo "[2/5] Trivy..."
t0=$(date +%s)
TRIVY_OUT="$RESULTS_DIR/${REPO_NAME}-trivy.json"
_prev_url=""
for _try in $(seq 1 400); do
  trivy_log=$(trivy fs --format json -o "$TRIVY_OUT" . 2>&1)
  ec=$?
  if echo "$trivy_log" | grep -q "429 Too Many Requests"; then
    _url=$(echo "$trivy_log" | grep -oP "(?<=for )https://repo\.maven\.apache\.org/maven2/\S+\.pom(?=\.)")
    if [ -z "$_url" ]; then
      echo "$trivy_log" >&2
      break
    fi
    # RELEASE/LATEST no se pueden descargar
    if [ "$_url" == "$_prev_url" ]; then
      echo "[trivy-retry] misma URL repetida, no se puede resolver (posible version meta como RELEASE/LATEST): $_url" >&2
      echo "$trivy_log" >&2
      break
    fi
    _prev_url="$_url"
    _relpath=${_url#https://repo.maven.apache.org/maven2/}
    _dest="$HOME/.m2/repository/$_relpath"
    echo "  [trivy-retry $_try] descargando: $_url" >&2
    mkdir -p "$(dirname "$_dest")"
    curl -s -o "$_dest" "$_url"
    continue
  else
    echo "$trivy_log" >&2
    break
  fi
done
elapsed=$(( $(date +%s) - t0 ))
TOTAL_SECONDS=$((TOTAL_SECONDS + elapsed))
log_timing "trivy" "$elapsed" "$ec"

echo ""
echo "[3/5] Syft (generacion de SBOM)..."
t0=$(date +%s)
syft . -o cyclonedx-json > "$RESULTS_DIR/${REPO_NAME}-sbom.json" 2> "$RESULTS_DIR/${REPO_NAME}-syft.err"
ec=$?
elapsed=$(( $(date +%s) - t0 ))
TOTAL_SECONDS=$((TOTAL_SECONDS + elapsed))
log_timing "syft" "$elapsed" "$ec"

echo ""
echo "[4/5] Grype..."
t0=$(date +%s)
grype sbom:"$RESULTS_DIR/${REPO_NAME}-sbom.json" -o json > "$RESULTS_DIR/${REPO_NAME}-grype.json"
ec=$?
elapsed=$(( $(date +%s) - t0 ))
TOTAL_SECONDS=$((TOTAL_SECONDS + elapsed))
log_timing "grype" "$elapsed" "$ec"

echo ""
echo "[5/5] OWASP Dependency-Check..."
if [ -z "${NVD_API_KEY:-}" ]; then
    echo "[warn] la variable NVD_API_KEY no esta definida; el escaneo puede fallar por rate limit de NVD"
fi
t0=$(date +%s)
dependency-check.sh \
    --project "$REPO_NAME" \
    --out "$RESULTS_DIR/dc" \
    --scan . \
    --enableExperimental \
    --format ALL \
    --nvdApiKey "${NVD_API_KEY:-}"
ec=$?
elapsed=$(( $(date +%s) - t0 ))
TOTAL_SECONDS=$((TOTAL_SECONDS + elapsed))
log_timing "dependency-check" "$elapsed" "$ec"

log_timing "TOTAL_5_HERRAMIENTAS" "$TOTAL_SECONDS" ""

echo ""
echo "=== Canonicalizando resultados de $REPO_NAME ==="
if [ ! -f "$CANONICALIZE_SCRIPT" ]; then
    echo "[warn] no se encontro canonicalize_sca.py en $SCRIPT_DIR"
    echo "       colocalo en el mismo directorio que scan_repo.sh, o corre la canonicalizacion a mano:"
    echo ""
    echo "python3 canonicalize_sca.py --trivy $RESULTS_DIR/${REPO_NAME}-trivy.json --grype $RESULTS_DIR/${REPO_NAME}-grype.json --osv-scanner $RESULTS_DIR/${REPO_NAME}-osv.json --dependency-check $RESULTS_DIR/dc/dependency-check-report.json --repo-name $REPO_NAME --out-dir $RESULTS_DIR"
    exit 0
fi

SUMMARY_FILE="$RESULTS_DIR/${REPO_NAME}-summary.txt"

if python3 "$CANONICALIZE_SCRIPT" \
    --trivy "$RESULTS_DIR/${REPO_NAME}-trivy.json" \
    --grype "$RESULTS_DIR/${REPO_NAME}-grype.json" \
    --osv-scanner "$RESULTS_DIR/${REPO_NAME}-osv.json" \
    --dependency-check "$RESULTS_DIR/dc/dependency-check-report.json" \
    --repo-name "$REPO_NAME" \
    --out-dir "$RESULTS_DIR" > "$SUMMARY_FILE" 2>&1; then
    cat "$SUMMARY_FILE"
    echo ""
    echo "[done] Todos los resultados de $REPO_NAME estan en: $RESULTS_DIR"
    echo "[done] Tiempo total (5 herramientas): $((TOTAL_SECONDS / 60)) min $((TOTAL_SECONDS % 60)) s (detalle en $TIMING_FILE)"
else
    echo "[error] canonicalize_sca.py fallo para $REPO_NAME:" >&2
    cat "$SUMMARY_FILE" >&2
    rm -f "$SUMMARY_FILE"
    echo "[error] no se genero $SUMMARY_FILE -- este repo se reintentara en el siguiente pase de scan_all_corpus.sh" >&2
    exit 5
fi
