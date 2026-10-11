#!/usr/bin/env bash
# Lanza analizar_alcanzabilidad.sh sobre los repos Maven del corpus. Uso: ./analizar_todos_maven.sh [repo ...]

set -uo pipefail

CORPUS="${CORPUS:-$HOME/corpus}"
DATASET="${DATASET:-$CORPUS/resultados_enriquecidos_v2.csv}"
OUT="${OUT:-$HOME/alcanzabilidad-resultados}"
DBS="${DBS:-$HOME/codeql-dbs}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALIZAR="${ANALIZAR:-$SCRIPT_DIR/analizar_alcanzabilidad.sh}"
export QL_DIR="${QL_DIR:-$SCRIPT_DIR/ql}"
LISTAS="$OUT/cves_por_repo"

[ -f "$DATASET" ]   || { echo "no encuentro el dataset en $DATASET"; exit 1; }
[ -f "$ANALIZAR" ]  || { echo "no encuentro $ANALIZAR"; exit 1; }
[ -d "$QL_DIR" ]    || { echo "no encuentro las consultas en $QL_DIR"; exit 1; }

mkdir -p "$OUT" "$LISTAS"
CENSO="$OUT/censo_maven.csv"
[ -s "$CENSO" ] || echo "repo,categoria,modo_extraccion,veredicto_bd,cves_en_el_repo,cves_arbitrados,segundos" > "$CENSO"

mapfile -t CANDIDATOS < <(find "$CORPUS" -mindepth 3 -maxdepth 3 -type d -path "*/maven/*" \
                       ! -name 'results*' ! -path "*/results*/*" | sort)

TODOS=()
OMITIDOS=()
for d in "${CANDIDATOS[@]}"; do
  if [ -f "$d/pom.xml" ] || [ -n "$(find "$d" -maxdepth 3 -name pom.xml -print -quit 2>/dev/null)" ]; then
    TODOS+=("$d")
  else
    OMITIDOS+=("$(basename "$d")")
  fi
done

if [ ${#OMITIDOS[@]} -gt 0 ]; then
  echo "Omitidos por no tener pom.xml (no son repos Maven):"
  printf '  %s\n' "${OMITIDOS[@]}"
  echo
fi

if [ $# -gt 0 ]; then
  SELECCION=()
  for pedido in "$@"; do
    for r in "${TODOS[@]}"; do
      [ "$(basename "$r")" = "$pedido" ] && SELECCION+=("$r")
    done
  done
  TODOS=("${SELECCION[@]}")
fi

echo "=============================================================="
echo "  Censo de alcanzabilidad, ${#TODOS[@]} repos Maven"
echo "=============================================================="
printf '  %s\n' "${TODOS[@]##*/}"
echo

for REPO in "${TODOS[@]}"; do
  NOMBRE=$(basename "$REPO")
  CATEGORIA=$(basename "$(dirname "$(dirname "$REPO")")")

  if grep -q "^\"$NOMBRE\"," "$OUT/diagnostico_bd.csv" 2>/dev/null &&
     grep "^\"$NOMBRE\"," "$OUT/diagnostico_bd.csv" | grep -qE '"(APTA|PARCIAL[^"]*|NO-APTA[^"]*)"$'; then
    echo "[salto] $NOMBRE, ya analizado con veredicto valido"
    if ! grep -q "^\"$NOMBRE\"," "$CENSO" 2>/dev/null; then
      F=$(grep "^\"$NOMBRE\"," "$OUT/diagnostico_bd.csv" | tail -1)
      M=$(echo "$F" | cut -d, -f2 | tr -d '"')
      V=$(echo "$F" | sed 's/.*,"/"/; s/"$//' | tr -d '"' | cut -c1-40)
      N=$(awk -F, -v repo="$NOMBRE" '$2=="maven" && $3==repo {print $7}' "$DATASET" \
            | tr ';' '\n' | grep -coE 'CVE-[0-9]{4}-[0-9]+' || true)
      C=$(grep "^\"$NOMBRE\"," "$OUT/cobertura_mapa.csv" 2>/dev/null | tail -1 | awk -F, '{print $3}')
      echo "\"$NOMBRE\",\"$CATEGORIA\",\"$M\",\"$V\",${N:-0},${C:-0},0" >> "$CENSO"
      echo "        (fila de censo anadida a posteriori)"
    fi
    continue
  fi

  echo
  echo "  $NOMBRE  ($CATEGORIA)"

  LISTA="$LISTAS/${NOMBRE}.txt"
  awk -F, -v repo="$NOMBRE" '$2=="maven" && $3==repo {print $7}' "$DATASET" \
    | tr ';' '\n' | grep -oE 'CVE-[0-9]{4}-[0-9]+' | sort -u > "$LISTA"
  N_CVES=$(wc -l < "$LISTA")
  echo "  CVE reportados por las herramientas SCA: $N_CVES"

  if [ "$N_CVES" -eq 0 ]; then
    echo "  [aviso] sin CVE en el dataset. Se analiza igual, para el censo de aptitud."
  fi

  if [ "${GO_OFFLINE:-0}" = "1" ]; then
    echo "  precacheando dependencias con Maven (puede tardar)..."
    ( cd "$REPO" && mvn -B dependency:go-offline -fn >/dev/null 2>&1 )
  fi

  T0=$(date +%s)
  CVES="$LISTA" OUT="$OUT" DBS="$DBS" QL_DIR="$QL_DIR" \
    bash "$ANALIZAR" "$REPO" "$NOMBRE"
  T1=$(date +%s)
  SEGS=$((T1 - T0))

  FILA_DIAG=$(grep "^\"$NOMBRE\"," "$OUT/diagnostico_bd.csv" 2>/dev/null | tail -1)
  MODO=$(echo "$FILA_DIAG" | cut -d, -f2 | tr -d '"')
  VER_BD=$(echo "$FILA_DIAG" | sed 's/.*,"/"/; s/"$//' | tr -d '"' | cut -c1-40)
  CUBIERTOS=$(grep "^\"$NOMBRE\"," "$OUT/cobertura_mapa.csv" 2>/dev/null | tail -1 | awk -F, '{print $3}')
  CUBIERTOS=${CUBIERTOS:-0}

  echo "\"$NOMBRE\",\"$CATEGORIA\",\"$MODO\",\"$VER_BD\",$N_CVES,$CUBIERTOS,$SEGS" >> "$CENSO"
  echo "  -> $SEGS s, modo=$MODO, bd=$VER_BD, cubiertos=$CUBIERTOS/$N_CVES"

  if [ "${KEEP_DB:-0}" != "1" ]; then
    rm -rf "${DBS:?}/$NOMBRE"
    echo "  base de datos borrada. Disponible: $(df -h "$HOME" | awk 'NR==2{print $4}')"
  fi
done

echo
echo "=============================================================="
echo "  CENSO TERMINADO"
echo "=============================================================="
total=$(($(wc -l < "$CENSO") - 1))
compilan=$(grep -c '"compilado"' "$CENSO" || true)
aptas=$(grep -c '"APTA"' "$CENSO" || true)
parciales=$(grep -c '"PARCIAL' "$CENSO" || true)
echo "  repos Maven analizados ........... $total"
echo "  compilan con Maven ............... $compilan"
echo "  base de datos APTA ............... $aptas"
echo "  base de datos PARCIAL ............ $parciales  (se analizan igual)"
echo
echo "  (una base de datos puede ser APTA sin que el repo compile, ver README)"
echo
awk -F, 'NR>1 {gsub(/"/,""); printf "  %-32s %-12s %-10s %3s/%-3s CVE\n", $1, $3, substr($4,1,10), $6, $5}' "$CENSO"
echo
echo "  censo en      $CENSO"
echo "  veredictos en $OUT/alcanzabilidad_repo.csv"
echo "  cobertura en  $OUT/cobertura_mapa.csv"
