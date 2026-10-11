#!/usr/bin/env bash
# Alcanzabilidad de un repo Maven con CodeQL. Uso: ./analizar_alcanzabilidad.sh <repo> [nombre]

set -uo pipefail

REPO="${1:?uso: analizar_alcanzabilidad.sh <ruta-al-repo> [nombre]}"
NOMBRE="${2:-$(basename "$REPO")}"

CODEQL="${CODEQL:-$HOME/codeql/codeql}"
QL_DIR="${QL_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ql}"
OUT="${OUT:-$HOME/alcanzabilidad-resultados}"
DBS="${DBS:-$HOME/codeql-dbs}"

mkdir -p "$OUT" "$DBS" "$OUT/logs"

[ -x "$CODEQL" ] || { echo "no encuentro la CLI de CodeQL en $CODEQL (instala CodeQL o define CODEQL)"; exit 1; }
[ -d "$QL_DIR" ] || { echo "no encuentro las consultas en $QL_DIR"; exit 1; }
[ -d "$REPO" ]   || { echo "no encuentro el repo en $REPO"; exit 1; }

RES_RESUMEN="$OUT/alcanzabilidad_resumen.csv"
RES_DETALLE="$OUT/alcanzabilidad_detalle.csv"
RES_CADENA="$OUT/alcanzabilidad_cadenas.csv"
RES_DIAG="$OUT/diagnostico_bd.csv"
LOG="$OUT/logs/${NOMBRE}.log"

[ -s "$RES_RESUMEN" ] || echo "repo,modo_extraccion,cve,biblioteca_usada,invocaciones,veredicto,nivel_mapa" > "$RES_RESUMEN"
[ -s "$RES_DETALLE" ] || echo "repo,modo_extraccion,cve,simbolo,invocado_desde,ubicacion,veredicto,procedencia_del_simbolo" > "$RES_DETALLE"
[ -s "$RES_CADENA" ]  || echo "repo,modo_extraccion,cve,punto_entrada,metodo_invocador,saltos" > "$RES_CADENA"
[ -s "$RES_DIAG" ]    || echo "repo,modo_extraccion,callables_en_fuente,llamadas_desde_fuente,llamadas_a_biblioteca,tipos_externos_distintos,tipos_del_mapa_resueltos,tipos_importados_sin_resolver,tipos_sin_resolver,veredicto_bd" > "$RES_DIAG"

echo "=============================================================="
echo "  $NOMBRE"
echo "=============================================================="

DB="$DBS/$NOMBRE"
rm -rf "$DB"

BUILD_CMD="${BUILD_CMD:-mvn -B -q clean compile -DskipTests -Dmaven.test.skip=true}"
printf '#!/usr/bin/env bash\nset -e\n%s\n' "$BUILD_CMD" > /tmp/build_${NOMBRE//\//_}.sh

echo "[1/4] compilando y extrayendo con CodeQL..."
T0=$(date +%s)
# si no compila se reintenta con --build-mode=none
if "$CODEQL" database create "$DB" --language=java --overwrite \
     --source-root="$REPO" \
     --command="bash /tmp/build_${NOMBRE//\//_}.sh" >> "$LOG" 2>&1; then
  COMPILA=si
else
  COMPILA=no
  echo "      [aviso] el build fallo. Ver $LOG"
  echo "      reintentando con --build-mode=none. CodeQL puede resolver las"
  echo "      dependencias por su cuenta si alcanza el repositorio o ya estan"
  echo "      en ~/.m2, y entonces el resultado SI vale. Lo decide el paso 2."
  rm -rf "$DB"
  "$CODEQL" database create "$DB" --language=java --build-mode=none --overwrite \
     --source-root="$REPO" >> "$LOG" 2>&1 || {
       echo "\"$NOMBRE\",\"ninguno\",0,0,0,0,0,0,\"NO-APTA: ni siquiera se pudo extraer el codigo\"" >> "$RES_DIAG"
       echo "      [FALLO] no se pudo construir ninguna base de datos"
       exit 0
     }
fi
T1=$(date +%s)
if [ "$COMPILA" = si ]; then MODO=compilado; else MODO=sin-compilar; fi
echo "      modo=$MODO, $((T1-T0))s"

LISTA_CVES="/tmp/cves_repo_${NOMBRE//\//_}.txt"
PATRONES="/tmp/patrones_repo_${NOMBRE//\//_}.txt"
FILTRAR=no
if [ -n "${CVES:-}" ] && [ -f "$CVES" ]; then
  FILTRAR=si
  sort -u "$CVES" | grep -E '^(CVE|GHSA)' > "$LISTA_CVES" || true
  sed 's/.*/,"&",/' "$LISTA_CVES" > "$PATRONES"
fi

ejecutar() {  # $1 fichero .ql  $2 csv destino  $3 "filtrar" para quedarse con los CVE del repo
  local ql="$1" destino="$2" filtro="${3:-}"
  "$CODEQL" query run "$QL_DIR/$ql" --database="$DB" --output=/tmp/q.bqrs >> "$LOG" 2>&1 || return 1
  if [ "$filtro" = filtrar ] && [ "$FILTRAR" = si ]; then
    "$CODEQL" bqrs decode /tmp/q.bqrs --format=csv --no-titles 2>>"$LOG" \
      | sed "s|^|\"$NOMBRE\",\"$MODO\",|" | { grep -F -f "$PATRONES" || true; } >> "$destino"
  else
    "$CODEQL" bqrs decode /tmp/q.bqrs --format=csv --no-titles 2>>"$LOG" \
      | sed "s|^|\"$NOMBRE\",\"$MODO\",|" >> "$destino"
  fi
}

echo "[2/4] diagnostico de aptitud de la base de datos..."
ejecutar diagnostico_bd.ql "$RES_DIAG"
tail -1 "$RES_DIAG" | sed 's/.*,"/      /; s/"$//' | fold -s -w 78 | sed '2,$s/^/      /'

if tail -1 "$RES_DIAG" | grep -q ',"NO-APTA'; then
  echo "[3/4] base de datos NO APTA: no hay nada que analizar aqui."
  echo "      Esto es distinto de PARCIAL. NO-APTA significa que no hay codigo"
  echo "      fuente o que no resuelve ni una sola llamada externa."
  echo "\"$NOMBRE\",\"$MODO\",,,,\"NO-ANALIZABLE\"," >> "$RES_RESUMEN"
  exit 0
fi

echo "[3/4] resumen por CVE..."
ejecutar alcanzabilidad_resumen.ql "$RES_RESUMEN"
echo "[4/4] detalle y cadenas de llamada..."
ejecutar alcanzabilidad_detalle.ql "$RES_DETALLE" filtrar
ejecutar cadena.ql "$RES_CADENA" filtrar

RES_FILTRADO="$OUT/alcanzabilidad_repo.csv"
RES_COBERTURA="$OUT/cobertura_mapa.csv"

if [ "$FILTRAR" = si ]; then
  [ -s "$RES_FILTRADO" ] || head -1 "$RES_RESUMEN" > "$RES_FILTRADO"
  [ -s "$RES_COBERTURA" ] || echo "repo,cves_en_el_repo,arbitrados,sin_simbolo_runtime,no_concluyentes,fuera_del_mapa" > "$RES_COBERTURA"

  total=$(wc -l < "$LISTA_CVES")

  grep "^\"$NOMBRE\"," "$RES_RESUMEN" | grep -F -f "$PATRONES" >> "$RES_FILTRADO" || true

  filas=$(grep "^\"$NOMBRE\"," "$RES_FILTRADO" || true)
  if [ -z "$filas" ]; then
    sin_simbolo=0; no_concluyentes=0; arbitrados=0
  else
    sin_simbolo=$(printf '%s\n' "$filas" | grep -c "SIN-SIMBOLO-DE-APLICACION" || true)
    no_concluyentes=$(printf '%s\n' "$filas" | grep -c "NO-CONCLUYENTE" || true)
    arbitrados=$(printf '%s\n' "$filas" | grep -v "SIN-SIMBOLO-DE-APLICACION" | grep -vc "NO-CONCLUYENTE" || true)
  fi
  en_mapa=$((arbitrados + sin_simbolo + no_concluyentes))
  fuera=$((total - en_mapa))

  echo "\"$NOMBRE\",$total,$arbitrados,$sin_simbolo,$no_concluyentes,$fuera" >> "$RES_COBERTURA"

  echo
  echo "Cobertura del mapa de simbolos en este repo:"
  echo "  CVE reportados por las herramientas SCA ... $total"
  echo "  ARBITRADOS con veredicto util ............ $arbitrados"
  echo "  de runtime, sin simbolo de aplicacion .... $sin_simbolo"
  echo "  sin arbitrar, tipo no resuelto ........... $no_concluyentes"
  echo "  todavia fuera del mapa ................... $fuera"
  if [ "$fuera" -gt 0 ]; then
    echo "  (los que faltan por mapear:)"
    comm -23 "$LISTA_CVES" <(grep "^\"$NOMBRE\"," "$RES_FILTRADO" | cut -d, -f3 | tr -d '"' | sort -u) | head -20 | sed 's/^/    /'
  fi
fi

echo
echo "Veredictos de este repo:"
if [ "$FILTRAR" = si ]; then
  grep "^\"$NOMBRE\"," "$RES_FILTRADO" | sed 's/","/  |  /g; s/"//g' | sed 's/^/  /'
else
  grep "^\"$NOMBRE\"" "$RES_RESUMEN" | grep -v "BIBLIOTECA-NO-USADA" | sed 's/","/  |  /g; s/"//g' | sed 's/^/  /'
fi
echo
echo "CSV en $OUT"
