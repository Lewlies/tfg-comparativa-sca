#!/usr/bin/env bash
# Escanea los repos Maven con OSV-Scanner sin --no-resolve

set -uo pipefail

DEST="$HOME/corpus/experimento_osv_sin_noresolve"
CORPUS="$HOME/corpus"
SINT="$HOME/corpus-sintetico"

TIMEOUT_NATIVE="${TIMEOUT_NATIVE:-300s}"
# KEV que solo detectaba Trivy
KEV_RE="CVE-2023-44487|CVE-2025-24813|CVE-2020-1938|CVE-2022-22965"
# transitiva de synthetic-maven-mixed
GT_SINT="CVE-2017-18640"

mkdir -p "$DEST/native" "$DEST/depsdev"

echo "=== Registrando versiones ==="
{
  echo "# OSV-Scanner sin --no-resolve sobre los repos Maven"
  echo "# Fecha de ejecucion: $(date -u +%Y-%m-%dT%H:%M:%SZ) UTC"
  echo "# Host: $(uname -srm)"
  echo
  echo "## osv-scanner"
  osv-scanner --version 2>&1 | head -5
  echo
  echo "## Estado de Maven Central (si la fase native da 429 sus resultados no valen)"
  curl -s -o /dev/null -w "#   curl a Maven Central -> %{http_code}\n" \
    "https://repo.maven.apache.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.pom?cb=$RANDOM"
} > "$DEST/LEEME.txt"
cat "$DEST/LEEME.txt"
echo

echo "=== Fase 1: --data-source=native sobre 3 repos ==="
echo

fase1_repos=()
[ -d "$SINT/mixed/maven/synthetic-maven-mixed" ] && fase1_repos+=("$SINT/mixed/maven/synthetic-maven-mixed")
for r in spring-boot-demo TestHub; do
  d=$(ls -d "$CORPUS"/*/maven/"$r" 2>/dev/null | head -1)
  [ -n "$d" ] && fase1_repos+=("$d")
done

for d in "${fase1_repos[@]}"; do
  repo=$(basename "$d")
  echo "[native] $repo"
  ( cd "$d" && timeout "${TIMEOUT_NATIVE}" osv-scanner scan -r . --no-ignore \
      --data-source=native --format json \
      > "$DEST/native/$repo.json" 2> "$DEST/native/$repo.err" )
  rc=$?
  if [ "$rc" -eq 124 ]; then
    echo "    no termina en ${TIMEOUT_NATIVE}"
    echo "TIMEOUT tras ${TIMEOUT_NATIVE}" >> "$DEST/native/$repo.err"
  fi
  aborta=$(grep -c "Error during extraction" "$DEST/native/$repo.err" 2>/dev/null || true); aborta=${aborta:-0}
  n429=$(grep -c "429" "$DEST/native/$repo.err" 2>/dev/null || true)
  vacio=$(grep -c "invalid empty constraint" "$DEST/native/$repo.err" 2>/dev/null || true)
  kev=$(grep -oE "$KEV_RE" "$DEST/native/$repo.json" 2>/dev/null | sort -u | tr '\n' ' ')
  gt=$(grep -c "$GT_SINT" "$DEST/native/$repo.json" 2>/dev/null || true)
  echo "    aborta=$aborta  429=$n429  constraint_vacia=$vacio"
  echo "    KEV vistos: ${kev:-ninguno}"
  [[ "$repo" == synthetic-maven-mixed ]] && echo "    ground truth $GT_SINT encontrado: $gt"
  sleep 3
done
echo

echo "=== Fase 2: fuente por defecto (deps.dev) sobre los 16 repos Maven ==="
echo

total=0; abortan=0; resuelven=""
for d in "$CORPUS"/*/maven/*/; do
  [ "$(basename "$d")" = "results" ] && continue
  find "$d" -name pom.xml -print -quit 2>/dev/null | grep -q . || continue
  repo=$(basename "$d"); total=$((total+1))
  ( cd "$d" && osv-scanner scan -r . --no-ignore --format json \
      > "$DEST/depsdev/$repo.json" 2> "$DEST/depsdev/$repo.err" )
  if grep -q "Error during extraction" "$DEST/depsdev/$repo.err" 2>/dev/null; then
    abortan=$((abortan+1)); estado="aborta"
  else
    resuelven="$resuelven $repo"; estado="resuelve"
  fi
  kev=$(grep -oE "$KEV_RE" "$DEST/depsdev/$repo.json" 2>/dev/null | sort -u | tr '\n' ' ')
  printf '  %-34s %-10s KEV: %s\n' "$repo" "$estado" "${kev:-ninguno}"
done
echo
echo "  repos Maven con pom.xml: $total"
echo "  el resolvedor aborta en: $abortan"
echo "  resuelve limpio en:${resuelven:- ninguno}"
echo

echo "=== Disparadores del fallo (constraint vacia) ==="
grep -h "failed parsing version constraint" "$DEST/depsdev"/*.err 2>/dev/null \
  | sed 's/.*constraint //' | sort | uniq -c | sort -rn | head -10
echo

echo "=== CVE de KEV que ve OSV-Scanner sin --no-resolve ==="
for r in spring-boot-demo TestHub dubbo thymeleaf; do
  j="$DEST/depsdev/$r.json"
  [ -f "$j" ] || { printf '  %-22s no probado\n' "$r"; continue; }
  kev=$(grep -oE "$KEV_RE" "$j" 2>/dev/null | sort -u | tr '\n' ' ')
  printf '  %-22s %s\n' "$r" "${kev:-ninguno}"
done
echo
echo "Resultados en $DEST"
