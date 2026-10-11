#!/usr/bin/env bash
# Comprueba si cada repo del corpus tiene manifiesto y lockfile en la raiz (necesita gh)

set -uo pipefail

OUT="manifiestos_report.csv"
echo "ecosistema,categoria,repo,url,manifiesto_ok,archivos_manifiesto,lockfile_ok,archivos_lock,notas" > "$OUT"

if ! gh auth status >/dev/null 2>&1; then
  echo "ERROR: gh CLI no esta autenticado. Ejecuta: gh auth login" >&2
  exit 1
fi

check_repo() {
  local ecosystem="$1" categoria="$2" repo="$3"
  local url="https://github.com/$repo"
  local files
  files=$(gh api "repos/$repo/contents" --jq '.[].name' 2>/dev/null)
  local status=$?

  if [ $status -ne 0 ] || [ -z "$files" ]; then
    echo "$ecosystem,$categoria,$repo,$url,ERROR,,ERROR,,no se pudo listar la raiz (repo privado / borrado / error de red)" >> "$OUT"
    return
  fi

  local manifest_files="" lock_files="" manifest_ok="NO" lock_ok="NO" notas=""

  case "$ecosystem" in
    npm)
      echo "$files" | grep -qx package.json && manifest_files=" package.json"
      for f in package-lock.json yarn.lock pnpm-lock.yaml; do
        echo "$files" | grep -qx "$f" && lock_files="$lock_files $f"
      done
      [ -n "$manifest_files" ] && manifest_ok="SI"
      [ -n "$lock_files" ] && lock_ok="SI"
      [ "$manifest_ok" = "SI" ] && [ "$lock_ok" = "NO" ] && notas="sin lockfile en raiz: revisar reproducibilidad de versiones"
      ;;
    pypi)
      for f in requirements.txt pyproject.toml setup.py setup.cfg Pipfile; do
        echo "$files" | grep -qx "$f" && manifest_files="$manifest_files $f"
      done
      for f in poetry.lock Pipfile.lock; do
        echo "$files" | grep -qx "$f" && lock_files="$lock_files $f"
      done
      [ -n "$manifest_files" ] && manifest_ok="SI"
      [ -n "$lock_files" ] && lock_ok="SI"
      if [ "$manifest_ok" = "SI" ] && [ "$lock_ok" = "NO" ]; then
        notas="sin lockfile: normal en librerias (pyproject/setup.py con rangos), revisar si es libreria o app"
      fi
      ;;
    maven)
      echo "$files" | grep -qx "pom.xml" && manifest_files="pom.xml"
      [ -n "$manifest_files" ] && manifest_ok="SI"
      lock_ok="N/A"
      notas="Maven no usa lockfile estandar; verificar manualmente que pom.xml no use rangos de version [1.0,2.0)"
      ;;
  esac

  if [ "$manifest_ok" = "NO" ]; then
    notas="MANIFIESTO NO ENCONTRADO EN RAIZ - posible monorepo, revisar subdirectorios manualmente. $notas"
  fi

  echo "$ecosystem,$categoria,$repo,$url,$manifest_ok,\"$manifest_files\",$lock_ok,\"$lock_files\",\"$notas\"" >> "$OUT"
  echo "  [$ecosystem/$categoria] $repo -> manifiesto:$manifest_ok lock:$lock_ok"
}

echo "Verificando manifiestos/lockfiles de los 48 repos del corpus..."
echo ""

check_repo npm "Muchas estrellas" "react/react"
check_repo npm "Muchas estrellas" "vercel/next.js"
check_repo npm "Muchas estrellas" "axios/axios"
check_repo npm "Muchas estrellas" "trekhleb/javascript-algorithms"
check_repo npm "Mediana" "lowdefy/lowdefy"
check_repo npm "Mediana" "greggman/twgl.js"
check_repo npm "Mediana" "journey-ad/Moe-Counter"
check_repo npm "Mediana" "GoogleCloudPlatform/nodejs-docs-samples"
check_repo npm "Pequena" "nextcloud/unsplash"
check_repo npm "Pequena" "derikb/character-sheet-app"
check_repo npm "Pequena" "atomicman57/naija-state-local-government"
check_repo npm "Pequena" "ankit1329/Eml-Parser"
check_repo npm "Abandonado" "atom/atom"
check_repo npm "Abandonado" "angular/angular.js"
check_repo npm "Abandonado" "algorithm-visualizer/algorithm-visualizer"
check_repo npm "Abandonado" "GitSquared/edex-ui"

check_repo pypi "Muchas estrellas" "psf/requests"
check_repo pypi "Muchas estrellas" "scrapy/scrapy"
check_repo pypi "Muchas estrellas" "home-assistant/core"
check_repo pypi "Muchas estrellas" "django/django"
check_repo pypi "Mediana" "python-arq/arq"
check_repo pypi "Mediana" "benedekrozemberczki/pytorch_geometric_temporal"
check_repo pypi "Mediana" "containers/ramalama"
check_repo pypi "Mediana" "Eladlev/AutoPrompt"
check_repo pypi "Pequena" "cvlab-kaist/DiffTrack"
check_repo pypi "Pequena" "bofh69/nfc2klipper"
check_repo pypi "Pequena" "dertwist/Hammer5Tools"
check_repo pypi "Pequena" "natiginfo/CommandLineWeather"
check_repo pypi "Abandonado" "nvbn/thefuck"
check_repo pypi "Abandonado" "zai-org/ChatGLM-6B"
check_repo pypi "Abandonado" "d2l-ai/d2l-zh"
check_repo pypi "Abandonado" "awolfly9/IPProxyTool"

check_repo maven "Muchas estrellas" "iluwatar/java-design-patterns"
check_repo maven "Muchas estrellas" "apache/dubbo"
check_repo maven "Muchas estrellas" "apache/rocketmq"
check_repo maven "Muchas estrellas" "google/guava"
check_repo maven "Mediana" "apache/commons-lang"
check_repo maven "Mediana" "tlaplus/tlaplus"
check_repo maven "Mediana" "thymeleaf/thymeleaf"
check_repo maven "Mediana" "OpenHFT/Chronicle-Map"
check_repo maven "Pequena" "contentful/contentful.java"
check_repo maven "Pequena" "pddon/easy-spring-boot-api"
check_repo maven "Pequena" "dromara/TestHub"
check_repo maven "Pequena" "apache/juneau"
check_repo maven "Abandonado" "spotify/docker-maven-plugin"
check_repo maven "Abandonado" "xkcoding/spring-boot-demo"
check_repo maven "Abandonado" "ityouknow/spring-boot-examples"
check_repo maven "Abandonado" "ltsopensource/light-task-scheduler"

echo ""
echo "Listo. Resultado en $OUT"
echo ""
echo "Resumen:"
echo "  Manifiesto NO encontrado en raiz:"
awk -F',' 'NR>1 && $5=="NO" {print "    - " $3}' "$OUT"
echo "  Errores de consulta:"
awk -F',' 'NR>1 && $5=="ERROR" {print "    - " $3}' "$OUT"
