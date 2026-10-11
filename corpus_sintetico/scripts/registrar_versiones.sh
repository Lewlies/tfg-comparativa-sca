#!/usr/bin/env bash
# Versiones de las herramientas y fecha de sus bases de datos

set -uo pipefail

echo "# Versiones de herramienta y BBDD"
echo "# Fecha de la corrida: $(date -u +%Y-%m-%dT%H:%M:%SZ) (UTC)"
echo "# Host: $(uname -srm)"
echo

echo "## osv-scanner"
osv-scanner --version 2>&1 | head -5 || echo "no disponible"
echo

echo "## trivy"
trivy --version 2>&1 | head -10 || echo "no disponible"
echo

echo "## syft"
syft version 2>&1 | head -5 || echo "no disponible"
echo

echo "## grype"
grype version 2>&1 | head -8 || echo "no disponible"
echo "### grype db status"
grype db status 2>&1 | head -10 || true
echo

echo "## dependency-check"
dependency-check.sh --version 2>&1 | head -3 || dependency-check --version 2>&1 | head -3 || echo "no disponible"
echo "### fecha del feed NVD en cache"
ls -l --time-style=long-iso ~/.local/share/dependency-check/data/*.db 2>/dev/null \
  || ls -l --time-style=long-iso /usr/share/dependency-check/data 2>/dev/null \
  || echo "no localizo la cache de DC, apunta la fecha a mano"
echo

echo "## entorno de los ecosistemas"
node --version 2>&1 | sed 's/^/node /' || true
npm --version 2>&1 | sed 's/^/npm /' || true
python3 --version 2>&1 || true
pip --version 2>&1 | head -1 || true
mvn --version 2>&1 | head -1 || true
java --version 2>&1 | head -1 || true
