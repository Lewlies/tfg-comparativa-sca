# Comparativa de herramientas SCA de código abierto en npm, PyPI y Maven

Material de reproducción del Trabajo Fin de Grado de Unai Cartagena. Contiene los scripts que construyen el banco de pruebas, ejecutan las cuatro herramientas SCA de línea de comandos (OSV-Scanner, Trivy, Grype junto a Syft y OWASP Dependency-Check), unifican sus resultados y los cruzan con EPSS y el catálogo KEV de CISA, además de los resultados obtenidos.

El código de la herramienta de integración continua `sca-gate` y su validación están en su propio repositorio.

## Contenido

| Carpeta | Contenido |
|---|---|
| `corpus_real/` | Manifiesto de los 48 repositorios reales con el SHA analizado, sus estrellas, último *push* y licencia en el momento de la búsqueda (`candidatos_repos_tfg.csv`), y scripts de descarga y verificación de manifiestos |
| `escaneo/` | Ejecución de las cuatro herramientas por repositorio y sobre todo el corpus, y canonicalización de identificadores mediante la API de alias de OSV |
| `analisis/` | Agregación de los resultados por repositorio y cruce con EPSS y KEV |
| `resultados/` | Resultados consolidados, resultados enriquecidos con EPSS y KEV, y tiempos de ejecución |
| `corpus_sintetico/` | Los 12 repositorios sintéticos (manifiestos, ficheros de bloqueo y verdad de referencia), los scripts que los escanean y puntúan, y los resultados |
| `holdout/` | Los 6 repositorios de reserva usados para validar `sca-gate`, con su verdad de referencia y el árbol de dependencias de los dos repositorios Maven |
| `alcanzabilidad/` | Análisis estático de alcanzabilidad con CodeQL para Maven |

## Requisitos

Linux (las pruebas se hicieron en Ubuntu 24.04 sobre WSL2), git, Python 3.8 o superior con PyYAML, Maven, y OSV-Scanner, Trivy, Syft, Grype y Dependency-Check en el `PATH`. `verificar_manifiestos.sh` usa además la CLI `gh` para consultar el contenido de cada repositorio. Dependency-Check usa la variable de entorno `NVD_API_KEY` si está definida. El análisis de alcanzabilidad necesita además la CLI de CodeQL, que por defecto se busca en `~/codeql/codeql` (se puede cambiar con la variable `CODEQL`).

## Reproducir el corpus real

1. Descargar los 48 repositorios en el commit analizado.

   ```bash
   python3 corpus_real/reproducir_corpus.py --dest ~/corpus
   ```

2. Escanear y canonicalizar (alrededor de una hora para los 48 repositorios).

   ```bash
   bash escaneo/scan_all_corpus.sh ~/corpus
   ```

3. Agregar los resultados de cada repositorio.

   ```bash
   python3 analisis/agregar_resultados.py ~/corpus
   ```

4. Cruzar con EPSS y KEV.

   ```bash
   cd ~/corpus && python3 /ruta/al/repo/analisis/cruzar_epss_kev.py
   ```

Las bases de datos de vulnerabilidades, EPSS y KEV cambian a diario, de modo que una ejecución posterior puede dar cifras distintas aunque el código analizado sea el mismo. Los CSV de `resultados/` son los usados en la memoria.

## Corpus sintético

1. `bash corpus_sintetico/scripts/montar_corpus_sintetico.sh`
2. `bash corpus_sintetico/scripts/registrar_versiones.sh > ~/corpus-sintetico/versiones.txt`
3. `bash escaneo/scan_all_corpus.sh ~/corpus-sintetico`
4. `python3 corpus_sintetico/scripts/puntuar_sinteticos.py --gt corpus_sintetico --corpus ~/corpus-sintetico`
5. `python3 corpus_sintetico/scripts/cruzar_sintetico_epss_kev.py`

Los resultados de Dependabot incluidos en `corpus_sintetico/resultados/` son los usados en la memoria. Los hallazgos clasificados como `CANDIDATO_FP` no se cuentan como falsos positivos hasta revisarlos a mano. `corpus_sintetico/scripts/experimento_osv_resolver.sh` repite el escaneo de los repositorios Maven con OSV-Scanner sin `--no-resolve`.
