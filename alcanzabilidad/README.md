# Alcanzabilidad estática en Maven con CodeQL

Las herramientas SCA indican que una versión de un paquete tiene una vulnerabilidad, pero no si la aplicación llega a usar la parte vulnerable de ese paquete. Los scripts de esta carpeta responden a esa segunda pregunta en proyectos Maven. Para ello usan CodeQL y buscan en el grafo de llamadas un camino desde un punto de entrada de la aplicación hasta el método que el aviso de seguridad señala como vía de explotación. El análisis es estático, así que sus dos respuestas no valen lo mismo. Cuando no hay camino, la vulnerabilidad no se puede explotar por esa vía, salvo por reflexión, inyección de dependencias o carga dinámica de clases. Cuando sí lo hay, solo queda demostrado que el código puede llegar al método, no que lo haga en producción.

## Banco de validación

Los repositorios sintéticos del trabajo solo contienen manifiestos y no tienen código, así que sirven para validar la detección pero no la alcanzabilidad. Por eso `crear_banco_alcanzabilidad.sh` genera cinco proyectos Java pequeños en los que se conoce de antemano la respuesta correcta.

| Caso | Proyecto | CVE | Usa la biblioteca | Invoca la API vulnerable | Alcanzable desde `main` |
|---|---|---|---|---|---|
| A | `log4j-unreachable` | CVE-2021-44228 | no | no | no |
| B | `log4j-reachable` | CVE-2021-44228 | sí | sí | sí |
| C | `log4j-deadcode` | CVE-2021-44228 | sí | sí | no |
| D | `snakeyaml-dump-only` | CVE-2022-1471 | sí | no | no |
| E | `snakeyaml-load` | CVE-2022-1471 | sí | sí | sí |

Cada caso aísla una situación que un análisis más simple confundiría. El caso A declara log4j sin llamarlo nunca, que es el falso positivo típico de las herramientas SCA. En el caso B la llamada a `Logger.error` está al final de una cadena de cuatro métodos repartida en cuatro ficheros, de modo que solo se encuentra recorriendo el grafo de llamadas. El caso C contiene la llamada vulnerable en un método que compila pero al que nadie llama, y es el que distingue este análisis de una búsqueda de texto. El caso D usa snakeyaml solo para escribir con `dump()`, mientras que la vulnerabilidad está en `load()`, y el caso E es el control positivo directo de esa misma biblioteca.

El banco se ejecutó tres veces, una en un contenedor con dependencias sustituidas por clases con la misma firma y dos en WSL con las dependencias reales, con y sin compilar, y los cinco veredictos coincidieron con la respuesta esperada en las tres. El caso C sale como `ALCANZABLE-SOLO-LAXO`, que es el resultado correcto, porque el método que contiene la llamada es público y la política laxa de puntos de entrada lo cuenta como uno más. En `resultados_validacion/` están los CSV de la primera ejecución.

## Cómo funciona

El análisis necesita saber qué método hay que alcanzar en cada CVE, y ese dato no está en los avisos de seguridad, que solo indican el paquete y el rango de versiones afectado. Por eso el mapa de CVE a símbolo vulnerable se construye en dos niveles que se informan por separado en la columna `nivel_mapa`. El nivel manual, en `ql/Alcanzabilidad.qll`, contiene 15 CVE cuyo símbolo se identificó leyendo el aviso, el *commit* de corrección y la prueba de concepto. El nivel por regla lo genera `generar_mapa.py` en `ql/MapaGenerado.qll` a partir del paquete al que OSV asocia cada CVE, que obtiene `ranking_paquetes.py`. Asigna a todo CVE de jackson-databind los métodos de lectura de `ObjectMapper` y `ObjectReader`, y declara sin símbolo de aplicación los de Spring y Tomcat, porque esas vulnerabilidades las dispara el propio framework y no una llamada de la aplicación.

Antes de las consultas, `diagnostico_bd.ql` comprueba que la base de datos de CodeQL sea apta. Cuando CodeQL no encuentra las clases de una dependencia, elimina las llamadas a ese tipo sin avisar, y el análisis respondería que nada es alcanzable sin que se pudiera distinguir de un proyecto limpio. Un tipo importado cuya clase no se ha encontrado aparece en la base de datos sin ningún método, y eso es lo que detecta el diagnóstico. Los CVE de los tipos afectados quedan como `NO-CONCLUYENTE-BD-INCOMPLETA` y el resto del repositorio se analiza con normalidad.

La respuesta depende de qué se considera un punto de entrada, así que las consultas informan dos políticas en lugar de elegir una. La estricta parte de `main` y de los manejadores web, y la laxa añade cualquier método público, lo que es correcto en una biblioteca pero en una aplicación puede marcar como alcanzable código que nadie llama.

## Uso

Hace falta la CLI de CodeQL, que se busca en `~/codeql/codeql` salvo que se indique otra ruta con la variable `CODEQL`, además de Maven y un JDK 17 o superior. Los proyectos del banco fijan la versión 3.13.0 de `maven-compiler-plugin`, porque la que trae por defecto Maven 3.8.7 no funciona con JDK 21.

```bash
bash crear_banco_alcanzabilidad.sh                     # crea el banco en ~/reach-bench
for p in ~/reach-bench/*/; do bash analizar_alcanzabilidad.sh "$p"; done

bash analizar_alcanzabilidad.sh ~/corpus/<categoria>/maven/<repo>
BUILD_CMD="./gradlew classes" bash analizar_alcanzabilidad.sh ~/ruta/repo
```

El censo de los 16 repositorios Maven del corpus real parte de `~/corpus/resultados_enriquecidos_v2.csv`, que genera `analisis/cruzar_epss_kev.py`. `ranking_paquetes.py` consulta OSV para asociar cada CVE a su paquete, `generar_mapa.py` escribe el mapa por regla y `analizar_todos_maven.sh` analiza cada repositorio y cruza sus veredictos con los CVE que las herramientas SCA reportaron en él.

```bash
python3 ranking_paquetes.py
python3 generar_mapa.py
bash analizar_todos_maven.sh
```

Los resultados se escriben en `~/alcanzabilidad-resultados/`, o en la carpeta que indique la variable `OUT`.

| Fichero | Contenido |
|---|---|
| `diagnostico_bd.csv` | Aptitud de la base de datos de cada repositorio, que conviene revisar antes que el resto |
| `alcanzabilidad_resumen.csv` | Una fila por repositorio y CVE del mapa, con el veredicto y el nivel del mapa |
| `alcanzabilidad_repo.csv` | El resumen limitado a los CVE que las herramientas SCA reportaron en cada repositorio |
| `alcanzabilidad_detalle.csv` | Una fila por invocación de un símbolo vulnerable, con fichero, línea y procedencia del símbolo |
| `alcanzabilidad_cadenas.csv` | El punto de entrada más cercano a cada invocación y el número de saltos |
| `cobertura_mapa.csv` | Por repositorio, cuántos CVE se arbitran, cuántos no tienen símbolo y cuántos quedan fuera del mapa |
| `censo_maven.csv` | Resumen del censo, con una fila por repositorio |

## Veredictos

| Veredicto | Significado |
|---|---|
| `ALCANZABLE-ESTRICTO` | Hay un camino desde `main` o desde un manejador web |
| `ALCANZABLE-SOLO-LAXO` | Solo hay camino desde un método público que no es punto de entrada estricto |
| `INVOCADO-PERO-NO-ALCANZABLE` | El código invoca el símbolo, pero ningún punto de entrada llega a esa invocación |
| `BIBLIOTECA-USADA-API-VULNERABLE-NO` | El código usa la biblioteca, pero no la parte vulnerable |
| `BIBLIOTECA-NO-USADA` | La dependencia está declarada y el código no la usa |
| `NO-CONCLUYENTE-BD-INCOMPLETA` | La base de datos no resuelve el tipo, así que no hay veredicto |
| `SIN-SIMBOLO-DE-APLICACION` | La vulnerabilidad la dispara el framework o el contenedor, y no se puede arbitrar con este análisis |

## Limitaciones

El grafo de llamadas no recoge las llamadas hechas por reflexión, por inyección de dependencias o con `ServiceLoader`, de modo que en proyectos Spring la política estricta se queda corta y la laxa se pasa, y por eso se informan las dos. El análisis tampoco entra en el código de las dependencias y se detiene en la API pública de la biblioteca vulnerable, así que no ve los usos que hace otra dependencia, una fachada como slf4j sobre log4j o el propio framework, como Spring MVC cuando deserializa con jackson el cuerpo de una petición. Por ese motivo, un descarte solo se considera sólido después de comprobar a mano que no existe ninguna de esas vías. Por último, las reglas del segundo nivel del mapa asignan un símbolo o un motivo a un paquete entero, y sus veredictos se informan aparte de los del nivel manual para no mezclar las dos precisiones. El código de *test* queda fuera del análisis, porque un camino que solo existe en los *tests* no forma parte de la superficie de ataque.
