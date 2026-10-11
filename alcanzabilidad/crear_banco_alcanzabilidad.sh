#!/usr/bin/env bash
# Crea los cinco proyectos del banco de alcanzabilidad. Uso: ./crear_banco_alcanzabilidad.sh [destino]

set -euo pipefail

DEST="${1:-$HOME/reach-bench}"
mkdir -p "$DEST"
cd "$DEST"

GROUP="eus.ehu.tfg"
JAVA_RELEASE=17

escribir_pom() {
  local art="$1"; shift
  local deps="$1"; shift
  mkdir -p "$art"
  cat > "$art/pom.xml" <<POM
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>${GROUP}</groupId>
  <artifactId>${art}</artifactId>
  <version>1.0.0</version>
  <packaging>jar</packaging>
  <properties>
    <maven.compiler.release>${JAVA_RELEASE}</maven.compiler.release>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <dependencies>
${deps}
  </dependencies>
  <build>
    <plugins>
      <!-- el plugin por defecto de Maven 3.8.7 no entiende <release> -->
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.13.0</version>
        <configuration>
          <release>${JAVA_RELEASE}</release>
        </configuration>
      </plugin>
    </plugins>
  </build>
</project>
POM
}

DEPS_LOG4J='    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-api</artifactId>
      <version>2.14.1</version>
    </dependency>'

DEPS_SNAKEYAML='    <dependency>
      <groupId>org.yaml</groupId>
      <artifactId>snakeyaml</artifactId>
      <version>1.33</version>
    </dependency>'

src() { mkdir -p "$1/src/main/java/eus/ehu/tfg"; echo "$1/src/main/java/eus/ehu/tfg"; }

A=log4j-unreachable
escribir_pom "$A" "$DEPS_LOG4J"
D=$(src "$A")
cat > "$D/App.java" <<'JAVA'
package eus.ehu.tfg;

// Caso A: log4j esta en el pom pero el codigo no lo usa. No alcanzable.
public class App {
    public static void main(String[] args) {
        String entrada = args.length > 0 ? args[0] : "sin-entrada";
        System.out.println("procesando: " + Normalizador.normalizar(entrada));
    }
}
JAVA
cat > "$D/Normalizador.java" <<'JAVA'
package eus.ehu.tfg;

public class Normalizador {
    public static String normalizar(String s) {
        return s == null ? "" : s.trim().toLowerCase();
    }
}
JAVA

B=log4j-reachable
escribir_pom "$B" "$DEPS_LOG4J"
D=$(src "$B")
cat > "$D/App.java" <<'JAVA'
package eus.ehu.tfg;

// Caso B: se llega a Logger.error en cuatro saltos y cuatro ficheros. Alcanzable.
public class App {
    public static void main(String[] args) {
        String entrada = args.length > 0 ? args[0] : "anonimo";
        new Controlador().atender(entrada);
    }
}
JAVA
cat > "$D/Controlador.java" <<'JAVA'
package eus.ehu.tfg;

public class Controlador {
    private final Servicio servicio = new Servicio();

    public void atender(String peticion) {
        servicio.procesar(peticion);
    }
}
JAVA
cat > "$D/Servicio.java" <<'JAVA'
package eus.ehu.tfg;

public class Servicio {
    private final Auditor auditor = new Auditor();

    public void procesar(String datos) {
        auditor.registrar(datos);
    }
}
JAVA
cat > "$D/Auditor.java" <<'JAVA'
package eus.ehu.tfg;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Auditor {
    private static final Logger LOG = LogManager.getLogger(Auditor.class);

    public void registrar(String datosUsuario) {
        LOG.error("peticion recibida de " + datosUsuario);
    }
}
JAVA

C=log4j-deadcode
escribir_pom "$C" "$DEPS_LOG4J"
D=$(src "$C")
cat > "$D/App.java" <<'JAVA'
package eus.ehu.tfg;

// Caso C: la llamada a log4j esta en AuditorObsoleto, que main nunca usa. No alcanzable.
public class App {
    public static void main(String[] args) {
        System.out.println("ok: " + args.length);
    }
}
JAVA
cat > "$D/AuditorObsoleto.java" <<'JAVA'
package eus.ehu.tfg;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuditorObsoleto {
    private static final Logger LOG = LogManager.getLogger(AuditorObsoleto.class);

    public void registrarAntiguo(String datosUsuario) {
        LOG.error("formato antiguo: " + datosUsuario);
    }
}
JAVA

Dd=snakeyaml-dump-only
escribir_pom "$Dd" "$DEPS_SNAKEYAML"
D=$(src "$Dd")
cat > "$D/App.java" <<'JAVA'
package eus.ehu.tfg;

import java.util.LinkedHashMap;
import java.util.Map;
import org.yaml.snakeyaml.Yaml;

// Caso D: se usa snakeyaml pero solo dump(); la vulnerabilidad esta en load(). No alcanzable.
public class App {
    public static void main(String[] args) {
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("servicio", "tfg");
        config.put("puerto", 8080);
        System.out.println(new Yaml().dump(config));
    }
}
JAVA

E=snakeyaml-load
escribir_pom "$E" "$DEPS_SNAKEYAML"
D=$(src "$E")
cat > "$D/App.java" <<'JAVA'
package eus.ehu.tfg;

import org.yaml.snakeyaml.Yaml;

// Caso E: Yaml.load sobre una entrada externa. Alcanzable.
public class App {
    public static void main(String[] args) {
        String yaml = args.length > 0 ? args[0] : "clave: valor";
        Object cargado = new Yaml().load(yaml);
        System.out.println("cargado: " + cargado);
    }
}
JAVA

cat > ground_truth_alcanzabilidad.yaml <<'YAML'
# Verdad de referencia de alcanzabilidad de los cinco casos del banco.

casos:
  - id: A
    proyecto: log4j-unreachable
    dependencia: org.apache.logging.log4j:log4j-core:2.14.1
    vulnerabilidad: CVE-2021-44228
    simbolo_vulnerable: "org.apache.logging.log4j.Logger.error / JndiLookup.lookup"
    biblioteca_invocada: false
    api_vulnerable_invocada: false
    alcanzable_desde_main: false
    proposito: >
      Dependencia declarada que el codigo nunca toca. Las cinco herramientas SCA
      la reportan; la alcanzabilidad debe descartarla.

  - id: B
    proyecto: log4j-reachable
    dependencia: org.apache.logging.log4j:log4j-core:2.14.1
    vulnerabilidad: CVE-2021-44228
    simbolo_vulnerable: "org.apache.logging.log4j.Logger.error"
    biblioteca_invocada: true
    api_vulnerable_invocada: true
    alcanzable_desde_main: true
    saltos_esperados: 4
    cadena: "App.main -> Controlador.atender -> Servicio.procesar -> Auditor.registrar -> Logger.error"
    proposito: >
      Control positivo interprocedural. Un analisis intra-fichero falla aqui.

  - id: C
    proyecto: log4j-deadcode
    dependencia: org.apache.logging.log4j:log4j-core:2.14.1
    vulnerabilidad: CVE-2021-44228
    simbolo_vulnerable: "org.apache.logging.log4j.Logger.error"
    biblioteca_invocada: true
    api_vulnerable_invocada: true
    alcanzable_desde_main: false
    proposito: >
      Codigo muerto. Caso discriminante entre busqueda textual y grafo de
      llamadas: grep da falso positivo, el grafo responde bien.

  - id: D
    proyecto: snakeyaml-dump-only
    dependencia: org.yaml:snakeyaml:1.33
    vulnerabilidad: CVE-2022-1471
    simbolo_vulnerable: "org.yaml.snakeyaml.Yaml.load"
    biblioteca_invocada: true
    api_vulnerable_invocada: false
    alcanzable_desde_main: false
    proposito: >
      La biblioteca se usa, pero solo por su API segura. Separa alcanzabilidad
      de artefacto de alcanzabilidad de simbolo.

  - id: E
    proyecto: snakeyaml-load
    dependencia: org.yaml:snakeyaml:1.33
    vulnerabilidad: CVE-2022-1471
    simbolo_vulnerable: "org.yaml.snakeyaml.Yaml.load"
    biblioteca_invocada: true
    api_vulnerable_invocada: true
    alcanzable_desde_main: true
    proposito: Control positivo directo.
YAML

echo "Banco creado en $DEST"
ls -1
