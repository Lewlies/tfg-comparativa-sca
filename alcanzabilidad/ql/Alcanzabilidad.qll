import java
import MapaGenerado

// Mapa manual CVE -> metodo de la API publica que lleva al codigo vulnerable
predicate simboloVulnerable(string cve, string tipo, string metodo, string nota) {
  cve = "CVE-2021-44228" and
  tipo = "org.apache.logging.log4j.Logger" and
  metodo = ["error", "warn", "info", "debug", "trace", "fatal", "log", "printf"] and
  nota = "advisory GHSA-jfh8-c2jp-5v3q; sink interno JndiLookup.lookup, frontera de la aplicacion Logger.*"
  or
  cve = "CVE-2022-1471" and
  tipo = "org.yaml.snakeyaml.Yaml" and
  metodo = ["load", "loadAll", "loadAs"] and
  nota = "advisory GHSA-mjmj-j48q-9wg2; dump y loadAs con SafeConstructor no son via de explotacion"
  or
  cve = "CVE-2017-18640" and
  tipo = "org.yaml.snakeyaml.Yaml" and
  metodo = ["load", "loadAll"] and
  nota = "advisory GHSA-c4r9-r8fh-9vj2; misma frontera que CVE-2022-1471"
  or
  cve = "CVE-2022-42889" and
  tipo = "org.apache.commons.text.StringSubstitutor" and
  metodo = ["replace", "replaceIn", "createInterpolator"] and
  nota = "advisory GHSA-599f-7c49-w659; solo el interpolador por defecto es via de explotacion"
  or
  cve = ["CVE-2019-12384", "CVE-2019-14379", "CVE-2020-36518", "CVE-2020-9548"] and
  tipo = ["com.fasterxml.jackson.databind.ObjectMapper", "com.fasterxml.jackson.databind.ObjectReader"] and
  metodo = ["readValue", "readValues", "readTree", "convertValue", "treeToValue", "enableDefaultTyping", "activateDefaultTyping"] and
  nota = "verificado a mano. La explotacion exige tipado por defecto activo Y entrada no confiable; comprobar enableDefaultTyping aparte"
  or
  simboloGenerado(cve, tipo, metodo, nota)
}

// CVE que se explotan sin llamada de la aplicacion
predicate cveSinSimboloDeAplicacion(string cve, string componente, string motivo) {
  cve = "CVE-2020-1938" and
  componente = "Apache Tomcat, conector AJP" and
  motivo = "Ghostcat. Se explota hablando AJP con el conector del servidor. El codigo de la aplicacion no interviene."
  or
  cve = "CVE-2023-44487" and
  componente = "pila HTTP/2 del servidor" and
  motivo = "Rapid Reset. Agotamiento de recursos en el manejo de tramas del protocolo, por debajo de la aplicacion."
  or
  cve = "CVE-2025-24813" and
  componente = "Apache Tomcat, servlet por defecto" and
  motivo = "PUT parcial y deserializacion de sesion. Depende de la configuracion del contenedor, no de llamadas de la aplicacion."
  or
  cve = "CVE-2022-22965" and
  componente = "Spring, enlace de datos" and
  motivo = "Spring4Shell. La via es el enlace de datos del framework sobre un objeto de comando de un controlador, no una llamada explicita. Alcanzable en la practica si hay controladores Spring con objeto de comando, lo cual se aproxima con puntoEntradaWeb, pero no es un simbolo invocado."
  or
  cve = "CVE-2021-42392" and
  componente = "consola web de H2" and
  motivo = "Se explota por una consola expuesta, cuestion de configuracion de despliegue."
  or
  cve = "CVE-2015-6420" and
  componente = "commons-collections, cadena de gadgets" and
  motivo = "No hay simbolo que la aplicacion invoque. El gadget se activa al deserializar datos no confiables en cualquier punto, que es el sitio que hay que buscar, no la biblioteca."
  or
  cve = "CVE-2021-44832" and
  componente = "log4j, appender JDBC" and
  motivo = "Exige control sobre el fichero de configuracion de log4j. Es una via de configuracion, no de llamada."
  or
  sinSimboloGenerado(cve, componente, motivo)
}

string nivelMapa(string cve) {
  cveEnMapa(cve) and
  if simboloGenerado(cve, _, _, _) or sinSimboloGenerado(cve, _, _)
  then result = "regla"
  else result = "manual"
}

predicate cveEnMapa(string cve) {
  simboloVulnerable(cve, _, _, _) or cveSinSimboloDeAplicacion(cve, _, _)
}

bindingset[tipo]
string nombreSimple(string tipo) { result = tipo.regexpCapture(".*?([^.]+)$", 1) }

predicate tipoImportado(string tipo) {
  simboloVulnerable(_, tipo, _, _) and
  (
    exists(ImportType i | i.getImportedType().getQualifiedName() = tipo)
    or
    exists(ImportOnDemandFromPackage i |
      i.getPackageHoldingImport().getName() = tipo.regexpCapture("(.*)\\.[^.]+$", 1)
    )
  )
}

predicate tipoResueltoEnLlamadas(string tipo) {
  simboloVulnerable(_, tipo, _, _) and
  exists(Call c |
    c.getCaller().fromSource() and
    c.getCallee().getDeclaringType().getQualifiedName() = tipo
  )
}

// tipo importado sin metodos en la base de datos
predicate tipoImportadoNoResuelto(string tipo) {
  simboloVulnerable(_, tipo, _, _) and
  (tipoImportado(tipo) or exists(RefType r | r.getQualifiedName() = tipo)) and
  not exists(Method m | m.getDeclaringType().getQualifiedName() = tipo)
}

predicate cveNoConcluyente(string cve) {
  exists(string tipo | simboloVulnerable(cve, tipo, _, _) and tipoImportadoNoResuelto(tipo))
}

predicate llamadaDirecta(Callable llamante, Callable llamado) {
  exists(Call c | c.getCaller() = llamante and c.getCallee() = llamado)
}

// despacho virtual
predicate llamadaVirtual(Callable llamante, Callable llamado) {
  exists(Method m |
    llamadaDirecta(llamante, m) and
    llamado.(Method).overrides+(m) and
    llamado.fromSource()
  )
}

// inicializadores de la clase
predicate aristaInicializador(Callable llamante, Callable llamado) {
  llamado instanceof InitializerMethod and
  llamado.getDeclaringType() = llamante.getDeclaringType() and
  not llamante instanceof InitializerMethod
}

predicate arista(Callable a, Callable b) {
  llamadaDirecta(a, b) or
  llamadaVirtual(a, b) or
  aristaInicializador(a, b)
}

predicate esMain(Callable c) {
  c.(Method).hasName("main") and
  c.(Method).isStatic() and
  c.getNumberOfParameters() = 1
}

predicate puntoEntradaWeb(Callable c) {
  exists(Annotation a |
    a = c.getAnAnnotation() and
    a.getType().getQualifiedName() =
      [
        "org.springframework.web.bind.annotation.RequestMapping",
        "org.springframework.web.bind.annotation.GetMapping",
        "org.springframework.web.bind.annotation.PostMapping",
        "org.springframework.web.bind.annotation.PutMapping",
        "org.springframework.web.bind.annotation.DeleteMapping",
        "org.springframework.web.bind.annotation.PatchMapping",
        "jakarta.ws.rs.GET", "jakarta.ws.rs.POST", "jakarta.ws.rs.PUT",
        "jakarta.ws.rs.DELETE", "jakarta.ws.rs.Path",
        "javax.ws.rs.GET", "javax.ws.rs.POST", "javax.ws.rs.PUT",
        "javax.ws.rs.DELETE", "javax.ws.rs.Path"
      ]
  )
  or
  exists(Method m | m = c |
    m.getDeclaringType().getASupertype*().hasQualifiedName("javax.servlet.http", "HttpServlet") and
    m.hasName(["doGet", "doPost", "doPut", "doDelete", "service"])
  )
}

predicate esTest(Callable c) {
  exists(Annotation a |
    a = c.getAnAnnotation() and
    a.getType().getQualifiedName().matches("%junit%Test%")
  )
  or
  c.getCompilationUnit().getRelativePath().matches("%src/test/%")
  or
  c.getDeclaringType().getName().matches(["%Test", "Test%", "%Tests", "%TestCase"])
}

// estricto: main y manejadores web; laxo: cualquier metodo publico
predicate puntoEntradaEstricto(Callable c) {
  c.fromSource() and
  not esTest(c) and
  (esMain(c) or puntoEntradaWeb(c))
}

predicate puntoEntradaLaxo(Callable c) {
  c.fromSource() and
  not esTest(c) and
  c.isPublic() and
  c.getDeclaringType().isPublic()
}

predicate simboloDeLlamada(Call c, string cve, string nota) {
  exists(string tipo, string metodo |
    simboloVulnerable(cve, tipo, metodo, nota) and
    c.getCallee().getDeclaringType().getQualifiedName() = tipo and
    c.getCallee().getName() = metodo
  )
}

class InvocacionVulnerable extends Call {
  InvocacionVulnerable() {
    simboloDeLlamada(this, _, _) and
    this.getCaller().fromSource() and
    not esTest(this.getCaller())
  }

  string getCve() { simboloDeLlamada(this, result, _) }

  string getNota(string cve) { simboloDeLlamada(this, cve, result) }

  string getSimbolo() {
    result = this.getCallee().getDeclaringType().getQualifiedName() + "." +
             this.getCallee().getName()
  }
}

predicate alcanzableEstricto(Callable origen, Callable destino) {
  puntoEntradaEstricto(origen) and arista*(origen, destino)
}

predicate alcanzableLaxo(Callable origen, Callable destino) {
  puntoEntradaLaxo(origen) and arista*(origen, destino)
}

// maximo 12 saltos
predicate alcanzaEn(Callable origen, Callable destino, int n) {
  n = 0 and origen = destino and (origen.fromSource() or destino.fromSource())
  or
  n in [1 .. 12] and
  exists(Callable medio | arista(origen, medio) and alcanzaEn(medio, destino, n - 1))
}

int saltosMinimos(Callable origen, Callable destino) {
  result = min(int n | alcanzaEn(origen, destino, n))
}
