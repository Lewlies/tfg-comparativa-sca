// Comprueba si la base de datos sirve para el analisis
import java
import Alcanzabilidad

int callablesEnFuente() { result = count(Callable c | c.fromSource()) }

int llamadasTotales() { result = count(Call c | c.getCaller().fromSource()) }

int llamadasAExterno() {
  result = count(Call c | c.getCaller().fromSource() and not c.getCallee().fromSource())
}

int tiposExternosDistintos() {
  result =
    count(RefType t |
      not t.fromSource() and
      exists(Call c | c.getCaller().fromSource() and c.getCallee().getDeclaringType() = t)
    )
}

int tiposVulnerablesResueltos() {
  result =
    count(string tipo |
      simboloVulnerable(_, tipo, _, _) and
      exists(RefType t | t.getQualifiedName() = tipo)
    )
}

int tiposImportadosNoResueltos() { result = count(string t | tipoImportadoNoResuelto(t)) }

string listaTiposSinResolver() {
  result = concat(string t | tipoImportadoNoResuelto(t) | t, " ")
}

string veredicto() {
  if callablesEnFuente() = 0
  then result = "NO-APTA: la base de datos no contiene codigo fuente"
  else
    if llamadasAExterno() = 0
    then
      result =
        "NO-APTA: ninguna llamada resuelve a codigo externo. Reconstruir " +
          "compilando el proyecto con sus dependencias."
    else
      if tiposImportadosNoResueltos() > 0
      then
        result =
          "PARCIAL: " + tiposImportadosNoResueltos() +
            " tipo(s) del mapa sin resolver (" + listaTiposSinResolver() +
            "). Los CVE de esos tipos salen NO-CONCLUYENTE; el resto del " +
            "repositorio se analiza con normalidad."
      else result = "APTA"
}

select callablesEnFuente() as callables_en_fuente, llamadasTotales() as llamadas_desde_fuente,
  llamadasAExterno() as llamadas_a_biblioteca, tiposExternosDistintos() as tipos_externos_distintos,
  tiposVulnerablesResueltos() as tipos_del_mapa_resueltos,
  tiposImportadosNoResueltos() as tipos_importados_sin_resolver,
  listaTiposSinResolver() as tipos_sin_resolver, veredicto() as veredicto
