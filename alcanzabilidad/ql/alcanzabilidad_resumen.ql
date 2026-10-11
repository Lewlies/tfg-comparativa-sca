// Veredicto de alcanzabilidad por CVE
import java
import Alcanzabilidad

predicate bibliotecaReferenciada(string cve) {
  exists(RefType t, string tipo |
    simboloVulnerable(cve, tipo, _, _) and
    t.getQualifiedName() = tipo and
    exists(Call c | c.getCallee().getDeclaringType() = t and c.getCaller().fromSource())
  )
}

predicate invocacionPresente(string cve) { exists(InvocacionVulnerable i | i.getCve() = cve) }

predicate alcanzableEstrictoCve(string cve) {
  exists(InvocacionVulnerable i, Callable e |
    i.getCve() = cve and alcanzableEstricto(e, i.getCaller())
  )
}

predicate alcanzableLaxoCve(string cve) {
  exists(InvocacionVulnerable i, Callable e | i.getCve() = cve and alcanzableLaxo(e, i.getCaller()))
}

string bibliotecaUsadaTexto(string cve) {
  cveEnMapa(cve) and
  if bibliotecaReferenciada(cve) then result = "si" else result = "no"
}

from string cve, string veredicto
where
  cveEnMapa(cve) and
  (
    cveSinSimboloDeAplicacion(cve, _, _) and
    veredicto = "SIN-SIMBOLO-DE-APLICACION"
    or
    not cveSinSimboloDeAplicacion(cve, _, _) and
    (
    cveNoConcluyente(cve) and
    veredicto = "NO-CONCLUYENTE-BD-INCOMPLETA"
    or
    not cveNoConcluyente(cve) and
    (
      alcanzableEstrictoCve(cve) and veredicto = "ALCANZABLE-ESTRICTO"
      or
      not alcanzableEstrictoCve(cve) and
      alcanzableLaxoCve(cve) and
      veredicto = "ALCANZABLE-SOLO-LAXO"
      or
      not alcanzableLaxoCve(cve) and
      invocacionPresente(cve) and
      veredicto = "INVOCADO-PERO-NO-ALCANZABLE"
      or
      not invocacionPresente(cve) and
      bibliotecaReferenciada(cve) and
      veredicto = "BIBLIOTECA-USADA-API-VULNERABLE-NO"
      or
      not bibliotecaReferenciada(cve) and veredicto = "BIBLIOTECA-NO-USADA"
    )
    )
  )
select cve,
  bibliotecaUsadaTexto(cve) as biblioteca_usada,
  count(InvocacionVulnerable i | i.getCve() = cve) as invocaciones,
  veredicto, nivelMapa(cve) as nivel_mapa
