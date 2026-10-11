// Invocaciones vulnerables con su veredicto
import java
import Alcanzabilidad

string veredicto(Call inv) {
  if exists(Callable e | alcanzableEstricto(e, inv.getCaller()))
  then result = "ALCANZABLE-ESTRICTO"
  else
    if exists(Callable e | alcanzableLaxo(e, inv.getCaller()))
    then result = "ALCANZABLE-SOLO-LAXO"
    else result = "NO-ALCANZABLE"
}

from InvocacionVulnerable inv, string cve
where cve = inv.getCve()
select cve,
  inv.getSimbolo() as simbolo,
  inv.getCaller().getDeclaringType().getQualifiedName() + "." + inv.getCaller().getName() as
    invocado_desde,
  inv.getLocation().getFile().getRelativePath() + ":" + inv.getLocation().getStartLine() as ubicacion,
  veredicto(inv) as veredicto,
  inv.getNota(cve) as procedencia_del_simbolo
