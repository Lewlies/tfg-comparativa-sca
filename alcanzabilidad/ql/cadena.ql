// Camino mas corto desde un punto de entrada
import java
import Alcanzabilidad

from InvocacionVulnerable inv, Callable entrada, int n
where
  n = min(Callable e | puntoEntradaEstricto(e) | saltosMinimos(e, inv.getCaller())) and
  puntoEntradaEstricto(entrada) and
  saltosMinimos(entrada, inv.getCaller()) = n
select inv.getCve() as cve,
  entrada.getDeclaringType().getQualifiedName() + "." + entrada.getName() as punto_entrada,
  inv.getCaller().getDeclaringType().getQualifiedName() + "." + inv.getCaller().getName() as metodo_invocador,
  n as saltos
