// Generado por generar_mapa.py

predicate simboloGenerado(string cve, string tipo, string metodo, string nota) {
  cve = [
    "CVE-2017-15095", "CVE-2017-17485", "CVE-2017-7525", "CVE-2018-11307",
    "CVE-2018-12022", "CVE-2018-14718", "CVE-2018-14719", "CVE-2018-19360",
    "CVE-2018-19361", "CVE-2018-19362", "CVE-2018-5968", "CVE-2018-7489",
    "CVE-2019-12086", "CVE-2019-12814", "CVE-2019-14439", "CVE-2019-14540",
    "CVE-2019-14892", "CVE-2019-14893", "CVE-2019-16335", "CVE-2019-16942",
    "CVE-2019-16943", "CVE-2019-17267", "CVE-2019-17531", "CVE-2019-20330",
    "CVE-2020-10650", "CVE-2020-10672", "CVE-2020-10673", "CVE-2020-10968",
    "CVE-2020-10969", "CVE-2020-11111", "CVE-2020-11112", "CVE-2020-11113",
    "CVE-2020-11619", "CVE-2020-11620", "CVE-2020-14060", "CVE-2020-14061",
    "CVE-2020-14062", "CVE-2020-14195", "CVE-2020-24616", "CVE-2020-24750",
    "CVE-2020-25649", "CVE-2020-35490", "CVE-2020-35491", "CVE-2020-35728",
    "CVE-2020-36179", "CVE-2020-36180", "CVE-2020-36181", "CVE-2020-36182",
    "CVE-2020-36183", "CVE-2020-36184", "CVE-2020-36185", "CVE-2020-36186",
    "CVE-2020-36187", "CVE-2020-36188", "CVE-2020-36189", "CVE-2020-8840",
    "CVE-2020-9546", "CVE-2020-9547", "CVE-2021-20190", "CVE-2022-42003",
    "CVE-2022-42004", "CVE-2026-54512", "CVE-2026-54513", "CVE-2026-54514",
    "CVE-2026-54515", "CVE-2026-59888"
  ] and
  tipo = ["com.fasterxml.jackson.databind.ObjectMapper", "com.fasterxml.jackson.databind.ObjectReader", "tools.jackson.databind.ObjectMapper", "tools.jackson.databind.ObjectReader"] and
  metodo = ["readValue", "readValues", "readTree", "convertValue", "treeToValue", "enableDefaultTyping", "activateDefaultTyping"] and
  nota = "asignado por regla de paquete (jackson-databind). La familia de gadgets exige tipado por defecto activo y entrada no confiable; la de denegacion de servicio solo entrada no confiable"
}

predicate sinSimboloGenerado(string cve, string componente, string motivo) {
  cve = [
    "CVE-2016-1000027", "CVE-2016-5007", "CVE-2016-9878", "CVE-2018-1257",
    "CVE-2018-1271", "CVE-2018-1272", "CVE-2018-15756", "CVE-2022-22968",
    "CVE-2022-22970", "CVE-2022-27772", "CVE-2023-20883", "CVE-2024-22243",
    "CVE-2024-22259", "CVE-2024-22262", "CVE-2024-38809", "CVE-2024-38819",
    "CVE-2024-38820", "CVE-2025-22233", "CVE-2025-22235", "CVE-2025-41242",
    "CVE-2025-41249", "CVE-2026-22731", "CVE-2026-22733", "CVE-2026-22735",
    "CVE-2026-22737", "CVE-2026-22741", "CVE-2026-22745", "CVE-2026-40973",
    "CVE-2026-40985", "CVE-2026-40986", "CVE-2026-41001", "CVE-2026-41008",
    "CVE-2026-41706", "CVE-2026-41710", "CVE-2026-41726", "CVE-2026-41727",
    "CVE-2026-41731", "CVE-2026-41841", "CVE-2026-41842", "CVE-2026-41843",
    "CVE-2026-41844", "CVE-2026-41845", "CVE-2026-41846", "CVE-2026-41848",
    "CVE-2026-41853", "CVE-2026-41854", "CVE-2026-47838"
  ] and
  componente = "Spring Framework" and
  motivo = "Vulnerabilidad del framework Spring. La dispara el propio framework al atender una peticion, enlazar datos, resolver rutas o cargar configuracion, no una llamada explicita de la aplicacion. Asignado por regla de paquete."
  or
  cve = [
    "CVE-2026-41850", "CVE-2026-41851", "CVE-2026-41852"
  ] and
  componente = "Spring Expression Language" and
  motivo = "Spring Expression Language. Explotable si se evaluan expresiones con entrada no confiable; en la mayoria de aplicaciones las evalua el propio framework (anotaciones, seguridad, rutas), por eso se clasifica sin simbolo de aplicacion, con la salvedad de que una aplicacion que invoque SpelExpressionParser directamente si tendria punto de contacto. Asignado por regla de paquete."
  or
  cve = [
    "CVE-2026-41284", "CVE-2026-41293", "CVE-2026-42498", "CVE-2026-43512",
    "CVE-2026-43513", "CVE-2026-43514", "CVE-2026-43515"
  ] and
  componente = "Apache Tomcat" and
  motivo = "Vulnerabilidad del contenedor de servlets Apache Tomcat. La dispara el servidor al procesar el protocolo, las sesiones o su configuracion, sin intervencion del codigo de la aplicacion. Asignado por regla de paquete."
}
