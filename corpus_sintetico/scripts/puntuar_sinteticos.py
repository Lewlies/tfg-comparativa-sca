#!/usr/bin/env python3
# Puntua cada herramienta contra los ground_truth.yaml. Uso: python3 puntuar_sinteticos.py --gt corpus_sintetico --corpus ~/corpus-sintetico

import argparse
import csv
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("Falta PyYAML. Instalalo con:  pip install pyyaml")

ECOS = ["npm", "pypi", "maven"]
DIMS = ["mixed", "boundary-vulnerable", "boundary-patched", "control"]

# ruido documentado en el ground truth, no puntua
CLAVES_RUIDO = (
    "hallazgos_adicionales_reales_no_disenados",
    "hallazgos_compartidos_con_el_par_parcheado",
    "hallazgos_compartidos_con_el_par_vulnerable",
    "hallazgos_compartidos",
    "hallazgos_propios_del_paquete",
)

ESPERA_DETECCION = ("DETECTAR", "DETECTAR_VIA_CANONICA")


def norm_id(valor):
    if not valor:
        return None
    v = str(valor).strip().upper()
    if not v or v in ("(SIN CVE)", "SIN CVE", "NONE", "NULL"):
        return None
    return v


# se compara solo el artifactId
def norm_pkg(valor):
    if not valor:
        return None
    v = str(valor).strip().lower()
    for sep in (":", "/"):
        if sep in v:
            v = v.split(sep)[-1]
    return v or None


def norm_ver(valor):
    if not valor:
        return None
    return str(valor).strip().lower().lstrip("v") or None


def purl_a_pkg_ver(purl):
    if not purl or not str(purl).startswith("pkg:"):
        return None, None
    cuerpo = str(purl)[4:].split("?")[0]
    nombre, _, version = cuerpo.partition("@")
    return norm_pkg(nombre), norm_ver(version)

PISTAS_NOMBRE = [
    ("dependabot", "dependabot"),
    ("osv-scanner", "osv-scanner"),
    ("osv", "osv-scanner"),
    ("trivy", "trivy"),
    ("grype", "grype"),
    ("dependency-check", "dependency-check"),
    ("depcheck", "dependency-check"),
    ("syft", "sbom-syft"),
    ("sbom", "sbom-syft"),
]


def detectar_por_nombre(nombre):
    n = nombre.lower()
    for fragmento, herramienta in PISTAS_NOMBRE:
        if fragmento in n:
            return herramienta
    return None


def detectar_herramienta(datos):
    if isinstance(datos, list):
        if datos and isinstance(datos[0], dict) and "security_advisory" in datos[0]:
            return "dependabot"
        return None
    if not isinstance(datos, dict):
        return None

    if "spdxVersion" in datos or datos.get("bomFormat") == "CycloneDX":
        return "sbom-syft"

    if "Results" in datos and ("SchemaVersion" in datos or "ArtifactName" in datos):
        return "trivy"
    if "matches" in datos:
        return "grype"
    if "results" in datos and isinstance(datos.get("results"), list):
        return "osv-scanner"
    if "dependencies" in datos and ("scanInfo" in datos or "projectInfo" in datos):
        return "dependency-check"
    return None


def extraer_trivy(datos):
    for res in datos.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            ids = [v.get("VulnerabilityID")]
            for extra in (v.get("VendorIDs") or []):
                ids.append(extra)
            yield ids, v.get("PkgName"), v.get("InstalledVersion")


def extraer_grype(datos):
    for m in datos.get("matches") or []:
        vuln = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        ids = [vuln.get("id")]
        for rel in (m.get("relatedVulnerabilities") or []):
            ids.append(rel.get("id"))
        yield ids, art.get("name"), art.get("version")


def extraer_osv(datos):
    for res in datos.get("results") or []:
        for paq in res.get("packages") or []:
            info = paq.get("package") or {}
            nombre, version = info.get("name"), info.get("version")
            for v in paq.get("vulnerabilities") or []:
                ids = [v.get("id")] + list(v.get("aliases") or [])
                yield ids, nombre, version


def extraer_dc(datos):
    for dep in datos.get("dependencies") or []:
        nombre = version = None
        for paq in dep.get("packages") or []:
            nombre, version = purl_a_pkg_ver(paq.get("id"))
            if nombre:
                break
        if not nombre:
            for ident in dep.get("identifiers") or []:
                nombre, version = purl_a_pkg_ver(ident.get("id"))
                if nombre:
                    break
        if not nombre:
            nombre = dep.get("fileName")
        for v in dep.get("vulnerabilities") or []:
            ids = [v.get("name")]
            for extra in (v.get("vulnerabilityIds") or []):
                ids.append(extra.get("id") if isinstance(extra, dict) else extra)
            yield ids, nombre, version


def extraer_dependabot(datos):
    for alerta in datos or []:
        if alerta.get("state") == "dismissed":
            continue
        adv = alerta.get("security_advisory") or {}
        ids = [adv.get("cve_id"), adv.get("ghsa_id")]
        for ident in (adv.get("identifiers") or []):
            ids.append(ident.get("value"))
        dep = ((alerta.get("dependency") or {}).get("package") or {})
        yield ids, dep.get("name"), None

EXTRACTORES = {
    "trivy": extraer_trivy,
    "grype": extraer_grype,
    "osv-scanner": extraer_osv,
    "dependency-check": extraer_dc,
    "dependabot": extraer_dependabot,
}

HERRAMIENTAS_ESPERADAS = ["trivy", "grype", "osv-scanner", "dependency-check", "dependabot"]


def leer_resultados(dir_resultados):
    salida, diagnostico = {}, []
    if not dir_resultados.is_dir():
        return salida, diagnostico

    for ruta in sorted(dir_resultados.rglob("*.json")):
        tam = ruta.stat().st_size
        por_nombre = detectar_por_nombre(ruta.name)

        if tam == 0:
            diagnostico.append({"fichero": ruta.name, "bytes": 0,
                                "detectado": por_nombre or "?", "estado": "VACIO",
                                "hallazgos": ""})
            continue
        try:
            with open(ruta, encoding="utf-8", errors="replace") as f:
                datos = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            diagnostico.append({"fichero": ruta.name, "bytes": tam,
                                "detectado": por_nombre or "?",
                                "estado": f"ILEGIBLE ({type(e).__name__})", "hallazgos": ""})
            continue

        herramienta = detectar_herramienta(datos) or por_nombre
        if not herramienta:
            diagnostico.append({"fichero": ruta.name, "bytes": tam, "detectado": "?",
                                "estado": "NO_RECONOCIDO", "hallazgos": ""})
            continue
        if herramienta == "sbom-syft":
            diagnostico.append({"fichero": ruta.name, "bytes": tam, "detectado": "syft",
                                "estado": "SBOM (no aporta vulnerabilidades)", "hallazgos": ""})
            continue

        hallazgos = []
        for ids, pkg, ver in EXTRACTORES[herramienta](datos):
            limpios = {i for i in (norm_id(x) for x in ids) if i}
            if limpios:
                hallazgos.append({"ids": limpios, "pkg": norm_pkg(pkg), "ver": norm_ver(ver)})

        diagnostico.append({"fichero": ruta.name, "bytes": tam, "detectado": herramienta,
                            "estado": "ok", "hallazgos": len(hallazgos)})
        if herramienta not in salida or len(hallazgos) > len(salida[herramienta]):
            salida[herramienta] = hallazgos

    return salida, diagnostico


def ids_de(entrada):
    ids = set()
    for clave in ("id_vuln_canonico", "id_vuln_referencia", "id_vuln_referenciado", "advisory_retirada"):
        i = norm_id(entrada.get(clave))
        if i:
            ids.add(i)
    for clave in ("aliases", "aliases_advisory_canonica"):
        for a in entrada.get(clave) or []:
            i = norm_id(a)
            if i:
                ids.add(i)
    return ids


def recolectar_ruido(nodo, acumulador):
    if isinstance(nodo, dict):
        for clave, valor in nodo.items():
            if clave in CLAVES_RUIDO and isinstance(valor, list):
                for entrada in valor:
                    if isinstance(entrada, dict):
                        acumulador |= ids_de(entrada)
            else:
                recolectar_ruido(valor, acumulador)
    elif isinstance(nodo, list):
        for item in nodo:
            recolectar_ruido(item, acumulador)


def cargar_gt(ruta):
    with open(ruta, encoding="utf-8") as f:
        gt = yaml.safe_load(f)

    esperados, retiradas = [], {}
    for h in gt.get("hallazgos_esperados") or []:
        esperado = (h.get("resultado_esperado") or "").strip().upper()
        ids = ids_de(h)
        id_retirada = norm_id(h.get("advisory_retirada"))
        if id_retirada:
            retiradas[id_retirada] = h.get("id_finding") or h.get("paquete") or "?"
            ids.discard(id_retirada)
        if esperado in ESPERA_DETECCION and ids:
            esperados.append({
                "id_finding": h.get("id_finding") or "?",
                "dimension": h.get("dimension") or "?",
                "paquete": norm_pkg(h.get("paquete")),
                "version": norm_ver(h.get("version")),
                "objetivo": bool(h.get("hallazgo_objetivo")),
                "ids": ids,
            })

    ruido = set()
    recolectar_ruido(gt, ruido)
    for e in esperados:
        ruido -= e["ids"]

    fp_diseno = set()
    global_esperado = (gt.get("resultado_esperado_global") or "").strip().upper()
    pbp = gt.get("paquete_bajo_prueba") or {}
    if pbp:
        fp_diseno |= ids_de(pbp)
    es_control = global_esperado.startswith("CERO_HALLAZGOS") and not pbp

    return {
        "repo": gt.get("repo") or ruta.parent.name,
        "esperados": esperados,
        "ruido": ruido,
        "fp_diseno": fp_diseno,
        "retiradas": retiradas,
        "es_control": es_control,
    }


def coincide(hallazgo, esperado, ambiguo):
    if not (hallazgo["ids"] & esperado["ids"]):
        return False
    if esperado["paquete"] and hallazgo["pkg"] and hallazgo["pkg"] != esperado["paquete"]:
        return False
    # la version solo desempata si dos esperados comparten ID
    if ambiguo and esperado["version"] and hallazgo["ver"]:
        return hallazgo["ver"] == esperado["version"]
    return True


def puntuar(gt, hallazgos_herramienta):
    detalle, extras = [], []

    conteo_ids = defaultdict(int)
    for e in gt["esperados"]:
        for i in e["ids"]:
            conteo_ids[i] += 1

    consumidos = set()
    for e in gt["esperados"]:
        ambiguo = any(conteo_ids[i] > 1 for i in e["ids"])
        encontrado = None
        for idx, h in enumerate(hallazgos_herramienta):
            if coincide(h, e, ambiguo):
                encontrado = h
                consumidos.add(idx)
                break
        detalle.append({
            "id_finding": e["id_finding"],
            "dimension": e["dimension"],
            "objetivo": "si" if e["objetivo"] else "no",
            "paquete": e["paquete"] or "",
            "version": e["version"] or "",
            "ids_aceptados": "|".join(sorted(e["ids"])),
            "veredicto": "TP" if encontrado else "FN",
            "id_reportado": "|".join(sorted(encontrado["ids"] & e["ids"])) if encontrado else "",
            "version_reportada": (encontrado or {}).get("ver") or "",
        })

    for idx, h in enumerate(hallazgos_herramienta):
        if idx in consumidos:
            continue
        ids = h["ids"]
        if ids & set(gt["retiradas"]):
            clase = "RETIRADA"
        elif gt["es_control"] or (ids & gt["fp_diseno"]):
            clase = "FP_CONFIRMADO"
        elif ids & gt["ruido"]:
            clase = "NO_PUNTUA"
        else:
            # se revisa a mano, no cuenta como FP
            clase = "CANDIDATO_FP"
        extras.append({
            "ids": "|".join(sorted(ids)),
            "paquete": h["pkg"] or "",
            "version": h["ver"] or "",
            "clasificacion": clase,
        })

    return detalle, extras


def main():
    ap = argparse.ArgumentParser(description="Puntuacion del corpus sintetico contra la verdad de referencia")
    ap.add_argument("--gt", required=True,
                    help="Carpeta que contiene npm/ pypi/ maven/ con los ground_truth.yaml")
    ap.add_argument("--corpus", required=True,
                    help="Raiz del corpus sintetico escaneado (~/corpus-sintetico)")
    ap.add_argument("--salida", default=None, help="Carpeta de salida (por defecto <corpus>/puntuacion)")
    ap.add_argument("--diagnostico", action="store_true",
                    help="Lista cada JSON encontrado, su tamano y como se ha interpretado")
    args = ap.parse_args()

    dir_gt = Path(os.path.expanduser(args.gt))
    dir_corpus = Path(os.path.expanduser(args.corpus))
    dir_salida = Path(os.path.expanduser(args.salida)) if args.salida else dir_corpus / "puntuacion"
    dir_salida.mkdir(parents=True, exist_ok=True)

    filas_detalle, filas_extras, filas_disputadas, filas_cobertura = [], [], [], []
    resumen = defaultdict(lambda: defaultdict(int))
    repos_sin_resultados = []
    incidencias = []

    for dim in DIMS:
        for eco in ECOS:
            repo = f"synthetic-{eco}-{dim}"
            ruta_gt = dir_gt / eco / dim / "ground_truth.yaml"
            if not ruta_gt.is_file():
                print(f"[SALTADO] no encuentro {ruta_gt}")
                continue
            gt = cargar_gt(ruta_gt)

            dir_res = dir_corpus / dim / eco / "results" / repo
            print(f"[{repo}]")
            resultados, diagnostico = leer_resultados(dir_res)

            if args.diagnostico:
                for d in diagnostico:
                    print(f"    . {d['fichero']:<42}{d['bytes']:>9} B  "
                          f"{d['detectado']:<18}{d['estado']}  {d['hallazgos']}")

            for herramienta in HERRAMIENTAS_ESPERADAS:
                incidencia = ""
                if herramienta in resultados:
                    estado = "con datos" if resultados[herramienta] else "corrio, 0 hallazgos"
                else:
                    estado = "SIN DATOS"
                    pistas = [d for d in diagnostico if d["detectado"] == herramienta]
                    if pistas:
                        incidencia = "; ".join(f"{d['fichero']}={d['estado']}" for d in pistas)
                    else:
                        incidencia = "no se ha encontrado ningun fichero de esta herramienta"
                    incidencias.append((repo, herramienta, incidencia))
                filas_cobertura.append({
                    "repo": repo, "ecosistema": eco, "dimension_repo": dim,
                    "herramienta": herramienta, "estado": estado,
                    "n_hallazgos": len(resultados.get(herramienta, [])) if herramienta in resultados else "",
                    "incidencia": incidencia,
                })

            if not resultados:
                print("    sin resultados de ninguna herramienta")
                repos_sin_resultados.append(repo)
                continue

            for herramienta in sorted(resultados):
                hallazgos = resultados[herramienta]
                detalle, extras = puntuar(gt, hallazgos)

                for d in detalle:
                    filas_detalle.append({"repo": repo, "ecosistema": eco, "dimension_repo": dim,
                                          "herramienta": herramienta, **d})
                    resumen[(herramienta, eco)][d["veredicto"]] += 1
                for x in extras:
                    filas_extras.append({"repo": repo, "ecosistema": eco, "dimension_repo": dim,
                                         "herramienta": herramienta, **x})
                    resumen[(herramienta, eco)][x["clasificacion"]] += 1

                if gt["retiradas"]:
                    todos = set().union(*(h["ids"] for h in hallazgos)) if hallazgos else set()
                    for id_ret, quien in gt["retiradas"].items():
                        canonicos = set()
                        for e in gt["esperados"]:
                            if e["id_finding"] == quien:
                                canonicos = e["ids"]
                        usa_ret = id_ret in todos
                        usa_can = bool(canonicos & todos)
                        if usa_ret and usa_can:
                            veredicto = "DUPLICA_AMBOS"
                        elif usa_can:
                            veredicto = "SOLO_CANONICO_correcto"
                        elif usa_ret:
                            veredicto = "SOLO_RETIRADO_bbdd_desactualizada"
                        else:
                            veredicto = "NO_REPORTA_NINGUNO"
                        filas_disputadas.append({
                            "repo": repo, "ecosistema": eco, "herramienta": herramienta,
                            "hallazgo": quien, "id_retirado": id_ret,
                            "ids_canonicos": "|".join(sorted(canonicos)) or "(sin canonico de reemplazo)",
                            "veredicto": veredicto,
                        })

                tp = sum(1 for d in detalle if d["veredicto"] == "TP")
                fn = sum(1 for d in detalle if d["veredicto"] == "FN")
                fp = sum(1 for x in extras if x["clasificacion"] == "FP_CONFIRMADO")
                cand = sum(1 for x in extras if x["clasificacion"] == "CANDIDATO_FP")
                print(f"    {herramienta:<18} TP={tp} FN={fn} FP={fp} candidatos_FP={cand}")
            print()

    def escribir(nombre, filas, campos):
        ruta = dir_salida / nombre
        with open(ruta, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=campos)
            w.writeheader()
            w.writerows(filas)
        print(f"  {ruta}  ({len(filas)} filas)")

    filas_resumen = []
    for (herramienta, eco), c in sorted(resumen.items()):
        tp, fn, fp = c["TP"], c["FN"], c["FP_CONFIRMADO"]
        filas_resumen.append({
            "herramienta": herramienta, "ecosistema": eco,
            "TP": tp, "FN": fn, "FP_CONFIRMADO": fp,
            "CANDIDATO_FP": c["CANDIDATO_FP"], "NO_PUNTUA": c["NO_PUNTUA"],
            "RETIRADA": c["RETIRADA"],
            "recall": round(tp / (tp + fn), 3) if (tp + fn) else "",
            "precision_estricta": round(tp / (tp + fp), 3) if (tp + fp) else "",
        })

    print("=== Ficheros generados ===")
    escribir("puntuacion_resumen.csv", filas_resumen,
             ["herramienta", "ecosistema", "TP", "FN", "FP_CONFIRMADO", "CANDIDATO_FP",
              "NO_PUNTUA", "RETIRADA", "recall", "precision_estricta"])
    escribir("puntuacion_detalle.csv", filas_detalle,
             ["repo", "ecosistema", "dimension_repo", "herramienta", "id_finding", "dimension",
              "objetivo", "paquete", "version", "ids_aceptados", "veredicto", "id_reportado",
              "version_reportada"])
    escribir("puntuacion_extras.csv", filas_extras,
             ["repo", "ecosistema", "dimension_repo", "herramienta", "ids", "paquete",
              "version", "clasificacion"])
    escribir("disputadas_ids_crudos.csv", filas_disputadas,
             ["repo", "ecosistema", "herramienta", "hallazgo", "id_retirado", "ids_canonicos",
              "veredicto"])
    escribir("cobertura_herramientas.csv", filas_cobertura,
             ["repo", "ecosistema", "dimension_repo", "herramienta", "estado", "n_hallazgos",
              "incidencia"])

    print()
    print("=== Resumen ===")
    ancho = f"{'herramienta':<18}{'eco':<8}{'TP':>4}{'FN':>4}{'FP':>4}{'cand':>6}{'recall':>8}"
    print(ancho)
    for f in filas_resumen:
        print(f"{f['herramienta']:<18}{f['ecosistema']:<8}{f['TP']:>4}{f['FN']:>4}"
              f"{f['FP_CONFIRMADO']:>4}{f['CANDIDATO_FP']:>6}{str(f['recall']):>8}")

    if incidencias:
        faltan = defaultdict(list)
        for repo, herramienta, motivo in incidencias:
            faltan[herramienta].append((repo, motivo))
        print()
        print("Herramientas sin datos en algun repo:")
        for herramienta in sorted(faltan):
            repos = faltan[herramienta]
            print(f"  {herramienta}: sin datos en {len(repos)}/12 repos")
            motivos = {m for _, m in repos}
            for m in sorted(motivos):
                print(f"      motivo: {m}")
        print("  Detalle completo en cobertura_herramientas.csv")

    pendientes = [f for f in filas_extras if f["clasificacion"] == "CANDIDATO_FP"]
    print()
    if pendientes:
        print(f"{len(pendientes)} candidatos a falso positivo pendientes de revision manual "
              "(puntuacion_extras.csv)")
    else:
        print("Sin candidatos a falso positivo pendientes de revision.")
    if repos_sin_resultados:
        print()
        print("Repos sin resultados de ninguna herramienta: " + ", ".join(repos_sin_resultados))

if __name__ == "__main__":
    main()
