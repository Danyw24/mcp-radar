#!/usr/bin/env python3
"""Mapa de exposición — quién sigue corriendo una versión ya parcheada río arriba.

Por qué esto vale más que cazar parches silenciosos: es **aritmética, no
adivinanza**. El advisory publica el rango afectado y la versión con el fix; el
dependiente escribe su pin en `requirements.txt`. Comparás dos números. No hay
falso positivo posible por construcción: o el pin está abajo del corte o no.

La ventana no dura horas: dura meses, porque nadie actualiza hasta que algo lo
obliga. El fix es público y ellos siguen corriendo la versión rota.

  python3 exposure.py            # calcula y escribe exposure.json
  python3 exposure.py --tabla    # además imprime la tabla

LÍMITE HONESTO: un pin viejo da un CANDIDATO, no una víctima. Puede que no usen
el módulo afectado, que ese archivo sea de un ejemplo, o que el repo esté muerto.
Antes de escribirle a nadie hay que confirmar que ese pin es el que corre.
"""
import json, os, re, sys, time, urllib.request, urllib.parse, urllib.error
import versiones as V
import gh_search as G

AQUI = os.path.dirname(os.path.abspath(__file__))
SALIDA = os.path.join(AQUI, "exposure.json")

PAQUETES = [("mcp", "PyPI"), ("fastmcp", "PyPI"), ("litellm", "PyPI")]

# Manifiestos por fuerza de evidencia. Un lock registra la version RESUELTA que
# de verdad se instalo; un requirements o un pyproject declaran una intencion
# que pip puede resolver a otra cosa. El mapa lo dice en vez de mezclarlos.
MANIFIESTOS = [
    ("poetry.lock",    "alta",  "lock: version resuelta"),
    ("uv.lock",        "alta",  "lock: version resuelta"),
    ("Pipfile.lock",   "alta",  "lock: version resuelta"),
    ("requirements.txt", "media", "declaracion, puede no ser lo instalado"),
    ("pyproject.toml", "media", "declaracion, normalmente un rango"),
]


def token():
    t = os.environ.get("GITHUB_TOKEN")
    if t:
        return t.strip()
    f = os.path.expanduser("~/.config/mcp-radar/github-token")
    return open(f).read().strip() if os.path.exists(f) else None


def gh(url):
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json", "User-Agent": "mcp-radar-exposure",
        "Authorization": f"Bearer {token()}"})
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        print(f"  [aviso] HTTP {e.code}", file=sys.stderr)
        return None


def ver(s):
    """Normaliza a tupla comparable. '2.13.0.2' -> (2,13,0)."""
    n = [int(x) for x in re.findall(r"\d+", s)[:3]]
    return tuple(n + [0] * (3 - len(n)))


def advisories(paquete, eco):
    """Devuelve la VENTANA de cada advisory: [introduced, fixed).

    Antes esto devolvia solo `fixed` y se comparaba pin < fix. Eso marcaba
    expuesto a quien corre una version ANTERIOR a que el bug existiera: 371 de
    2484 pares (14,9%) eran acusaciones falsas — OpenSPG/KAG con mcp==1.6.0
    contra una ventana que empieza en 1.23.0. Un advisory no es un corte, es un
    intervalo, y mirar un solo extremo es la mitad de la aritmetica.
    """
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=json.dumps({"package": {"name": paquete, "ecosystem": eco}}).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "mcp-radar"})
    try:
        vulns = json.load(urllib.request.urlopen(req, timeout=40)).get("vulns", [])
    except Exception as e:
        print(f"  [aviso] OSV {paquete}: {e}", file=sys.stderr)
        return []
    out, vistos = [], set()
    for v in vulns:
        if v["id"].startswith("PYSEC"):      # duplican los GHSA
            continue
        for a in v.get("affected", []):
            if a["package"]["name"] != paquete:
                continue
            for r_ in a.get("ranges", []):
                ev = r_.get("events", [])
                intro = next((e["introduced"] for e in ev if "introduced" in e), "0")
                fix = next((e["fixed"] for e in ev if "fixed" in e), None)
                # last_affected: los advisories sin `fixed` se descartaban
                # enteros (5 de litellm). Con la cota superior cerrada el
                # veredicto igual se puede dar.
                last = next((e["last_affected"] for e in ev if "last_affected" in e), None)
                if (fix or last) and v["id"] not in vistos:
                    vistos.add(v["id"])
                    sev = (v.get("database_specific", {}) or {}).get("severity", "")
                    out.append({"id": v["id"], "introduced": intro, "fix": fix,
                                "last_affected": last, "severidad": sev,
                                "resumen": (v.get("summary") or "")[:120]})
    return sorted(out, key=lambda x: V.clave_orden(x["fix"] or x["last_affected"] or "0"),
                  reverse=True)


def meta_repo(full, _cache={}):
    """Datos de impacto. Un repo muerto o sin usuarios NO es un objetivo,
    aunque lo alcancen ocho advisories."""
    if full in _cache:
        return _cache[full]
    d = gh(f"https://api.github.com/repos/{full}") or {}
    _cache[full] = {
        "estrellas": d.get("stargazers_count", 0),
        "forks": d.get("forks_count", 0),
        "ultimo_push": (d.get("pushed_at") or "")[:10],
        "archivado": bool(d.get("archived")),
        "es_fork": bool(d.get("fork")),
    }
    return _cache[full]


def impacto(meta, n_advisories):
    """Score 0-100. Ordena la cola de trabajo por a quién le importa de verdad.

    Ordenar por cantidad de advisories era el criterio equivocado: un repo de 3
    estrellas alcanzado por 8 advisories no le importa a nadie; microsoft/UFO
    con los mismos 8 sí. Lo que manda es el alcance, después la vigencia, y
    recién al final cuántos advisories acumula.
    """
    if meta["archivado"] or meta["es_fork"]:
        return 0
    e = meta["estrellas"]
    alcance = 45 if e >= 5000 else 35 if e >= 1000 else 25 if e >= 200 else \
              15 if e >= 50 else 6 if e >= 10 else 0
    vigencia = 0
    p = meta["ultimo_push"]
    if p:
        vigencia = 30 if p >= "2026-07-01" else 20 if p >= "2026-04-01" else \
                   10 if p >= "2025-07-01" else 0
    forks = min(10, meta["forks"] // 20)
    return min(100, alcance + vigencia + forks + min(15, n_advisories))


def versiones_publicadas(paquete):
    """Todas las versiones del paquete en PyPI. Alimentan el particionado:
    sin la lista real no se puede dividir el espacio de busqueda."""
    try:
        d = json.load(urllib.request.urlopen(
            f"https://pypi.org/pypi/{paquete}/json", timeout=30))
        return sorted(d.get("releases", {}).keys())
    except Exception as e:
        print(f"  [aviso] PyPI {paquete}: {e}", file=sys.stderr)
        return []


def buscar_pins(paquete, archivo="requirements.txt", particionar=True):
    """Cobertura real en vez de muestreo.

    Antes: 2 paginas de 50 sobre una poblacion de 6640 = se miraba el 0,7%.
    Ahora: walk pagina hasta agotar el bucket, y si el bucket satura (tope de
    1000 FILAS, que dan ~541 unicos por el 46% de solapamiento medido) se parte
    por version. `total_count` no se usa para nada: miente arriba de ~1000
    —`extension:txt` reporta menos que su propio subconjunto— asi que la
    saturacion se detecta por el COMPORTAMIENTO del walk.
    """
    todos = {}
    if particionar:
        vers = versiones_publicadas(paquete)
        if vers:
            for q, unicos in G.buckets(paquete, archivo, vers):
                todos.update(unicos)
                print(f"      bucket {q[:52]:52} +{len(unicos)}", flush=True)
            return list(todos.values())
    unicos, _, sat = G.walk(f'"{paquete}" filename:{archivo}')
    if sat:
        print(f"      [aviso] {archivo} saturo el tope: cobertura parcial", file=sys.stderr)
    return list(unicos.values())


def main():
    resultado = {"generado": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
                 "paquetes": {}}
    for paquete, eco in PAQUETES:
        advs = advisories(paquete, eco)
        if not advs:
            continue
        corte_max = advs[0]["fix"] or advs[0]["last_affected"] or "?"
        print(f"\n### {paquete} — {len(advs)} advisories, corte más alto {corte_max}")
        hits, fuerza_de = [], {}
        for archivo, fuerza, nota in MANIFIESTOS:
            part = archivo == "requirements.txt"
            h = buscar_pins(paquete, archivo, particionar=part)
            for it in h:
                k = (it["repository"]["full_name"], it["path"])
                if k not in fuerza_de:
                    fuerza_de[k] = (fuerza, nota)
                    hits.append(it)
            print(f"    {archivo:18} {len(h):>5} archivos ({fuerza})")
        print(f"    total únicos a evaluar: {len(hits)}")
        expuestos = []
        for it in hits:
            full = it["repository"]["full_name"]
            try:
                raw = urllib.request.urlopen(urllib.request.Request(
                    f"https://raw.githubusercontent.com/{full}/HEAD/{it['path']}",
                    headers={"User-Agent": "x"}), timeout=15).read().decode("utf8", "replace")
            except Exception:
                continue
            # spec_en_requirements entiende ==, >=, ~=, ^ y rangos; antes el
            # regex solo capturaba pins exactos y descartaba en silencio a todo
            # el que declara un rango, que es un falso NEGATIVO invisible.
            ruta = it["path"]
            if ruta.endswith("package.json"):
                pin = V.spec_en_package_json(raw, paquete)
            else:
                pin = V.spec_en_requirements(raw, paquete)
            if not pin:
                continue
            fuerza, nota_f = fuerza_de.get((full, ruta), ("media", ""))
            afecta, dudosos = [], []
            for a in advs:
                v_ = V.expuesto_ventana(pin, a["introduced"], a["fix"],
                                        a.get("last_affected"), eco)
                if v_ == "expuesto":
                    afecta.append({**a, "veredicto": "expuesto"})
                elif v_ == "indeterminado":
                    dudosos.append({**a, "veredicto": "indeterminado"})
            if afecta or dudosos:
                mt = meta_repo(full)
                expuestos.append({
                    "repo": full, "pin": pin, "archivo": it["path"],
                    "url_repo": f"https://github.com/{full}",
                    "url_archivo": f"https://github.com/{full}/blob/HEAD/{it['path']}",
                    "advisories": afecta, "indeterminados": dudosos,
                    "estrellas": mt["estrellas"], "ultimo_push": mt["ultimo_push"],
                    "archivado": mt["archivado"], "es_fork": mt["es_fork"],
                    "impacto": impacto(mt, len(afecta)),
                    "certeza": "expuesto" if afecta else "indeterminado",
                    "fuerza_evidencia": fuerza, "nota_evidencia": nota_f,
                })
            time.sleep(0.12)
        # ordenar por IMPACTO, no por cantidad de advisories
        expuestos.sort(key=lambda x: (-x["impacto"], -len(x["advisories"])))
        resultado["paquetes"][paquete] = {
            "corte_seguro": corte_max, "poblacion_github": total,
            "muestra": len(hits), "expuestos": expuestos,
            "advisories": [{"id": a["id"], "introduced": a["introduced"],
                            "fix": a["fix"], "resumen": a["resumen"]} for a in advs]}
        print(f"    expuestos en la muestra: {len(expuestos)}")
        time.sleep(6)

    json.dump(resultado, open(SALIDA, "w"), indent=1, ensure_ascii=False)
    print(f"\nescrito {SALIDA}")

    if "--tabla" in sys.argv:
        for paq, d in resultado["paquetes"].items():
            print(f"\n===== {paq} (seguro >= {d['corte_seguro']}) =====")
            print(f"  {'imp':>4} {'⭐':>7}  {'push':10}  {'repo':34} {'pin':13} {'ev':5} adv")
            for e in d["expuestos"][:14]:
                print(f"  {e['impacto']:>4} {e['estrellas']:>7}  {e['ultimo_push']:10}  "
                      f"{e['repo'][:34]:34} {e['pin'][:13]:13} "
                      f"{e.get('fuerza_evidencia','?')[:5]:5} {len(e['advisories'])}")
            muertos = sum(1 for e in d["expuestos"] if e["impacto"] == 0)
            print(f"  ({muertos} con impacto 0: archivados, forks o sin usuarios — al fondo)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
