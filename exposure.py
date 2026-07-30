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

AQUI = os.path.dirname(os.path.abspath(__file__))
SALIDA = os.path.join(AQUI, "exposure.json")

# (paquete, ecosistema OSV, patrón de pin, archivos donde buscar)
PAQUETES = [
    ("mcp", "PyPI", "requirements.txt"),
    ("fastmcp", "PyPI", "requirements.txt"),
    ("litellm", "PyPI", "requirements.txt"),
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
    """Devuelve [(id, version_fix, resumen, severidad)] con fix conocido."""
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
                fix = [e["fixed"] for e in r_.get("events", []) if "fixed" in e]
                if fix and v["id"] not in vistos:
                    vistos.add(v["id"])
                    sev = (v.get("database_specific", {}) or {}).get("severity", "")
                    out.append((v["id"], fix[0], (v.get("summary") or "")[:120], sev))
    return sorted(out, key=lambda x: ver(x[1]), reverse=True)


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


def buscar_pins(paquete, archivo, paginas=2):
    hits = []
    for pag in range(1, paginas + 1):
        q = urllib.parse.quote(f'"{paquete}==" filename:{archivo}')
        r = gh(f"https://api.github.com/search/code?q={q}&per_page=50&page={pag}")
        if not r:
            break
        hits += r.get("items", [])
        if len(r.get("items", [])) < 50:
            break
        time.sleep(3)
    return hits, (r or {}).get("total_count", 0)


def main():
    resultado = {"generado": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
                 "paquetes": {}}
    for paquete, eco, archivo in PAQUETES:
        advs = advisories(paquete, eco)
        if not advs:
            continue
        corte_max = advs[0][1]
        print(f"\n### {paquete} — {len(advs)} advisories, corte más alto {corte_max}")
        hits, total = buscar_pins(paquete, archivo)
        print(f"    población en GitHub: {total} · muestra: {len(hits)}")
        expuestos = []
        for it in hits:
            full = it["repository"]["full_name"]
            try:
                raw = urllib.request.urlopen(urllib.request.Request(
                    f"https://raw.githubusercontent.com/{full}/HEAD/{it['path']}",
                    headers={"User-Agent": "x"}), timeout=15).read().decode("utf8", "replace")
            except Exception:
                continue
            m = re.search(rf"^\s*{re.escape(paquete)}==([0-9][\w.\-]*)", raw, re.M | re.I)
            if not m:
                continue
            pin = m.group(1)
            afecta = [{"id": a, "fix": f, "resumen": s, "severidad": sv}
                      for a, f, s, sv in advs if ver(pin) < ver(f)]
            if afecta:
                mt = meta_repo(full)
                expuestos.append({
                    "repo": full, "pin": pin, "archivo": it["path"],
                    "url_repo": f"https://github.com/{full}",
                    "url_archivo": f"https://github.com/{full}/blob/HEAD/{it['path']}",
                    "advisories": afecta,
                    "estrellas": mt["estrellas"], "ultimo_push": mt["ultimo_push"],
                    "archivado": mt["archivado"], "es_fork": mt["es_fork"],
                    "impacto": impacto(mt, len(afecta)),
                })
            time.sleep(0.12)
        # ordenar por IMPACTO, no por cantidad de advisories
        expuestos.sort(key=lambda x: (-x["impacto"], -len(x["advisories"])))
        resultado["paquetes"][paquete] = {
            "corte_seguro": corte_max, "poblacion_github": total,
            "muestra": len(hits), "expuestos": expuestos,
            "advisories": [{"id": a, "fix": f, "resumen": s} for a, f, s, _ in advs]}
        print(f"    expuestos en la muestra: {len(expuestos)}")
        time.sleep(6)

    json.dump(resultado, open(SALIDA, "w"), indent=1, ensure_ascii=False)
    print(f"\nescrito {SALIDA}")

    if "--tabla" in sys.argv:
        for paq, d in resultado["paquetes"].items():
            print(f"\n===== {paq} (seguro >= {d['corte_seguro']}) =====")
            print(f"  {'impacto':>7} {'⭐':>7}  {'último push':11}  {'repo':38} {'pin':12} adv")
            for e in d["expuestos"][:14]:
                print(f"  {e['impacto']:>7} {e['estrellas']:>7}  {e['ultimo_push']:11}  "
                      f"{e['repo'][:38]:38} {e['pin']:<12} {len(e['advisories'])}")
            muertos = sum(1 for e in d["expuestos"] if e["impacto"] == 0)
            print(f"  ({muertos} con impacto 0: archivados, forks o sin usuarios — al fondo)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
