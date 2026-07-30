#!/usr/bin/env python3
"""Cliente único de GitHub code search: throttle, walk con dedupe y partición.

TODO el acceso a /search/code del proyecto pasa por acá. No es estética: el
bucket real es `code_search` = 10 req/min (NO los 30/min de `search`, que es lo
que muestra primero /rate_limit), así que dos procesos del proyecto corriendo a
la vez (p.ej. un confirm.py --top 5 en paralelo) se comen el presupuesto mutuo.
Un solo módulo con el throttle adentro + un lockfile es la única forma barata.
"""
import fcntl, json, os, re, sys, time, urllib.parse, urllib.request

TOKEN = open(os.path.expanduser("~/.config/mcp-radar/github-token")).read().strip()
API = "https://api.github.com/search/code"
# 10/min medidos => 6.5 s de piso. El time.sleep(3) anterior iba a 20/min, el
# DOBLE del límite, y comía 403s.
INTERVALO = 6.5
LOCK = "/tmp/mcp-radar-codesearch.lock"
_ultima = [0.0]


def _throttle():
    espera = INTERVALO - (time.time() - _ultima[0])
    if espera > 0:
        time.sleep(espera)
    _ultima[0] = time.time()


def buscar(q, page=1, per_page=100, reintentos=3):
    """Una request a /search/code. Devuelve dict o None.

    per_page=100 es el máximo real: 101 y 150 NO dan error, devuelven 100 items
    con recorte silencioso. El bucket cobra por REQUEST, no por item: bajar a 50
    (lo que hacía buscar_pins) tiraba la mitad del presupuesto.

    text-match trae el fragmento con las líneas vecinas, sin coste extra de rate
    limit, y con eso se decide el pin SIN bajar el raw: son miles de GET a
    raw.githubusercontent que desaparecen.
    """
    url = f"{API}?q={urllib.parse.quote(q)}&per_page={min(per_page, 100)}&page={page}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github.text-match+json",
        "User-Agent": "mcp-radar"})
    for _ in range(reintentos):
        with open(LOCK, "w") as lk:
            fcntl.flock(lk, fcntl.LOCK_EX)      # un solo proceso del proyecto a la vez
            _throttle()
            try:
                with urllib.request.urlopen(req, timeout=40) as r:
                    return json.load(r)
            except urllib.error.HTTPError as e:
                rem = e.headers.get("X-RateLimit-Remaining")
                if e.code == 422:
                    # "Cannot access beyond the first 1000 results" o query mal
                    # formada (fork:false es 422 fatal). No se reintenta.
                    return None
                if e.code == 403 and rem == "0":
                    # NO es 429 y NO trae Retry-After (verificado en 6 respuestas
                    # seguidas): un backoff que dependa de esa cabecera se rompe,
                    # y un handler genérico lo confunde con "token sin permisos".
                    reset = int(e.headers.get("X-RateLimit-Reset", time.time() + 60))
                    time.sleep(max(2, reset - time.time() + 2))
                    continue
                if e.code == 403:
                    raise                        # 403 con remaining>0 = permisos de verdad
                time.sleep(5)
            except Exception:
                time.sleep(5)
    return None


def walk(q, tope_filas=1000):
    """Camina un bucket hasta página corta o hasta el tope de 1000 FILAS.

    Devuelve (unicos, filas, saturado). `unicos` es {(repo, path): item}.

    El tope de 1000 es de FILAS, no de archivos únicos: las páginas se solapan.
    Medido sobre `"mcp==" filename:requirements.txt`: 1000 filas -> 541 únicos,
    459 duplicados (46% de basura), determinista y reproducible. Un bucket sano
    da diferencia CERO; una diferencia >5% significa query saturada = hay que
    partir. Por eso `saturado` sale del COMPORTAMIENTO del walk y nunca de
    total_count, que arriba de ~1000 es mentira demostrable
    (`extension:txt`=3728 < su propio subconjunto `filename:requirements.txt`=6672).
    """
    unicos, filas, page = {}, 0, 1
    while filas < tope_filas:
        r = buscar(q, page)
        if not r:
            break
        items = r.get("items", [])
        filas += len(items)
        for it in items:
            unicos.setdefault((it["repository"]["full_name"], it["path"]), it)
        if len(items) < 100:
            return unicos, filas, False          # página corta = bucket COMPLETO
        page += 1
    return unicos, filas, filas >= tope_filas


def fragmento(item):
    """Texto de los text_matches, con saltos de línea, para correr el regex
    line-anchored sin bajar el raw."""
    return "\n".join(m.get("fragment", "") for m in item.get("text_matches", []))


def pin_en_fragmento(item, paquete):
    """Pin del paquete en el fragmento, o None.

    `"mcp=="` matchea `fastmcp==` por substring: prueba limpia, mcp no tiene
    versión 2.14 y `"mcp==2.14"` da 300 hits, de los cuales ~54/60 inspeccionados
    eran fastmcp. El ancla `^\\s*` lo descarta. NO se arregla con `-fastmcp` en la
    query: eso tira los 106 archivos que fijan mcp Y fastmcp, justo los proyectos
    MCP más serios. Se filtra en el cliente, nunca en la query.
    """
    m = re.search(rf"^\s*{re.escape(paquete)}\s*(?:\[[^\]]*\])?\s*"
                  rf"(?P<spec>(?:[=<>!~]=|[<>])[^;#\n]*)",
                  fragmento(item), re.M | re.I)
    return m.group("spec").strip() if m else None


def buckets(paquete, archivo, versiones):
    """Descenso adaptativo de 3 niveles. Rinde (query, unicos) por bucket cerrado.

    Nivel 1 `pkg==X.Y` -> si el walk NO satura, el bucket está completo y exacto.
    Nivel 2 `pkg==X.Y.Z` -> medido: `mcp==1.9` saturó (1000 filas, 808 únicos) y
            sus 5 hijos dieron 1439 únicos, +631 recuperados, 0 perdidos (x1.78).
    Nivel 3 `size:` -> exacto y disjunto: sobre mcp==1.9.4, <150=30 + 150..600=61
            + >600=366 = 457, unión IDÉNTICA al walk directo (0 de diferencia).
    Nunca se baja de nivel sin que el walk lo pida: litellm entra entero a nivel
    X.Y (9 buckets sondeados, máximo 372 hits).
    """
    xy = sorted({".".join(v.split(".")[:2]) for v in versiones})
    for menor in xy:                     # más viejas primero: máxima exposición
        q1 = f'"{paquete}=={menor}" filename:{archivo}'
        u1, f1, sat1 = walk(q1)
        if not sat1:
            yield q1, u1
            continue
        for v in sorted(x for x in versiones if x.startswith(menor + ".")):
            q2 = f'"{paquete}=={v}" filename:{archivo}'
            u2, f2, sat2 = walk(q2)
            if not sat2:
                yield q2, u2
                continue
            for tramo in ("size:<150", "size:150..600", "size:>600"):
                q3 = f"{q2} {tramo}"
                u3, _, _ = walk(q3)
                yield q3, u3


if __name__ == "__main__":
    print(json.dumps(buscar(sys.argv[1] if len(sys.argv) > 1
                            else '"mcp==1.9.4" filename:requirements.txt',
                            per_page=100).get("total_count"), indent=1))
