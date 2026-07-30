#!/usr/bin/env python3
"""Confirmación — ¿el candidato usa de verdad el componente vulnerable?

Un pin viejo NO prueba exposición. Cada advisory afecta a una parte del paquete,
no a todo: el SSRF de fastmcp es del proveedor OpenAPI, así que un proyecto que
nunca lo instancia no está expuesto por más viejo que tenga el pin.

Este paso convierte «candidato» en «usa el componente afectado», que es la
diferencia entre avisarle a alguien con fundamento y mandarle spam.

Dos confirmaciones independientes:
  1. VERSIÓN  — busca lockfiles, que registran la versión resuelta de verdad.
                Un requirements.txt es una declaración; un lock es evidencia.
  2. USO      — extrae del texto del advisory los símbolos de código que cita
                (van entre backticks) y los busca dentro del repo candidato.

LÍMITE: encontrar el símbolo prueba que lo usan. NO encontrarlo no prueba que no
— puede haber uso indirecto o dinámico. Es evidencia positiva, no negativa.

  python3 confirm.py            # top 10 por impacto de cada paquete
  python3 confirm.py --top 25
"""
import json, os, re, sys, time, urllib.request, urllib.parse, urllib.error

AQUI = os.path.dirname(os.path.abspath(__file__))
ECO_DE = {"mcp": "PyPI", "fastmcp": "PyPI", "litellm": "PyPI",
          "@modelcontextprotocol/sdk": "npm"}
LOCKS = ["poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "requirements.lock"]

# Palabras que aparecen entre backticks pero NO son símbolos de código útiles.
RUIDO = {"code", "state", "none", "host", "origin", "authorization", "true", "false",
         "get", "post", "null", "error", "token", "session", "user", "id", "name",
         "cmd.exe", "bash", "sh", "python", "json", "http", "https"}

# Modulos de la stdlib y librerias ubicuas: matchean en cualquier repo y no
# prueban absolutamente nada sobre el uso del componente vulnerable.
UBICUO = re.compile(r"^(urllib|os|sys|json|re|typing|logging|asyncio|pathlib|"
                    r"subprocess|requests|httpx|pydantic|fastapi|starlette)\.", re.I)
# Dominios disfrazados de ruta de modulo (mcp.mintlify.app y compania).
DOMINIO = re.compile(r"\.(app|com|io|dev|org|net|ai|sh)$", re.I)


def token():
    t = os.environ.get("GITHUB_TOKEN")
    if t:
        return t.strip()
    f = os.path.expanduser("~/.config/mcp-radar/github-token")
    return open(f).read().strip() if os.path.exists(f) else None


def gh(url):
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json", "User-Agent": "mcp-radar-confirm",
        "Authorization": f"Bearer {token()}"})
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 403:
            time.sleep(20)
        return None
    except Exception:
        return None


def simbolos_del_advisory(gid, _cache={}):
    """Extrae del texto del advisory los identificadores de código que cita.

    Se queda solo con lo que parece código de verdad: CamelCase con dos
    mayúsculas o más, o rutas de módulo con puntos. Descarta palabras sueltas
    como `code` o `state`, que son ruido y matchean en cualquier repo.
    """
    if gid in _cache:
        return _cache[gid]
    try:
        d = json.load(urllib.request.urlopen(
            f"https://api.osv.dev/v1/vulns/{gid}", timeout=30))
    except Exception:
        _cache[gid] = []
        return []
    texto = (d.get("details") or "") + " " + (d.get("summary") or "")
    crudos = set(re.findall(r"`([A-Za-z_][\w.]{3,60})`", texto))
    crudos |= set(re.findall(r"\b([a-z_]+(?:\.[a-z_]+){2,})\b", texto))   # rutas de módulo
    buenos = []
    for s in crudos:
        if s.lower() in RUIDO or s.endswith(".py"):
            continue
        if UBICUO.match(s) or DOMINIO.search(s):
            continue
        camel = len(re.findall(r"[A-Z]", s)) >= 2 and len(s) >= 8
        ruta = s.count(".") >= 2
        if camel or ruta:
            buenos.append(s)
    _cache[gid] = sorted(buenos)[:6]
    return _cache[gid]


# El ecosistema del paquete decide en que lenguaje buscar. Sin esto, un symbolo
# de un advisory de PyPI matchea en un .go y da CONFIRMADO falso — paso exacto
# con `TaskStore` en csghub-server: codigo Go propio, nada que ver con el SDK.
LENG = {"PyPI": "python", "npm": "typescript", "Go": "go", "crates.io": "rust"}


def busca_en_repo(full, simbolo, eco="PyPI"):
    leng = LENG.get(eco, "python")
    q = urllib.parse.quote(f'"{simbolo}" repo:{full} language:{leng}')
    r = gh(f"https://api.github.com/search/code?q={q}&per_page=3")
    time.sleep(2.2)                       # search: 30/min
    if not r:
        return None
    return [(i["path"], i["html_url"]) for i in r.get("items", [])]


def lockfiles(full):
    hallados = []
    for L in LOCKS:
        q = urllib.parse.quote(f"filename:{L} repo:{full}")
        r = gh(f"https://api.github.com/search/code?q={q}&per_page=2")
        time.sleep(2.2)
        for it in (r or {}).get("items", []):
            hallados.append(it["path"])
    return hallados


def main():
    top = 10
    if "--top" in sys.argv:
        top = int(sys.argv[sys.argv.index("--top") + 1])
    datos = json.load(open(os.path.join(AQUI, "exposure.json")))
    salida = {}
    for paq, info in datos.get("paquetes", {}).items():
        print(f"\n########## {paq} — confirmando top {top} por impacto")
        conf = []
        for e in info["expuestos"][:top]:
            full = e["repo"]
            locks = lockfiles(full)
            usos, sin_mapeo = [], 0
            for a in e["advisories"][:4]:
                sims = simbolos_del_advisory(a["id"])
                if not sims:
                    sin_mapeo += 1
                    continue
                for s in sims[:3]:
                    hits = busca_en_repo(full, s, ECO_DE.get(paq, "PyPI"))
                    if hits:
                        usos.append({"advisory": a["id"], "simbolo": s,
                                     "archivo": hits[0][0], "url": hits[0][1]})
                        break
            estado = ("CONFIRMADO" if usos else
                      "sin-evidencia-de-uso" if not sin_mapeo else "sin-mapeo")
            conf.append({**e, "lockfiles": locks, "usos": usos, "estado": estado})
            marca = {"CONFIRMADO": "🔴", "sin-evidencia-de-uso": "⚪", "sin-mapeo": "🟡"}[estado]
            print(f"  {marca} {full[:40]:40} imp {e['impacto']:>3} · "
                  f"{'lock:' + locks[0][:18] if locks else 'sin lockfile':24} · {estado}")
            for u in usos[:2]:
                print(f"        usa `{u['simbolo']}` en {u['archivo']}  ({u['advisory']})")
        salida[paq] = conf
    json.dump(salida, open(os.path.join(AQUI, "confirmed.json"), "w"),
              indent=1, ensure_ascii=False)
    tot = sum(1 for v in salida.values() for c in v if c["estado"] == "CONFIRMADO")
    print(f"\nconfirmados con uso del componente afectado: {tot}")
    print("escrito confirmed.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
