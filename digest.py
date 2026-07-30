#!/usr/bin/env python3
"""MCP Radar — digest diario con diff.

Pega a cuatro APIs publicas y gratuitas, filtra al nicho IA/agentes/MCP, y emite
SOLO lo que no habia visto antes. Correrlo dos veces el mismo dia debe devolver
vacio la segunda vez: ese es el test de que el diff funciona.

  python3 digest.py                # imprime el digest
  python3 digest.py --send         # ademas lo manda por Telegram via hermes
  python3 digest.py --reset        # borra el estado (empieza de cero)

GITHUB_TOKEN en el entorno sube el limite de rate de 60/h a 5000/h (opcional).
"""
import json, os, re, sys, time, subprocess, urllib.request, urllib.error, urllib.parse
from datetime import datetime, timedelta, timezone

AQUI = os.path.dirname(os.path.abspath(__file__))
ESTADO = os.path.join(AQUI, "radar-state.json")
SALIDA = os.path.join(AQUI, "digest")

# Dos filtros distintos a proposito.
#
# NICHO_ANCHO: para busqueda de repos, donde el contexto ya es "seguridad de IA"
# por la query, asi que "agent" solo es seguro y conviene no perderse nada.
NICHO_ANCHO = re.compile(
    r"\bmcp\b|model context protocol|\bagent(s|ic)?\b|\bllm\b|prompt inject|"
    r"tool poisoning|langchain|langgraph|ollama|vllm|litellm|autogen|crewai",
    re.I)

# NICHO_ESTRICTO: para KEV y advisories, que cubren TODO el software del mundo.
# Ahi "agent" suelto trae Veritas Backup Exec Agent y Exim Mail Transfer Agent,
# que no tienen nada que ver. Se exige contexto de IA de verdad.
NICHO_ESTRICTO = re.compile(
    r"\bmcp\b|model context protocol|\bai agent|\bagentic\b|agent framework|"
    r"\bllm\b|large language model|prompt inject|tool poisoning|jailbreak|"
    r"langchain|langgraph|llamaindex|ollama|vllm|litellm|berriai|autogen|crewai|"
    r"anthropic|openai|huggingface|bedrock|copilot",
    re.I)

BUSQUEDAS_REPO = ["mcp security", "ai agent security", "llm security",
                  "prompt injection", "agent guardrail", "mcp scanner"]

PAQUETES_OSV = [("mcp", "PyPI"), ("fastmcp", "PyPI"),
                ("@modelcontextprotocol/sdk", "npm")]

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")


# Fuentes que fallaron en la corrida actual. Es lo que evita el peor modo de
# falla: que el digest imprima "sin novedades" cuando en realidad no pudo leer
# nada. Un radar en el que no podes confiar es peor que no tener radar.
FALLOS = []


def http(url, data=None, etiqueta=""):
    cab = {"User-Agent": "mcp-radar", "Accept": "application/vnd.github+json"}
    tok = os.environ.get("GITHUB_TOKEN")
    if tok and "api.github.com" in url:
        cab["Authorization"] = f"Bearer {tok}"
    if data is not None:
        data = json.dumps(data).encode()
        cab["Content-Type"] = "application/json"
    for intento in range(2):
        try:
            with urllib.request.urlopen(
                    urllib.request.Request(url, data=data, headers=cab), timeout=40) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (403, 429) and intento == 0:
                time.sleep(20)          # rate limit: esperar y reintentar una vez
                continue
            motivo = f"HTTP {e.code}"
        except Exception as e:
            motivo = type(e).__name__
        FALLOS.append(f"{etiqueta or url[:50]} → {motivo}")
        print(f"  [fallo] {etiqueta or url[:60]}: {motivo}", file=sys.stderr)
        return None
    return None


def cargar_estado():
    if os.path.exists(ESTADO):
        return json.load(open(ESTADO))
    return {"repos": [], "advisories": [], "osv": [], "kev": []}


def recolectar():
    """Devuelve {seccion: [(id_unico, linea_markdown), ...]}"""
    out = {"repos": [], "advisories": [], "osv": [], "kev": []}
    desde = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")

    for q in BUSQUEDAS_REPO:
        url = ("https://api.github.com/search/repositories?q="
               + urllib.parse.quote(q) + f"+in:name,description+created:>{desde}"
               "&sort=stars&order=desc&per_page=30")
        r = http(url, etiqueta=f"búsqueda repos: {q}")
        for it in (r or {}).get("items", []):
            d = it.get("description") or ""
            if not NICHO_ANCHO.search(d + " " + it["full_name"]):
                continue
            out["repos"].append((
                it["full_name"],
                f"- **{it['full_name']}** · ⭐{it['stargazers_count']} · "
                f"{it['created_at'][:10]} · {d[:110]}"))

    r = http("https://api.github.com/advisories?per_page=100&sort=published&direction=desc",
             etiqueta="advisories de GitHub")
    for a in (r or []):
        res = (a.get("summary") or "")
        pk = ", ".join(p["package"]["name"] for p in a.get("vulnerabilities", [])
                       if p.get("package"))
        if not NICHO_ESTRICTO.search(res + " " + pk):
            continue
        out["advisories"].append((
            a["ghsa_id"],
            f"- **{a['ghsa_id']}** · {a.get('severity','?')} · `{pk[:50]}` · "
            f"{a['published_at'][:10]} · {res[:110]}"))

    for nom, eco in PAQUETES_OSV:
        r = http("https://api.osv.dev/v1/query",
                 {"package": {"name": nom, "ecosystem": eco}},
                 etiqueta=f"OSV: {nom} ({eco})")
        for v in (r or {}).get("vulns", []):
            out["osv"].append((
                v["id"],
                f"- **{v['id']}** · `{nom}` ({eco}) · {v.get('published','')[:10]} · "
                f"{(v.get('summary') or '')[:110]}"))

    r = http(KEV_URL, etiqueta="CISA KEV")
    for v in (r or {}).get("vulnerabilities", []):
        texto = v["vulnerabilityName"] + " " + v.get("shortDescription", "")
        if not NICHO_ESTRICTO.search(texto):
            continue
        out["kev"].append((
            v["cveID"],
            f"- **{v['cveID']}** · {v['vendorProject']} · añadido {v['dateAdded']} · "
            f"{v['vulnerabilityName'][:100]}"))
    return out


TITULOS = {
    "repos":      "🧭 Repos nuevos (esfuerzo)",
    "advisories": "🩸 Advisories nuevos (dolor)",
    "osv":        "📦 Vulns nuevas en paquetes MCP",
    "kev":        "🔥 KEV — explotado en la práctica",
}


def main():
    if "--reset" in sys.argv and os.path.exists(ESTADO):
        os.remove(ESTADO)
        print("estado borrado")

    estado = cargar_estado()
    FALLOS.clear()
    datos = recolectar()

    partes, total, revisados = [], 0, 0
    for sec in ("kev", "advisories", "osv", "repos"):   # dolor primero
        vistos = set(estado.get(sec, []))
        nuevos, ids = [], []
        for uid, linea in datos[sec]:
            if uid in vistos or uid in ids:
                continue
            ids.append(uid)
            nuevos.append(linea)
        revisados += len(datos[sec])
        if nuevos:
            partes.append(f"### {TITULOS[sec]}\n" + "\n".join(nuevos))
            total += len(nuevos)
        estado[sec] = sorted(vistos | set(ids))

    hoy = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    aviso = ""
    if FALLOS:
        aviso = ("\n\n⚠️ **" + str(len(FALLOS)) + " fuente(s) fallaron — la lectura está "
                 "incompleta:**\n" + "\n".join(f"- {f}" for f in FALLOS))
    pie = f"\n\n_{revisados} items revisados · {total} nuevos_"
    if total == 0:
        cuerpo = f"MCP Radar · {hoy}\n\nSin novedades.{pie}{aviso}"
    else:
        cuerpo = (f"# MCP Radar · {hoy}\n\n**{total} novedades**\n\n"
                  + "\n\n".join(partes) + pie + aviso)

    json.dump(estado, open(ESTADO, "w"), indent=1)
    os.makedirs(SALIDA, exist_ok=True)
    dest = os.path.join(SALIDA, datetime.now(timezone.utc).strftime("%Y-%m-%d") + ".md")
    if total:
        open(dest, "a").write(cuerpo + "\n\n")

    print(cuerpo)

    if "--send" in sys.argv and (total or FALLOS):
        try:
            subprocess.run(["hermes", "send", "-t", "telegram", cuerpo[:3500]],
                           check=True, timeout=60)
            print("\n[enviado a telegram]")
        except Exception as e:
            print(f"\n[fallo el envio: {e}]", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
