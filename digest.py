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

# Racimos para agrupar los repos. Una lista suelta de 168 lineas es ilegible y
# esconde lo unico que importa: que varios autores INDEPENDIENTES ataquen el
# mismo problema la misma semana. Eso es convergencia, y es la senal temprana.
RACIMOS = [
    # Orden = prioridad. El primero que matchea gana, asi que lo especifico va arriba.
    ("prompt injection",         r"prompt inject|jailbreak|tool poison|indirect inject"),
    ("scanner/audit de MCP",     r"mcp[\w\- ]*(scanner|audit|security|posture|shield)|"
                                 r"(scanner|audit|security|posture)[\w\- ]*mcp\b"),
    ("guardrails / firewall",    r"guardrail|firewall|\bwaf\b|sandbox|"
                                 r"(llm|prompt|agent|ai)[\w\- ]*(defen|protect|filter|shield|proxy|gateway)"),
    ("red team / ofensivo",      r"red.?team|offensive|pentest|exploit|attack|\bc2\b|honeypot|adversarial"),
    ("gobernanza / inventario",  r"inventor|governance|complian|posture|observab|audit|policy|"
                                 r"provenance|trace|telemetr"),
    ("superficie expuesta",      r"discover|expose|fingerprint|recon|shodan|crawl|enumerat"),
    ("evaluacion / benchmark",   r"benchmark|\beval\b|evaluat|test.*suite|red.?teaming.*bench"),
    ("servidores MCP varios",    r"\bmcp\b|model context protocol"),   # cajon MCP, va ultimo
]


def racimo_de(texto):
    for nombre, pat in RACIMOS:
        if re.search(pat, texto, re.I):
            return nombre
    return "otros"


def agrupar_repos(lineas):
    """Devuelve (resumen_corto, detalle_completo). El resumen va a Telegram y
    el detalle al archivo: no se pierde nada, solo se separan los canales."""
    grupos = {}
    for l in lineas:
        grupos.setdefault(racimo_de(l), []).append(l)

    def estrellas(l):
        m = re.search(r"⭐(\d+)", l)
        return int(m.group(1)) if m else 0

    def autores(ls):
        return len({l.split("**")[1].split("/")[0] for l in ls if "**" in l})

    # El marcador va AL REVES de la intuicion, y es la lección central del
    # analisis: convergencia de 3-8 autores independientes en un racimo flaco es
    # senal temprana y es donde hay lugar. Un racimo de 40 autores no es una
    # oportunidad, es un mercado al que llegaste tarde. Un aviso que suena
    # siempre no avisa nada.
    def marcar(n_repos, n_aut):
        if 3 <= n_aut <= 8 and n_repos <= 10:
            return "  🌱 TEMPRANO — pocos autores, esfuerzo independiente"
        if n_aut > 20:
            return "  (saturado)"
        return ""

    resumen, detalle = [], []
    for nombre, ls in sorted(grupos.items(), key=lambda x: -len(x[1])):
        n_aut = autores(ls)
        marca = marcar(len(ls), n_aut)
        resumen.append(f"**{nombre}** — {len(ls)} repos / {n_aut} autores distintos{marca}")
        for l in sorted(ls, key=estrellas, reverse=True)[:3]:
            resumen.append("  " + l)
        if len(ls) > 3:
            resumen.append(f"  _(+{len(ls)-3} más, en el archivo del día)_")
        detalle.append(f"#### {nombre} ({len(ls)} repos / {n_aut} autores)")
        detalle += sorted(ls, key=estrellas, reverse=True)
    return "\n".join(resumen), "\n".join(detalle)


def main():
    if "--reset" in sys.argv and os.path.exists(ESTADO):
        os.remove(ESTADO)
        print("estado borrado")

    estado = cargar_estado()
    FALLOS.clear()
    datos = recolectar()

    partes_msg, partes_arch, total, revisados = [], [], 0, 0
    for sec in ("kev", "advisories", "osv", "repos"):   # dolor primero
        vistos = set(estado.get(sec, []))
        nuevos, ids = [], []
        for uid, linea in datos[sec]:
            if uid in vistos or uid in ids:      # dedup: mismo repo en 2 queries
                continue
            ids.append(uid)
            nuevos.append(linea)
        # contar UNICOS, no crudos: el numero tiene que ser auditable
        revisados += len({uid for uid, _ in datos[sec]})
        if nuevos:
            total += len(nuevos)
            cab = f"### {TITULOS[sec]}"
            if sec == "repos":
                corto, largo = agrupar_repos(nuevos)
                partes_msg.append(f"{cab} — {len(nuevos)}\n{corto}")
                partes_arch.append(f"{cab} — {len(nuevos)}\n{largo}")
            else:
                bloque = f"{cab}\n" + "\n".join(nuevos)
                partes_msg.append(bloque)
                partes_arch.append(bloque)
        estado[sec] = sorted(vistos | set(ids))

    hoy = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    aviso = ""
    if FALLOS:
        aviso = ("\n\n⚠️ **" + str(len(FALLOS)) + " fuente(s) fallaron — la lectura está "
                 "incompleta:**\n" + "\n".join(f"- {f}" for f in FALLOS))
    pie = f"\n\n_{revisados} items únicos revisados · {total} nuevos_"
    if total == 0:
        cuerpo = archivo = f"MCP Radar · {hoy}\n\nSin novedades.{pie}{aviso}"
    else:
        enc = f"# MCP Radar · {hoy}\n\n**{total} novedades**\n\n"
        cuerpo  = enc + "\n\n".join(partes_msg) + pie + aviso
        archivo = enc + "\n\n".join(partes_arch) + pie + aviso

    json.dump(estado, open(ESTADO, "w"), indent=1)
    os.makedirs(SALIDA, exist_ok=True)
    dest = os.path.join(SALIDA, datetime.now(timezone.utc).strftime("%Y-%m-%d") + ".md")
    if total:
        open(dest, "a").write(archivo + "\n\n")   # el archivo lleva TODO

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
