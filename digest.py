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

# Los ecosistemas donde vive el software de agentes. Se consultan por separado
# para no depender de "los ultimos 100 del mundo", que se satura y pierde cosas.
ECOSISTEMAS = ["npm", "pip", "go", "rust", "actions"]

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")


# Fuentes que fallaron en la corrida actual. Es lo que evita el peor modo de
# falla: que el digest imprima "sin novedades" cuando en realidad no pudo leer
# nada. Un radar en el que no podes confiar es peor que no tener radar.
FALLOS = []


TOKEN_FILE = os.path.expanduser("~/.config/mcp-radar/github-token")


def token_github():
    """Sin token son 60 peticiones/hora y el digest hace ~35: se cae a la mitad
    de la corrida. Con token son 5000/h. Alcanza uno fine-grained de SOLO
    lectura publica — no hace falta ningun scope de escritura."""
    t = os.environ.get("GITHUB_TOKEN")
    if t:
        return t.strip()
    if os.path.exists(TOKEN_FILE):
        return open(TOKEN_FILE).read().strip()
    return None


def http(url, data=None, etiqueta=""):
    cab = {"User-Agent": "mcp-radar", "Accept": "application/vnd.github+json"}
    tok = token_github()
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
    base = {"repos": [], "advisories": [], "osv": [], "kev": [], "racimos": {}}
    if os.path.exists(ESTADO):
        base.update(json.load(open(ESTADO)))
    base.setdefault("racimos", {})
    return base


def semana_actual():
    a, s, _ = datetime.now(timezone.utc).isocalendar()
    return f"{a}-W{s:02d}"


def actualizar_racimos(estado, lineas_nuevas):
    """Acumula autores por racimo a lo largo de las semanas.

    El digest diario NO puede ver convergencia: un racimo emergente se forma en
    semanas y la ventana de busqueda es de 7 dias. Esto es lo que sí lo ve —
    guarda el historico de autores por racimo y detecta cuando uno FLACO suma
    varios autores nuevos e independientes en una semana. Esa es la senal
    temprana de verdad; un racimo con 40 autores ya es un mercado perdido.
    """
    sem = semana_actual()
    alertas = []
    for l in lineas_nuevas:
        if "**" not in l:
            continue
        autor = l.split("**")[1].split("/")[0]
        r = estado["racimos"].setdefault(racimo_de(l),
                                         {"autores": [], "por_semana": {}})
        if autor not in r["autores"]:
            r["autores"].append(autor)
            r["por_semana"][sem] = r["por_semana"].get(sem, 0) + 1

    for nombre, r in estado["racimos"].items():
        nuevos = r["por_semana"].get(sem, 0)
        total = len(r["autores"])
        previas = set(r["por_semana"]) - {sem}
        # Sin semanas anteriores esto es el baseline, no una senal: en la primera
        # corrida TODO autor es nuevo. Callar hasta tener con que comparar.
        if not previas:
            continue
        base = total - nuevos
        # Tres condiciones juntas, y las tres importan:
        #   base >= 2   -> ya habia un racimo, no es el primer registro
        #   nuevos >= 3 -> aceleracion real, no un entrante suelto
        #   total <= 15 -> sigue siendo flaco; con 40 autores llegaste tarde
        if base >= 2 and nuevos >= 3 and total <= 15:
            alertas.append(f"🌱 **{nombre}** — {nuevos} autores nuevos esta semana "
                           f"sobre una base de {base}. Racimo flaco recibiendo "
                           f"esfuerzo independiente: mirarlo ahora.")
    return alertas


def resumen_racimos(estado, top=6):
    filas = sorted(estado["racimos"].items(), key=lambda x: -len(x[1]["autores"]))
    out = []
    for nombre, r in filas[:top]:
        sem = r["por_semana"].get(semana_actual(), 0)
        delta = f" (+{sem} esta semana)" if sem else ""
        out.append(f"- {nombre}: {len(r['autores'])} autores acumulados{delta}")
    return "\n".join(out)


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

    # Antes se pedian "los ultimos 100 del mundo" sin filtro del lado del
    # servidor: un dia con avalancha de advisories empujaba los de MCP fuera de
    # esa pagina y se perdian EN SILENCIO. Ahora se consulta por ecosistema, con
    # ventana de fecha y paginando hasta agotar. Cobertura completa, no muestreo.
    # OJO: mandar `published` junto con `ecosystem` hace que GitHub DESCARTE el
    # filtro de ecosistema en silencio (ecosystem=npm devolvia nuget y maven).
    # Por eso el corte por fecha se hace del lado del cliente y `published` no
    # se manda. Sin esto uno cree tener cobertura por ecosistema y no la tiene.
    desde_adv = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
    for eco in ECOSISTEMAS:
        for pagina in range(1, 6):              # tope de seguridad: 500 por eco
            u = ("https://api.github.com/advisories?"
                 f"ecosystem={eco}&per_page=100&page={pagina}"
                 "&sort=published&direction=desc")
            r = http(u, etiqueta=f"advisories {eco} p{pagina}")
            if not r:
                break
            viejo = False
            for a in r:
                if a.get("published_at", "")[:10] < desde_adv:
                    viejo = True               # vienen ordenados desc: cortar
                    continue
                res = (a.get("summary") or "")
                pk = ", ".join(p["package"]["name"] for p in a.get("vulnerabilities", [])
                               if p.get("package"))
                if not NICHO_ESTRICTO.search(res + " " + pk):
                    continue
                out["advisories"].append((
                    a["ghsa_id"],
                    f"- **{a['ghsa_id']}** · {a.get('severity','?')} · `{pk[:50]}` · "
                    f"{a['published_at'][:10]} · {res[:110]}"))
            if viejo or len(r) < 100:
                break

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
    if not token_github():
        FALLOS.append("sin GITHUB_TOKEN → 60 req/h, la lectura va a quedar incompleta")
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
                alertas = actualizar_racimos(estado, nuevos)
                if alertas:      # lo mas importante del digest: va arriba de todo
                    partes_msg.insert(0, "## 🌱 CONVERGENCIA TEMPRANA\n" + "\n".join(alertas))
                    partes_arch.insert(0, "## 🌱 CONVERGENCIA TEMPRANA\n" + "\n".join(alertas))
                corto, largo = agrupar_repos(nuevos)
                hist = resumen_racimos(estado)
                partes_msg.append(f"{cab} — {len(nuevos)}\n{corto}")
                partes_arch.append(f"{cab} — {len(nuevos)}\n{largo}")
                partes_arch.append("### 📈 Acumulado histórico por racimo\n" + hist)
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
