#!/usr/bin/env python3
"""MCP Radar — consola de terminal.

Ver los datos y llegar de un tecleo al lugar exacto: el issue, el commit, el
archivo con el pin viejo, el advisory. Sin dependencias: curses de la stdlib.

  python3 tui.py

Teclas:  1/2/3 cambiar vista · ↑↓ o j/k mover · PgUp/PgDn saltar
         ENTER abrir lo principal · c commit · a advisory · r repo
         m o ESPACIO marcar revisado · v alternar qué se ve · n nota
         M marcar todo lo visible · u deshacer · f filtrar · R recargar · q salir
"""
import curses, json, os, re, subprocess, sys, textwrap, time, urllib.request

AQUI = os.path.dirname(os.path.abspath(__file__))
REPO = "Danyw24/mcp-radar"

# Estado "ya lo revisé". Vive al lado de los datos como el resto del estado del
# proyecto (radar-state.json, confirmed.json), pero se puede sacar del repo con
# MCP_RADAR_ESTADO: la lista de a quién ya miraste es inteligencia sobre TU
# operación — quién te importa y a quién ya contactaste — y no va en un repo
# público. Si el repo se sube: revisado.json al .gitignore.
ESTADO = os.environ.get("MCP_RADAR_ESTADO") or os.path.join(AQUI, "revisado.json")

MODOS = ["pendientes", "todo", "revisados"]     # qué filas se muestran


def token():
    t = os.environ.get("GITHUB_TOKEN")
    if t:
        return t.strip()
    f = os.path.expanduser("~/.config/mcp-radar/github-token")
    return open(f).read().strip() if os.path.exists(f) else None


def abrir(url):
    if not url:
        return
    env = dict(os.environ, DISPLAY=os.environ.get("DISPLAY", ":1"))
    subprocess.Popen(["xdg-open", url], env=env,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def leer_estado():
    """{clave: {cuando, huella, nota, titulo}}. Nunca revienta la consola."""
    try:
        d = json.load(open(ESTADO))
        return d.get("items", {}) if isinstance(d, dict) else {}
    except Exception:
        return {}


def guardar_estado(cambios):
    """Aplica SOLO las claves tocadas sobre lo que hay en disco.

    Releer antes de escribir en vez de volcar el dict en memoria: con dos
    consolas abiertas, la última en cerrar no pisa lo que marcó la otra. Y se
    escribe en un tmp con replace atómico porque una app curses muere de formas
    creativas (Ctrl-C, se cierra la terminal, SIGHUP) y un JSON cortado a la
    mitad es peor que no tener estado: te obliga a revisar todo de nuevo.
    """
    disco = leer_estado()
    for k, v in cambios.items():
        disco.pop(k, None) if v is None else disco.update({k: v})
    tmp = ESTADO + ".tmp"
    with open(tmp, "w") as fh:
        json.dump({"version": 1, "items": disco}, fh, indent=1, ensure_ascii=False)
    os.replace(tmp, ESTADO)


def cargar_hallazgos():
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{REPO}/issues?state=all&per_page=100",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "tui",
                     "Authorization": f"Bearer {token()}"})
        data = json.load(urllib.request.urlopen(req, timeout=30))
    except Exception as e:
        return [{"titulo": f"error cargando issues: {e}", "detalle": "", "urls": {}}]
    filas = []
    for i in data:
        if "pull_request" in i or not i["title"].startswith("[Vulnerability]"):
            continue
        L = {l["name"] for l in i["labels"]}
        ver = ("✅ real" if "true-positive" in L else
               "⚪ falso" if "false-positive" in L else "🟡 sin verificar")
        sev = next((l.split(":", 1)[1] for l in L if l.startswith("sev-verificada:")), "—")
        cuerpo = i.get("body") or ""
        mc = re.search(r"github\.com/([\w.-]+/[\w.-]+)/commit/([0-9a-f]{7,40})", cuerpo)
        filas.append({
            "titulo": f"#{i['number']:<3} {ver:16} sev:{sev:14} {i['title'][16:86]}",
            "detalle": cuerpo[:2000],
            "clave": f"iss:{i['number']}",
            # el número de issue no se mueve nunca; la huella es lo que hace que
            # vuelva a aparecer si alguien lo re-etiquetó después de tu revisión
            "huella": f"{ver}/{sev}/{i['state']}",
            "urls": {"principal": i["html_url"],
                     "commit": mc.group(0) if mc else "",
                     "repo": f"https://github.com/{mc.group(1)}" if mc else ""}})
    return filas or [{"titulo": "sin hallazgos", "detalle": "", "urls": {}}]


def cargar_exposicion():
    f = os.path.join(AQUI, "exposure.json")
    if not os.path.exists(f):
        return [{"titulo": "no hay exposure.json — corré: python3 exposure.py",
                 "detalle": "", "urls": {}}]
    d = json.load(open(f))
    filas = []
    for paq, info in d.get("paquetes", {}).items():
        filas.append({"titulo": f"── {paq}: seguro >= {info['corte_seguro']} · "
                                f"{info['poblacion_github']} repos en GitHub · "
                                f"{len(info['expuestos'])} expuestos en la muestra",
                      "detalle": "", "urls": {}, "cabecera": True})
        for e in info["expuestos"]:
            advs = e["advisories"]
            det = [f"repo: {e['repo']}", f"pin: {paq}=={e['pin']}  (seguro >= {info['corte_seguro']})",
                   f"archivo: {e['archivo']}", "",
                   f"{len(advs)} advisories lo alcanzan:"]
            det += [f"  · {a['id']}  fix en {a['fix']}  — {a['resumen'][:90]}" for a in advs[:12]]
            det += ["", "⚠️ un pin viejo es un CANDIDATO, no una víctima: hay que confirmar",
                    "   que ese archivo es el que corre y que usan el módulo afectado."]
            filas.append({
                "titulo": f"   {e['repo'][:44]:44} {paq}=={e['pin']:<12} {len(advs):>2} advisories",
                "detalle": "\n".join(det),
                # La clave sale de los DATOS, no del título: el título lleva el
                # pin y va truncado, así que cambia cuando el dueño toca una
                # línea del requirements. paquete+repo+ruta identifica el mismo
                # archivo entre corridas aunque exposure.json se regenere y las
                # filas cambien de orden (se ordenan por impacto, que se mueve).
                # repo en minúsculas porque GitHub no distingue mayúsculas en el
                # owner/nombre y la API las devuelve como las escribió el dueño.
                "clave": f"exp:{paq}|{e['repo'].lower()}|{e['archivo']}",
                # La huella queda AFUERA de la clave a propósito: si mañana
                # suben el pin o les cae otro advisory, sigue siendo el mismo
                # item (no lo revisás desde cero) pero reaparece marcado como
                # cambiado, que es exactamente la única novedad que vale mirar.
                "huella": f"{e['pin']}/{len(advs)}",
                "urls": {"principal": e["url_archivo"], "repo": e["url_repo"],
                         "advisory": f"https://github.com/advisories/{advs[0]['id']}" if advs else ""}})
    return filas


def cargar_digest():
    carpeta = os.path.join(AQUI, "digest")
    if not os.path.isdir(carpeta):
        return [{"titulo": "sin digests todavía", "detalle": "", "urls": {}}]
    filas = []
    for nombre in sorted(os.listdir(carpeta), reverse=True)[:10]:
        texto = open(os.path.join(carpeta, nombre)).read()
        filas.append({"titulo": f"── {nombre}  ({len(texto.splitlines())} líneas)",
                      "detalle": "", "urls": {}, "cabecera": True})
        for l in texto.splitlines():
            if l.startswith("- **"):
                m = re.search(r"\*\*([\w.\-/]+)\*\*", l)
                gh = re.search(r"(GHSA-[\w-]+)", l)
                # La clave NO incluye el nombre del digest: el mismo advisory
                # aparece en el de hoy y en el de ayer, y marcarlo una vez tiene
                # que callarlo en todos. Si la línea no trae nada identificable
                # se queda sin clave y entonces no se puede marcar (mejor eso
                # que una clave que colisione con otra fila distinta).
                ident = gh.group(1) if gh else m.group(1) if m else ""
                filas.append({
                    "titulo": "   " + re.sub(r"[*`]", "", l)[:110],
                    "detalle": l,
                    "clave": f"dig:{ident}" if ident else "",
                    "huella": ident,
                    "urls": {"principal": (f"https://github.com/advisories/{gh.group(1)}" if gh
                                           else f"https://github.com/{m.group(1)}" if m else "")}})
    return filas


VISTAS = [("1 Hallazgos", cargar_hallazgos),
          ("2 Exposición", cargar_exposicion),
          ("3 Digest", cargar_digest)]


def main(scr):
    curses.curs_set(0)
    curses.use_default_colors()
    for i, c in enumerate([curses.COLOR_CYAN, curses.COLOR_YELLOW, curses.COLOR_GREEN,
                           curses.COLOR_RED, curses.COLOR_MAGENTA], 1):
        curses.init_pair(i, c, -1)
    CY, AM, VE, RO, MA = (curses.color_pair(i) for i in range(1, 6))

    idx_vista, sel, desp, filtro = 0, 0, 0, ""
    cache = {}
    estado = leer_estado()
    modo = 0                       # arranca en "pendientes": el punto es no volver a mirar lo mismo
    deshacer = []                  # [(clave, valor_previo)] de la última operación

    def marca(fila):
        """(registro o None, ¿cambió desde que lo revisaste?)."""
        r = estado.get(fila.get("clave") or "")
        return (r, bool(r) and r.get("huella") != fila.get("huella"))

    def visible(fila):
        r, cambio = marca(fila)
        # Lo que cambió se muestra SIEMPRE aunque esté revisado: revisaste otra
        # cosa. Es la única fila que trae información nueva y esconderla es el
        # peor error posible de este sistema (te deja ciego creyendo que estás
        # al día). Las filas sin clave tampoco se ocultan nunca.
        if cambio or fila.get("cabecera") or not fila.get("clave"):
            return True
        return not r if modo == 0 else bool(r) if modo == 2 else True

    def compactar(filas):
        """Cabecera sin filas debajo = ruido. Al ocultar revisados, un paquete
        entero puede quedar vacío y su encabezado miente sobre lo que hay."""
        return [f for i, f in enumerate(filas)
                if not (f.get("cabecera") and
                        (i + 1 >= len(filas) or filas[i + 1].get("cabecera")))]

    def datos():
        n = VISTAS[idx_vista][0]
        if n not in cache:
            scr.addstr(1, 2, " cargando… ", AM | curses.A_BOLD)
            scr.refresh()
            cache[n] = VISTAS[idx_vista][1]()
        f = cache[n]
        if filtro:
            f = [x for x in f if filtro.lower() in x["titulo"].lower()]
        return compactar([x for x in f if visible(x)])

    def marcar(filas_a_marcar, quitar=False):
        """Marca o desmarca en bloque y persiste en una sola escritura."""
        ahora, cambios, previo = time.strftime("%Y-%m-%d %H:%M"), {}, []
        for f in filas_a_marcar:
            c = f.get("clave")
            if not c:
                continue
            previo.append((c, estado.get(c)))
            if quitar:
                estado.pop(c, None)
                cambios[c] = None
            else:
                cambios[c] = estado[c] = {"cuando": ahora, "huella": f.get("huella", ""),
                                          "titulo": f["titulo"].strip()[:110]}
        if cambios:
            guardar_estado(cambios)
        return previo

    while True:
        scr.erase()
        h, w = scr.getmaxyx()
        filas = datos()
        sel = max(0, min(sel, len(filas) - 1))

        tabs = "  ".join(f"[{n}]" if i == idx_vista else f" {n} "
                         for i, (n, _) in enumerate(VISTAS))
        scr.addstr(0, 0, " MCP RADAR ", curses.A_REVERSE | curses.A_BOLD)
        scr.addstr(0, 12, tabs[:w - 14], CY)
        # Contador siempre a la vista: ocultar filas sin decir cuántas ocultaste
        # convierte la consola en algo en lo que no podés confiar.
        marcables = [x for x in cache.get(VISTAS[idx_vista][0], []) if x.get("clave")]
        vistos = sum(1 for x in marcables if x["clave"] in estado)
        est = (f" ✓{vistos}/{len(marcables)} · {MODOS[modo]} "
               + (f"· filtro:{filtro} " if filtro else ""))
        if len(est) < w - 14:
            scr.addstr(0, w - len(est) - 1, est, MA)

        alto_lista = max(3, (h - 4) * 2 // 3)
        if sel < desp:
            desp = sel
        if sel >= desp + alto_lista:
            desp = sel - alto_lista + 1

        for n, fila in enumerate(filas[desp:desp + alto_lista]):
            y = 2 + n
            if y >= h - 1:
                break
            real = desp + n
            r, cambio = marca(fila)
            # ✓ y ↻ de un solo ancho, no emoji: curses cuenta celdas y los emoji
            # anchos descuadran la columna y rompen el addstr contra el borde.
            txt = (("↻ " if cambio else "✓ " if r else "  ") + fila["titulo"])[:w - 2]
            if fila.get("cabecera"):
                scr.addstr(y, 1, txt, AM | curses.A_BOLD)
            elif real == sel:
                scr.addstr(y, 1, txt.ljust(w - 2), curses.A_REVERSE)
            elif cambio:
                scr.addstr(y, 1, txt, MA | curses.A_BOLD)
            elif r:
                scr.addstr(y, 1, txt, curses.A_DIM)
            else:
                col = VE if "✅" in txt else RO if "⚠️" in txt or "🟡" in txt else 0
                scr.addstr(y, 1, txt, col)

        y0 = 2 + alto_lista
        scr.hline(y0, 0, curses.ACS_HLINE, w)
        det = filas[sel]["detalle"] if filas else ""
        if filas:
            r, cambio = marca(filas[sel])
            if r:
                enc = "✓ revisado " + r.get("cuando", "?")
                if r.get("nota"):
                    enc += f"  · nota: {r['nota']}"
                if cambio:
                    enc += (f"\n↻ CAMBIÓ desde entonces: {r.get('huella') or '?'} → "
                            f"{filas[sel].get('huella')}  (pin/advisories nuevos: vale volver a mirarlo)")
                det = enc + "\n\n" + det
        li = 1
        for parrafo in det.splitlines():
            for linea in textwrap.wrap(parrafo, w - 4) or [""]:
                if y0 + li >= h - 1:
                    break
                scr.addstr(y0 + li, 2, linea[:w - 3])
                li += 1
            if y0 + li >= h - 1:
                break

        urls = filas[sel].get("urls", {}) if filas else {}
        ayuda = " ENTER abrir · m/␣ revisado · v ver:" + MODOS[(modo + 1) % 3] + " · n nota " + \
                ("· c commit " if urls.get("commit") else "") + \
                ("· a advisory " if urls.get("advisory") else "") + \
                ("· r repo " if urls.get("repo") else "") + \
                "· M marcar visibles · u deshacer · f filtrar · R recargar · q salir"
        scr.addstr(h - 1, 0, ayuda[:w - 1].ljust(w - 1), curses.A_REVERSE)
        scr.refresh()

        k = scr.getch()
        if k in (ord("q"), 27):
            break
        elif k in (curses.KEY_DOWN, ord("j")):
            sel += 1
        elif k in (curses.KEY_UP, ord("k")):
            sel -= 1
        elif k == curses.KEY_NPAGE:
            sel += alto_lista
        elif k == curses.KEY_PPAGE:
            sel -= alto_lista
        elif k in (ord("1"), ord("2"), ord("3")):
            idx_vista, sel, desp = int(chr(k)) - 1, 0, 0
        elif k in (10, 13, curses.KEY_ENTER, ord("o")):
            abrir(urls.get("principal"))
        elif k == ord("c"):
            abrir(urls.get("commit"))
        elif k == ord("a"):
            abrir(urls.get("advisory"))
        elif k == ord("r"):
            abrir(urls.get("repo"))
        elif k == ord("R"):
            cache.clear()
            estado = leer_estado()          # otra consola pudo haber marcado cosas
        elif k in (ord("m"), ord(" ")) and filas and filas[sel].get("clave"):
            fila = filas[sel]
            deshacer = marcar([fila], quitar=bool(estado.get(fila["clave"])))
            # En modo "pendientes" la fila desaparece sola y sel ya apunta a la
            # siguiente, como una bandeja de entrada; en los otros modos hay que
            # bajar a mano para que ESPACIO sirva de "marcar y seguir".
            if k == ord(" ") and modo != 0:
                sel += 1
        elif k == ord("M") and filas:
            pend = [x for x in filas if x.get("clave") and x["clave"] not in estado]
            if pend:
                # Confirmación explícita: marcar 90 filas de un tecleo es fácil
                # de hacer sin querer y u sólo recuerda la última operación.
                scr.addstr(h - 1, 0, f" ¿marcar {len(pend)} filas visibles como revisadas? (s/n) "
                           .ljust(w - 1), curses.A_REVERSE)
                if scr.getch() in (ord("s"), ord("S"), ord("y")):
                    deshacer = marcar(pend)
        elif k == ord("u") and deshacer:
            cambios = {}
            for c, previo in deshacer:
                estado.pop(c, None) if previo is None else estado.update({c: previo})
                cambios[c] = previo
            guardar_estado(cambios)
            deshacer = []
        elif k == ord("n") and filas and filas[sel].get("clave"):
            fila = filas[sel]
            curses.echo()
            scr.addstr(h - 1, 0, " nota: ".ljust(w - 1), curses.A_REVERSE)
            nota = scr.getstr(h - 1, 7, 80).decode("utf8", "replace").strip()
            curses.noecho()
            # Escribir una nota ES haberlo revisado: marca sola, sin pedir dos teclas.
            if not estado.get(fila["clave"]):
                deshacer = marcar([fila])
            reg = dict(estado[fila["clave"]], nota=nota)
            estado[fila["clave"]] = reg
            guardar_estado({fila["clave"]: reg})
        elif k == ord("v"):
            modo, sel, desp = (modo + 1) % 3, 0, 0
        elif k == ord("f"):
            curses.echo()
            scr.addstr(h - 1, 0, " filtro: ".ljust(w - 1), curses.A_REVERSE)
            filtro = scr.getstr(h - 1, 9, 40).decode("utf8", "replace").strip()
            curses.noecho()
            sel = 0


if __name__ == "__main__":
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        pass
