#!/usr/bin/env python3
"""MCP Radar — consola de terminal.

Ver los datos y llegar de un tecleo al lugar exacto: el issue, el commit, el
archivo con el pin viejo, el advisory. Sin dependencias: curses de la stdlib.

  python3 tui.py

Teclas:  1/2/3 cambiar vista · ↑↓ o j/k mover · PgUp/PgDn saltar
         ENTER abrir lo principal · c commit · a advisory · r repo
         f filtrar · R recargar · q salir
"""
import curses, json, os, re, subprocess, sys, textwrap, urllib.request

AQUI = os.path.dirname(os.path.abspath(__file__))
REPO = "Danyw24/mcp-radar"


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
                filas.append({
                    "titulo": "   " + re.sub(r"[*`]", "", l)[:110],
                    "detalle": l,
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

    def datos():
        n = VISTAS[idx_vista][0]
        if n not in cache:
            scr.addstr(1, 2, " cargando… ", AM | curses.A_BOLD)
            scr.refresh()
            cache[n] = VISTAS[idx_vista][1]()
        f = cache[n]
        if filtro:
            f = [x for x in f if filtro.lower() in x["titulo"].lower()]
        return f

    while True:
        scr.erase()
        h, w = scr.getmaxyx()
        filas = datos()
        sel = max(0, min(sel, len(filas) - 1))

        tabs = "  ".join(f"[{n}]" if i == idx_vista else f" {n} "
                         for i, (n, _) in enumerate(VISTAS))
        scr.addstr(0, 0, " MCP RADAR ", curses.A_REVERSE | curses.A_BOLD)
        scr.addstr(0, 12, tabs[:w - 14], CY)
        if filtro:
            scr.addstr(0, max(12, w - len(filtro) - 12), f" filtro:{filtro} ", MA)

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
            txt = fila["titulo"][:w - 2]
            if fila.get("cabecera"):
                scr.addstr(y, 1, txt, AM | curses.A_BOLD)
            elif real == sel:
                scr.addstr(y, 1, txt.ljust(w - 2), curses.A_REVERSE)
            else:
                col = VE if "✅" in txt else RO if "⚠️" in txt or "🟡" in txt else 0
                scr.addstr(y, 1, txt, col)

        y0 = 2 + alto_lista
        scr.hline(y0, 0, curses.ACS_HLINE, w)
        det = filas[sel]["detalle"] if filas else ""
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
        ayuda = " ENTER abrir " + ("· c commit " if urls.get("commit") else "") + \
                ("· a advisory " if urls.get("advisory") else "") + \
                ("· r repo " if urls.get("repo") else "") + "· f filtrar · R recargar · q salir"
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
