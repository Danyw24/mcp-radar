#!/usr/bin/env python3
"""Auditoría del corpus vigilado — ¿estos 20 repos merecen estar?

La lista se armó priorizando cobertura del ecosistema, y ese fue el criterio
equivocado: de los 20, los 5 hallazgos salieron todos de uno solo. Un repo entra
si cumple LAS TRES cosas juntas, no una:

  1. IMPACTO    — tiene usuarios a los que un bug les haga daño
  2. RITMO      — commitea lo suficiente para que un parche silencioso ocurra
  3. SILENCIO   — tiende a arreglar sin publicar advisory (ahí está la ventana)

El tercero es el contraintuitivo: un repo que publica advisories por cada bug NO
tiene ventana que explotar, porque avisa. La ventana vive en los que arreglan y
siguen. Se aproxima con la razón entre advisories publicados y actividad.

  python3 audit_corpus.py
"""
import json, os, re, sys, time, urllib.request, urllib.parse, urllib.error
from datetime import datetime, timezone, timedelta

AQUI = os.path.dirname(os.path.abspath(__file__))
SENSIBLE = re.compile(r"auth|token|session|credential|permission|scope|oauth|jwt|"
                      r"crypto|transport|proxy|exec|shell|subprocess|path|upload", re.I)


def token():
    t = os.environ.get("GITHUB_TOKEN")
    if t:
        return t.strip()
    f = os.path.expanduser("~/.config/mcp-radar/github-token")
    return open(f).read().strip() if os.path.exists(f) else None


def gh(url):
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json", "User-Agent": "mcp-radar-audit",
        "Authorization": f"Bearer {token()}"})
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            return json.load(r)
    except urllib.error.HTTPError:
        return None


def advisories_del_repo(full):
    """Cuántos advisories publicó GitHub para paquetes de este repo."""
    nombre = full.split("/")[-1]
    r = gh(f"https://api.github.com/search/issues?q=" +
           urllib.parse.quote(f'repo:{full} type:issue label:security')) or {}
    # aproximación barata: advisories publicados en el repo
    adv = gh(f"https://api.github.com/repos/{full}/security-advisories?per_page=100")
    return len(adv) if isinstance(adv, list) else 0


def main():
    repos = json.load(open(os.path.join(AQUI, "repos.json")))
    desde = (datetime.now(timezone.utc) - timedelta(days=14)).strftime("%Y-%m-%dT00:00:00Z")
    filas = []
    for r in repos:
        full = f"{r['owner']}/{r['repo']}"
        d = gh(f"https://api.github.com/repos/{full}")
        if not d:
            print(f"  no accesible: {full}", file=sys.stderr)
            continue
        commits = gh(f"https://api.github.com/repos/{full}/commits?since={desde}&per_page=100") or []
        n_adv = advisories_del_repo(full)
        estrellas = d.get("stargazers_count", 0)
        ritmo = len(commits)

        # los tres criterios, cada uno 0-100
        impacto = min(100, 15 + estrellas // 300)
        actividad = 0 if ritmo == 0 else 30 if ritmo < 3 else 65 if ritmo < 20 else \
                    100 if ritmo < 120 else 55          # >120/14d = demasiado ruido
        # publica mucho => menos ventana. 0 advisories con actividad alta => ventana probable
        silencio = 90 if n_adv == 0 and ritmo > 3 else 60 if n_adv <= 2 else 30

        # Un repo de altisimo impacto con poco ritmo es BARATO de vigilar y
        # sigue valiendo: pocos commits = pocas llamadas de triaje, y un parche
        # silencioso ahi importa muchisimo. Solo se saca si ademas es chico.
        veredicto = ("MANTENER — bajo ritmo pero alto impacto" if ritmo <= 1 and estrellas >= 20000 else
                     "SACAR — sin ritmo" if ritmo <= 1 else
                     "SACAR — sin usuarios" if estrellas < 500 and ritmo < 10 else
                     "CASO APARTE — volumen alto, necesita filtro por ruta" if ritmo >= 120 else
                     "MANTENER")
        filas.append({"repo": full, "estrellas": estrellas, "commits14d": ritmo,
                      "advisories": n_adv, "impacto": impacto, "actividad": actividad,
                      "silencio": silencio,
                      "total": round((impacto + actividad + silencio) / 3),
                      "veredicto": veredicto})
        time.sleep(0.3)

    filas.sort(key=lambda x: -x["total"])
    print(f"{'total':>5} {'⭐':>7} {'c/14d':>6} {'adv':>4}  {'repo':40} veredicto")
    for f in filas:
        print(f"{f['total']:>5} {f['estrellas']:>7} {f['commits14d']:>6} {f['advisories']:>4}  "
              f"{f['repo'][:40]:40} {f['veredicto']}")

    sacar = [f for f in filas if f["veredicto"].startswith("SACAR")]
    aparte = [f for f in filas if f["veredicto"].startswith("CASO")]
    print(f"\nMANTENER: {len(filas)-len(sacar)-len(aparte)} · SACAR: {len(sacar)} · CASO APARTE: {len(aparte)}")
    if sacar:
        print("propuesta de poda: " + ", ".join(f["repo"] for f in sacar))

    json.dump(filas, open(os.path.join(AQUI, "corpus-audit.json"), "w"), indent=1)
    return 0


if __name__ == "__main__":
    import urllib.parse
    sys.exit(main())
