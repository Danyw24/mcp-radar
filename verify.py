#!/usr/bin/env python3
"""Verificador de hallazgos — post-filtro sobre los issues que abre el monitor.

Por que existe: el judge del action pregunta "¿esto es un arreglo de seguridad?"
y con eso pasa cualquier trabajo de auth, incluida documentacion. Un falso
positivo es peor que no tener nada: quema credibilidad con el mantenedor al que
despues le vas a reportar algo de verdad.

La senal mas afinada y mas barata NO es un LLM: son las **etiquetas del PR** que
puso el propio mantenedor, mas el cuerpo del PR donde explica que arreglaba.
Un `documentation` resuelve el caso sin gastar un token.

  python3 verify.py              # dry-run: solo muestra el veredicto
  python3 verify.py --apply      # ademas etiqueta y comenta en los issues
"""
import json, os, re, sys, urllib.request, urllib.error
from collections import defaultdict

REPO = "Danyw24/mcp-radar"
API = "https://api.github.com"

# Etiquetas de PR que deciden solas, sin consultar a ningun modelo.
DESCARTE = {"documentation", "docs", "chore", "dependencies", "ci", "build",
            "refactor", "test", "tests", "style"}
ESCALA = {"security", "vulnerability", "cve"}
CANDIDATA = {"bug", "auth", "authentication", "authorization", "fix"}


def token():
    t = os.environ.get("GITHUB_TOKEN")
    if t:
        return t.strip()
    f = os.path.expanduser("~/.config/mcp-radar/github-token")
    return open(f).read().strip() if os.path.exists(f) else None


def api(path, data=None, method=None):
    cab = {"Accept": "application/vnd.github+json", "User-Agent": "mcp-radar-verify",
           "Authorization": f"Bearer {token()}"}
    if data is not None:
        data = json.dumps(data).encode()
        cab["Content-Type"] = "application/json"
    req = urllib.request.Request(API + path, data=data, headers=cab, method=method)
    with urllib.request.urlopen(req, timeout=40) as r:
        return json.load(r) if r.status != 204 else {}


# Rutas donde un cambio pesa mas: si el diff cae aca, el contexto es sensible.
RUTAS_SENSIBLES = re.compile(
    r"auth|token|session|credential|permission|scope|oauth|jwt|crypto|"
    r"transport|middleware|proxy|exec|shell|subprocess|path|upload|deserial", re.I)

# Sinks: si una linea AGREGADA o QUITADA los toca, hay superficie de ataque real.
SINKS = re.compile(
    r"os\.system|subprocess|popen|eval\(|exec\(|pickle\.loads|yaml\.load\(|"
    r"open\(|os\.path\.join|shutil\.|__import__|innerHTML|child_process", re.I)

# Guardas: lo que un parche de seguridad AGREGA.
GUARDAS = re.compile(
    r"\b(if|assert|raise|throw)\b.*\b(valid|verify|check|allow|deny|forbid|"
    r"unauthor|permission|expect|match|require|sanitiz|escape|normaliz)", re.I)

# Confesiones: comentarios que admiten un hueco conocido. Si aparecen en lineas
# QUITADAS, el mantenedor esta cerrando una deuda que el mismo habia documentado
# — es trabajo anunciado, no un parche silencioso. Este era el agujero del #5.
CONFESION = re.compile(
    r"deliberately|on purpose|tracked separately|known (issue|limitation|gap)|"
    r"\bTODO\b|\bFIXME\b|\bXXX\b|for now|temporar|workaround|should be|"
    r"not (yet )?(safe|validated|checked)", re.I)


def evidencia_diff(repo, sha):
    """Lee el diff real y devuelve evidencia citable de dónde puede haber hueco."""
    try:
        d = api(f"/repos/{repo}/commits/{sha}")
    except urllib.error.HTTPError:
        return None
    ev = {"archivos_sensibles": [], "guardas": [], "sinks": [],
          "confesiones_quitadas": [], "tests_adversarios": 0, "solo_docs": True}
    for f in d.get("files", []):
        nombre = f["filename"]
        es_doc = nombre.endswith((".md", ".mdx", ".rst", ".txt")) or nombre.startswith("docs/")
        es_test = "test" in nombre.lower()
        if not es_doc:
            ev["solo_docs"] = False
        patch = f.get("patch") or ""
        if es_test:
            ev["tests_adversarios"] += sum(
                1 for l in patch.splitlines()
                if l.startswith("+") and re.search(r"malicious|attack|evil|inject|traversal|"
                                                   r"unauthor|bypass|forbid|boundary|escape", l, re.I))
            continue
        if es_doc:
            continue
        if RUTAS_SENSIBLES.search(nombre):
            ev["archivos_sensibles"].append(nombre)
        for linea in patch.splitlines():
            corta = linea[1:].strip()[:150]
            if linea.startswith("+") and not linea.startswith("+++"):
                if GUARDAS.search(linea):
                    ev["guardas"].append((nombre, corta))
                if SINKS.search(linea):
                    ev["sinks"].append((nombre, "+ " + corta))
            elif linea.startswith("-") and not linea.startswith("---"):
                if CONFESION.search(linea):
                    ev["confesiones_quitadas"].append((nombre, corta))
                if SINKS.search(linea):
                    ev["sinks"].append((nombre, "- " + corta))
    return ev


def veredicto(labels, cuerpo_pr, titulo_pr):
    """Devuelve (disposicion, motivo). Las etiquetas mandan sobre el texto."""
    ls = {l.lower() for l in labels}
    if ls & ESCALA:
        return "true-positive", f"el mantenedor lo etiquetó `{'`, `'.join(sorted(ls & ESCALA))}`"
    if ls & DESCARTE and not (ls & CANDIDATA):
        return "false-positive", f"PR etiquetado `{'`, `'.join(sorted(ls & DESCARTE))}` — no es un arreglo de seguridad"
    if ls & CANDIDATA:
        # bug/auth: candidato real, pero hay que ver si es silencioso o anunciado
        texto = (titulo_pr + " " + cuerpo_pr).lower()
        anunciado = re.search(r"tracked separately|by design|deliberate|known (issue|limitation)|"
                              r"follow-?up to|as discussed|refactor", texto)
        if anunciado:
            return "revisar", ("es `bug`/`auth` pero el PR lo explica como trabajo planificado "
                               f"(«{anunciado.group(0)}»): no es un parche silencioso")
        return "true-positive", f"PR etiquetado `{'`, `'.join(sorted(ls & CANDIDATA))}` y no se auto-explica como diseño"
    if not ls:
        return "revisar", "el PR no tiene etiquetas — hace falta leer el diff"
    return "revisar", f"etiquetas no concluyentes: `{'`, `'.join(sorted(ls))}`"


def main():
    aplicar = "--apply" in sys.argv
    issues = [i for i in api(f"/repos/{REPO}/issues?state=open&per_page=100")
              if "pull_request" not in i
              and not {l["name"] for l in i["labels"]} & {"true-positive", "false-positive", "dependency"}]
    print(f"{len(issues)} issues sin veredicto\n")

    por_pr = defaultdict(list)
    filas = []
    for i in issues:
        cuerpo = i.get("body") or ""
        m = re.search(r"github\.com/([\w.-]+/[\w.-]+)/commit/([0-9a-f]{7,40})", cuerpo)
        if not m:
            filas.append((i, None, "revisar", "no pude extraer el commit del issue", None))
            continue
        repo_up, sha = m.group(1), m.group(2)
        try:
            prs = api(f"/repos/{repo_up}/commits/{sha}/pulls")
        except urllib.error.HTTPError:
            prs = []
        if not prs:
            filas.append((i, None, "revisar", "el commit no vino de un PR — hay que leer el diff", None))
            continue
        p = prs[0]
        por_pr[(repo_up, p["number"])].append(i["number"])
        labels = [l["name"] for l in p.get("labels", [])]
        d, motivo = veredicto(labels, p.get("body") or "", p.get("title") or "")
        ev = evidencia_diff(repo_up, sha)
        if ev:
            if ev["solo_docs"]:
                d, motivo = "false-positive", "el diff no toca una sola línea de código: solo documentación"
            elif ev["confesiones_quitadas"] and d == "true-positive":
                d = "revisar"
                motivo += (" — PERO el diff quita un comentario que admitía el hueco "
                           "como conocido: es deuda anunciada, no parche silencioso")
        filas.append((i, p, d, motivo, ev))

    orden = {"true-positive": 0, "revisar": 1, "false-positive": 2}
    for i, p, d, motivo, ev in sorted(filas, key=lambda x: orden.get(x[2], 9)):
        icono = {"true-positive": "🔴", "revisar": "🟡", "false-positive": "⚪"}[d]
        pr = f"PR #{p['number']}" if p else "sin PR"
        print(f"\n{icono} #{i['number']:<3} [{d:14}] {pr:9} {i['title'][:60]}")
        print(f"        → {motivo}")
        if ev:
            if ev["archivos_sensibles"]:
                print(f"        📍 zona sensible: {', '.join(ev['archivos_sensibles'][:3])}")
            for f_, l_ in ev["confesiones_quitadas"][:2]:
                print(f"        🗣  confesión quitada en {f_.split('/')[-1]}: «{l_[:96]}»")
            for f_, l_ in ev["guardas"][:2]:
                print(f"        🛡  guarda agregada en {f_.split('/')[-1]}: {l_[:96]}")
            for f_, l_ in ev["sinks"][:2]:
                print(f"        ⚠️  sink tocado en {f_.split('/')[-1]}: {l_[:96]}")
            if ev["tests_adversarios"]:
                print(f"        🧪 {ev['tests_adversarios']} líneas de test adversario agregadas")

    # duplicados: varios issues para el MISMO PR
    dups = {k: v for k, v in por_pr.items() if len(v) > 1}
    if dups:
        print("\n⚠️ DUPLICADOS — varios issues para un mismo PR:")
        for (r, n), iss in dups.items():
            print(f"   {r} PR #{n} → issues {iss} (conservar #{min(iss)})")

    if not aplicar:
        print("\n(dry-run — usá --apply para etiquetar y comentar)")
        return 0

    for i, p, d, motivo, ev in filas:
        if d == "revisar":
            continue
        api(f"/repos/{REPO}/issues/{i['number']}/labels", {"labels": [d]})
        api(f"/repos/{REPO}/issues/{i['number']}/comments",
            {"body": f"**Verificación automática: `{d}`**\n\n{motivo}\n\n"
                     + (f"PR original: {p['html_url']} · etiquetas del mantenedor: "
                        f"`{'`, `'.join(l['name'] for l in p.get('labels', [])) or 'ninguna'}`"
                        if p else "")})
        print(f"  aplicado {d} a #{i['number']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
