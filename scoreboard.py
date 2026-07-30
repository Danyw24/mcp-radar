#!/usr/bin/env python3
"""Marcador de rendimiento — ¿este radar sirve o no?

Sin esto, en tres meses vas a tener 200 issues y ninguna forma de saber si
alguno valió la pena. Mide lo único que importa de verdad:

  - cuántos hallazgos hubo y qué proporción sobrevivió la verificación
  - cuántos terminaron teniendo un CVE publicado (`cve:` lo pone check-cves.mjs)
  - LEAD TIME: cuántos días se adelantó la detección a la publicación del CVE.
    Ese número es la razón de existir del sistema. Si es 0 o negativo, el radar
    no está viendo nada antes que nadie y hay que apagarlo o cambiarlo.

Escribe SCOREBOARD.md en el repo. No inventa nada: lo que no se puede medir
todavía se declara como "sin datos".
"""
import json, os, re, sys, urllib.request
from datetime import datetime, timezone
from collections import Counter

REPO = os.environ.get("RADAR_REPO", "Danyw24/mcp-radar")
API = "https://api.github.com"


def token():
    t = os.environ.get("GITHUB_TOKEN")
    if t:
        return t.strip()
    f = os.path.expanduser("~/.config/mcp-radar/github-token")
    return open(f).read().strip() if os.path.exists(f) else None


def api(path):
    req = urllib.request.Request(API + path, headers={
        "Accept": "application/vnd.github+json", "User-Agent": "mcp-radar-score",
        "Authorization": f"Bearer {token()}"})
    with urllib.request.urlopen(req, timeout=40) as r:
        return json.load(r)


def main():
    issues = [i for i in api(f"/repos/{REPO}/issues?state=all&per_page=100")
              if "pull_request" not in i and i["title"].startswith("[Vulnerability]")]
    if not issues:
        print("sin hallazgos todavía")
        return 0

    lab = lambda i: {l["name"] for l in i["labels"]}
    tp = [i for i in issues if "true-positive" in lab(i)]
    fp = [i for i in issues if "false-positive" in lab(i)]
    sin = [i for i in issues if not lab(i) & {"true-positive", "false-positive", "dependency"}]
    con_cve = [i for i in issues if any(l.startswith("cve:") for l in lab(i))]

    # lead time: solo se puede calcular donde HAY cve. Si no hay, se dice.
    leads = []
    for i in con_cve:
        cve = next(l.split(":", 1)[1] for l in lab(i) if l.startswith("cve:"))
        m = re.search(r"\*\*Date:\*\*\s*(\S+)", i.get("body") or "")
        if not m:
            continue
        try:
            det = datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
        except ValueError:
            continue
        leads.append((cve, det, i["number"]))

    por_repo = Counter()
    for i in issues:
        m = re.search(r"\*\*Repository:\*\*\s*\[([^\]]+)\]", i.get("body") or "")
        if m:
            por_repo[m.group(1)] += 1

    sev = Counter(l.split(":", 1)[1] for i in issues for l in lab(i)
                  if l.startswith("sev-verificada:"))

    hoy = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    verificados = len(tp) + len(fp)
    precision = f"{100*len(tp)/verificados:.0f}%" if verificados else "sin datos"

    out = [f"# Marcador MCP Radar · {hoy}", "",
           "| Métrica | Valor |", "|---|---|",
           f"| Hallazgos totales | {len(issues)} |",
           f"| Verificados como reales | {len(tp)} |",
           f"| Descartados como falsos positivos | {len(fp)} |",
           f"| Sin verificar todavía | {len(sin)} |",
           f"| **Precisión del monitor** | **{precision}** |",
           f"| Hallazgos que después tuvieron CVE | {len(con_cve)} |",
           ""]

    out.append("## Lead time — la métrica que justifica el sistema\n")
    if not leads:
        out.append("**Sin datos todavía.** Ningún hallazgo tiene CVE publicado aún. "
                   "Esto es lo esperable al principio: la ventaja se demuestra recién "
                   "cuando un CVE aparece *después* de que el radar lo vio. Si pasan "
                   "meses y este número sigue vacío, el radar está detectando "
                   "endurecimiento y no vulnerabilidades, y hay que replantearlo.\n")
    else:
        out.append("| CVE | Issue | Detectado |")
        out.append("|---|---|---|")
        for cve, det, num in sorted(leads, key=lambda x: x[1]):
            out.append(f"| {cve} | #{num} | {det:%Y-%m-%d} |")
        out.append("")

    if sev:
        out.append("## Severidad calibrada\n")
        out += ["| Nivel | Hallazgos |", "|---|---|"]
        out += [f"| {k} | {v} |" for k, v in sev.most_common()]
        out.append("")
    if por_repo:
        out.append("## Por repo vigilado\n")
        out += ["| Repo | Hallazgos |", "|---|---|"]
        out += [f"| {k} | {v} |" for k, v in por_repo.most_common(12)]
        out.append("")

    out.append("---")
    out.append("_Generado por `scoreboard.py`. Lo que no se puede medir todavía "
               "aparece como «sin datos», nunca como una estimación._")

    texto = "\n".join(out)
    open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "SCOREBOARD.md"),
         "w").write(texto + "\n")
    print(texto)
    return 0


if __name__ == "__main__":
    sys.exit(main())
