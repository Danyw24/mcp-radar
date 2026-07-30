#!/usr/bin/env python3
"""Comparación de versiones y veredicto de exposición. Solo stdlib.

Dos ecosistemas, dos gramáticas distintas: PEP 440 (PyPI) y semver 2.0.0 (npm).
El MISMO string cambia de significado según el ecosistema (`1.0.0-1` es post1 en
PyPI —MAYOR que 1.0.0— y prerelease en npm —MENOR—), así que toda función toma
`eco` y no existe una comparación universal correcta.

Todo veredicto tiene TRES estados. Un pin es aritmética; un rango es una apuesta
sobre cuándo se instaló. 'indeterminado' es la respuesta honesta a esa apuesta, y
un booleano ahí es un falso positivo disfrazado.

Autotest:  python3 versiones.py    (sale 1 si algo falla)
"""
import re

# Cota de longitud: int() revienta con ValueError arriba de 4300 dígitos
# (CVE-2020-10735 / sys.set_int_max_str_digits). Una versión legítima nunca
# pasa de esto; una entrada de 40 KB sí, y no puede tumbar el barrido.
_MAX = 4000

# ---------------------------------------------------------------- PEP 440 ---

# a < b < rc: la comparación es por la LETRA canónica, no por el texto escrito.
_PRE_CANON = {"a": "a", "alpha": "a", "b": "b", "beta": "b",
              "c": "rc", "pre": "rc", "preview": "rc", "rc": "rc"}

_RE_440 = re.compile(r"""
    ^\s*v?
    (?:(?P<epoch>[0-9]+)!)?                                    # 1!1.0 > 2.0
    (?P<release>[0-9]+(?:\.[0-9]+)*)                           # sin límite de 3
    (?:[-_.]?(?P<pre_l>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?P<post>-(?P<post_n1>[0-9]+)                              # 1.0-1 == 1.0.post1
        |[-_.]?(?:post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?)?
    (?:[-_.]?(?P<dev>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?             # local, NO release
    \s*$""", re.VERBOSE | re.IGNORECASE)


def _clave_pep440(s):
    m = _RE_440.match(s)
    if not m:
        return None
    epoch = int(m.group("epoch") or 0)
    release = tuple(int(x) for x in m.group("release").split("."))
    # 2.13 y 2.13.0 son LA MISMA versión: podar ceros finales lo vuelve exacto
    # sin rellenar a un largo arbitrario. Truncar a 3 (como hacía ver()) borra
    # información real: fastmcp publica 2.13.0.2.
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]

    pre = (_PRE_CANON[m.group("pre_l").lower()], int(m.group("pre_n") or 0)) \
        if m.group("pre_l") else None
    post = int(m.group("post_n1") or m.group("post_n2") or 0) \
        if m.group("post") else None
    dev = int(m.group("dev_n") or 0) if m.group("dev") else None

    if pre is None and post is None and dev is not None:
        k_pre = (-1, "", 0)          # 1.0.dev1 va antes que 1.0a1
    elif pre is None:
        k_pre = (1, "", 0)           # el release final va después de todo pre
    else:
        k_pre = (0, pre[0], pre[1])

    k_post = (0, "", post) if post is not None else (-1, "", 0)
    k_dev = (0, "", dev) if dev is not None else (1, "", 0)   # 1.0.dev1 < 1.0

    loc = m.group("local")
    if loc:
        # en el segmento local lo numérico ordena por encima de lo alfabético
        k_loc = tuple((1, "", int(p)) if p.isdigit() else (0, p.lower(), 0)
                      for p in re.split(r"[-_.]", loc))
    else:
        k_loc = ((-1, "", 0),)       # 1.0 < 1.0+local

    return (epoch, release, k_pre, k_post, k_dev, k_loc)


def clave_pep440(s):
    """Clave comparable PEP 440, o None si el texto no es una versión.

    Los campos se codifican como tuplas homogéneas (int, str, int) porque Python
    revienta al comparar int con str dentro de la misma tupla; los centinelas de
    `packaging` (Infinity/NegativeInfinity) se emulan con un rango entero al frente.
    Nunca lanza: entradas no-str, gigantes o basura devuelven None.
    """
    if not isinstance(s, str) or not s or len(s) > _MAX:
        return None
    try:
        return _clave_pep440(s)
    except (ValueError, TypeError):
        return None


# ----------------------------------------------------------- semver 2.0.0 ---

# pre/build NO admiten identificadores vacíos: "1.0.0-." y "1.2.3+a..b" son
# INVÁLIDAS para semver@7 y aceptarlas convertía basura en un pin exacto.
_RE_SEMVER = re.compile(r"""
    ^\s*v?
    (?P<maj>0|[1-9][0-9]*)
    (?:\.(?P<min>0|[1-9][0-9]*))?
    (?:\.(?P<pat>0|[1-9][0-9]*))?
    (?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?
    (?:\+(?P<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?
    \s*$""", re.VERBOSE)


def _clave_semver(s, laxo):
    t = s.strip()
    m = _RE_SEMVER.match(t)
    if not m and laxo:
        # pelar el 'v' ANTES de normalizar: con lookbehind alfanumérico,
        # "v01.2.3" no se normalizaba y devolvía None (npm loose lo acepta).
        t2 = re.sub(r"^\s*v", "", t)
        t2 = re.sub(r"(?<![0-9])0+([0-9])", r"\1", t2)   # 01.02.3 -> 1.2.3
        m = _RE_SEMVER.match(t2)
    if not m:
        return None
    nums = (int(m.group("maj")), int(m.group("min") or 0), int(m.group("pat") or 0))
    pre = m.group("pre")
    if pre is None:
        k_pre = ((2, "", 0),)        # sin prerelease: mayor que cualquier prerelease
    else:
        ids = []
        for p in pre.split("."):
            if p.isdigit() and (laxo or not (len(p) > 1 and p[0] == "0")):
                ids.append((0, "", int(p)))      # numérico < alfanumérico
            else:
                ids.append((1, p, 0))
        k_pre = tuple(ids)
    # el build metadata (+abc) NO participa de la precedencia: se descarta
    return (nums, k_pre)


def clave_semver(s, laxo=True):
    """Clave comparable semver 2.0.0, o None.

    `laxo` acepta lo que npm acepta en la práctica y el estándar no: ceros a la
    izquierda (`01.2.3`, `v01.2.3`) y versiones parciales (`1.2`).
    """
    if not isinstance(s, str) or not s or len(s) > _MAX:
        return None
    try:
        return _clave_semver(s, laxo)
    except (ValueError, TypeError):
        return None


# ----------------------------------------------------------------- API ------

def _es_npm(eco):
    return str(eco).lower() in ("npm", "semver", "node", "javascript", "js")


def clave(s, eco="PyPI"):
    """Clave comparable según ecosistema. None si no se entiende el texto."""
    return clave_semver(s) if _es_npm(eco) else clave_pep440(s)


def comparar(a, b, eco="PyPI"):
    """-1 si a<b, 0 si a==b, 1 si a>b. ValueError si alguna no parsea."""
    ka, kb = clave(a, eco), clave(b, eco)
    if ka is None or kb is None:
        raise ValueError(f"versión no parseable ({eco}): {a!r} / {b!r}")
    return -1 if ka < kb else (0 if ka == kb else 1)


def clave_orden(s, eco="PyPI"):
    """Clave para sorted() que nunca revienta: lo impresentable va al fondo."""
    k = clave(s, eco)
    return (1, k) if k is not None else (0, clave("0", eco))


# --------------------------------------------------- rangos y veredicto -----

def _epoch(s):
    """Prefijo de epoch ('1!' o ''). Sin esto, todo rango con epoch caía al
    universo epoch 0 y `==1!1.2.*` se declaraba expuesto contra un fix 1.3.0
    siendo que 1!1.2.0 es MAYOR que cualquier 1.x."""
    m = re.match(r"\s*v?([0-9]{1,9})!", s or "")
    return m.group(1) + "!" if m else ""


def _ints(s):
    """Componentes numéricos del release, ignorando epoch/pre/post/local."""
    if not isinstance(s, str) or len(s) > _MAX:
        return []
    m = re.match(r"\s*v?(?:[0-9]+!)?([0-9]+(?:\.[0-9]+)*)", s)
    if not m:
        return []
    try:
        return [int(x) for x in m.group(1).split(".")]
    except ValueError:
        return []


def _bump(partes, idx, ep=""):
    p = list(partes) + [0] * (idx + 1 - len(partes))
    p = p[:idx + 1]
    p[idx] += 1
    return ep + ".".join(str(x) for x in p)


def _clausula(c, eco):
    """(bajo, bajo_incl, alto, alto_incl) en CLAVES; None = sin cota."""
    c = (c or "").strip()
    LIBRE = (None, False, None, False)
    if not c or c.lower() in ("*", "x", "latest", "any", "-"):
        return LIBRE
    # workspace:, catalog:, file:, git+…, ${VER}: no son versiones, no acotan nada
    if re.match(r"^(git|http|file|link|workspace|catalog|portal|patch|npm|github|\$|\.)",
                c, re.I):
        return LIBRE

    npm = _es_npm(eco)
    op, resto = "==", c
    for cand in ("===", "==", "~=", ">=", "<=", "!=", "^", "~", ">", "<", "="):
        if c.startswith(cand):
            op, resto = cand, c[len(cand):].strip()
            break

    ep = _epoch(resto)
    # el comodín se detecta sobre la BASE (antes del '-' de prerelease): sin eso
    # `1.0.0-alpha.x` (semver VÁLIDA) se leía como wildcard y perdía exposición.
    base = resto.split("-", 1)[0].split("+", 1)[0]
    comodin = bool(re.search(r"[.*]\s*[*xX]\s*$|^\s*[*xX]\s*$", base)) or base.endswith(".*")
    partes = _ints(resto)
    if not partes:
        return LIBRE
    # En npm una versión PARCIAL es un rango, no un pin: "2" == ">=2.0.0 <3.0.0"
    # y "1.2" == ">=1.2.0 <1.3.0". Es la forma más común en package.json
    # ("react": "16") y tratarla como pin acusaba repos ya parcheados.
    # En PyPI, en cambio, `==1.2` SÍ es pin exacto: el guard es indispensable.
    if npm and len(partes) < 3 and not re.search(r"[-+]", resto):
        comodin = True

    k = clave(resto, eco)
    if k is None:
        if not comodin:
            return LIBRE          # basura con prefijo numérico: no se afirma nada
        k = clave(ep + ".".join(str(x) for x in partes), eco)
        if k is None:
            return LIBRE

    if op == "!=":
        return LIBRE                       # excluir una versión no acota nada
    if op == ">=":
        return (k, True, None, False)
    if op == ">":
        if npm and comodin:                # npm: >1.2 == >=1.3.0
            return (clave(_bump(partes, len(partes) - 1, ep), eco), True, None, False)
        return (k, False, None, False)
    if op == "<=":
        if npm and comodin:                # npm: <=1.2 == <1.3.0
            return (None, False, clave(_bump(partes, len(partes) - 1, ep), eco), False)
        return (None, False, k, True)
    if op == "<":
        return (None, False, k, False)
    if op == "~=":                         # PEP 440: ~=1.2.3 -> >=1.2.3,<1.3
        if len(partes) < 2:
            return (k, True, None, False)
        return (k, True, clave(_bump(partes, len(partes) - 2, ep), eco), False)
    if op == "^":                          # npm/poetry: el 0 mayor cambia la regla
        nz = next((i for i, v in enumerate(partes[:3]) if v), None)
        idx = nz if nz is not None else len(partes) - 1
        return (k, True, clave(_bump(partes, idx, ep), eco), False)
    if op == "~":                          # ~1.2.3 y ~1.2 -> <1.3 ; ~1 -> <2
        idx = 1 if len(partes) >= 2 else 0
        return (k, True, clave(_bump(partes, idx, ep), eco), False)
    # ==, ===, = y comodines
    if comodin:
        # el piso de `==1.53.1.*` NO es 1.53.1: el prefix-match incluye
        # 1.53.1.dev0 y 1.53.1rc1, que son MENORES. Usar el release final como
        # piso declaraba 'seguro' contra el fix real 1.53.1.dev1 de litellm.
        piso = clave(ep + ".".join(str(x) for x in partes) + ("-0" if npm else ".dev0"), eco) \
            or clave(ep + ".".join(str(x) for x in partes), eco)
        return (piso, True, clave(_bump(partes, len(partes) - 1, ep), eco), False)
    return (k, True, k, True)              # pin exacto


def intervalo(spec, eco="PyPI"):
    """Especificador entero -> un solo intervalo (bajo, bajo_incl, alto, alto_incl).

    `||` (npm) se resuelve por casco convexo: como el veredicto solo pregunta
    "¿todo lo alcanzable queda de un lado del fix?", basta la unión más amplia
    (conservador: puede decir 'indeterminado' de más, nunca 'expuesto' de más).
    """
    if not isinstance(spec, str):
        return None, False, None, False    # ni siquiera es texto: no acota nada
    spec = spec.strip()
    if len(spec) > _MAX:
        return None, False, None, False
    ramas = spec.split("||") if "||" in spec else [spec]
    bajos, altos = [], []
    for rama in ramas:
        rama = rama.strip()
        h = re.split(r"\s+-\s+", rama)
        if len(h) == 2:                    # rango con guion npm: 1.2.3 - 2.3.4
            b, bi, _, _ = _clausula(">=" + h[0], eco)
            hp = _ints(h[1])
            if _es_npm(eco) and hp and len(hp) < 3 and not re.search(r"[-+]", h[1]):
                # npm redondea hacia arriba la cota parcial: "1.2 - 2.3" es
                # <2.4.0, no <=2.3.0. Tratarla como <= acusaba a 2.3.1.
                a, ai = clave(_bump(hp, len(hp) - 1), eco), False
            else:
                _, _, a, ai = _clausula("<=" + h[1], eco)
        else:
            b, bi, a, ai = None, False, None, False
            # pegar cada operador a su versión ANTES de partir: si no,
            # ">= 1.2 , < 2" se parte en cuatro y los ">=" sueltos se leen como
            # pines exactos — eso daba "expuesto" contra un rango que no lo está.
            rama = re.sub(r"(===|==|~=|>=|<=|!=|\^|~|>|<|=)\s+", r"\1", rama)
            for c in [p for p in re.split(r"[,\s]+", rama) if p]:
                cb, cbi, ca, cai = _clausula(c, eco)
                # el empate con borde más estricto TAMBIÉN endurece el intervalo:
                # sin esto, "<=2.0,<2.0" quedaba inclusivo y el resultado
                # dependía del orden de las cláusulas.
                if cb is not None and (b is None or cb > b or (cb == b and bi and not cbi)):
                    b, bi = cb, cbi
                if ca is not None and (a is None or ca < a or (ca == a and ai and not cai)):
                    a, ai = ca, cai
        bajos.append((b, bi))
        altos.append((a, ai))
    if any(b is None for b, _ in bajos):
        bajo, bajo_i = None, False
    else:
        bajo, bajo_i = min(bajos, key=lambda t: t[0])
    if any(a is None for a, _ in altos):
        alto, alto_i = None, False
    else:
        alto, alto_i = max(altos, key=lambda t: t[0])
    return bajo, bajo_i, alto, alto_i


def veredicto(spec, fix, eco="PyPI"):
    """'expuesto' | 'seguro' | 'indeterminado' de un especificador contra el fix.

    Solo devuelve 'expuesto' cuando NINGUNA versión que satisfaga el rango llega
    al fix. Es la única forma de sostener la promesa de cero falsos positivos.
    OJO: esto responde "¿está por debajo del fix?", no "¿está en la ventana
    vulnerable?" — la ventana [introduced, fixed) la aplica el llamador
    (ver expuesto_ventana()).
    """
    kf = clave(fix, eco)
    if kf is None:
        return "indeterminado"
    bajo, bajo_i, alto, alto_i = intervalo(spec, eco)
    if bajo is not None and alto is not None and \
            (bajo > alto or (bajo == alto and not (bajo_i and alto_i))):
        return "indeterminado"             # rango vacío/contradictorio: no se afirma
    if alto is not None and (alto < kf or (alto == kf and not alto_i)):
        return "expuesto"                  # todo lo alcanzable queda por debajo
    if bajo is not None and bajo >= kf:
        return "seguro"                    # todo lo alcanzable ya trae el parche
    return "indeterminado"                 # el rango cruza el corte: falta el lock


def expuesto(spec, fix, eco="PyPI"):
    """Booleano conservador: True solo si es demostrable."""
    return veredicto(spec, fix, eco) == "expuesto"


def expuesto_ventana(spec, introduced, fixed, last_affected=None, eco="PyPI"):
    """Veredicto contra la ventana REAL del advisory, no contra [0, fixed).

    Leer solo `fixed` produjo 371 falsos positivos duros sobre 2484 pares
    (14,9%) medidos contra el exposure.json real: GHSA-hvrp-rf83-w775 tiene
    introduced=1.23.0 y el pipeline acusaba a repos con mcp==1.6.0, anteriores
    a que el bug existiera. Y `last_affected` sin `fixed` hacía DESCARTAR el
    advisory entero (5 de litellm perdidos así).

    Devuelve 'expuesto' si TODO el rango declarado cae dentro de la ventana;
    'seguro' si no la toca; 'indeterminado' si la cruza.
    """
    bajo, bajo_i, alto, alto_i = intervalo(spec, eco)
    ki = clave(introduced, eco) if introduced and introduced != "0" else None
    kf = clave(fixed, eco) if fixed else None
    kl = clave(last_affected, eco) if last_affected else None
    if kf is None and kl is None:
        return "indeterminado"             # ventana sin techo utilizable
    # ¿todo el rango está por encima de la ventana? -> seguro
    if kf is not None and bajo is not None and bajo >= kf:
        return "seguro"
    if kl is not None and bajo is not None and bajo > kl:
        return "seguro"
    # ¿todo el rango está por debajo del introduced? -> seguro (no existía el bug)
    if ki is not None and alto is not None and (alto < ki or (alto == ki and not alto_i)):
        return "seguro"
    if alto is None:
        return "indeterminado"             # sin techo, nunca acusable
    # techo dentro de la ventana...
    dentro_techo = (alto < kf or (alto == kf and not alto_i)) if kf is not None \
        else (alto < kl or alto == kl)
    piso_ok = ki is None or (bajo is not None and bajo >= ki)
    if dentro_techo and piso_ok:
        return "expuesto"
    return "indeterminado"


# ------------------------------------------------- lectura de manifiestos ---

_RE_REQ = re.compile(r"^(?:-e\s+|--editable\s+)?"
                     r"(?P<n>[A-Za-z0-9][A-Za-z0-9._-]*)"
                     r"(?:\[(?P<extras>[^\]]*)\])?\s*(?P<spec>.*)$")


def _norm(n):
    """Nombre normalizado PEP 503: -, _ y . son el mismo separador."""
    return re.sub(r"[-_.]+", "-", (n or "").strip()).lower()


def spec_en_requirements(texto, paquete):
    """Especificador crudo de `paquete` en un requirements.txt, o None si no está.

    El regex del proyecto (`^\\s*paquete==([0-9]...)`) solo veía pins con `==`:
    `mcp>=1.2,<2`, `mcp[cli]==1.9.4 ; python_version>="3.10"` o un `mcp` pelado
    eran invisibles, y esa invisibilidad se contaba como "no expuesto" sin que
    nadie lo decidiera. Devuelve '' si está sin constraint (distinto de None =
    ausente) y '__URL__' si es una dep PEP 508 por URL/git (no hay versión).

    El nombre se compara NORMALIZADO PEP 503 (`[-_.]+` -> `-`, minúsculas), no
    con un regex de literal: `Fast_MCP`, `fast.mcp` y `FAST-MCP` son el MISMO
    paquete que `fast-mcp`. OJO, honestidad: PEP 503 NO colapsa el separador
    ausente — `fastmcp` y `fast-mcp` son proyectos DISTINTOS en PyPI y este
    código los trata como distintos, que es lo correcto. De paso
    `mcp-server==1.0` deja de contarse como un pin de `mcp`.
    """
    if not isinstance(texto, str):
        return None
    objetivo = _norm(paquete)
    # unir continuaciones de línea y sacar el BOM antes de parsear
    t = texto.replace("\\\r\n", " ").replace("\\\n", " ").lstrip("\ufeff")
    for linea in t.splitlines():
        s = linea.strip()
        if not s or s.startswith("#") or (
                s.startswith("-") and not re.match(r"(-e|--editable)\s", s)):
            continue                       # -r, -c, --index-url, --find-links...
        s = re.sub(r"\s*--hash=\S+", "", s)
        s = re.split(r"\s+#", s, 1)[0].strip()    # comentario inline
        m = _RE_REQ.match(s)
        if not m or _norm(m.group("n")) != objetivo:
            continue
        spec = (m.group("spec") or "").split(";", 1)[0].strip()
        return "__URL__" if spec.startswith("@") else spec
    return None


def spec_en_package_json(texto, paquete):
    """Especificador crudo de `paquete` en un package.json, o None.

    Mira SEIS secciones: `overrides`/`resolutions` fuerzan la versión de una dep
    transitiva y muchas veces son el único lugar del repo donde la versión queda
    fijada o corregida. Blindado contra JSON válido con schema inválido
    (`{"dependencies": {"mcp": 1.2}}` o `[1,2]` reventaban con AttributeError).
    """
    import json as _json
    try:
        d = _json.loads(texto or "")
    except Exception:
        return None
    if not isinstance(d, dict):
        return None
    for k in ("dependencies", "devDependencies", "peerDependencies",
              "optionalDependencies", "overrides", "resolutions"):
        sec = d.get(k)
        if not isinstance(sec, dict):
            continue
        v = sec.get(paquete)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


# ------------------------------------------------------------- autotest -----

_CASOS = [
    ("1.0.0rc1", "1.0.0", -1, "PyPI"), ("1.0.0.post1", "1.0.0", 1, "PyPI"),
    ("2.13.0.2", "2.13.0", 1, "PyPI"), ("2.13", "2.13.0", 0, "PyPI"),
    ("2.13.0.1", "2.13.0.2", -1, "PyPI"), ("1.53.1.dev0", "1.53.1.dev1", -1, "PyPI"),
    ("1.53.1.dev1", "1.53.1", -1, "PyPI"), ("1.0.0.dev1", "1.0.0a1", -1, "PyPI"),
    ("1!1.0", "2.0", 1, "PyPI"), ("1.0+ubuntu1", "1.0.1", -1, "PyPI"),
    ("1.0+local", "1.0", 1, "PyPI"), ("1.02.3", "1.2.3", 0, "PyPI"),
    ("1.9.4", "1.10.0", -1, "PyPI"), ("1.0.0a10", "1.0.0a9", 1, "PyPI"),
    ("1.0.0b2", "1.0.0rc1", -1, "PyPI"), ("1.75.5.post1", "1.75.5", 1, "PyPI"),
    ("1.0.0.post1.dev2", "1.0.0.post1", -1, "PyPI"), ("1.0.0-1", "1.0.0", 1, "PyPI"),
    ("0.9.0", "0.10.0", -1, "PyPI"), ("v1.2.3", "1.2.3", 0, "PyPI"),
    ("1.0.0-alpha.1", "1.0.0-alpha.beta", -1, "npm"),
    ("1.0.0-alpha", "1.0.0-alpha.1", -1, "npm"), ("1.0.0-rc.1", "1.0.0", -1, "npm"),
    ("1.0.0+build.5", "1.0.0+build.9", 0, "npm"), ("1.0.0-1", "1.0.0-alpha", -1, "npm"),
    ("1.0.0-alpha.10", "1.0.0-alpha.9", 1, "npm"), ("2.13", "2.13.0", 0, "npm"),
]

_CASOS_RANGO = [
    # los 19 originales
    ("^2.13.0", "2.14.2", "indeterminado", "npm"), ("~2.13.0", "2.14.2", "expuesto", "npm"),
    ("^0.2.3", "0.3.0", "expuesto", "npm"), ("^0.0.3", "0.0.4", "expuesto", "npm"),
    ("^1.2.3", "2.0.0", "expuesto", "npm"), ("^1.2.3", "1.5.0", "indeterminado", "npm"),
    (">=1.2.0 <2.0.0", "2.0.0", "expuesto", "npm"), ("^2 || ^3", "3.2.0", "indeterminado", "npm"),
    ("1.x", "2.0.0", "expuesto", "npm"), (">=1.2", "1.9.4", "indeterminado", "PyPI"),
    (">= 1.2 , < 2", "1.9.4", "indeterminado", "PyPI"), (">=1.2,<2", "2.0.0", "expuesto", "PyPI"),
    ("~=1.2.3", "1.3.0", "expuesto", "PyPI"), ("~=1.2", "1.9.4", "indeterminado", "PyPI"),
    ("==1.2.*", "1.3.0", "expuesto", "PyPI"), ("1.28.1", "1.28.1", "seguro", "PyPI"),
    ("1.28.0", "1.28.1", "expuesto", "PyPI"), ("*", "1.0.0", "indeterminado", "npm"),
    ("git+https://github.com/x/y", "1.0.0", "indeterminado", "npm"),
    # regresiones de las refutaciones (cada una era un FP o un FN demostrado)
    ("==1!1.2.*", "1.3.0", "seguro", "PyPI"),            # epoch perdido en el bump
    ("==1!2.13.*", "2.14.2", "seguro", "PyPI"),
    ("~=1!1.2.3", "1!1.3.0", "expuesto", "PyPI"),
    ("==1.53.1.*", "1.53.1.dev1", "indeterminado", "PyPI"),  # piso wildcard con dev
    ("==2.0.0.*", "2.0.0", "indeterminado", "PyPI"),
    ("<=2.0,<2.0", "2.0", "expuesto", "PyPI"),           # empate de cota + borde
    ("<2.0,<=2.0", "2.0", "expuesto", "PyPI"),
    ("2", "2.0.1", "indeterminado", "npm"),              # parcial npm = X-range
    ("1.2", "1.2.3", "indeterminado", "npm"),
    ("=1.2", "1.2.1", "indeterminado", "npm"),
    ("v2", "2.0.1", "indeterminado", "npm"),
    ("0", "0.9.0", "indeterminado", "npm"),
    ("^1.2.3 || 2", "2.0.0", "indeterminado", "npm"),
    ("1.2 - 2.3", "2.3.1", "indeterminado", "npm"),      # guion con cota parcial
    ("1.2.3 - 2", "2.0.1", "indeterminado", "npm"),
    ("1.2.x - 2.x", "2.4.0", "indeterminado", "npm"),
    ("1.0.0-alpha.x", "1.0.0", "expuesto", "npm"),       # prerelease != comodín
    ("1.2", "1.3.0", "expuesto", "PyPI"),                # en PyPI SÍ es pin
    ("1.0.0-.", "1.0.0", "indeterminado", "npm"),        # basura no es pin
    ("1.2.3+a..b", "2.0.0", "indeterminado", "npm"),
    ("==" + "1" * 4400, "1.0.0", "indeterminado", "PyPI"),   # no revienta
    ("==1.0", "1" * 4400, "indeterminado", "PyPI"),
]

_CASOS_VENTANA = [
    # (spec, introduced, fixed, last_affected, eco, esperado)
    ("1.6.0", "1.23.0", "1.27.2", None, "PyPI", "seguro"),   # el FP del 14,9%
    ("1.25.0", "1.23.0", "1.27.2", None, "PyPI", "expuesto"),
    ("1.9.2", "1.23.0", "1.27.2", None, "PyPI", "seguro"),
    ("1.28.0", "0", "1.27.2", None, "PyPI", "seguro"),
    ("1.20.0", "0", None, "1.28.11", "PyPI", "expuesto"),    # advisory sin fix
    ("1.30.0", "0", None, "1.28.11", "PyPI", "seguro"),
    (">=1.2", "0", "1.27.2", None, "PyPI", "indeterminado"),
    ("^2.11.3", "0", "3.2.0", None, "PyPI", "expuesto"),     # EXPUESTO-CONGELADO
    ("^2.11.3", "0", "2.14.2", None, "PyPI", "indeterminado"),
]

if __name__ == "__main__":
    def ingenua(s):
        n = [int(x) for x in re.findall(r"\d+", s)[:3]]
        return tuple(n + [0] * (3 - len(n)))

    fallos = 0
    for a, b, esp, eco in _CASOS:
        got = comparar(a, b, eco)
        ki, kj = ingenua(a), ingenua(b)
        ing = -1 if ki < kj else (0 if ki == kj else 1)
        fallos += got != esp
        print(f"{a:22} {b:22} {eco:5} esp={esp:>2} got={got:>2} ingenua={ing:>2}"
              f"{'  <- la ingenua falla' if ing != esp else ''}"
              f"{'   ROTO' if got != esp else ''}")
    print()
    for spec, fix, esp, eco in _CASOS_RANGO:
        got = veredicto(spec, fix, eco)
        fallos += got != esp
        print(f"{spec[:34]:34} fix={fix[:12]:12} {eco:5} {esp:14} {got:14}"
              f"{'ROTO' if got != esp else ''}")
    print()
    for spec, intro, fix, last, eco, esp in _CASOS_VENTANA:
        got = expuesto_ventana(spec, intro, fix, last, eco)
        fallos += got != esp
        vent = "[" + str(intro) + "," + str(fix or last) + ")"
        print(f"{spec:12} {vent:22} {eco:5} {esp:14} {got:14}"
              f"{'ROTO' if got != esp else ''}")
    print(f"\nfallos: {fallos}")
    raise SystemExit(1 if fallos else 0)
