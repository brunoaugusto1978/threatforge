"""Similar domain generator (typosquatting), initially focused on the Brazilian scenario.

Generates permutations of a legitimate domain to detect brand abuse:
troca de caracteres visualmente parecidos, omissão/duplicação, teclas
adjacentes (QWERTY), inserção de hífen/termos isca e troca de TLD —
incluindo TLDs muito usados em golpes contra empresas brasileiras.
"""
from __future__ import annotations

import re

# TLDs frequentes em phishing contra marcas BR + genéricos baratos
TLDS = [
    "com", "com.br", "net", "net.br", "org", "app", "online", "site",
    "shop", "store", "info", "xyz", "top", "live", "vip", "digital",
    "com.co", "br.com", "sbs", "icu", "cfd",
]

# termos-isca comuns em golpes BR (banco, prêmio, suporte, etc.)
LURES = [
    "seguro", "suporte", "atendimento", "acesso", "login", "cliente",
    "promocao", "premio", "sorteio", "app", "central", "oficial",
    "br", "online", "conta", "cadastro", "verificar", "pagamento",
    "2via", "boleto", "pix", "ajuda",
]

# substituições homóglifas / visuais comuns
HOMOGLYPHS = {
    "o": ["0"], "0": ["o"], "i": ["1", "l"], "l": ["1", "i"],
    "e": ["3"], "a": ["4", "@"], "s": ["5", "$"], "b": ["8"],
    "g": ["9"], "t": ["7"], "rn": ["m"], "m": ["rn"], "cl": ["d"],
    "vv": ["w"], "w": ["vv"],
}

QWERTY = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh",
    "u": "yij", "i": "uok", "o": "ipl", "p": "ol", "a": "qsz", "s": "awdx",
    "d": "sefc", "f": "drgv", "g": "fthb", "h": "gyjn", "j": "hukm",
    "k": "jil", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv",
    "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}


def split_domain(domain: str) -> tuple[str, str]:
    """Separa label + tld. Trata TLDs de 2 níveis (com.br, net.br...)."""
    domain = domain.lower().strip()
    for tld in sorted(TLDS, key=len, reverse=True):
        suffix = "." + tld
        if domain.endswith(suffix):
            return domain[: -len(suffix)], tld
    parts = domain.split(".", 1)
    return (parts[0], parts[1]) if len(parts) == 2 else (domain, "com")


def _valid_label(label: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]", label))


def _char_swaps(label: str) -> set[str]:
    out: set[str] = set()
    # homóglifos (inclui sequências como 'rn'->'m')
    for src, repls in HOMOGLYPHS.items():
        idx = label.find(src)
        while idx != -1:
            for r in repls:
                out.add(label[:idx] + r + label[idx + len(src):])
            idx = label.find(src, idx + 1)
    # teclas adjacentes (typo de digitação)
    for i, ch in enumerate(label):
        for adj in QWERTY.get(ch, ""):
            out.add(label[:i] + adj + label[i + 1:])
    # omissão de um caractere
    for i in range(len(label)):
        out.add(label[:i] + label[i + 1:])
    # duplicação
    for i in range(len(label)):
        out.add(label[:i] + label[i] + label[i:])
    # transposição de adjacentes
    for i in range(len(label) - 1):
        out.add(label[:i] + label[i + 1] + label[i] + label[i + 2:])
    return out


def generate(domain: str, max_results: int = 600) -> list[str]:
    """Returns a list of typosquat candidate domains excluding the original."""
    label, tld = split_domain(domain)
    if not label:
        return []

    labels: set[str] = set()
    labels.update(_char_swaps(label))
    # termos-isca: prefixo, sufixo e com hífen
    for lure in LURES:
        labels.add(label + lure)
        labels.add(lure + label)
        labels.add(label + "-" + lure)
        labels.add(lure + "-" + label)
    # hífen interno (ex.: bancodobrasil -> banco-do-brasil é raro; foco em label-)
    labels.add(label + "-br")

    labels = {l for l in labels if _valid_label(l) and l != label}

    candidates: list[str] = []
    seen: set[str] = set()
    # mesmo label em vários TLDs + labels alterados no TLD original e .com/.com.br
    priority_tlds = [tld, "com", "com.br", "app", "online", "shop"]
    for lab in sorted(labels):
        for t in priority_tlds:
            fqdn = f"{lab}.{t}"
            if fqdn not in seen:
                seen.add(fqdn)
                candidates.append(fqdn)
            if len(candidates) >= max_results:
                return candidates
    return candidates
