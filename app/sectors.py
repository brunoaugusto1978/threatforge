"""Threat profile catalog by sector plus monitoring seed generation.

Taxonomia (critério principal):
- GLOBAL IOC.........: relevant to all tenants (KEV, URLhaus...). Lives in `observables`.
- IOC SETORIAL......: ameaças/tecnologias típicas do setor. scope="sector".
- ORGANIZATIONAL IOC: derived from organization brands/assets ({brand}+term, slug,
                      domains). scope="organization".
- FINDING...........: SÓ com evidência real coletada/enriquecida (tabela própria
                      brand_findings). NUNCA gerado aqui.

Tudo gerado aqui nasce status=candidate, confirmed=false, source_type=sector_profile.
"""
from __future__ import annotations

import re
import unicodedata

# Terms used to generate {brand}+term combinations for organizational scope.
TELECOM_SEED_TERMS = [
    "segunda via", "2via", "payment slip", "pix", "support", "service",
    "login", "password", "apk", "free premium", "top-up", "invoice",
    "desbloqueio", "central", "minha account",
]

SECTOR_PROFILES: dict[str, dict] = {
    "Telecom": {
        # (ameaça, confiança)
        "threats": [
            ("brand phishing", "high"),
            ("falso service / support técnico", "medium"),
            ("golpe de segunda via de payment slip", "high"),
            ("fraude Pix", "high"),
            ("smishing (SMS fraudulento)", "medium"),
            ("SIM swap", "high"),
            ("apps falsos / APK malicioso", "high"),
            ("domain typosquatting", "medium"),
            ("vazamento de credenciais", "high"),
            ("customer database sale", "high"),
            ("abuso de APIs", "medium"),
            ("top-up and promotion fraud", "low"),
        ],
        "keywords": TELECOM_SEED_TERMS,
        "seed_terms": TELECOM_SEED_TERMS,
        "ioc_categories": [
            "dominio", "subdominio", "url", "ip", "hash", "email", "telefone",
            "chave_pix", "cnpj", "perfil_social", "app_falso", "apk", "cve",
            "username", "grupo_canal", "carteira_cripto", "certificado_tls", "asn",
        ],
        # tecnologias com CVEs a vigiar no setor (escopo setorial)
        "cve_watchlist": [
            "VPN", "firewall", "SSO", "IAM", "webmail", "CRM", "billing",
            "API pública", "app mobile", "roteador", "DNS", "BGP",
            "customer portal", "remote access",
        ],
        "sources": [
            "certificate_transparency", "urlhaus", "cisa_kev", "epss",
            "typosquatting", "paste_sites", "telegram_publico", "github",
        ],
    },
    "Financeiro": {"threats": [("phishing bancário", "high"), ("fraude Pix", "high")],
                   "keywords": ["payment slip", "pix", "login", "invoice", "investment", "password"],
                   "seed_terms": ["payment slip", "pix", "login", "password", "invoice"],
                   "ioc_categories": ["dominio", "url", "chave_pix"], "cve_watchlist": ["internet banking", "API pública"],
                   "sources": ["certificate_transparency", "urlhaus", "cisa_kev"]},
    "Varejo": {"threats": [("loja falsa", "high"), ("golpe de frete", "medium")],
               "keywords": ["promocao", "frete", "cupom", "pedido", "pagamento", "login"],
               "seed_terms": ["promocao", "frete", "pagamento", "login"],
               "ioc_categories": ["dominio", "url"], "cve_watchlist": ["e-commerce", "gateway de pagamento"],
               "sources": ["certificate_transparency", "urlhaus"]},
    "Saúde": {"threats": [("vazamento de dados de paciente", "high")],
              "keywords": ["appointment", "exam", "health plan", "login", "password"],
              "seed_terms": ["appointment", "health plan", "login"],
              "ioc_categories": ["dominio", "url"], "cve_watchlist": ["portal do paciente"],
              "sources": ["certificate_transparency"]},
    "Governo": {"threats": [("falso benefício/auxílio", "high")],
                "keywords": ["beneficio", "auxilio", "imposto", "gov", "cadastro"],
                "seed_terms": ["beneficio", "auxilio", "cadastro"],
                "ioc_categories": ["dominio", "url"], "cve_watchlist": ["portal gov"],
                "sources": ["certificate_transparency"]},
    "Tecnologia": {"threats": [("comprometimento de account", "medium")],
                   "keywords": ["login", "support", "api", "account", "password"],
                   "seed_terms": ["login", "support", "password"],
                   "ioc_categories": ["dominio", "url", "cve"], "cve_watchlist": ["SSO", "API pública"],
                   "sources": ["cisa_kev", "epss", "github"]},
}

DEFAULT_PROFILE = {
    "threats": [], "keywords": ["login", "support", "service", "pagamento"],
    "seed_terms": ["login", "support", "pagamento"],
    "ioc_categories": ["dominio", "url"], "cve_watchlist": [],
    "sources": ["certificate_transparency", "urlhaus"],
}


def list_sectors() -> list[str]:
    return list(SECTOR_PROFILES.keys())


def get_profile(sector: str | None) -> dict:
    if not sector:
        return DEFAULT_PROFILE
    return SECTOR_PROFILES.get(sector, DEFAULT_PROFILE)


def profile_public(sector: str | None) -> dict:
    """Versão serializável para a API (achata threats em lista de strings)."""
    p = get_profile(sector)
    return {
        "threats": [t[0] for t in p.get("threats", [])],
        "keywords": p.get("keywords", []),
        "ioc_categories": p.get("ioc_categories", []),
        "cve_watchlist": p.get("cve_watchlist", []),
        "sources": p.get("sources", []),
    }


def slugify(name: str) -> str:
    """'Claro Música' -> 'claromusica' (sem acento, sem espaço)."""
    norm = unicodedata.normalize("NFKD", name or "")
    ascii_str = norm.encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]", "", ascii_str.lower())


def _display_term(term: str) -> str:
    """Acrônimos curtos em maiúsculas (apk -> APK); resto como está."""
    return term.upper() if len(term) <= 3 else term


def generate_seeds(sector: str | None, brands: list[dict]) -> list[dict]:
    """Gera seeds de monitoramento (NÃO findings).

    `brands`: lista de {"name": str, "domains": list[str]}.
    Retorna dicts: {seed, seed_type, scope, confidence}.
    """
    profile = get_profile(sector)
    seeds: list[dict] = []
    seen: set[str] = set()

    def add(seed: str, seed_type: str, scope: str, priority: str, source_type: str):
        key = seed.strip().lower()
        if not key or key in seen:
            return
        seen.add(key)
        # mantém a chave `confidence` no payload por compat de schema/modelo,
        # mas semanticamente representa PRIORIDADE/relevância de monitoramento.
        seeds.append({"seed": seed.strip(), "seed_type": seed_type, "scope": scope,
                      "confidence": priority, "source_type": source_type})

    # ---- ESCOPO SETORIAL: ameaças + tecnologias/CVEs do setor ----
    for threat, prio in profile.get("threats", []):
        add(threat, "threat", "sector", prio, "sector_profile")
    for tech in profile.get("cve_watchlist", []):
        add(f"CVE watchlist: {tech}", "cve_tech", "sector", "low", "sector_profile")

    # ---- ORGANIZATIONAL SCOPE: derived from brands ----
    terms = profile.get("seed_terms", profile.get("keywords", []))
    for b in brands:
        name = (b.get("name") or "").strip()
        if not name:
            continue
        # {brand}+term combinations derived from the brand plus sector risk terms
        for term in terms:
            add(f"{name} {_display_term(term)}", "keyword_combo", "organization",
                "low", "sector_profile+brand_profile")
        # brand slug (brand profile)
        slug = slugify(name)
        if slug:
            add(slug, "slug", "organization", "medium", "brand_profile")
        # official domains (brand asset)
        for d in (b.get("domains") or []):
            add(d.strip().lower(), "domain", "organization", "high", "brand_asset")

    return seeds


# compat: nome antigo usado em testes anteriores
def generate_seed_strings(sector: str | None, brand_names: list[str]) -> list[dict]:
    return generate_seeds(sector, [{"name": n, "domains": []} for n in brand_names])
