"""Catálogo de Threat Profiles por setor + geração de seeds de monitoramento.

Taxonomia (critério principal):
- IOC GLOBAL........: relevante para todos (KEV, URLhaus...). Vive em `observables`.
- IOC SETORIAL......: ameaças/tecnologias típicas do setor. scope="sector".
- IOC ORGANIZACIONAL: derivado das marcas/ativos da org ({marca}+termo, slug,
                      domains). scope="organization".
- FINDING...........: SÓ com evidência real coletada/enriquecida (tabela própria
                      brand_findings). NUNCA gerado aqui.

Tudo gerado aqui nasce status=candidate, confirmed=false, source_type=sector_profile.
"""
from __future__ import annotations

import re
import unicodedata

# Termos usados para gerar combinações {marca}+termo (escopo organizacional).
TELECOM_SEED_TERMS = [
    "segunda via", "2via", "boleto", "pix", "suporte", "atendimento",
    "login", "senha", "apk", "premium gratis", "recarga", "fatura",
    "desbloqueio", "central", "minha conta",
]

SECTOR_PROFILES: dict[str, dict] = {
    "Telecom": {
        # (ameaça, confiança)
        "threats": [
            ("phishing usando a marca", "high"),
            ("falso atendimento / suporte técnico", "medium"),
            ("golpe de segunda via de boleto", "high"),
            ("fraude Pix", "high"),
            ("smishing (SMS fraudulento)", "medium"),
            ("SIM swap", "high"),
            ("apps falsos / APK malicioso", "high"),
            ("domain typosquatting", "medium"),
            ("vazamento de credenciais", "high"),
            ("venda de base de clientes", "high"),
            ("abuso de APIs", "medium"),
            ("fraude em recarga e promoções", "low"),
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
            "portal do cliente", "acesso remoto",
        ],
        "sources": [
            "certificate_transparency", "urlhaus", "cisa_kev", "epss",
            "typosquatting", "paste_sites", "telegram_publico", "github",
        ],
    },
    "Financeiro": {"threats": [("phishing bancário", "high"), ("fraude Pix", "high")],
                   "keywords": ["boleto", "pix", "login", "fatura", "investimento", "senha"],
                   "seed_terms": ["boleto", "pix", "login", "senha", "fatura"],
                   "ioc_categories": ["dominio", "url", "chave_pix"], "cve_watchlist": ["internet banking", "API pública"],
                   "sources": ["certificate_transparency", "urlhaus", "cisa_kev"]},
    "Varejo": {"threats": [("loja falsa", "high"), ("golpe de frete", "medium")],
               "keywords": ["promocao", "frete", "cupom", "pedido", "pagamento", "login"],
               "seed_terms": ["promocao", "frete", "pagamento", "login"],
               "ioc_categories": ["dominio", "url"], "cve_watchlist": ["e-commerce", "gateway de pagamento"],
               "sources": ["certificate_transparency", "urlhaus"]},
    "Saúde": {"threats": [("vazamento de dados de paciente", "high")],
              "keywords": ["agendamento", "exame", "convenio", "login", "senha"],
              "seed_terms": ["agendamento", "convenio", "login"],
              "ioc_categories": ["dominio", "url"], "cve_watchlist": ["portal do paciente"],
              "sources": ["certificate_transparency"]},
    "Governo": {"threats": [("falso benefício/auxílio", "high")],
                "keywords": ["beneficio", "auxilio", "imposto", "gov", "cadastro"],
                "seed_terms": ["beneficio", "auxilio", "cadastro"],
                "ioc_categories": ["dominio", "url"], "cve_watchlist": ["portal gov"],
                "sources": ["certificate_transparency"]},
    "Tecnologia": {"threats": [("comprometimento de conta", "medium")],
                   "keywords": ["login", "suporte", "api", "conta", "senha"],
                   "seed_terms": ["login", "suporte", "senha"],
                   "ioc_categories": ["dominio", "url", "cve"], "cve_watchlist": ["SSO", "API pública"],
                   "sources": ["cisa_kev", "epss", "github"]},
}

DEFAULT_PROFILE = {
    "threats": [], "keywords": ["login", "suporte", "atendimento", "pagamento"],
    "seed_terms": ["login", "suporte", "pagamento"],
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

    # ---- ESCOPO ORGANIZACIONAL: derivado das marcas ----
    terms = profile.get("seed_terms", profile.get("keywords", []))
    for b in brands:
        name = (b.get("name") or "").strip()
        if not name:
            continue
        # combinações {marca}+termo: derivam de marca + termo de risco do setor
        for term in terms:
            add(f"{name} {_display_term(term)}", "keyword_combo", "organization",
                "low", "sector_profile+brand_profile")
        # slug da marca (perfil da marca)
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
