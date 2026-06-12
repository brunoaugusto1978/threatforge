"""Catálogo de Threat Profiles por setor.

Cada perfil descreve ameaças comuns, keywords, categorias de IOC, watchlist de
tecnologias/CVEs e fontes recomendadas. A partir dele geramos SEEDS de
monitoramento (status candidate) — NUNCA findings confirmados. Um finding só
nasce depois, com evidência real (CT log, DNS ativo, URLhaus, etc.).
"""
from __future__ import annotations

# Perfis setoriais. Telecom vem populado (enxuto); os demais servem de estrutura.
SECTOR_PROFILES: dict[str, dict] = {
    "Telecom": {
        "threats": [
            "phishing usando a marca",
            "falso atendimento/suporte técnico",
            "golpe de segunda via de boleto",
            "fraude Pix",
            "smishing (SMS fraudulento)",
            "SIM swap",
            "typosquatting de domínios",
            "apps falsos / APK malicioso",
            "perfis falsos em redes sociais",
            "grupos de fraude no Telegram",
            "vazamento de credenciais",
            "fraude em recarga e promoções",
        ],
        "keywords": [
            "segunda via", "2via", "boleto", "pix", "recarga", "plano", "chip",
            "esim", "portabilidade", "desbloqueio", "suporte", "atendimento",
            "central", "fatura", "login", "minha conta", "app", "promocao",
            "fibra", "regularizacao", "contestacao",
        ],
        "ioc_categories": [
            "dominio", "subdominio", "url", "ip", "hash", "email", "telefone",
            "chave_pix", "cnpj", "perfil_social", "app_falso", "apk", "cve",
            "username", "grupo_canal", "carteira_cripto", "certificado_tls", "asn",
        ],
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
    # Estrutura genérica para outros setores (preenchimento futuro)
    "Financeiro": {"threats": [], "keywords": ["boleto", "pix", "login", "fatura", "investimento"],
                   "ioc_categories": ["dominio", "url", "chave_pix"], "cve_watchlist": [], "sources": ["certificate_transparency", "urlhaus"]},
    "Varejo": {"threats": [], "keywords": ["promocao", "frete", "cupom", "pedido", "pagamento"],
               "ioc_categories": ["dominio", "url"], "cve_watchlist": [], "sources": ["certificate_transparency", "urlhaus"]},
    "Saúde": {"threats": [], "keywords": ["agendamento", "exame", "convenio", "login"],
              "ioc_categories": ["dominio", "url"], "cve_watchlist": [], "sources": ["certificate_transparency"]},
    "Governo": {"threats": [], "keywords": ["beneficio", "auxilio", "imposto", "gov", "cadastro"],
                "ioc_categories": ["dominio", "url"], "cve_watchlist": [], "sources": ["certificate_transparency"]},
    "Tecnologia": {"threats": [], "keywords": ["login", "suporte", "api", "conta"],
                   "ioc_categories": ["dominio", "url", "cve"], "cve_watchlist": [], "sources": ["cisa_kev", "epss", "github"]},
}

DEFAULT_PROFILE = {
    "threats": [], "keywords": ["login", "suporte", "atendimento", "pagamento"],
    "ioc_categories": ["dominio", "url"], "cve_watchlist": [],
    "sources": ["certificate_transparency", "urlhaus"],
}


def list_sectors() -> list[str]:
    return list(SECTOR_PROFILES.keys())


def get_profile(sector: str | None) -> dict:
    if not sector:
        return DEFAULT_PROFILE
    return SECTOR_PROFILES.get(sector, DEFAULT_PROFILE)


def generate_seed_strings(sector: str | None, brand_names: list[str]) -> list[dict]:
    """Gera combinações {marca}+keyword como seeds candidatas (não-findings).

    Retorna lista de dicts: {seed, seed_type, confidence}.
    """
    profile = get_profile(sector)
    seeds: list[dict] = []
    seen: set[str] = set()

    for brand in brand_names:
        b = (brand or "").strip()
        if not b:
            continue
        for kw in profile.get("keywords", []):
            combo = f"{b} {kw}".strip().lower()
            if combo in seen:
                continue
            seen.add(combo)
            seeds.append({"seed": combo, "seed_type": "keyword_combo", "confidence": "low"})

    # ameaças e tecnologias do setor entram como contexto de watchlist
    for threat in profile.get("threats", []):
        key = threat.lower()
        if key not in seen:
            seen.add(key)
            seeds.append({"seed": threat, "seed_type": "threat", "confidence": "low"})

    return seeds
