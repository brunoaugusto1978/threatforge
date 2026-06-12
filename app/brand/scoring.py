"""Scoring explicável para findings de marca.

Combina similaridade, idade do domínio (RDAP), presença de DNS/MX,
certificado recente (CT), termos-isca e cruzamento com URLhaus.
Tudo com justificativa — nada de nota mágica.
"""
from dataclasses import asdict, dataclass

from app.brand.typosquat import LURES

VERDICTS = [(70, "malicious"), (45, "suspicious"), (20, "low")]


@dataclass
class Factor:
    name: str
    points: int
    reason: str
    source: str


def score_finding(
    domain: str,
    similarity: int,
    evidence: dict,
) -> tuple[int, str, list[dict]]:
    """evidence pode conter: resolves(bool), mx(bool), age_days(int|None),
    cert_age_days(int|None), urlhaus_listed(bool), ns(list)."""
    factors: list[Factor] = []

    # 1. Similaridade com a marca
    if similarity >= 90:
        factors.append(Factor("high_similarity", 25,
            f"Domínio {similarity}% similar à marca monitorada.", "ThreatForge"))
    elif similarity >= 75:
        factors.append(Factor("similarity", 15,
            f"Domínio {similarity}% similar à marca monitorada.", "ThreatForge"))
    elif similarity >= 60:
        factors.append(Factor("similarity", 8,
            f"Domínio {similarity}% similar à marca.", "ThreatForge"))

    # 2. Termo-isca presente no domínio
    lure_hit = next((l for l in LURES if l in domain), None)
    if lure_hit:
        factors.append(Factor("lure_term", 12,
            f"Contém termo-isca típico de golpe: '{lure_hit}'.", "ThreatForge"))

    # 3. Domínio resolve (está ativo)
    if evidence.get("resolves"):
        factors.append(Factor("resolves", 15,
            "Domínio resolve para um IP (infraestrutura ativa).", "DNS"))
    if evidence.get("mx"):
        factors.append(Factor("mx_record", 10,
            "Possui registro MX — capaz de enviar/receber e-mail (phishing).", "DNS"))

    # 4. Idade do domínio (RDAP) — recém-registrado é forte sinal
    age = evidence.get("age_days")
    if age is not None:
        if age <= 7:
            factors.append(Factor("very_new_domain", 25,
                f"Registrado há apenas {age} dia(s) — típico de campanha ativa.", "RDAP"))
        elif age <= 30:
            factors.append(Factor("new_domain", 15,
                f"Registrado há {age} dias.", "RDAP"))
        elif age <= 90:
            factors.append(Factor("recent_domain", 7,
                f"Registrado há {age} dias.", "RDAP"))

    # 5. Certificado recente (Certificate Transparency)
    cert_age = evidence.get("cert_age_days")
    if cert_age is not None and cert_age <= 7:
        factors.append(Factor("fresh_cert", 12,
            f"Certificado TLS emitido há {cert_age} dia(s) (CT logs).", "crt.sh"))

    # 6. Já listado como malicioso no URLhaus
    if evidence.get("urlhaus_listed"):
        factors.append(Factor("urlhaus", 40,
            "Domínio já consta no URLhaus como distribuição de malware/phishing.",
            "abuse.ch URLhaus"))

    score = min(100, max(0, sum(f.points for f in factors)))
    verdict = "info"
    for threshold, name in VERDICTS:
        if score >= threshold:
            verdict = name
            break
    return score, verdict, [asdict(f) for f in factors]
