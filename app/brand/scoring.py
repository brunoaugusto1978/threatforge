"""Scoring explicável para findings de marca.

Principle: separate EXISTENCE (similar domain exists/resolves) from THREAT
ATIVA (capaz de phishing ou já malicioso). Similaridade e "resolve" sozinhos
são contexto fraco — geram no máximo "low". Para "suspicious"/"malicious" é
preciso ao menos um sinal forte: MX, URLhaus, registro recente ou cert novo.

This reduces false positives from parked/for-sale domains, which are
especulação de revenda, não ataque.
"""
from dataclasses import asdict, dataclass

from app.brand.typosquat import LURES

VERDICTS = [(70, "malicious"), (45, "suspicious"), (15, "low")]

# sinais que, sozinhos, NÃO bastam para passar de "low"
_STRONG_SIGNALS = {"mx_record", "urlhaus", "very_new_domain", "new_domain", "fresh_cert"}


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
    cert_age_days(int|None), urlhaus_listed(bool), parked(bool),
    nameservers(list)."""
    factors: list[Factor] = []
    strong = set()

    # 1. Similaridade — contexto, pesos baixos
    if similarity >= 90:
        factors.append(Factor("high_similarity", 20,
            f"Domain {similarity}% similar to the monitored brand.", "ThreatForge"))
    elif similarity >= 75:
        factors.append(Factor("similarity", 10,
            f"Domain {similarity}% similar to the monitored brand.", "ThreatForge"))
    elif similarity >= 60:
        factors.append(Factor("similarity", 5,
            f"Domain {similarity}% similar to the brand.", "ThreatForge"))

    # 2. Termo-isca
    lure_hit = next((l for l in LURES if l in domain), None)
    if lure_hit:
        factors.append(Factor("lure_term", 8,
            f"Contém termo-isca típico de golpe: '{lure_hit}'.", "ThreatForge"))

    # 3. Existência ativa — fraco
    if evidence.get("resolves"):
        factors.append(Factor("resolves", 6,
            "Domain resolves to an IP address (infrastructure exists).", "DNS"))

    # 4. SINAL FORTE: MX (capaz de phishing por e-mail)
    if evidence.get("mx"):
        factors.append(Factor("mx_record", 22,
            "Possui registro MX — capaz de enviar/receber e-mail (phishing).", "DNS"))
        strong.add("mx_record")

    # 5. STRONG SIGNAL: domain age (RDAP)
    age = evidence.get("age_days")
    if age is not None:
        if age <= 7:
            factors.append(Factor("very_new_domain", 25,
                f"Registrado há apenas {age} dia(s) — típico de campanha ativa.", "RDAP"))
            strong.add("very_new_domain")
        elif age <= 30:
            factors.append(Factor("new_domain", 15,
                f"Registrado há {age} dias.", "RDAP"))
            strong.add("new_domain")
        elif age <= 90:
            factors.append(Factor("recent_domain", 6,
                f"Registrado há {age} dias.", "RDAP"))

    # 6. SINAL FORTE: certificado recente (CT)
    cert_age = evidence.get("cert_age_days")
    if cert_age is not None and cert_age <= 7:
        factors.append(Factor("fresh_cert", 12,
            f"Certificado TLS emitido há {cert_age} dia(s) (CT logs).", "crt.sh"))
        strong.add("fresh_cert")

    # 7. SINAL FORTE: já malicioso no URLhaus
    if evidence.get("urlhaus_listed"):
        factors.append(Factor("urlhaus", 45,
            "Domain is already listed in URLhaus as malware/phishing.", "abuse.ch URLhaus"))
        strong.add("urlhaus")

    score = min(100, max(0, sum(f.points for f in factors)))

    # --- Redutores de falso positivo ---
    parked = bool(evidence.get("parked"))
    if parked:
        factors.append(Factor("parked", 0,
            "Parked/for-sale domain (parking nameserver). Likely "
            "especulação de revenda, não ataque ativo.", "DNS/NS"))

    verdict = "info"
    for threshold, name in VERDICTS:
        if score >= threshold:
            verdict = name
            break

    # Sem nenhum sinal FORTE de ameaça, rebaixa para no máximo "low":
    # similaridade + resolve + termo-isca não bastam para "suspeito".
    if verdict in ("suspicious", "malicious") and not strong:
        verdict = "low"

    # Parked/for-sale domain never exceeds "low" if there is no
    # sinal forte de uso ativo malicioso (MX/URLhaus).
    if parked and not ({"mx_record", "urlhaus"} & strong):
        if verdict in ("suspicious", "malicious"):
            verdict = "low"

    return score, verdict, [asdict(f) for f in factors]
