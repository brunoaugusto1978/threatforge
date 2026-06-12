"""Engine de scoring explicável.

Cada regra retorna fatores com pontos + justificativa. O score final é a
soma limitada a 0–100. Nada de nota mágica: todo ponto tem um porquê.
"""
from dataclasses import asdict, dataclass


@dataclass
class ScoreFactor:
    name: str
    points: int
    reason: str
    source: str


VERDICTS = [(70, "malicious"), (40, "suspicious"), (1, "low")]


def compute_score(enrichments: dict[str, dict | None]) -> tuple[int, str, list[dict]]:
    """Recebe {nome_do_conector: dados} e devolve (score, verdict, fatores)."""
    factors: list[ScoreFactor] = []

    kev = enrichments.get("cisa_kev")
    if kev and kev.get("listed"):
        factors.append(
            ScoreFactor(
                "kev_listed",
                50,
                f"CVE consta no catálogo CISA KEV (exploração ativa confirmada). "
                f"Adicionada em {kev.get('date_added')}.",
                "CISA KEV",
            )
        )
        if (kev.get("known_ransomware") or "").lower() == "known":
            factors.append(
                ScoreFactor(
                    "kev_ransomware",
                    10,
                    "Uso conhecido em campanhas de ransomware segundo a CISA.",
                    "CISA KEV",
                )
            )

    epss = enrichments.get("epss")
    if epss and epss.get("epss") is not None:
        prob = float(epss["epss"])
        pts = round(prob * 30)
        if pts > 0:
            factors.append(
                ScoreFactor(
                    "epss",
                    pts,
                    f"Probabilidade EPSS de exploração em 30 dias: {prob:.1%} "
                    f"(percentil {float(epss.get('percentile', 0)):.1%}).",
                    "FIRST EPSS",
                )
            )

    uh = enrichments.get("urlhaus")
    if uh and uh.get("listed"):
        if "url_status" in uh:  # consulta por URL
            factors.append(
                ScoreFactor(
                    "urlhaus_url",
                    45,
                    f"URL listada no URLhaus (ameaça: {uh.get('threat') or 'n/d'}, "
                    f"tags: {', '.join(uh.get('tags') or []) or 'n/d'}).",
                    "abuse.ch URLhaus",
                )
            )
            if uh.get("url_status") == "online":
                factors.append(
                    ScoreFactor(
                        "urlhaus_online",
                        10,
                        "URL maliciosa ainda ONLINE no momento da consulta.",
                        "abuse.ch URLhaus",
                    )
                )
        elif "blacklists" in uh or "url_count" in uh and "file_type" not in uh:
            factors.append(
                ScoreFactor(
                    "urlhaus_host",
                    35,
                    f"Host associado a {uh.get('url_count', '?')} URL(s) de "
                    f"distribuição de malware no URLhaus.",
                    "abuse.ch URLhaus",
                )
            )
        if "file_type" in uh:
            factors.append(
                ScoreFactor(
                    "urlhaus_payload",
                    45,
                    f"Hash corresponde a payload conhecido no URLhaus "
                    f"(assinatura: {uh.get('signature') or 'n/d'}).",
                    "abuse.ch URLhaus",
                )
            )

    score = min(100, max(0, sum(f.points for f in factors)))
    verdict = "no_known_threat"
    for threshold, name in VERDICTS:
        if score >= threshold:
            verdict = name
            break
    return score, verdict, [asdict(f) for f in factors]
