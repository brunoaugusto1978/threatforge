"""Technical Markdown report generation for an observable."""
from datetime import datetime, timezone

from app.models import Observable

_VERDICT_PT = {
    "malicious": "MALICIOSO",
    "suspicious": "SUSPEITO",
    "low": "RISCO BAIXO",
    "no_known_threat": "SEM AMEAÇA CONHECIDA",
    "unknown": "NÃO ANALISADO",
}


def _md_escape(text: str) -> str:
    """Avoids Markdown/HTML injection from controllable values."""
    for ch in ("\\", "`", "*", "_", "[", "]", "<", ">", "|", "#"):
        text = text.replace(ch, "\\" + ch)
    return text


def _defang(value: str) -> str:
    return (
        value.replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace(".", "[.]")
    )


def render_report(obs: Observable) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    value_safe = _md_escape(_defang(obs.value) if obs.type in ("url", "domain", "ip") else obs.value)
    verdict = _VERDICT_PT.get(obs.verdict, obs.verdict)

    lines = [
        f"# Relatório de Inteligência — {value_safe}",
        "",
        f"**Gerado por:** ThreatForge v0.1 | **Data:** {now} | **TLP:** CLEAR",
        "",
        "## Resumo",
        "",
        f"| Campo | Valor |",
        f"|-------|-------|",
        f"| Tipo | `{obs.type}` |",
        f"| Indicador | `{value_safe}` |",
        f"| Score | **{obs.score}/100** |",
        f"| Veredito | **{verdict}** |",
        f"| Cadastrado em | {obs.created_at:%Y-%m-%d %H:%M UTC} |",
        f"| Último enriquecimento | "
        + (f"{obs.last_enriched_at:%Y-%m-%d %H:%M UTC}" if obs.last_enriched_at else "never")
        + " |",
        "",
        "## Fatores de score (explicáveis)",
        "",
    ]

    if obs.score_factors:
        lines += ["| Factor | Points | Rationale | Source |", "|---|---|---|---|"]
        for f in obs.score_factors:
            lines.append(
                f"| {f['name']} | +{f['points']} | {_md_escape(f['reason'])} | {f['source']} |"
            )
    else:
        lines.append("Nenhum fator de risco identificado nas fontes consultadas.")

    lines += ["", "## Evidências por fonte", ""]
    if obs.enrichments:
        for e in obs.enrichments:
            lines.append(f"### {e.source} ({e.created_at:%Y-%m-%d %H:%M UTC})")
            lines.append("")
            data = e.data or {}
            if data.get("skipped"):
                lines.append(f"_Source not queried: {_md_escape(str(data.get('reason')))}_")
            elif not data or data.get("listed") is False:
                lines.append("_Nenhum registro encontrado nesta fonte._")
            else:
                for k, v in data.items():
                    if v in (None, "", []):
                        continue
                    lines.append(f"- **{k}**: {_md_escape(str(v))}")
            lines.append("")
    else:
        lines.append("_Observable has not been enriched yet. Use `POST /observables/{id}/enrich`._")

    lines += [
        "",
        "## Recommendations",
        "",
    ]
    if obs.verdict == "malicious":
        lines.append(
            "- Bloquear o indicador em firewall/proxy/EDR e buscar ocorrências "
            "retroativas em logs (SIEM)."
        )
        lines.append("- Treat as an incident if confirmed communication with the indicator exists.")
    elif obs.verdict == "suspicious":
        lines.append("- Monitor the indicator and prioritize manual investigation.")
    elif obs.verdict in ("low", "no_known_threat"):
        lines.append(
            "- No immediate action. Absence from queried sources "
            "does not guarantee the indicator is benign."
        )
    else:
        lines.append("- Enrich the observable before making any decision.")

    lines += [
        "",
        "---",
        "_Sources: CISA KEV, FIRST EPSS, abuse.ch URLhaus, MITRE ATT&CK. "
        "Relatório gerado automaticamente; revise antes de distribuir._",
    ]
    return "\n".join(lines)
