"""Geração de relatório técnico em Markdown por observável."""
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
    """Evita injeção de Markdown/HTML a partir de valores controláveis."""
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
        + (f"{obs.last_enriched_at:%Y-%m-%d %H:%M UTC}" if obs.last_enriched_at else "nunca")
        + " |",
        "",
        "## Fatores de score (explicáveis)",
        "",
    ]

    if obs.score_factors:
        lines += ["| Fator | Pontos | Justificativa | Fonte |", "|---|---|---|---|"]
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
                lines.append(f"_Fonte não consultada: {_md_escape(str(data.get('reason')))}_")
            elif not data or data.get("listed") is False:
                lines.append("_Nenhum registro encontrado nesta fonte._")
            else:
                for k, v in data.items():
                    if v in (None, "", []):
                        continue
                    lines.append(f"- **{k}**: {_md_escape(str(v))}")
            lines.append("")
    else:
        lines.append("_Observável ainda não enriquecido. Use `POST /observables/{id}/enrich`._")

    lines += [
        "",
        "## Recomendações",
        "",
    ]
    if obs.verdict == "malicious":
        lines.append(
            "- Bloquear o indicador em firewall/proxy/EDR e buscar ocorrências "
            "retroativas em logs (SIEM)."
        )
        lines.append("- Tratar como incidente se houver comunicação confirmada com o indicador.")
    elif obs.verdict == "suspicious":
        lines.append("- Monitorar o indicador e priorizar investigação manual.")
    elif obs.verdict in ("low", "no_known_threat"):
        lines.append(
            "- Sem ação imediata. Ausência de registro nas fontes consultadas "
            "não garante que o indicador seja benigno."
        )
    else:
        lines.append("- Enriquecer o observável antes de qualquer decisão.")

    lines += [
        "",
        "---",
        "_Fontes: CISA KEV, FIRST EPSS, abuse.ch URLhaus, MITRE ATT&CK. "
        "Relatório gerado automaticamente; revise antes de distribuir._",
    ]
    return "\n".join(lines)
