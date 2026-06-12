"""Conector CISA Known Exploited Vulnerabilities (KEV).

Sync: baixa o feed JSON público e popula a tabela local kev_entries.
Enrich: lookup local por CVE (rápido, sem rate limit).
"""
from sqlalchemy.orm import Session

from app import config
from app.connectors.base import Connector
from app.models import KEVEntry


class CisaKevConnector(Connector):
    name = "cisa_kev"
    supported_types = ("cve",)

    def sync(self, db: Session) -> int:
        with self._client() as client:
            resp = client.get(config.KEV_FEED_URL)
            resp.raise_for_status()
            payload = resp.json()

        vulns = payload.get("vulnerabilities", [])
        for v in vulns:
            cve_id = v.get("cveID")
            if not cve_id:
                continue
            entry = db.get(KEVEntry, cve_id) or KEVEntry(cve_id=cve_id)
            entry.vendor = v.get("vendorProject")
            entry.product = v.get("product")
            entry.name = v.get("vulnerabilityName")
            entry.description = (v.get("shortDescription") or "")[:4000]
            entry.date_added = v.get("dateAdded")
            entry.due_date = v.get("dueDate")
            entry.known_ransomware = v.get("knownRansomwareCampaignUse")
            db.merge(entry)
        db.commit()
        return len(vulns)

    def enrich(self, observable_type: str, value: str, db: Session) -> dict | None:
        entry = db.get(KEVEntry, value)
        if entry is None:
            return None
        return {
            "listed": True,
            "vendor": entry.vendor,
            "product": entry.product,
            "name": entry.name,
            "description": entry.description,
            "date_added": entry.date_added,
            "due_date": entry.due_date,
            "known_ransomware": entry.known_ransomware,
        }
