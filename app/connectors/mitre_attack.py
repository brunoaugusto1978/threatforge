"""Conector MITRE ATT&CK (Enterprise).

Sync: downloads the public STIX bundle and populates the local techniques table,
used to provide TTP context in reports and lookups.
"""
from sqlalchemy.orm import Session

from app import config
from app.connectors.base import Connector
from app.models import AttackTechnique


class MitreAttackConnector(Connector):
    name = "mitre_attack"
    supported_types = ()  # context/lookup only; it does not enrich IOCs directly in the MVP

    def sync(self, db: Session) -> int:
        with self._client() as client:
            resp = client.get(config.MITRE_ATTACK_URL)
            resp.raise_for_status()
            bundle = resp.json()

        count = 0
        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern" or obj.get("revoked"):
                continue
            ext = next(
                (
                    r
                    for r in obj.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"
                ),
                None,
            )
            if not ext or not ext.get("external_id"):
                continue
            tid = ext["external_id"]
            tactics = ",".join(
                p.get("phase_name", "")
                for p in obj.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            )
            tech = db.get(AttackTechnique, tid) or AttackTechnique(technique_id=tid)
            tech.name = obj.get("name")
            tech.tactics = tactics
            tech.description = (obj.get("description") or "")[:4000]
            tech.url = ext.get("url")
            db.merge(tech)
            count += 1
        db.commit()
        return count

    def enrich(self, observable_type: str, value: str, db) -> dict | None:
        return None
