"""Conector EPSS (FIRST.org) — probabilidade de exploração de CVEs."""
from app import config
from app.connectors.base import Connector


class EpssConnector(Connector):
    name = "epss"
    supported_types = ("cve",)

    def enrich(self, observable_type: str, value: str, db) -> dict | None:
        with self._client() as client:
            resp = client.get(config.EPSS_API, params={"cve": value})
            resp.raise_for_status()
            data = resp.json()

        items = data.get("data", [])
        if not items:
            return None
        item = items[0]
        return {
            "epss": float(item.get("epss", 0.0)),
            "percentile": float(item.get("percentile", 0.0)),
            "date": item.get("date"),
        }
