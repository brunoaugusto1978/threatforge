"""Conector URLhaus (abuse.ch).

Queries the public API by URL, host (domain/IP) or payload hash.
A API do abuse.ch exige Auth-Key (gratuita): https://auth.abuse.ch
"""
import logging

from app import config
from app.connectors.base import Connector

logger = logging.getLogger(__name__)


class UrlhausConnector(Connector):
    name = "urlhaus"
    supported_types = ("url", "domain", "ip", "hash")

    def _headers(self) -> dict:
        h = {}
        if config.ABUSECH_API_KEY:
            h["Auth-Key"] = config.ABUSECH_API_KEY
        return h

    def enrich(self, observable_type: str, value: str, db) -> dict | None:
        if not config.ABUSECH_API_KEY:
            logger.warning("URLhaus pulado: ABUSECH_API_KEY não configurada")
            return {"skipped": True, "reason": "ABUSECH_API_KEY não configurada"}

        if observable_type == "url":
            endpoint, payload = "/url/", {"url": value}
        elif observable_type in ("domain", "ip"):
            endpoint, payload = "/host/", {"host": value}
        else:  # hash
            key = {32: "md5_hash", 40: "sha1_hash", 64: "sha256_hash"}[len(value)]
            endpoint, payload = "/payload/", {key: value}

        with self._client() as client:
            resp = client.post(
                config.URLHAUS_API + endpoint, data=payload, headers=self._headers()
            )
            resp.raise_for_status()
            data = resp.json()

        status = data.get("query_status")
        if status != "ok":
            return {"listed": False, "query_status": status}

        result: dict = {"listed": True, "query_status": "ok"}
        if observable_type == "url":
            result.update(
                url_status=data.get("url_status"),
                threat=data.get("threat"),
                date_added=data.get("date_added"),
                tags=data.get("tags"),
                reference=data.get("urlhaus_reference"),
            )
        elif observable_type in ("domain", "ip"):
            result.update(
                url_count=data.get("url_count"),
                first_seen=data.get("firstseen"),
                blacklists=data.get("blacklists"),
                reference=data.get("urlhaus_reference"),
            )
        else:
            result.update(
                file_type=data.get("file_type"),
                signature=data.get("signature"),
                url_count=data.get("url_count"),
                first_seen=data.get("firstseen"),
            )
        return result
