"""Interface padrão para conectores.

Para criar um conector novo: herde de Connector, defina `name` e os tipos
suportados, e implemente `enrich()` retornando um dict serializável (ou None
se a fonte não tem nada sobre o IOC).
"""
from abc import ABC, abstractmethod

import httpx

from app import config


class Connector(ABC):
    name: str = "base"
    supported_types: tuple[str, ...] = ()

    def supports(self, observable_type: str) -> bool:
        return observable_type in self.supported_types

    def _client(self) -> httpx.Client:
        return httpx.Client(
            timeout=config.HTTP_TIMEOUT,
            headers={"User-Agent": "ThreatForge/0.1 (open-source CTI)"},
            follow_redirects=True,
        )

    @abstractmethod
    def enrich(self, observable_type: str, value: str, db) -> dict | None:
        """Consulta a fonte e retorna dados brutos relevantes (ou None)."""
