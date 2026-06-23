"""Armazenamento de evidências. Hash SHA-256 calculado no servidor durante leitura
em chunks (limite aplicado durante a leitura, não após carregar tudo na memória).
storage_key é gerado pelo servidor (UUID); nunca usa o filename do usuário no path."""
from __future__ import annotations

import hashlib
import os
import uuid

from app import config


class EvidenceTooLarge(Exception):
    pass


class EvidenceConfigError(Exception):
    pass


# assinaturas (magic bytes) para sniff mínimo no servidor
_MAGIC = {
    "application/pdf": [b"%PDF"],
    "image/png": [b"\x89PNG\r\n\x1a\n"],
    "image/jpeg": [b"\xff\xd8\xff"],
    "image/gif": [b"GIF87a", b"GIF89a"],
    "application/zip": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
}
_TEXT_LIKE = {"text/plain", "text/csv", "application/json", "message/rfc822"}


def sniff_ok(declared: str, head: bytes) -> bool:
    """Valida o conteúdo contra o MIME declarado (anti content-type forjado)."""
    if declared == "image/webp":
        return len(head) >= 12 and head[0:4] == b"RIFF" and head[8:12] == b"WEBP"
    if declared in _MAGIC:
        return any(head.startswith(sig) for sig in _MAGIC[declared])
    if declared in _TEXT_LIKE:
        if b"\x00" in head:   # binário disfarçado de texto
            return False
        if declared == "application/json":
            stripped = head.lstrip()
            if stripped and stripped[:1] not in (b"{", b"[", b"\"", b"-") and not stripped[:1].isdigit():
                return False
        return True
    return False


def _full(storage_key: str) -> str:
    return os.path.join(config.EVIDENCE_STORAGE_DIR, storage_key)


def save_stream(upload, tenant_id: int, case_id: int) -> dict:
    """Lê o upload em chunks, calcula SHA-256 e (se backend=local) grava em disco.
    Retorna {sha256, size, storage_key|None, backend}."""
    backend = config.EVIDENCE_STORAGE_BACKEND
    if backend not in ("local", "none"):
        raise EvidenceConfigError(f"invalid EVIDENCE_STORAGE_BACKEND: {backend!r}")
    h = hashlib.sha256()
    size = 0
    storage_key = None
    out = None
    full = None
    if backend == "local":
        storage_key = f"{tenant_id}/{case_id}/{uuid.uuid4().hex}.bin"
        full = _full(storage_key)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        out = open(full, "wb")
    try:
        while True:
            chunk = upload.file.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > config.EVIDENCE_MAX_BYTES:
                raise EvidenceTooLarge()
            h.update(chunk)
            if out:
                out.write(chunk)
    except EvidenceTooLarge:
        if out:
            out.close()
            out = None
        if full and os.path.exists(full):
            os.remove(full)
        raise
    finally:
        if out:
            out.close()
    return {"sha256": h.hexdigest(), "size": size,
            "storage_key": storage_key, "backend": backend}


def path_for(storage_key: str) -> str:
    return _full(storage_key)


def delete_key(storage_key: str | None) -> None:
    if not storage_key:
        return
    full = _full(storage_key)
    try:
        if os.path.exists(full):
            os.remove(full)
    except OSError:
        pass
