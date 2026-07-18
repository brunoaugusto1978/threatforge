"""TF-VERIFY control-message handling (residual req #6).

The message ``TF-VERIFY-<nonce>`` is a control/handshake used to confirm a
source test. It MUST NOT:

  * enter the classifier;
  * generate correlation;
  * create a finding;
  * create a case;
  * generate an alert.

It only confirms the test and produces telemetry. We store the **hash** of the
nonce, not the nonce itself, and never log the nonce integrally.
"""
from __future__ import annotations

import hashlib
import re

# TF-VERIFY-<nonce>. Nonce is url-safe token, 8..128 chars.
_VERIFY_RE = re.compile(r"\bTF-VERIFY-([A-Za-z0-9_-]{8,128})\b")


def parse_verify_nonce(text: str | None) -> str | None:
    """Return the nonce if ``text`` is a TF-VERIFY control message, else None."""
    if not text or not isinstance(text, str):
        return None
    m = _VERIFY_RE.search(text)
    return m.group(1) if m else None


def is_control_message(text: str | None) -> bool:
    return parse_verify_nonce(text) is not None


def nonce_hash(nonce: str) -> str:
    """SHA-256 of the nonce. Store/compare this, never the raw nonce."""
    return hashlib.sha256(str(nonce).encode("utf-8")).hexdigest()


def redact_for_log(text: str | None) -> str:
    """Replace any TF-VERIFY nonce with a short hash prefix for safe logging."""
    if not text:
        return ""

    def _sub(m: re.Match) -> str:
        return f"TF-VERIFY-<nonce:{nonce_hash(m.group(1))[:12]}>"

    return _VERIFY_RE.sub(_sub, text)
