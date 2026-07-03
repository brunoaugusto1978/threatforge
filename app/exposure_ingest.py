"""Exposure ingestion pipeline (Community): parse → normalize → fingerprint →
dedup → redact, plus field classification and PII masking by role.

Security invariants:
- Secrets/credentials are NEVER stored or returned in plaintext. On ingestion,
  passwords/tokens/secrets are reduced to SHA-256 fingerprint + partial mask.
- No outbound network, no premium SDKs. Local parsers only.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
from typing import Iterable

# ---------------------------------------------------------------------------
# Field classification & masking
# ---------------------------------------------------------------------------
PUBLIC, PII, CREDENTIAL, SECRET = "PUBLIC", "PII", "CREDENTIAL", "SECRET"

# classe por nome de campo (chaves do detail / asset)
_FIELD_CLASS = {
    "email": PII, "person_label": PII, "person": PII, "full_name": PII, "cpf": PII,
    "phone": PII, "url": PUBLIC, "url_defanged": PUBLIC, "domain": PUBLIC,
    "platform": PUBLIC, "exposure_kind": PUBLIC, "stealer_family": PUBLIC,
    "breach_name": PUBLIC, "line_source": PUBLIC,
    "password": CREDENTIAL, "password_masked": CREDENTIAL, "password_sha256": CREDENTIAL,
    "token": SECRET, "api_key": SECRET, "secret": SECRET, "private_key": SECRET,
    "fingerprint": SECRET,
}

# chaves que NUNCA podem ser persistidas/retornadas em claro (removidas na redação)
_PLAINTEXT_SECRET_KEYS = {"password", "token", "api_key", "secret", "private_key",
                         "auth_key", "client_secret", "passwd", "pwd",
                         "cookie", "cookies", "session", "autofill", "card", "cvv",
                         "wallet", "crypto_wallet", "seed_phrase"}

# valores que NUNCA são retidos (nem hash) — dados sensíveis de stealer log
_DROP_KEYS = {"cookie", "cookies", "session", "sessions", "autofill", "card", "cc",
              "cvv", "wallet", "crypto_wallet", "seed_phrase"}


def classify(field: str) -> str:
    return _FIELD_CLASS.get(field.lower(), PUBLIC)


def _mask_email(value: str) -> str:
    v = str(value or "")
    if "@" not in v:
        return _mask_generic(v)
    local, _, domain = v.partition("@")
    dom_name, _, tld = domain.rpartition(".")
    return f"{local[:1]}***@{(dom_name[:1] + '***') if dom_name else '***'}{('.' + tld) if tld else ''}"


def _mask_generic(value: str) -> str:
    v = str(value or "")
    if len(v) <= 2:
        return "***"
    return f"{v[0]}***{v[-1]}"


def mask_value(value, data_class: str, role: str, policy: str) -> str:
    """Aplica a política de visualização a UM valor.

    SECRET/CREDENTIAL: nunca revela (só hash/máscara já existem no armazenamento).
    PII: revela por padrão (policy 'off'); em 'by_role', só admin vê completo.
    """
    if value is None:
        return value
    if data_class in (SECRET, CREDENTIAL):
        return value  # o que existe já é hash/máscara; nada a revelar
    if data_class == PII and policy == "by_role" and role != "admin":
        return _mask_email(value) if "@" in str(value) else _mask_generic(value)
    return value


def mask_detail(detail: dict, role: str, policy: str) -> dict:
    if not isinstance(detail, dict):
        return detail
    out = {}
    for k, v in detail.items():
        cls = classify(k)
        out[k] = mask_value(v, cls, role, policy) if isinstance(v, str) else v
    return out


# ---------------------------------------------------------------------------
# Normalization & redaction
# ---------------------------------------------------------------------------
def norm(value) -> str:
    return (str(value or "")).strip().lower()


def sha256_norm(value) -> str:
    return hashlib.sha256(norm(value).encode("utf-8")).hexdigest()


def mask_secret(value) -> str:
    v = str(value or "")
    if not v:
        return ""
    if len(v) <= 3:
        return "***"
    return f"{v[:2]}****{v[-1]}"


def redact_detail(detail: dict) -> dict:
    """Remove qualquer segredo em claro, substituindo por hash + máscara.

    Ex.: {'password': 'S3nha!x'} -> {'password_sha256': '...', 'password_masked': 'S3****x'}.
    Chaves de segredo cruas são SEMPRE removidas.
    """
    if not isinstance(detail, dict):
        return {}
    out = {}
    for k, v in detail.items():
        kl = k.lower()
        if kl in _DROP_KEYS:
            continue  # nunca retido (nem hash)
        if kl in ("password", "passwd", "pwd"):
            if v:
                out["password_sha256"] = sha256_norm(v)
                out["password_masked"] = mask_secret(v)
        elif kl in ("token", "api_key", "secret", "private_key", "auth_key", "client_secret"):
            if v:
                out["fingerprint"] = hashlib.sha256(str(v).encode("utf-8")).hexdigest()
                out["secret_masked"] = mask_secret(v)
        else:
            out[k] = v
    return out


def has_plaintext_secret(detail: dict) -> bool:
    return isinstance(detail, dict) and bool(_PLAINTEXT_SECRET_KEYS & {k.lower() for k in detail})


# ---------------------------------------------------------------------------
# Fingerprint / dedup
# ---------------------------------------------------------------------------
def dedup_key(tenant_id: int, exposure_type: str, detail: dict) -> str:
    d = detail or {}
    if exposure_type == "credential_exposure":
        parts = [str(tenant_id), exposure_type, norm(d.get("email")),
                 str(d.get("password_sha256") or "")]
    elif exposure_type == "identity_exposure":
        parts = [str(tenant_id), exposure_type, norm(d.get("email") or d.get("person_label")),
                 norm(d.get("exposure_kind")), norm(d.get("url") or d.get("url_defanged"))]
    else:
        parts = [str(tenant_id), exposure_type, json.dumps(d, sort_keys=True)]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Parsers (local; parser_version versionado p/ reprocessamento)
# ---------------------------------------------------------------------------
PARSER_VERSIONS = {"combolist": "1.0", "csv_generic": "1.0", "json_findings": "1.0",
                   "stealer_log": "1.0", "breach": "1.0"}


def _machine_id_hash(v) -> str:
    return hashlib.sha256(("mid:" + norm(v)).encode("utf-8")).hexdigest()


def _rec_credential(email, password, extra=None):
    detail = {"email": norm(email)}
    if password:
        detail["password"] = password  # será redigido em redact_detail
    if extra:
        detail.update(extra)
    return {"exposure_type": "credential_exposure",
            "title": f"Credential exposure {norm(email)}",
            "detail": detail}


def parse_combolist(text: str) -> Iterable[dict]:
    """Linhas 'email:senha' (ou 'email;senha'). Uma credencial por linha."""
    for i, line in enumerate(text.splitlines()):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        sep = ":" if ":" in line else (";" if ";" in line else None)
        if not sep:
            yield {"_error": "no separator", "_line": i + 1}
            continue
        email, _, pw = line.partition(sep)
        if "@" not in email:
            yield {"_error": "invalid email", "_line": i + 1}
            continue
        rec = _rec_credential(email, pw)
        rec["_line"] = i + 1
        yield rec


def parse_csv_generic(text: str) -> Iterable[dict]:
    """CSV com cabeçalho. Colunas reconhecidas: email, password, domain, url,
    exposure_kind, person_label. Sem cabeçalho de e-mail -> erro por linha."""
    reader = csv.DictReader(io.StringIO(text))
    for i, row in enumerate(reader):
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        email = row.get("email")
        if email and "@" in email:
            extra = {k: row[k] for k in ("domain", "url", "exposure_kind") if row.get(k)}
            if row.get("password"):
                rec = _rec_credential(email, row["password"], extra)
            else:
                detail = {"email": norm(email), **extra}
                rec = {"exposure_type": "identity_exposure",
                       "title": f"Identity exposure {norm(email)}", "detail": detail}
            rec["_line"] = i + 2
            yield rec
        else:
            yield {"_error": "missing/invalid email", "_line": i + 2}


def parse_json_findings(text: str) -> Iterable[dict]:
    """Lista JSON de findings estruturados [{exposure_type, title, detail, ...}]."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        yield {"_error": f"invalid json: {e.msg}", "_line": 0}
        return
    if not isinstance(data, list):
        yield {"_error": "expected a JSON array", "_line": 0}
        return
    for i, item in enumerate(data):
        if not isinstance(item, dict) or "exposure_type" not in item:
            yield {"_error": "record missing exposure_type", "_line": i + 1}
            continue
        item.setdefault("detail", {})
        item.setdefault("title", f"{item['exposure_type']} #{i + 1}")
        item["_line"] = i + 1
        yield item


_STEALER_META_KEYS = {
    "build": "stealer_family", "stealer": "stealer_family", "software": "stealer_family",
    "machineid": "machine_id", "machine id": "machine_id", "hwid": "machine_id", "pc": "machine_id",
    "date": "malware_date", "log date": "malware_date", "install date": "malware_date",
}


def parse_stealer_log(text: str):
    """Stealer log (estilo Passwords.txt): metadados globais (Build/MachineID/Date)
    + blocos URL/Login/Password. Retém SÓ metadados (family/date/machine_id_hash/
    captured_types); senha é redigida; cookies/tokens nunca entram."""
    fam = mid = mdate = None
    blocks, cur, cur_line = [], {}, 0

    def _flush():
        if cur.get("login") and cur.get("password"):
            blocks.append((dict(cur), cur_line))

    for i, raw in enumerate(text.splitlines()):
        line = raw.strip()
        if not line:
            _flush(); cur.clear(); cur_line = 0
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip().lower(); val = val.strip()
        meta = _STEALER_META_KEYS.get(key)
        if meta == "stealer_family":
            fam = fam or val.lower()
        elif meta == "machine_id":
            mid = mid or val
        elif meta == "malware_date":
            mdate = mdate or val
        elif key in ("url", "host", "soft"):
            if cur.get("login") and cur.get("password"):
                _flush(); cur.clear(); cur_line = 0
            cur["url"] = val; cur_line = cur_line or (i + 1)
        elif key in ("login", "username", "user", "email", "user name"):
            cur["login"] = val; cur_line = cur_line or (i + 1)
        elif key in ("password", "pass", "passwd"):
            cur["password"] = val; cur_line = cur_line or (i + 1)
    _flush()

    for blk, line_no in blocks:
        login = blk.get("login", "")
        if "@" not in login:
            yield {"_error": "login is not an email", "_line": line_no}
            continue
        extra = {"source_kind": "stealer", "captured_types": ["passwords"]}
        if fam:
            extra["stealer_family"] = fam
        if mdate:
            extra["malware_date"] = mdate
        if mid:
            extra["machine_id_hash"] = _machine_id_hash(mid)  # pseudônimo, nunca cru
        if blk.get("url"):
            extra["url"] = blk["url"]
        rec = _rec_credential(login, blk["password"], extra)
        rec["_line"] = line_no
        yield rec


def parse_breach(text: str):
    """Breach dump em CSV. Colunas: email (obrig.), password (opcional -> redigida),
    breach/breach_name, domain. source_kind=breach."""
    reader = csv.DictReader(io.StringIO(text))
    for i, row in enumerate(reader):
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        email = row.get("email")
        if not email or "@" not in email:
            yield {"_error": "missing/invalid email", "_line": i + 2}
            continue
        extra = {"source_kind": "breach"}
        bn = row.get("breach") or row.get("breach_name")
        if bn:
            extra["breach_name"] = bn
        if row.get("domain"):
            extra["domain"] = row["domain"]
        rec = _rec_credential(email, row.get("password"), extra)
        rec["_line"] = i + 2
        yield rec


PARSERS = {
    "combolist": parse_combolist,
    "csv_generic": parse_csv_generic,
    "json_findings": parse_json_findings,
    "stealer_log": parse_stealer_log,
    "breach": parse_breach,
}
