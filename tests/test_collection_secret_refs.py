from __future__ import annotations

from app.collection import secrets


def test_environment_reference_is_namespaced(monkeypatch):
    monkeypatch.setenv("THREATFORGE_TEST_BOT_TOKEN", "synthetic-token")
    ref = secrets.validate_opaque_ref(
        "secretref://env/THREATFORGE_TEST_BOT_TOKEN"
    )
    assert secrets.resolve_opaque_ref(ref) == "synthetic-token"


def test_file_reference_is_confined_to_secret_directory(monkeypatch, tmp_path):
    secret = tmp_path / "telegram-collection-bot-token"
    secret.write_text("synthetic-token")
    monkeypatch.setenv("THREATFORGE_SECRET_DIR", str(tmp_path))
    ref = secrets.validate_opaque_ref(
        "secretref://file/telegram-collection-bot-token"
    )
    assert secrets.resolve_opaque_ref(ref) == "synthetic-token"
    assert secrets.resolve_opaque_ref("secretref://file/../escape") is None


def test_raw_value_is_not_a_supported_reference():
    try:
        secrets.validate_opaque_ref("123456:raw-token")
    except ValueError as exc:
        assert str(exc) == "unsupported_secret_reference"
    else:
        raise AssertionError("raw secret unexpectedly accepted")


def test_file_reference_rejects_symlink_even_inside_secret_directory(monkeypatch, tmp_path):
    target = tmp_path / "real-token"
    target.write_text("synthetic-token")
    link = tmp_path / "telegram-collection-bot-token"
    link.symlink_to(target)
    monkeypatch.setenv("THREATFORGE_SECRET_DIR", str(tmp_path))
    assert secrets.resolve_opaque_ref(
        "secretref://file/telegram-collection-bot-token"
    ) is None
