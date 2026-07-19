from __future__ import annotations

import os

from app.collection import healthcheck


def test_heartbeat_probe_accepts_fresh_file_and_rejects_stale(tmp_path):
    path = tmp_path / "heartbeat"
    healthcheck.touch_heartbeat(path)
    modified = path.stat().st_mtime
    assert healthcheck.is_healthy(path, max_age_seconds=10, now=modified + 5)
    assert not healthcheck.is_healthy(path, max_age_seconds=10, now=modified + 11)


def test_heartbeat_probe_rejects_missing_file_and_invalid_configuration(
    tmp_path, monkeypatch
):
    path = tmp_path / "missing"
    assert not healthcheck.is_healthy(path, max_age_seconds=10)
    monkeypatch.setenv("THREATFORGE_COLLECTION_HEARTBEAT_MAX_AGE", "invalid")
    assert not healthcheck.is_healthy(path)


def test_heartbeat_file_uses_environment_override(tmp_path, monkeypatch):
    path = tmp_path / "custom-heartbeat"
    monkeypatch.setenv("THREATFORGE_COLLECTION_HEARTBEAT_FILE", os.fspath(path))
    healthcheck.touch_heartbeat()
    assert path.exists()
    assert healthcheck.main() == 0
