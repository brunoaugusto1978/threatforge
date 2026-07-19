"""Docker health probe for the isolated collection worker.

The API image also serves the worker process, so the API's HTTP healthcheck is
not valid for the worker container.  The worker writes a local heartbeat before
and after each bounded cycle; this probe verifies that the loop is still alive
without contacting Telegram or exposing credentials.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

DEFAULT_HEARTBEAT_FILE = "/tmp/threatforge-collector-heartbeat"
DEFAULT_MAX_AGE_SECONDS = 90


def heartbeat_file() -> Path:
    return Path(
        os.getenv(
            "THREATFORGE_COLLECTION_HEARTBEAT_FILE",
            DEFAULT_HEARTBEAT_FILE,
        )
    )


def touch_heartbeat(path: Path | None = None) -> None:
    target = path or heartbeat_file()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.touch(exist_ok=True)


def heartbeat_age_seconds(
    path: Path | None = None, *, now: float | None = None
) -> float | None:
    target = path or heartbeat_file()
    try:
        modified = target.stat().st_mtime
    except FileNotFoundError:
        return None
    return max(0.0, (time.time() if now is None else now) - modified)


def is_healthy(
    path: Path | None = None,
    *,
    max_age_seconds: int | None = None,
    now: float | None = None,
) -> bool:
    if max_age_seconds is None:
        try:
            max_age_seconds = int(
                os.getenv(
                    "THREATFORGE_COLLECTION_HEARTBEAT_MAX_AGE",
                    str(DEFAULT_MAX_AGE_SECONDS),
                )
            )
        except ValueError:
            return False
    if max_age_seconds < 1:
        return False
    age = heartbeat_age_seconds(path, now=now)
    return age is not None and age <= max_age_seconds


def main() -> int:
    return 0 if is_healthy() else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
