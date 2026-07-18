from pathlib import Path


def test_static_ui_contains_locked_catalog_and_safe_source_surface():
    source = Path("app/static/app.js").read_text()
    assert '"/collection/catalog"' in source
    assert '"/collection/connections"' in source
    assert "Telegram Intelligence sources" in source
    assert "secretref://file/telegram-collection-bot-token" in source
    assert "Links and message content are rendered as inert text" in source
    # Source/provider strings are interpolated only through the shared esc helper.
    assert "${esc(src.name || src.source_ref)}" in source
    assert "${esc(conn.name)}" in source
