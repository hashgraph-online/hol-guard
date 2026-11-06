from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.daemon.dashboard_bundle import (
    dashboard_build_id,
    is_pinned_path,
    pin_dashboard_bundle,
    pinned_dashboard_file,
    stamp_dashboard_build,
)


def _write_bundle(static_dir: Path, generation: str) -> None:
    (static_dir / "assets" / "chunks").mkdir(parents=True, exist_ok=True)
    (static_dir / "index.html").write_text(f"<html>{generation}</html>", encoding="utf-8")
    (static_dir / "assets" / "guard-dashboard.js").write_text(f"entry {generation}", encoding="utf-8")
    (static_dir / "assets" / "chunks" / "home-dashboard.js").write_text(f"home {generation}", encoding="utf-8")


def test_running_daemon_keeps_serving_its_own_bundle_after_upgrade(tmp_path: Path) -> None:
    static_dir = tmp_path / "static"
    _write_bundle(static_dir, "old")
    pin_dashboard_bundle(static_dir)

    _write_bundle(static_dir, "new")
    (static_dir / "assets" / "chunks" / "added-later.js").write_text("new only", encoding="utf-8")

    assert pinned_dashboard_file(static_dir, "index.html") == b"<html>old</html>"
    assert pinned_dashboard_file(static_dir, "assets/guard-dashboard.js") == b"entry old"
    assert pinned_dashboard_file(static_dir, "assets/chunks/home-dashboard.js") == b"home old"
    assert pinned_dashboard_file(static_dir, "assets/chunks/added-later.js") is None


def test_pinned_lookup_only_matches_exact_bundle_paths(tmp_path: Path) -> None:
    static_dir = tmp_path / "static"
    _write_bundle(static_dir, "only")
    (tmp_path / "secret.txt").write_text("outside", encoding="utf-8")
    pin_dashboard_bundle(static_dir)

    assert pinned_dashboard_file(static_dir, "assets/../../secret.txt") is None
    assert pinned_dashboard_file(static_dir, "assets/chunks/../guard-dashboard.js") is None
    assert is_pinned_path("assets/chunks/home-dashboard.js")
    assert is_pinned_path("index.html")
    assert not is_pinned_path("brand/Logo_Icon_Dark.png")
    assert not is_pinned_path("favicon.ico")


def test_lookup_pins_on_first_use_when_startup_did_not(tmp_path: Path) -> None:
    static_dir = tmp_path / "static"
    _write_bundle(static_dir, "first")

    assert pinned_dashboard_file(static_dir, "assets/guard-dashboard.js") == b"entry first"
    _write_bundle(static_dir, "second")
    assert pinned_dashboard_file(static_dir, "assets/guard-dashboard.js") == b"entry first"


def test_build_id_follows_the_pinned_bundle_not_the_disk(tmp_path: Path) -> None:
    static_dir = tmp_path / "static"
    _write_bundle(static_dir, "old")
    pin_dashboard_bundle(static_dir)
    pinned_id = dashboard_build_id(static_dir)

    _write_bundle(static_dir, "new")

    assert pinned_id is not None
    assert dashboard_build_id(static_dir) == pinned_id

    other_dir = tmp_path / "other"
    _write_bundle(other_dir, "new")
    assert dashboard_build_id(other_dir) not in (None, pinned_id)


def test_build_id_is_none_without_a_bundled_dashboard(tmp_path: Path) -> None:
    static_dir = tmp_path / "empty"
    static_dir.mkdir()

    assert dashboard_build_id(static_dir) is None
    assert stamp_dashboard_build(b"<html><head></head></html>", None) == b"<html><head></head></html>"


def test_shell_is_stamped_once_inside_head() -> None:
    stamped = stamp_dashboard_build(b"<html><head><title>x</title></head><body></body></html>", "abc123")

    assert stamped.count(b'<meta name="guard-dashboard-build" content="abc123" />') == 1
    assert stamped.index(b"guard-dashboard-build") < stamped.index(b"</head>")
    assert stamp_dashboard_build(b"<html></html>", "abc123") == b"<html></html>"
