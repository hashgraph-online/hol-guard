from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import live_identity, manager, runtime_repair, start_lock


def test_repair_restarts_authenticated_older_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    retired: list[Path] = []
    events: list[str] = []

    @contextmanager
    def lifecycle_lock(_home: Path):
        events.append("lock-enter")
        yield
        events.append("lock-exit")

    monkeypatch.setattr(
        runtime_repair,
        "verified_live_guard_daemon_identity",
        lambda _home: {"package_version": "3.0.18", "runtime_fingerprint": "older"},
    )
    monkeypatch.setattr(runtime_repair, "_guard_daemon_start_lock", lifecycle_lock)
    monkeypatch.setattr(runtime_repair, "_verified_live_runtime", lambda _state: None)
    monkeypatch.setattr(
        runtime_repair,
        "repair_approval_center_locator",
        lambda _home: {"repaired": True, "cleared": []},
    )
    monkeypatch.setattr(
        runtime_repair,
        "retire_all_guard_daemons_for_home",
        lambda home: retired.append(home) or [321],
    )
    monkeypatch.setattr(runtime_repair, "guard_daemon_retirement_is_complete", lambda _home: True)
    monkeypatch.setattr(runtime_repair, "clear_guard_daemon_state", lambda _home: None)
    monkeypatch.setattr(runtime_repair, "__version__", "3.0.34")
    monkeypatch.setattr(
        runtime_repair,
        "ensure_guard_daemon_after_update",
        lambda _home, *, home_dir: events.append("ensure") or "http://127.0.0.1:5474",
    )

    result = runtime_repair.repair_guard_daemon_runtime(guard_home, home_dir=home_dir)

    assert result["runtime_status"] == "restarted"
    assert result["daemon_version"] == "3.0.18"
    assert result["cli_version"] == "3.0.34"
    assert result["retired"] == [321]
    assert retired == [guard_home]
    assert events == ["lock-enter", "ensure", "lock-exit"]


def test_repair_retains_authenticated_newer_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(
        runtime_repair,
        "verified_live_guard_daemon_identity",
        lambda _home: {
            "package_version": "3.0.35",
            "runtime_fingerprint": "newer",
            "compatibility_version": manager.GUARD_DAEMON_COMPATIBILITY_VERSION,
            "source_root": "Library/Application Support/org.hol.guard.desktop/core/versions/3.0.35/hol-guard",
        },
    )
    monkeypatch.setattr(
        runtime_repair,
        "_verified_live_runtime",
        lambda _state: (runtime_repair.Version("3.0.35"), "3.0.35", "newer"),
    )
    monkeypatch.setattr(
        runtime_repair,
        "repair_approval_center_locator",
        lambda _home: {"repaired": True, "cleared": []},
    )
    monkeypatch.setattr(runtime_repair, "__version__", "3.0.34")
    monkeypatch.setattr(
        runtime_repair,
        "retire_all_guard_daemons_for_home",
        lambda _home: (_ for _ in ()).throw(AssertionError("newer runtime must remain active")),
    )

    result = runtime_repair.repair_guard_daemon_runtime(guard_home)

    assert result["runtime_status"] == "retained_newer_runtime"
    assert result["daemon_version"] == "3.0.35"


def test_ensure_keeps_newer_live_daemon_when_older_executable_is_requested(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setattr(manager, "desktop_preflight_requested", lambda: False)
    monkeypatch.setattr(manager, "_schedule_stale_ephemeral_guard_daemon_reap", lambda **_kwargs: None)
    monkeypatch.setattr(manager, "_schedule_duplicate_guard_daemon_retirement", lambda _home: None)
    monkeypatch.setattr(
        manager,
        "_live_or_newer_daemon_url",
        lambda _home, *, executable, preferred_port: "http://127.0.0.1:59999",
    )

    url = manager.ensure_guard_daemon(
        tmp_path / "guard-home",
        home_dir=home_dir,
        executable=tmp_path / "older-core" / "hol-guard",
        preferred_port=5474,
    )

    assert url == "http://127.0.0.1:59999"


def test_live_or_newer_daemon_url_port_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.daemon import runtime_peer

    monkeypatch.setattr(runtime_peer, "retain_newer_live_daemon_url", lambda *_a, **_k: "http://127.0.0.1:59999")
    monkeypatch.setattr(manager, "load_guard_daemon_url", lambda _home: "http://127.0.0.1:59999")
    monkeypatch.setattr(manager, "_guard_daemon_url_port", lambda _url: 59999)
    kept = runtime_peer.live_or_newer_daemon_url(
        tmp_path, executable=tmp_path / "older", preferred_port=5474, current_version="3.0.1"
    )
    skipped = runtime_peer.live_or_newer_daemon_url(
        tmp_path, executable=None, preferred_port=5474, current_version="3.0.1"
    )
    assert kept == "http://127.0.0.1:59999"
    assert skipped is None


def test_repair_restarts_newer_mismatched_non_desktop_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setattr(
        runtime_repair,
        "verified_live_guard_daemon_identity",
        lambda _home: {
            "package_version": "3.0.35",
            "runtime_fingerprint": "foreign-runtime",
            "compatibility_version": manager.GUARD_DAEMON_COMPATIBILITY_VERSION,
            "source_root": "/opt/hol-guard/lib/python",
        },
    )
    monkeypatch.setattr(
        runtime_repair,
        "_verified_live_runtime",
        lambda _state: (runtime_repair.Version("3.0.35"), "3.0.35", "foreign-runtime"),
    )
    monkeypatch.setattr(runtime_repair, "__version__", "3.0.34")
    monkeypatch.setattr(
        runtime_repair,
        "repair_approval_center_locator",
        lambda _home: {"repaired": True, "cleared": []},
    )
    monkeypatch.setattr(runtime_repair, "retire_all_guard_daemons_for_home", lambda _home: [321])
    monkeypatch.setattr(runtime_repair, "guard_daemon_retirement_is_complete", lambda _home: True)
    monkeypatch.setattr(runtime_repair, "clear_guard_daemon_state", lambda _home: None)
    monkeypatch.setattr(
        runtime_repair,
        "ensure_guard_daemon_after_update",
        lambda _home, *, home_dir: "http://127.0.0.1:5474",
    )

    result = runtime_repair.repair_guard_daemon_runtime(guard_home, home_dir=home_dir)

    assert result["runtime_status"] == "restarted"
    assert result["daemon_version"] == "3.0.35"


def test_repair_validates_home_before_retiring_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_home = tmp_path / "missing-home"
    monkeypatch.setattr(
        runtime_repair,
        "retire_all_guard_daemons_for_home",
        lambda _home: (_ for _ in ()).throw(AssertionError("invalid home must fail before retirement")),
    )

    with pytest.raises(FileNotFoundError):
        runtime_repair.repair_guard_daemon_runtime(tmp_path / "guard-home", home_dir=missing_home)


def test_repair_retains_equal_version_peer_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setattr(
        runtime_repair,
        "verified_live_guard_daemon_identity",
        lambda _home: {
            "package_version": "3.0.34",
            "runtime_fingerprint": "desktop-sidecar",
            "compatibility_version": manager.GUARD_DAEMON_COMPATIBILITY_VERSION,
        },
    )
    monkeypatch.setattr(runtime_repair, "__version__", "3.0.34")
    monkeypatch.setattr(
        runtime_repair,
        "repair_approval_center_locator",
        lambda _home: {"repaired": True, "cleared": []},
    )
    monkeypatch.setattr(
        runtime_repair,
        "retire_all_guard_daemons_for_home",
        lambda _home: (_ for _ in ()).throw(AssertionError("same-release peer runtime must remain active")),
    )

    result = runtime_repair.repair_guard_daemon_runtime(guard_home, home_dir=home_dir)

    assert result["runtime_status"] == "current"
    assert result["daemon_version"] == "3.0.34"
    assert result["cli_version"] == "3.0.34"


def test_repair_restarts_older_desktop_core_sidecar(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    source_root = "Library/Application Support/org.hol.guard.desktop/core/versions/3.0.45/hol-guard"
    monkeypatch.setattr(
        runtime_repair,
        "verified_live_guard_daemon_identity",
        lambda _home: {
            "package_version": "3.0.45",
            "runtime_fingerprint": "desktop-sidecar",
            "source_root": source_root,
        },
    )
    monkeypatch.setattr(
        runtime_repair,
        "_verified_live_runtime",
        lambda _state: (runtime_repair.Version("3.0.45"), "3.0.45", "desktop-sidecar"),
    )
    monkeypatch.setattr(runtime_repair, "__version__", "3.0.46")
    monkeypatch.setattr(
        runtime_repair,
        "repair_approval_center_locator",
        lambda _home: {"repaired": True, "cleared": []},
    )
    monkeypatch.setattr(runtime_repair, "retire_all_guard_daemons_for_home", lambda _home: [321])
    monkeypatch.setattr(runtime_repair, "guard_daemon_retirement_is_complete", lambda _home: True)
    monkeypatch.setattr(runtime_repair, "clear_guard_daemon_state", lambda _home: None)
    monkeypatch.setattr(
        runtime_repair,
        "ensure_guard_daemon_after_update",
        lambda _home, *, home_dir: "http://127.0.0.1:5474",
    )

    result = runtime_repair.repair_guard_daemon_runtime(guard_home, home_dir=home_dir)

    assert result["runtime_status"] == "restarted"
    assert result["daemon_version"] == "3.0.45"
    assert result["cli_version"] == "3.0.46"


def test_repair_restarts_desktop_sidecar_with_invalid_package_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    source_root = "Library/Application Support/org.hol.guard.desktop/core/versions/3.0.45/hol-guard"
    monkeypatch.setattr(
        runtime_repair,
        "verified_live_guard_daemon_identity",
        lambda _home: {
            "package_version": "not-a-version",
            "runtime_fingerprint": "desktop-sidecar",
            "source_root": source_root,
        },
    )
    monkeypatch.setattr(runtime_repair, "__version__", "3.0.46")
    monkeypatch.setattr(
        runtime_repair,
        "repair_approval_center_locator",
        lambda _home: {"repaired": True, "cleared": []},
    )
    monkeypatch.setattr(runtime_repair, "retire_all_guard_daemons_for_home", lambda _home: [321])
    monkeypatch.setattr(runtime_repair, "guard_daemon_retirement_is_complete", lambda _home: True)
    monkeypatch.setattr(runtime_repair, "clear_guard_daemon_state", lambda _home: None)
    monkeypatch.setattr(
        runtime_repair,
        "ensure_guard_daemon_after_update",
        lambda _home, *, home_dir: "http://127.0.0.1:5474",
    )

    result = runtime_repair.repair_guard_daemon_runtime(guard_home, home_dir=home_dir)

    assert result["runtime_status"] == "restarted"
    assert result["daemon_version"] == "not-a-version"
    assert result["cli_version"] == "3.0.46"


def test_repair_recycles_missing_absolute_desktop_core_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    missing = tmp_path / "org.hol.guard.desktop" / "core" / "versions" / "3.0.45" / "hol-guard"
    monkeypatch.setattr(
        runtime_repair,
        "verified_live_guard_daemon_identity",
        lambda _home: {
            "package_version": "3.0.45",
            "runtime_fingerprint": "desktop-sidecar",
            "source_root": str(missing),
        },
    )
    monkeypatch.setattr(runtime_repair, "__version__", "3.0.46")
    monkeypatch.setattr(
        runtime_repair,
        "repair_approval_center_locator",
        lambda _home: {"repaired": True, "cleared": []},
    )
    monkeypatch.setattr(runtime_repair, "retire_all_guard_daemons_for_home", lambda _home: [321])
    monkeypatch.setattr(runtime_repair, "guard_daemon_retirement_is_complete", lambda _home: True)
    monkeypatch.setattr(runtime_repair, "clear_guard_daemon_state", lambda _home: None)
    monkeypatch.setattr(
        runtime_repair,
        "ensure_guard_daemon_after_update",
        lambda _home, *, home_dir: "http://127.0.0.1:5474",
    )

    result = runtime_repair.repair_guard_daemon_runtime(guard_home, home_dir=home_dir)

    assert result["runtime_status"] == "restarted"
    assert result["daemon_version"] == "3.0.45"


def test_repair_restarts_when_authenticated_state_is_absent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setattr(runtime_repair, "verified_live_guard_daemon_identity", lambda _home: None)
    monkeypatch.setattr(runtime_repair, "__version__", "3.0.34")
    monkeypatch.setattr(
        runtime_repair,
        "repair_approval_center_locator",
        lambda _home: {"repaired": True, "cleared": []},
    )
    monkeypatch.setattr(runtime_repair, "retire_all_guard_daemons_for_home", lambda _home: [])
    monkeypatch.setattr(runtime_repair, "guard_daemon_retirement_is_complete", lambda _home: True)
    monkeypatch.setattr(runtime_repair, "clear_guard_daemon_state", lambda _home: None)
    monkeypatch.setattr(
        runtime_repair,
        "ensure_guard_daemon_after_update",
        lambda _home, *, home_dir: "http://127.0.0.1:5474",
    )

    result = runtime_repair.repair_guard_daemon_runtime(guard_home, home_dir=home_dir)

    assert result["runtime_status"] == "restarted"
    assert result["daemon_version"] == "unknown"


def test_repair_rejects_invalid_installed_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setattr(runtime_repair, "verified_live_guard_daemon_identity", lambda _home: None)
    monkeypatch.setattr(runtime_repair, "__version__", "invalid version")
    monkeypatch.setattr(
        runtime_repair,
        "repair_approval_center_locator",
        lambda _home: {"repaired": True, "cleared": []},
    )

    with pytest.raises(RuntimeError, match="package version is invalid"):
        runtime_repair.repair_guard_daemon_runtime(tmp_path / "guard-home", home_dir=home_dir)


def test_repair_rejects_home_file(
    tmp_path: Path,
) -> None:
    home_file = tmp_path / "home-file"
    home_file.write_text("not a directory", encoding="utf-8")

    with pytest.raises(RuntimeError, match="user home directory"):
        runtime_repair.repair_guard_daemon_runtime(tmp_path / "guard-home", home_dir=home_file)


@pytest.mark.parametrize("host", [[], {}])
def test_live_identity_rejects_non_string_host(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    host: object,
) -> None:
    monkeypatch.setattr(
        live_identity,
        "load_authenticated_daemon_state",
        lambda _home: {
            "package_version": "3.0.34",
            "host": host,
            "port": 5474,
            "pid": 321,
            "compatibility_version": manager.GUARD_DAEMON_COMPATIBILITY_VERSION,
            "runtime_fingerprint": "fingerprint",
        },
    )
    monkeypatch.setattr(live_identity, "load_guard_daemon_auth_token", lambda _home: "token")

    assert live_identity.verified_live_guard_daemon_identity(tmp_path) is None


def test_live_identity_rejects_empty_health_guard_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {
        "package_version": "3.0.34",
        "host": "127.0.0.1",
        "port": 5474,
        "pid": 321,
        "compatibility_version": manager.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "runtime_fingerprint": "fingerprint",
    }
    monkeypatch.setattr(live_identity, "load_authenticated_daemon_state", lambda _home: state)
    monkeypatch.setattr(live_identity, "load_guard_daemon_auth_token", lambda _home: "token")
    monkeypatch.setattr(
        live_identity,
        "_proxy_disabled_health_details",
        lambda _url, _token: {**state, "ok": True, "guard_home": ""},
    )

    assert live_identity.verified_live_guard_daemon_identity(tmp_path) is None


def test_live_identity_rejects_authenticated_probe_redirects() -> None:
    request = live_identity.urllib.request.Request("http://127.0.0.1:5474/v1/healthz/details")
    handler = live_identity._RejectRedirectHandler()

    redirected = handler.redirect_request(
        request,
        None,
        302,
        "Found",
        {},
        "https://example.invalid/collect",
    )

    assert redirected is None


def test_daemon_start_lock_is_reentrant_for_repair_transaction(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"

    with manager._guard_daemon_start_lock(guard_home), manager._guard_daemon_start_lock(guard_home):
        assert start_lock._THREAD_DEPTHS[(start_lock.threading.get_ident(), str(guard_home.resolve()))] == 2

    assert start_lock._THREAD_DEPTHS == {}
