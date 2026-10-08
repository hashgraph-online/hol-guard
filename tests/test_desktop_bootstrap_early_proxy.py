"""Desktop bootstrap answers from the running daemon before frozen imports."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
FROZEN_ENTRYPOINT = ROOT / "scripts" / "mdm" / "hol-guard-entry.py"


def _poison_guard_import(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    marker = tmp_path / "guard-imported"
    package = tmp_path / "codex_plugin_scanner"
    package.mkdir()
    (package / "__init__.py").write_text(
        "import os\nfrom pathlib import Path\nPath(os.environ['GUARD_IMPORT_MARKER']).write_text('imported')\n",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(tmp_path)
    environment["GUARD_IMPORT_MARKER"] = str(marker)
    environment["HOME"] = str(tmp_path)
    return marker, environment


def _write_daemon_identity(
    home: Path,
    *,
    host: str,
    port: int,
    token: str = "desktop-bootstrap-test-token",
    tamper_signature: bool = False,
    executable: str | None = None,
) -> None:
    from codex_plugin_scanner.guard.daemon.discovery import authenticate_daemon_state
    from codex_plugin_scanner.version import __version__

    guard_home = home / ".hol-guard"
    guard_home.mkdir()
    discovery_key = "ab" * 32
    state = authenticate_daemon_state(
        {
            "host": host,
            "port": port,
            "package_version": __version__,
            "executable": executable if executable is not None else str(Path(sys.executable).resolve(strict=True)),
        },
        discovery_key=discovery_key,
    )
    if tamper_signature:
        signature = state["state_signature"]
        assert isinstance(signature, str)
        state["state_signature"] = f"{signature[:-1]}{'0' if signature[-1] != '0' else '1'}"
    files = {
        guard_home / "daemon-discovery-key": discovery_key,
        guard_home / "daemon-state.json": json.dumps(state),
        guard_home / "daemon-auth-token": token,
    }
    for path, contents in files.items():
        path.write_text(contents, encoding="utf-8")
        path.chmod(0o600)


def _serve_bootstrap(body: bytes, *, status: int = 200) -> tuple[ThreadingHTTPServer, list[tuple[str, str | None]]]:
    hits: list[tuple[str, str | None]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            hits.append((self.path, self.headers.get("X-Guard-Token")))
            payload = body if status == 200 else b""
            self.send_response(status)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, template: str, *args: object) -> None:
            del template, args

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, hits


def test_desktop_bootstrap_proxy_answers_before_guard_imports(tmp_path: Path) -> None:
    document = {"coreVersion": "9.9.9", "schema": "guard-desktop-bootstrap.v1"}
    server, hits = _serve_bootstrap(json.dumps(document).encode("utf-8"))
    try:
        _write_daemon_identity(tmp_path, host="127.0.0.1", port=server.server_address[1])
        marker, environment = _poison_guard_import(tmp_path)
        result = subprocess.run(
            [sys.executable, str(FROZEN_ENTRYPOINT), "desktop", "bootstrap", "--json"],
            capture_output=True,
            env=environment,
            check=False,
            text=True,
        )
    finally:
        server.shutdown()
    assert result.returncode == 0
    assert json.loads(result.stdout) == document
    assert result.stderr == ""
    assert not marker.exists()
    assert hits == [("/v1/desktop/bootstrap", "desktop-bootstrap-test-token")]


def test_desktop_bootstrap_proxy_falls_through_when_daemon_lacks_route(tmp_path: Path) -> None:
    server, _hits = _serve_bootstrap(b"", status=404)
    try:
        _write_daemon_identity(tmp_path, host="127.0.0.1", port=server.server_address[1])
        marker, environment = _poison_guard_import(tmp_path)
        result = subprocess.run(
            [sys.executable, str(FROZEN_ENTRYPOINT), "desktop", "bootstrap", "--json"],
            capture_output=True,
            env=environment,
            check=False,
            text=True,
        )
    finally:
        server.shutdown()
    assert result.returncode != 0
    assert "guard-desktop-bootstrap.v1" not in result.stdout
    assert marker.is_file()


def test_desktop_bootstrap_proxy_ignores_non_loopback_daemon_state(tmp_path: Path) -> None:
    server, hits = _serve_bootstrap(b'{"schema":"guard-desktop-bootstrap.v1"}')
    try:
        _write_daemon_identity(tmp_path, host="10.0.0.8", port=server.server_address[1])
        marker, environment = _poison_guard_import(tmp_path)
        result = subprocess.run(
            [sys.executable, str(FROZEN_ENTRYPOINT), "desktop", "bootstrap", "--json"],
            capture_output=True,
            env=environment,
            check=False,
            text=True,
        )
    finally:
        server.shutdown()
    assert result.returncode != 0
    assert hits == []
    assert marker.is_file()


def test_desktop_bootstrap_proxy_ignores_unauthenticated_daemon_state(tmp_path: Path) -> None:
    server, hits = _serve_bootstrap(b'{"schema":"guard-desktop-bootstrap.v1"}')
    try:
        _write_daemon_identity(
            tmp_path,
            host="127.0.0.1",
            port=server.server_address[1],
            tamper_signature=True,
        )
        marker, environment = _poison_guard_import(tmp_path)
        result = subprocess.run(
            [sys.executable, str(FROZEN_ENTRYPOINT), "desktop", "bootstrap", "--json"],
            capture_output=True,
            env=environment,
            check=False,
            text=True,
        )
    finally:
        server.shutdown()
    assert result.returncode != 0
    assert hits == []
    assert marker.is_file()


def test_desktop_bootstrap_proxy_skips_candidate_preflight(tmp_path: Path) -> None:
    document = {"coreVersion": "9.9.9", "schema": "guard-desktop-bootstrap.v1"}
    server, hits = _serve_bootstrap(json.dumps(document).encode("utf-8"))
    try:
        _write_daemon_identity(tmp_path, host="127.0.0.1", port=server.server_address[1])
        marker, environment = _poison_guard_import(tmp_path)
        environment["HOL_GUARD_DESKTOP_PREFLIGHT"] = "1"
        result = subprocess.run(
            [sys.executable, str(FROZEN_ENTRYPOINT), "desktop", "bootstrap", "--json"],
            capture_output=True,
            env=environment,
            check=False,
            text=True,
        )
    finally:
        server.shutdown()
    assert result.returncode != 0
    assert hits == []
    assert "guard-desktop-bootstrap.v1" not in result.stdout
    assert marker.is_file()


def test_desktop_bootstrap_proxy_ignores_different_executable(tmp_path: Path) -> None:
    document = {"coreVersion": "9.9.9", "schema": "guard-desktop-bootstrap.v1"}
    server, hits = _serve_bootstrap(json.dumps(document).encode("utf-8"))
    try:
        _write_daemon_identity(
            tmp_path,
            host="127.0.0.1",
            port=server.server_address[1],
            executable="/usr/bin/false",
        )
        marker, environment = _poison_guard_import(tmp_path)
        result = subprocess.run(
            [sys.executable, str(FROZEN_ENTRYPOINT), "desktop", "bootstrap", "--json"],
            capture_output=True,
            env=environment,
            check=False,
            text=True,
        )
    finally:
        server.shutdown()
    assert result.returncode != 0
    assert hits == []
    assert marker.is_file()


def test_cached_desktop_bootstrap_document_skips_rebuild_while_fresh() -> None:
    from codex_plugin_scanner.guard.cli.commands_dispatch_desktop import (
        cached_desktop_bootstrap_document,
        reset_desktop_bootstrap_cache,
    )

    reset_desktop_bootstrap_cache()
    try:
        calls = 0

        def build() -> dict[str, object]:
            nonlocal calls
            calls += 1
            return {"schema": "guard-desktop-bootstrap.v1", "n": calls}

        key = ("guard-home", "http://127.0.0.1:1", "token-a")
        other = ("guard-home", "http://127.0.0.1:2", "token-b")
        assert cached_desktop_bootstrap_document(key, build)["n"] == 1
        assert cached_desktop_bootstrap_document(key, build)["n"] == 1
        assert cached_desktop_bootstrap_document(other, build)["n"] == 2
        assert calls == 2
    finally:
        reset_desktop_bootstrap_cache()


def test_cached_desktop_bootstrap_document_single_flights_a_miss() -> None:
    from codex_plugin_scanner.guard.cli.commands_dispatch_desktop import (
        cached_desktop_bootstrap_document,
        reset_desktop_bootstrap_cache,
    )

    reset_desktop_bootstrap_cache()
    entered = threading.Event()
    release = threading.Event()
    calls = 0
    try:

        def build() -> dict[str, object]:
            nonlocal calls
            calls += 1
            entered.set()
            assert release.wait(timeout=2)
            return {"schema": "guard-desktop-bootstrap.v1", "n": calls}

        key = ("guard-home", "http://127.0.0.1:1", "token-a")
        leader: dict[str, object] = {}
        follower: dict[str, object] = {}

        def lead() -> None:
            leader["document"] = cached_desktop_bootstrap_document(key, build)

        def follow() -> None:
            follower["document"] = cached_desktop_bootstrap_document(key, build)

        worker = threading.Thread(target=lead)
        worker.start()
        assert entered.wait(timeout=2)
        waiter = threading.Thread(target=follow)
        waiter.start()
        time.sleep(0.05)
        assert calls == 1
        release.set()
        worker.join(timeout=2)
        waiter.join(timeout=2)
        assert calls == 1
        assert follower["document"] == leader["document"]
    finally:
        release.set()
        reset_desktop_bootstrap_cache()


def test_desktop_bootstrap_route_is_critical() -> None:
    from codex_plugin_scanner.guard.daemon.server import _DAEMON_CRITICAL_PATHS
    from codex_plugin_scanner.guard.dashboard_launcher import build_desktop_dashboard_session_url_for_daemon

    assert "/v1/desktop/bootstrap" in _DAEMON_CRITICAL_PATHS
    with pytest.raises(ValueError):
        build_desktop_dashboard_session_url_for_daemon(daemon_url="http://10.0.0.8:9", auth_token="token")
    with pytest.raises(ValueError):
        build_desktop_dashboard_session_url_for_daemon(
            daemon_url="http://user:secret@127.0.0.1:9",
            auth_token="token",
        )


def test_daemon_state_executable_falls_back_when_resolution_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.daemon import manager

    def fail_resolve(self: Path, strict: bool = False) -> Path:
        del self, strict
        raise OSError("unresolvable")

    monkeypatch.setattr(manager.Path, "resolve", fail_resolve)
    assert manager._daemon_state_executable() == sys.executable


def test_bootstrap_cache_key_canonicalizes_guard_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.cli.commands_dispatch_desktop import desktop_bootstrap_cache_key

    home, url, token_id = desktop_bootstrap_cache_key(
        guard_home=tmp_path,
        daemon_url="http://127.0.0.1:1",
        auth_token="token",
    )
    assert home == str(tmp_path.resolve())
    assert url == "http://127.0.0.1:1"
    assert token_id

    def fail_resolve(self: Path, strict: bool = False) -> Path:
        del self, strict
        raise OSError("unresolvable")

    monkeypatch.setattr(Path, "resolve", fail_resolve)
    fallback, _, _ = desktop_bootstrap_cache_key(
        guard_home=Path("guard-home"),
        daemon_url="http://127.0.0.1:1",
        auth_token="token",
    )
    assert fallback == "guard-home"


def test_cached_bootstrap_document_covers_refresh_and_failure_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.cli import commands_dispatch_desktop as desktop

    desktop.reset_desktop_bootstrap_cache()
    key = ("guard-home", "http://127.0.0.1:1", "token-a")
    monkeypatch.setattr(desktop, "_CACHE_WAIT_SECONDS", 0.05)
    try:
        desktop._cached_documents[key] = ({"n": 1}, time.monotonic())
        desktop._publish_cached_document(key, {"n": 9}, started_at=time.monotonic() - 5)
        assert desktop._cached_documents[key][0]["n"] == 1

        desktop._cached_documents[key] = ({"n": 1}, time.monotonic() - 40)
        refreshed = threading.Event()

        def refresh_build() -> dict[str, object]:
            refreshed.set()
            return {"n": 2}

        assert desktop.cached_desktop_bootstrap_document(key, refresh_build)["n"] == 1
        assert refreshed.wait(timeout=2)
        deadline = time.monotonic() + 2
        while desktop._cached_documents[key][0]["n"] != 2:
            assert time.monotonic() < deadline
            time.sleep(0.02)

        desktop._cached_documents[key] = ({"n": 2}, time.monotonic() - 40)
        failed = threading.Event()

        def failing_refresh() -> dict[str, object]:
            failed.set()
            raise RuntimeError("refresh failed")

        assert desktop.cached_desktop_bootstrap_document(key, failing_refresh)["n"] == 2
        assert failed.wait(timeout=2)
        deadline = time.monotonic() + 2
        while key in desktop._cache_builds:
            assert time.monotonic() < deadline
            time.sleep(0.02)

        blocked = threading.Event()
        release = threading.Event()

        def blocked_build() -> dict[str, object]:
            blocked.set()
            assert release.wait(timeout=2)
            return {"n": 3}

        desktop._refresh_cached_document(key, blocked_build)
        assert blocked.wait(timeout=2)
        desktop._refresh_cached_document(key, blocked_build)
        release.set()
        deadline = time.monotonic() + 2
        while key in desktop._cache_builds:
            assert time.monotonic() < deadline
            time.sleep(0.02)

        desktop.reset_desktop_bootstrap_cache()

        def fail_build() -> dict[str, object]:
            raise RuntimeError("build failed")

        with pytest.raises(RuntimeError, match="build failed"):
            desktop.cached_desktop_bootstrap_document(key, fail_build)

        monkeypatch.setattr(desktop, "_CACHE_WAIT_SECONDS", 0.05)
        held = threading.Event()
        release_hold = threading.Event()

        def held_build() -> dict[str, object]:
            held.set()
            assert release_hold.wait(timeout=2)
            return {"n": 5}

        holder = threading.Thread(target=lambda: desktop.cached_desktop_bootstrap_document(key, held_build))
        holder.start()
        assert held.wait(timeout=2)
        with pytest.raises(TimeoutError):
            desktop.cached_desktop_bootstrap_document(key, lambda: {"n": 4})
        release_hold.set()
        holder.join(timeout=2)
        assert not holder.is_alive()

        desktop.reset_desktop_bootstrap_cache()
        monkeypatch.setattr(desktop, "_CACHE_WAIT_SECONDS", 2)
        leader_started = threading.Event()
        release_leader = threading.Event()
        follower_done = threading.Event()
        follower_error: dict[str, BaseException] = {}

        def failing_leader() -> dict[str, object]:
            leader_started.set()
            assert release_leader.wait(timeout=2)
            raise RuntimeError("leader failed")

        def follow() -> None:
            try:
                desktop.cached_desktop_bootstrap_document(key, lambda: {"n": 4})
            except TimeoutError as error:
                follower_error["error"] = error
            follower_done.set()

        def lead() -> None:
            try:
                desktop.cached_desktop_bootstrap_document(key, failing_leader)
            except RuntimeError:
                return

        worker = threading.Thread(target=lead)
        worker.start()
        assert leader_started.wait(timeout=2)
        waiter = threading.Thread(target=follow)
        waiter.start()
        time.sleep(0.05)
        release_leader.set()
        assert follower_done.wait(timeout=2)
        worker.join(timeout=2)
        waiter.join(timeout=2)
        assert not worker.is_alive()
        assert not waiter.is_alive()
        assert "error" in follower_error
    finally:
        desktop.reset_desktop_bootstrap_cache()


def test_desktop_bootstrap_route_records_auth_and_build_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.cli import commands_dispatch_desktop as desktop
    from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer, _GuardDaemonHandler

    events: list[str] = []

    class Handler:
        def __init__(self, path: str, *, authorized: bool, diagnostics: object | None) -> None:
            self.path = path
            self.server = SimpleNamespace(
                home_dir=Path("."),
                auth_token="token",
                diagnostics=diagnostics,
                daemon_port=lambda: 9,
            )
            self.authorized = authorized
            self.unauthorized = 0
            self.payloads: list[tuple[dict[str, object], int]] = []

        def _query_has_guard_token(self, query: str) -> bool:
            return "guard_token=" in query

        def _record_query_token_rejection(self) -> None:
            events.append("query-token")

        def _write_unauthorized(self, *, extra_headers: dict[str, str] | None = None) -> None:
            del extra_headers
            self.unauthorized += 1

        def _header_token_is_valid(self) -> bool:
            return self.authorized

        def _cors_headers_for_request(self) -> dict[str, str]:
            return {}

        def _write_json(self, payload: dict[str, object], *, status: int = 200) -> None:
            self.payloads.append((payload, status))

    query = Handler("/v1/desktop/bootstrap?guard_token=1", authorized=True, diagnostics=None)
    _GuardDaemonHandler._serve_desktop_bootstrap(query, object())  # type: ignore[arg-type]
    assert query.unauthorized == 1

    denied = Handler("/v1/desktop/bootstrap", authorized=False, diagnostics=None)
    _GuardDaemonHandler._serve_desktop_bootstrap(denied, object())  # type: ignore[arg-type]
    assert denied.unauthorized == 1

    monkeypatch.setattr(
        desktop,
        "desktop_bootstrap_document_for_running_daemon",
        lambda **_kwargs: {"schema": "guard-desktop-bootstrap.v1"},
    )
    diagnostics = SimpleNamespace(record_exception=lambda event: events.append(event))
    served = Handler("/v1/desktop/bootstrap", authorized=True, diagnostics=diagnostics)
    _GuardDaemonHandler._serve_desktop_bootstrap(served, object())  # type: ignore[arg-type]
    assert served.payloads == [({"schema": "guard-desktop-bootstrap.v1"}, 200)]

    def fail(**_kwargs: object) -> dict[str, object]:
        raise RuntimeError("bootstrap failed")

    monkeypatch.setattr(desktop, "desktop_bootstrap_document_for_running_daemon", fail)
    failed = Handler("/v1/desktop/bootstrap", authorized=True, diagnostics=diagnostics)
    _GuardDaemonHandler._serve_desktop_bootstrap(failed, object())  # type: ignore[arg-type]
    assert failed.payloads == [({"error": "desktop_bootstrap_unavailable"}, 503)]
    assert "desktop_bootstrap_unavailable" in events

    owner = SimpleNamespace(
        _server=SimpleNamespace(store=object(), home_dir=Path("."), auth_token="token", daemon_port=lambda: 9),
        _diagnostics=diagnostics,
    )
    GuardDaemonServer._warm_desktop_bootstrap_cache(owner)  # type: ignore[arg-type]
    deadline = time.monotonic() + 2
    while "desktop_bootstrap_warmup_failed" not in events:
        assert time.monotonic() < deadline
        time.sleep(0.02)
