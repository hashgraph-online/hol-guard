"""Daemon API for harness version compatibility: additive reads, authenticated writes."""

from __future__ import annotations

import copy
import json
import os
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.harness_versions import service
from codex_plugin_scanner.guard.harness_versions.discovery import current_platform
from codex_plugin_scanner.guard.harness_versions.manifest import ManifestLoad, parse_manifest
from codex_plugin_scanner.guard.local_dashboard_session import build_local_dashboard_session_token
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.version import __version__
from tests.test_guard_harness_version_coverage import FIXTURE

PACKAGE = "@oh-my-pi/pi-coding-agent"


def _call(
    daemon: GuardDaemonServer,
    path: str,
    payload: dict[str, object] | None = None,
    *,
    token: str | None = None,
    dashboard_session: str | None = None,
) -> tuple[int, dict[str, object]]:
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["X-Guard-Token"] = token
    if dashboard_session is not None:
        headers["X-Guard-Dashboard-Session"] = dashboard_session
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}{path}",
        data=json.dumps(payload).encode("utf-8") if payload is not None else None,
        headers=headers,
        method="POST" if payload is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8") or "{}")


@pytest.fixture
def daemon(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[GuardDaemonServer]:
    home = tmp_path / "home"
    package_root = home / ".bun" / "install" / "global" / "node_modules" / "@oh-my-pi" / "pi-coding-agent"
    (package_root / "dist").mkdir(parents=True)
    (package_root / "package.json").write_text(json.dumps({"name": PACKAGE, "version": "18.11.2"}), encoding="utf-8")
    (package_root / "dist" / "cli.js").write_text("#!/usr/bin/env node\n", encoding="utf-8")
    (home / ".bun" / "bin").mkdir(parents=True)
    (home / ".bun" / "bin" / "omp").symlink_to(package_root / "dist" / "cli.js")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path / "empty-bin"), "/usr/bin", "/bin"]))
    service._observations.clear()
    server = GuardDaemonServer(GuardStore(tmp_path / "guard-home"), host="127.0.0.1", port=0)
    server.start()
    try:
        yield server
    finally:
        server.stop()
        service._observations.clear()


def _session(daemon: GuardDaemonServer) -> str:
    return build_local_dashboard_session_token(auth_token=daemon._server.auth_token, surface="dashboard")


def _omp(items: object) -> dict[str, object]:
    assert isinstance(items, list)
    return next(item for item in items if item["harness"] == "omp")


@pytest.mark.skipif(os.name == "nt", reason="symlinked bun shim fixture")
def test_harness_list_carries_additive_version_compatibility(daemon: GuardDaemonServer) -> None:
    status, payload = _call(daemon, "/v1/harnesses", token=daemon._server.auth_token)
    assert status == 200
    omp = _omp(payload["items"])
    compatibility = omp["version_compatibility"]
    assert isinstance(compatibility, dict)
    # The bundled manifest carries no OMP evidence yet, so nothing renders as tested.
    assert compatibility["state"] == "coverage_unavailable"
    assert compatibility["detected_version"] == "18.11.2"
    assert compatibility["enforcement_effect"] == "none"
    assert str(Path.home()) not in json.dumps(compatibility)


@pytest.mark.parametrize(
    "path",
    [
        "/v1/harness-versions/refresh",
        "/v1/harness-versions/acknowledge",
        "/v1/harness-versions/clear-acknowledgement",
    ],
)
def test_version_writes_require_authentication(daemon: GuardDaemonServer, path: str) -> None:
    status, _ = _call(daemon, path, {"harness": "omp"})
    assert status in {401, 403}


@pytest.mark.skipif(os.name == "nt", reason="symlinked bun shim fixture")
def test_version_writes_with_dashboard_session(daemon: GuardDaemonServer) -> None:
    session = _session(daemon)
    status, payload = _call(daemon, "/v1/harness-versions/refresh", {"harness": "omp"}, dashboard_session=session)
    assert status == 200
    assert payload["version_compatibility"]["detected_version"] == "18.11.2"  # type: ignore[index]

    status, payload = _call(daemon, "/v1/harness-versions/refresh", {"harness": "../omp"}, dashboard_session=session)
    assert (status, payload) == (400, {"error": "invalid_harness"})

    # Without bundled evidence the version is not "untested", so it cannot be acknowledged.
    status, payload = _call(
        daemon,
        "/v1/harness-versions/acknowledge",
        {"harness": "omp", "acknowledgement_key": "a" * 64},
        dashboard_session=session,
    )
    assert (status, payload) == (409, {"error": "acknowledgement_not_eligible"})

    status, payload = _call(
        daemon, "/v1/harness-versions/clear-acknowledgement", {"harness": "omp"}, dashboard_session=session
    )
    assert status == 200
    assert payload["version_compatibility"]["acknowledgement"]["acknowledged"] is False  # type: ignore[index]


def _install_omp(root: Path, version: str, link: Path) -> None:
    (root / "dist").mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(json.dumps({"name": PACKAGE, "version": version}), encoding="utf-8")
    (root / "dist" / "cli.js").write_text("#!/usr/bin/env node\n", encoding="utf-8")
    (root / "dist" / "cli.js").chmod(0o755)
    link.parent.mkdir(parents=True, exist_ok=True)
    if not link.is_symlink():
        link.symlink_to(root / "dist" / "cli.js")


@pytest.mark.skipif(os.name == "nt", reason="symlinked bun shim fixture")
def test_untested_acknowledge_then_version_change_flow(
    daemon: GuardDaemonServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Fixture evidence bound to this Guard release and platform; 18.4.12 and 18.8.3 are
    # regression fixture values, not production coverage claims.
    fixture = copy.deepcopy(FIXTURE)
    for harness in fixture["harnesses"]:  # type: ignore[union-attr]
        for record in harness["records"]:
            record["guard_version"] = __version__
            record["platforms"] = [current_platform()]
    monkeypatch.setattr(service, "_manifest", ManifestLoad(parse_manifest(fixture), None))
    session = _session(daemon)
    bun_root = Path.home() / ".bun" / "install" / "global" / "node_modules" / "@oh-my-pi" / "pi-coding-agent"

    def current() -> dict[str, object]:
        status, payload = _call(daemon, "/v1/harnesses", dashboard_session=session)
        assert status == 200
        compatibility = _omp(payload["items"])["version_compatibility"]
        assert isinstance(compatibility, dict)
        return compatibility

    def refresh() -> dict[str, object]:
        status, payload = _call(daemon, "/v1/harness-versions/refresh", {"harness": "omp"}, dashboard_session=session)
        assert status == 200
        return payload["version_compatibility"]  # type: ignore[return-value]

    untested = current()
    assert (untested["state"], untested["detected_version"]) == ("untested", "18.11.2")
    key = untested["acknowledgement"]["key"]  # type: ignore[index]

    status, payload = _call(
        daemon,
        "/v1/harness-versions/acknowledge",
        {"harness": "omp", "acknowledgement_key": key},
        dashboard_session=session,
    )
    assert status == 200
    assert payload["version_compatibility"]["acknowledgement"]["acknowledged"] is True  # type: ignore[index]

    # A fresh daemon process has no cached observation; the acknowledgement is on disk.
    service._observations.clear()
    assert current()["acknowledgement"]["acknowledged"] is True  # type: ignore[index]

    _install_omp(bun_root, "18.8.3", Path.home() / ".bun" / "bin" / "omp")
    tested = refresh()
    assert tested["state"] == "tested"
    assert tested["evidence"]

    _install_omp(bun_root, "18.6.0", Path.home() / ".bun" / "bin" / "omp")
    between = refresh()
    assert between["state"] == "untested"
    assert between["acknowledgement"]["acknowledged"] is False  # type: ignore[index]

    _install_omp(
        Path.home() / ".npm-global" / "lib" / "node_modules" / "@oh-my-pi" / "pi-coding-agent",
        "18.8.3",
        tmp_path / "empty-bin" / "omp",
    )
    ambiguous = refresh()
    assert ambiguous["state"] == "version_unknown"
    assert ambiguous["acknowledgement"]["eligible"] is False  # type: ignore[index]
    status, payload = _call(
        daemon,
        "/v1/harness-versions/acknowledge",
        {"harness": "omp", "acknowledgement_key": key},
        dashboard_session=session,
    )
    assert (status, payload) == (409, {"error": "acknowledgement_not_eligible"})


def test_acknowledgement_store_failure_returns_json_error(
    daemon: GuardDaemonServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise PermissionError("read-only guard home")

    monkeypatch.setattr(service, "clear_acknowledgement", unavailable)
    status, payload = _call(
        daemon, "/v1/harness-versions/clear-acknowledgement", {"harness": "omp"}, dashboard_session=_session(daemon)
    )
    assert (status, payload) == (500, {"error": "acknowledgement_store_unavailable"})
