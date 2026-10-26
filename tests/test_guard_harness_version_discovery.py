"""Harness version discovery, acknowledgement storage, and the cached service."""

from __future__ import annotations

import ast
import json
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.harness_versions import acknowledgements, service
from codex_plugin_scanner.guard.harness_versions.compatibility import STATE_UNTESTED, STATE_VERSION_UNKNOWN
from codex_plugin_scanner.guard.harness_versions.discovery import (
    observation_identity_changed,
    observe_harness_version,
)
from codex_plugin_scanner.guard.harness_versions.manifest import ManifestLoad, parse_manifest
from tests.test_guard_harness_version_coverage import FIXTURE, GUARD, PLATFORM

PACKAGE = "@oh-my-pi/pi-coding-agent"
PROJECT_SRC = Path(__file__).resolve().parents[1] / "src" / "codex_plugin_scanner" / "guard"


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return HarnessContext(home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard-home")


def _install(root: Path, version: object, *, name: str = PACKAGE) -> Path:
    package_root = root / "node_modules" / "@oh-my-pi" / "pi-coding-agent"
    (package_root / "dist").mkdir(parents=True, exist_ok=True)
    (package_root / "package.json").write_text(json.dumps({"name": name, "version": version}), encoding="utf-8")
    cli = package_root / "dist" / "cli.js"
    cli.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    return cli


def _link_bun(context: HarnessContext, target: Path) -> None:
    bin_dir = context.home_dir / ".bun" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    (bin_dir / "omp").symlink_to(target)


def _no_probe(*_args: object, **_kwargs: object) -> dict[str, object]:
    raise AssertionError("package metadata must be preferred over running the harness")


def _observe(context: HarnessContext, **kwargs: object):
    options: dict[str, object] = {"which": lambda _name: None, "run_probe": _no_probe, "clock": lambda: 1000.0}
    options.update(kwargs)
    return observe_harness_version("omp", context, **options)  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def _isolated_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The service re-checks installs with the real PATH; keep a developer's own omp out of it.
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))


@pytest.fixture(autouse=True)
def _reset_service_cache() -> Iterator[None]:
    service._observations.clear()
    yield
    service._observations.clear()


class TestDiscovery:
    def test_reads_trusted_package_metadata(self, tmp_path: Path) -> None:
        context = _context(tmp_path)
        _link_bun(context, _install(tmp_path / "bun", "18.8.3"))
        observation = _observe(context)
        assert observation.state == "observed"
        assert observation.version is not None and observation.version.canonical == "18.8.3"
        assert observation.source == "package-metadata"
        assert observation.installation_id and str(tmp_path) not in observation.installation_id

    def test_missing_executable_is_unknown(self, tmp_path: Path) -> None:
        observation = _observe(_context(tmp_path))
        assert (observation.state, observation.reason) == ("unavailable", "executable_missing")

    @pytest.mark.parametrize("version", ["18.x", None, "latest"])
    def test_malformed_metadata_is_unknown(self, tmp_path: Path, version: object) -> None:
        context = _context(tmp_path)
        _link_bun(context, _install(tmp_path / "bun", version))
        observation = _observe(context)
        assert (observation.state, observation.reason) == ("unavailable", "metadata_malformed")

    def test_script_without_owning_package_is_not_executed(self, tmp_path: Path) -> None:
        context = _context(tmp_path)
        _link_bun(context, _install(tmp_path / "bun", "18.8.3", name="something-else"))
        observation = _observe(context)
        assert (observation.state, observation.reason) == ("unavailable", "metadata_unavailable")

    def test_disagreeing_installations_are_ambiguous(self, tmp_path: Path) -> None:
        context = _context(tmp_path)
        _link_bun(context, _install(tmp_path / "bun", "18.11.2"))
        npm_cli = _install(tmp_path / "npm", "18.8.3")
        observation = _observe(context, which=lambda _name: str(npm_cli))
        assert (observation.state, observation.reason) == ("ambiguous", "multiple_installations")
        assert observation.version is None

    def test_agreeing_installations_are_observed(self, tmp_path: Path) -> None:
        context = _context(tmp_path)
        _link_bun(context, _install(tmp_path / "bun", "18.8.3"))
        npm_cli = _install(tmp_path / "npm", "18.8.3")
        assert _observe(context, which=lambda _name: str(npm_cli)).state == "observed"

    def test_guard_shim_is_not_treated_as_the_harness(self, tmp_path: Path) -> None:
        context = _context(tmp_path)
        shim = context.guard_home / "bin" / "omp"
        shim.parent.mkdir(parents=True)
        shim.write_text("#!/bin/sh\n", encoding="utf-8")
        assert _observe(context, which=lambda _name: str(shim)).reason == "executable_missing"

    def _standalone(self, tmp_path: Path) -> tuple[HarnessContext, Path]:
        context = _context(tmp_path)
        binary = tmp_path / "standalone" / "omp"
        binary.parent.mkdir()
        binary.write_bytes(b"\x7fELF")
        return context, binary

    @pytest.mark.parametrize(
        ("result", "state", "reason"),
        [
            ({"ok": True, "stdout": "omp 18.8.3\n"}, "observed", None),
            ({"ok": True, "stdout": "omp/18.11.2\n"}, "observed", None),
            ({"ok": False, "timed_out": True}, "unavailable", "probe_timeout"),
            ({"ok": False, "stdout": ""}, "unavailable", "probe_failed"),
            ({"ok": True, "stdout": "omp 18.8.3 18.8.4"}, "unavailable", "banner_malformed"),
        ],
    )
    def test_standalone_binary_uses_bounded_probe(
        self, tmp_path: Path, result: dict[str, object], state: str, reason: str | None
    ) -> None:
        context, binary = self._standalone(tmp_path)
        calls: list[tuple[list[str], dict[str, object]]] = []

        def probe(argv: list[str], **kwargs: object) -> dict[str, object]:
            calls.append((argv, kwargs))
            return result

        observation = _observe(context, which=lambda _name: str(binary), run_probe=probe)
        assert (observation.state, observation.reason) == (state, reason)
        argv, kwargs = calls[0]
        assert argv == [str(binary.resolve()), "--version"]
        assert kwargs["timeout_seconds"] == 3
        assert Path(str(kwargs["cwd"])).is_relative_to(context.guard_home)
        assert set(kwargs["env"]) <= {"PATH", "HOME", "NO_COLOR", "SYSTEMROOT", "TEMP", "TMP"}  # type: ignore[arg-type]

    def test_replaced_package_changes_identity(self, tmp_path: Path) -> None:
        context = _context(tmp_path)
        cli = _install(tmp_path / "bun", "18.8.3")
        _link_bun(context, cli)
        observation = _observe(context)
        assert not observation_identity_changed(observation)
        package_json = cli.parent.parent / "package.json"
        package_json.write_text(json.dumps({"name": PACKAGE, "version": "18.11.20"}), encoding="utf-8")
        os.utime(package_json, ns=(1, 1))
        assert observation_identity_changed(observation)

    def test_new_installation_on_path_changes_identity(self, tmp_path: Path) -> None:
        context = _context(tmp_path)
        _link_bun(context, _install(tmp_path / "bun", "18.8.3"))
        observation = _observe(context)
        assert not observation_identity_changed(observation, context, which=lambda _name: None)
        second = _install(tmp_path / "npm", "18.11.2")
        assert observation_identity_changed(observation, context, which=lambda _name: str(second))


class TestAcknowledgementStore:
    KEY = "a" * 64

    def test_record_and_clear(self, tmp_path: Path) -> None:
        acknowledgements.record_acknowledgement(tmp_path, harness="omp", key=self.KEY)
        assert acknowledgements.acknowledged_keys(tmp_path, "omp") == {self.KEY}
        if os.name != "nt":
            assert (tmp_path / acknowledgements.ACKNOWLEDGEMENTS_FILENAME).stat().st_mode & 0o777 == 0o600
        acknowledgements.record_acknowledgement(tmp_path, harness="omp", key="b" * 64)
        assert acknowledgements.acknowledged_keys(tmp_path, "omp") == {"b" * 64}
        assert acknowledgements.clear_acknowledgements(tmp_path, harness="omp") == 1
        assert acknowledgements.acknowledged_keys(tmp_path, "omp") == frozenset()

    @pytest.mark.parametrize(
        "content",
        [b"{not json", b'{"version": 2, "items": []}', b"\xff\xfe", b'{"version": 1, "items": {}}', b"x" * 20000],
    )
    def test_corrupt_store_acknowledges_nothing(self, tmp_path: Path, content: bytes) -> None:
        (tmp_path / acknowledgements.ACKNOWLEDGEMENTS_FILENAME).write_bytes(content)
        assert acknowledgements.acknowledged_keys(tmp_path, "omp") == frozenset()

    def test_rejects_malformed_keys(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            acknowledgements.record_acknowledgement(tmp_path, harness="omp", key="../../etc")


class TestService:
    def _compat(self, context: HarnessContext, **kwargs: object) -> dict[str, object]:
        options: dict[str, object] = {
            "manifest_load": ManifestLoad(parse_manifest(FIXTURE), None),
            "guard_version": GUARD,
            "platform": PLATFORM,
            "observe": lambda harness, ctx, clock: _observe(ctx, clock=clock),
            "clock": lambda: 1000.0,
        }
        options.update(kwargs)
        return service.compatibility_for("omp", context, **options)  # type: ignore[arg-type]

    def test_acknowledge_flow_and_version_change(self, tmp_path: Path) -> None:
        context = _context(tmp_path)
        cli = _install(tmp_path / "bun", "18.11.2")
        _link_bun(context, cli)
        options = {
            "manifest_load": ManifestLoad(parse_manifest(FIXTURE), None),
            "guard_version": GUARD,
            "platform": PLATFORM,
            "observe": lambda harness, ctx, clock: _observe(ctx, clock=clock),
            "clock": lambda: 1000.0,
        }
        first = self._compat(context)
        assert first["state"] == STATE_UNTESTED
        key = first["acknowledgement"]["key"]  # type: ignore[index]

        with pytest.raises(service.AcknowledgementRejectedError, match="stale"):
            service.acknowledge("omp", "f" * 64, context, **options)
        acked = service.acknowledge("omp", key, context, **options)
        assert acked["acknowledgement"]["acknowledged"] is True  # type: ignore[index]
        assert acked["state"] == STATE_UNTESTED

        package_json = cli.parent.parent / "package.json"
        package_json.write_text(json.dumps({"name": PACKAGE, "version": "18.12.0"}), encoding="utf-8")
        os.utime(package_json, ns=(1, 1))
        moved = self._compat(context)
        assert moved["detected_version"] == "18.12.0"
        assert moved["acknowledgement"]["acknowledged"] is False  # type: ignore[index]

        cleared = service.clear_acknowledgement("omp", context, **options)
        assert cleared["acknowledgement"]["acknowledged"] is False  # type: ignore[index]

    def test_unknown_version_cannot_be_acknowledged(self, tmp_path: Path) -> None:
        context = _context(tmp_path)
        assert self._compat(context)["state"] == STATE_VERSION_UNKNOWN
        with pytest.raises(service.AcknowledgementRejectedError, match="not_eligible"):
            service.acknowledge(
                "omp",
                "a" * 64,
                context,
                manifest_load=ManifestLoad(parse_manifest(FIXTURE), None),
                guard_version=GUARD,
                platform=PLATFORM,
                observe=lambda harness, ctx, clock: _observe(ctx, clock=clock),
            )
        assert not (context.guard_home / acknowledgements.ACKNOWLEDGEMENTS_FILENAME).exists()

    def test_cache_expires_and_invalidates(self, tmp_path: Path) -> None:
        context = _context(tmp_path)
        calls: list[float] = []

        def observe(harness: str, ctx: HarnessContext, clock):  # type: ignore[no-untyped-def]
            calls.append(clock())
            return _observe(ctx, clock=clock)

        self._compat(context, observe=observe)
        self._compat(context, observe=observe)
        assert len(calls) == 1
        self._compat(context, observe=observe, clock=lambda: 1000.0 + service.CACHE_TTL_SECONDS + 1)
        assert len(calls) == 2
        service.invalidate(context.guard_home, "omp")
        self._compat(context, observe=observe)
        assert len(calls) == 3


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
        elif isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
    return names


def test_enforcement_never_reads_version_compatibility() -> None:
    allowed = {
        PROJECT_SRC / "daemon" / "harness_version_api.py",
        PROJECT_SRC / "daemon" / "server_dashboard_runtime_read.py",
        PROJECT_SRC / "daemon" / "server_control_routes_post.py",
        PROJECT_SRC / "daemon" / "server_control_misc.py",
    }
    readers = {
        path
        for path in PROJECT_SRC.rglob("*.py")
        if "harness_versions" not in path.parts and any("harness_version" in module for module in _imports(path))
    }
    assert readers <= allowed, sorted(str(path.relative_to(PROJECT_SRC)) for path in readers - allowed)
