"""Harness version discovery and the cached service."""

from __future__ import annotations

import ast
import json
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.harness_versions import service
from codex_plugin_scanner.guard.harness_versions.compatibility import STATE_UNTESTED, STATE_VERSION_UNKNOWN
from codex_plugin_scanner.guard.harness_versions.discovery import (
    VersionObservation,
    observation_identity_changed,
    observe_harness_version,
)
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


def _observe(context: HarnessContext, **kwargs: object) -> VersionObservation:
    options: dict[str, object] = {"clock": lambda: 1000.0}
    options.update(kwargs)
    return observe_harness_version("omp", context, **options)  # type: ignore[arg-type]


def _on_path(monkeypatch: pytest.MonkeyPatch, executable: Path) -> None:
    link_dir = executable.parents[4] / "path-bin"
    link_dir.mkdir(exist_ok=True)
    (link_dir / "omp").symlink_to(executable)
    monkeypatch.setenv("PATH", str(link_dir))


@pytest.fixture(autouse=True)
def _isolated_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Discovery reads the real PATH; keep a developer's own omp out of it.
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))


@pytest.fixture(autouse=True)
def _reset_service_cache() -> Iterator[None]:
    service._observations.clear()
    yield
    service._observations.clear()


@pytest.mark.skipif(os.name == "nt", reason="symlinked bun shim fixture")
class TestDiscovery:
    """The native runtime holds the full discovery table; these pin the shim."""

    def test_reads_trusted_package_metadata(self, tmp_path: Path) -> None:
        context = _context(tmp_path)
        _link_bun(context, _install(tmp_path / "bun", "18.8.3"))
        observation = _observe(context)
        assert observation.state == "observed"
        assert observation.version == "18.8.3"
        assert observation.source == "package-metadata"
        assert observation.observed_at == 1000.0
        assert observation.installation_id and str(tmp_path) not in observation.installation_id
        assert not (context.guard_home / "runtime").exists()

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

    def test_disagreeing_installations_are_ambiguous(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        context = _context(tmp_path)
        _link_bun(context, _install(tmp_path / "bun", "18.11.2"))
        _on_path(monkeypatch, _install(tmp_path / "npm", "18.8.3"))
        observation = _observe(context)
        assert (observation.state, observation.reason) == ("ambiguous", "multiple_installations")
        assert observation.version is None
        assert len(observation.candidates) == 2

    def test_agreeing_installations_are_observed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        context = _context(tmp_path)
        _link_bun(context, _install(tmp_path / "bun", "18.8.3"))
        _on_path(monkeypatch, _install(tmp_path / "npm", "18.8.3"))
        assert _observe(context).state == "observed"

    def test_guard_shim_is_not_treated_as_the_harness(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        context = _context(tmp_path)
        shim = context.guard_home / "bin" / "omp"
        shim.parent.mkdir(parents=True)
        shim.write_text("#!/bin/sh\necho 9.9.9\n", encoding="utf-8")
        shim.chmod(0o755)
        monkeypatch.setenv("PATH", str(shim.parent))
        assert _observe(context).reason == "executable_missing"

    def test_standalone_binary_uses_the_bounded_probe(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        context = _context(tmp_path)
        binary = tmp_path / "standalone" / "omp"
        binary.parent.mkdir()
        binary.write_text("#!/bin/sh\necho omp/18.11.2\n", encoding="utf-8")
        binary.chmod(0o755)
        monkeypatch.setenv("PATH", str(binary.parent))
        observation = _observe(context)
        assert (observation.state, observation.version, observation.source) == (
            "observed",
            "18.11.2",
            "version-probe",
        )

    def test_replaced_package_changes_identity(self, tmp_path: Path) -> None:
        context = _context(tmp_path)
        cli = _install(tmp_path / "bun", "18.8.3")
        _link_bun(context, cli)
        observation = _observe(context)
        assert not observation_identity_changed(observation, context)
        package_json = cli.parent.parent / "package.json"
        package_json.write_text(json.dumps({"name": PACKAGE, "version": "18.11.20"}), encoding="utf-8")
        os.utime(package_json, ns=(1, 1))
        assert observation_identity_changed(observation, context)

    def test_new_installation_on_path_changes_identity(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        context = _context(tmp_path)
        _link_bun(context, _install(tmp_path / "bun", "18.8.3"))
        observation = _observe(context)
        assert not observation_identity_changed(observation, context)
        _on_path(monkeypatch, _install(tmp_path / "npm", "18.11.2"))
        assert observation_identity_changed(observation, context)


def test_without_a_runtime_the_version_is_unknown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("codex_plugin_scanner.guard.mdm.runtime_request.runtime_answer", lambda *_a, **_k: None)
    context = _context(tmp_path)
    observation = _observe(context)
    assert (observation.state, observation.version, observation.reason) == (
        "unavailable",
        None,
        "runtime_unavailable",
    )
    # An observation the runtime cannot confirm is never reused.
    assert observation_identity_changed(observation, context)


def _fixture_manifest(context: HarnessContext) -> Path:
    path = context.home_dir / "coverage.json"
    path.write_text(json.dumps(FIXTURE), encoding="utf-8")
    return path


class TestService:
    def _compat(self, context: HarnessContext, **kwargs: object) -> dict[str, object]:
        options: dict[str, object] = {
            "guard_version": GUARD,
            "platform": PLATFORM,
            "observe": lambda harness, ctx, clock: _observe(ctx, clock=clock),
            "clock": lambda: 1000.0,
        }
        options.update(kwargs)
        if "manifest_path" not in options:
            # Writing the fixture again would change its stamp and miss the decision cache.
            options["manifest_path"] = _fixture_manifest(context)
        return service.compatibility_for("omp", context, **options)  # type: ignore[arg-type]

    def test_acknowledge_flow_and_version_change(self, tmp_path: Path) -> None:
        context = _context(tmp_path)
        cli = _install(tmp_path / "bun", "18.11.2")
        _link_bun(context, cli)
        options = {
            "manifest_path": _fixture_manifest(context),
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
                manifest_path=_fixture_manifest(context),
                guard_version=GUARD,
                platform=PLATFORM,
                observe=lambda harness, ctx, clock: _observe(ctx, clock=clock),
            )
        assert not (context.guard_home / "harness-version-acknowledgements.json").exists()

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

    def test_identical_inputs_reuse_one_decision(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        context = _context(tmp_path)
        _link_bun(context, _install(tmp_path / "bun", "18.11.2"))
        manifest = _fixture_manifest(context)
        decide = service.decide_compatibility
        calls: list[object] = []

        def counted(**fields: object) -> dict[str, object]:
            calls.append(fields["now"])
            return decide(**fields)  # type: ignore[arg-type]

        monkeypatch.setattr(service, "decide_compatibility", counted)
        first = self._compat(context, manifest_path=manifest)
        first["state"] = "tampered"
        assert self._compat(context, manifest_path=manifest)["state"] == STATE_UNTESTED
        assert len(calls) == 1, "a list read must not ask the runtime again for an unchanged row"

        later = 1000.0 + service.DECISION_TTL_SECONDS
        key = self._compat(context, manifest_path=manifest, clock=lambda: later)["acknowledgement"]["key"]  # type: ignore[index]
        assert len(calls) == 2, "a decision expires"

        service.acknowledge(
            "omp",
            key,
            context,
            manifest_path=manifest,
            guard_version=GUARD,
            platform=PLATFORM,
            observe=lambda harness, ctx, clock: _observe(ctx, clock=clock),
            clock=lambda: later,
        )
        acked = self._compat(context, manifest_path=manifest, clock=lambda: later)
        assert acked["acknowledgement"]["acknowledged"] is True  # type: ignore[index]

        manifest.write_text(manifest.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        os.utime(manifest, ns=(1, 1))
        before = len(calls)
        _ = self._compat(context, manifest_path=manifest, clock=lambda: later)
        assert len(calls) == before + 1, "an edited manifest is decided again"


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
