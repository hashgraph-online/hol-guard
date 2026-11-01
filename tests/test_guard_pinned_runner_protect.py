from __future__ import annotations

from pathlib import Path

import pytest

import codex_plugin_scanner.guard.local_supply_chain as local_supply_chain_module
from codex_plugin_scanner.guard.local_supply_chain import build_package_protect_payload
from codex_plugin_scanner.guard.store import GuardStore
from tests.manifest_install_fixtures import (
    _fake_policy_integrity_keyring,  # noqa: F401 -- registers the module autouse fixture
    _native_package_intent,  # noqa: F401 -- registers the module autouse fixture
    _package_policy_config,
    _review_package_evaluation,
)


def _write_executable(path: Path, marker: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\n# {marker}\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)


def _lockfile_body(manager: str, package: str, locked: str) -> str:
    """What `manager`'s lockfile says when it pins `package` at `locked`."""

    if manager == "bun.lock":
        return f'{{"packages": {{"{package}": ["{package}@{locked}", "", {{}}, ""]}}}}\n'
    if manager == "pnpm-lock.yaml":
        return (
            "lockfileVersion: '9.0'\n"
            "packages:\n"
            f"  {package}@{locked}:\n"
            "    resolution: {integrity: sha512-demo}\n"
        )
    if manager == "yarn.lock":
        return (
            f"{package}@^4.22.4:\n"
            f'  version "{locked}"\n'
            f'  resolved "https://registry.yarnpkg.com/{package}/-/{package}-{locked}.tgz#abc"\n'
        )
    raise AssertionError(f"no body for {manager}")


def _pinned_runner_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    *,
    locked: str,
    package: str | None = None,
    lockfile: str = "bun.lock",
) -> Path:
    """A runner the manifest asks for, installed, and agreed on by a lockfile.

    `package` names the registry package when it differs from the executable,
    which is how npm installs `tsc`: the tree, the manifest entry and the
    lockfile all say `typescript`. `lockfile` picks which package manager
    wrote the workspace, since each one writes its pins in its own dialect.
    """

    package = package or name
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text(
        f'{{"name":"demo","dependencies":{{"{package}":"^4.22.4"}}}}\n',
        encoding="utf-8",
    )
    (workspace / lockfile).write_text(
        _lockfile_body(lockfile, package, locked),
        encoding="utf-8",
    )
    installed = workspace / "node_modules" / package
    installed.mkdir(parents=True)
    (installed / "package.json").write_text(
        f'{{"name":"{package}","version":"4.22.4"}}\n',
        encoding="utf-8",
    )
    _write_executable(installed / "dist" / "cli.mjs", "runner")
    # npm and bun install the entry point as a link into the package itself;
    # the verdict requires the resolved executable to live under that package.
    entry = workspace / "node_modules" / ".bin" / name
    entry.parent.mkdir(parents=True, exist_ok=True)
    entry.symlink_to(Path("..") / package / "dist" / "cli.mjs")
    managers = tmp_path / "bin"
    for manager in ("npx", "bunx"):
        _write_executable(managers / manager, "manager")
    monkeypatch.setenv("PATH", str(managers))
    return workspace


def _protect(
    tmp_path: Path,
    workspace: Path,
    command: list[str],
) -> tuple[dict[str, object], int] | None:
    store = GuardStore(tmp_path / "guard-home")
    config = _package_policy_config(guard_home=store.guard_home, workspace_dir=workspace)
    return build_package_protect_payload(
        command=command,
        store=store,
        workspace_dir=workspace,
        dry_run=True,
        now="2026-07-17T00:01:00Z",
        config=config,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )


@pytest.fixture(autouse=True)
def _feed_asks_for_review(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any request that survives the pinned-runner verdict is reviewed.

    The verdict is the only thing under test, so the feed answer behind it is
    held still: a payload coming back at all means a package request was built.
    """

    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _review_package_evaluation(),
    )


@pytest.mark.parametrize("manager", ["npx", "bunx"])
def test_protect_builds_no_package_request_for_a_pinned_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    manager: str,
) -> None:
    workspace = _pinned_runner_workspace(tmp_path, monkeypatch, "tsx", locked="4.22.4")

    assert _protect(tmp_path, workspace, [manager, "tsx", "scripts/generate-inventory.ts"]) is None


@pytest.mark.parametrize("manager", ["npx", "bunx"])
def test_protect_reviews_a_runner_the_lockfile_contradicts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    manager: str,
) -> None:
    workspace = _pinned_runner_workspace(tmp_path, monkeypatch, "tsx", locked="4.9.0")

    assert _protect(tmp_path, workspace, [manager, "tsx", "scripts/generate-inventory.ts"]) is not None


@pytest.mark.parametrize("manager", ["npx", "bunx"])
def test_protect_reviews_a_runner_a_second_lockfile_never_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    manager: str,
) -> None:
    """A second lockfile that parses but omits the runner binds nothing."""

    workspace = _pinned_runner_workspace(tmp_path, monkeypatch, "tsx", locked="4.22.4")
    (workspace / "package-lock.json").write_text(
        '{"packages": {"node_modules/other": {"version": "1.0.0"}}}\n',
        encoding="utf-8",
    )

    assert _protect(tmp_path, workspace, [manager, "tsx", "scripts/generate-inventory.ts"]) is not None


@pytest.mark.parametrize("manager", ["npx", "bunx"])
def test_protect_reviews_a_package_name_outside_the_runner_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    manager: str,
) -> None:
    """Being pinned is not enough: only the routine runners take the verdict."""

    workspace = _pinned_runner_workspace(tmp_path, monkeypatch, "cowsay", locked="4.22.4")

    assert _protect(tmp_path, workspace, [manager, "cowsay", "hello"]) is not None


@pytest.mark.parametrize("manager", ["npx", "bunx"])
def test_protect_builds_no_package_request_for_a_pinned_tsc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    manager: str,
) -> None:
    """`tsc` ships inside `typescript`, so the tree never holds `node_modules/tsc`."""

    workspace = _pinned_runner_workspace(
        tmp_path, monkeypatch, "tsc", locked="4.22.4", package="typescript"
    )

    assert _protect(tmp_path, workspace, [manager, "tsc", "-p", "tsconfig.json"]) is None


@pytest.mark.parametrize("manager", ["npx", "bunx"])
def test_protect_reviews_a_tsc_the_lockfile_contradicts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    manager: str,
) -> None:
    workspace = _pinned_runner_workspace(
        tmp_path, monkeypatch, "tsc", locked="4.9.0", package="typescript"
    )

    assert _protect(tmp_path, workspace, [manager, "tsc", "-p", "tsconfig.json"]) is not None


@pytest.mark.parametrize("lockfile", ["pnpm-lock.yaml", "yarn.lock"])
@pytest.mark.parametrize("manager", ["npx", "bunx"])
def test_protect_builds_no_package_request_for_a_pinned_runner_in_any_dialect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    manager: str,
    lockfile: str,
) -> None:
    """pnpm and yarn pin a runner as firmly as npm and bun do."""

    workspace = _pinned_runner_workspace(
        tmp_path, monkeypatch, "tsx", locked="4.22.4", lockfile=lockfile
    )

    assert _protect(tmp_path, workspace, [manager, "tsx", "scripts/generate-inventory.ts"]) is None


@pytest.mark.parametrize("lockfile", ["pnpm-lock.yaml", "yarn.lock"])
@pytest.mark.parametrize("manager", ["npx", "bunx"])
def test_protect_reviews_a_runner_another_dialect_contradicts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    manager: str,
    lockfile: str,
) -> None:
    workspace = _pinned_runner_workspace(
        tmp_path, monkeypatch, "tsx", locked="4.9.0", lockfile=lockfile
    )

    assert (
        _protect(tmp_path, workspace, [manager, "tsx", "scripts/generate-inventory.ts"]) is not None
    )
