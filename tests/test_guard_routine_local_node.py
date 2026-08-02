from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.runtime import routine_local_node as routine_module
from codex_plugin_scanner.guard.runtime.routine_local_node import routine_package_tree_digest
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


def _write(path: Path, text: str, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(text, encoding="utf-8")
    if executable:
        _ = path.chmod(0o755)


def _workspace(tmp_path: Path, runner: str, *, version: str = "1.2.3") -> tuple[Path, Path, Path]:
    home = tmp_path / "home"
    active = home / "active"
    workspace = home / "sibling"
    active.mkdir(parents=True)
    workspace.mkdir()
    package = {"next": "next", "eslint": "eslint", "tsc": "typescript"}[runner]
    target = {"next": "dist/bin/next", "eslint": "bin/eslint.js", "tsc": "bin/tsc"}[runner]
    _write(workspace / "package.json", json.dumps({"devDependencies": {package: f"^{version}"}}))
    _write(
        workspace / "package-lock.json",
        json.dumps(
            {
                "packages": {
                    f"node_modules/{package}": {
                        "version": version,
                        "resolved": f"https://registry.npmjs.org/{package}/-/{package}-{version}.tgz",
                        "integrity": "sha512-Zml4dHVyZS10ZXN0LWludGVncml0eQ==",
                    }
                }
            }
        ),
    )
    _write(
        workspace / "node_modules" / package / "package.json",
        json.dumps({"name": package, "version": version, "bin": {runner: target}}),
    )
    executable = workspace / "node_modules" / package / target
    _write(executable, "#!/usr/bin/env node\n", executable=True)
    binary = workspace / "node_modules" / ".bin" / runner
    binary.parent.mkdir(parents=True)
    binary.symlink_to(executable)
    return home, active, workspace


def _trust_fixture_package(monkeypatch: pytest.MonkeyPatch, workspace: Path, runner: str) -> None:
    package = {"next": "next", "eslint": "eslint", "tsc": "typescript"}[runner]
    payload = cast(
        dict[str, object],
        json.loads((workspace / "node_modules" / package / "package.json").read_text(encoding="utf-8")),
    )
    version = cast(str, payload["version"])
    monkeypatch.setitem(
        routine_module.TRUSTED_PACKAGE_TREES,
        (package, version, "sha512-Zml4dHVyZS10ZXN0LWludGVncml0eQ=="),
        routine_package_tree_digest(workspace / "node_modules" / package),
    )


def test_exact_prerelease_next_dependency_is_bound(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home, active, workspace = _workspace(tmp_path, "next", version="16.3.0-preview.8")
    package = cast(dict[str, object], json.loads((workspace / "package.json").read_text(encoding="utf-8")))
    dependencies = cast(dict[str, str], package["devDependencies"])
    dependencies["next"] = "16.3.0-preview.8"
    _ = (workspace / "package.json").write_text(json.dumps(package), encoding="utf-8")
    _trust_fixture_package(monkeypatch, workspace, "next")

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": f"cd {workspace} && ./node_modules/.bin/next build --webpack"},
        cwd=active,
        home_dir=home,
    )

    assert match is None


@pytest.mark.parametrize(
    ("runner", "invocation"),
    (
        (
            "next",
            "HOL_NEXT_BUILD_CPUS=1 NODE_OPTIONS=--max-old-space-size=8192 "
            + "./node_modules/.bin/next build --webpack 2>&1 | tail -30",
        ),
        ("eslint", "./node_modules/.bin/eslint src tests 2>&1 | head -40"),
        ("tsc", "./node_modules/.bin/tsc --noEmit -p tsconfig.json 2>&1 | tail -50"),
    ),
)
def test_dependency_bound_local_routine_after_sibling_cd_is_allowed(
    tmp_path: Path,
    runner: str,
    invocation: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, active, workspace = _workspace(tmp_path, runner)
    _trust_fixture_package(monkeypatch, workspace, runner)

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": f"cd {workspace} && {invocation}"},
        cwd=active,
        home_dir=home,
    )

    assert match is None


@pytest.mark.parametrize(
    "invocation",
    (
        "NODE_OPTIONS=--require=./bootstrap.js ./node_modules/.bin/next build --webpack 2>&1 | tail -30",
        "./node_modules/.bin/next dev 2>&1 | tail -30",
        "./node_modules/.bin/next build --webpack > build.log",
        "./node_modules/.bin/next build --webpack 2>&1 | tail -1001",
        "./node_modules/.bin/next build --webpack 2>&1 | sh",
        "./node_modules/.bin/next build --webpack $(touch marker)",
    ),
)
def test_local_next_variants_with_execution_or_write_risk_remain_reviewable(
    tmp_path: Path,
    invocation: str,
) -> None:
    home, active, workspace = _workspace(tmp_path, "next")

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": f"cd {workspace} && {invocation}"},
        cwd=active,
        home_dir=home,
    )

    assert match is not None


@pytest.mark.parametrize(
    "invocation",
    (
        "./node_modules/.bin/eslint --fix src/example.ts",
        "./node_modules/.bin/eslint --config ./attacker.js src/example.ts",
        "./node_modules/.bin/eslint --plugin attacker src/example.ts",
        "./node_modules/.bin/tsc --emitDeclarationOnly",
        "./node_modules/.bin/tsc --noEmit --project ../tsconfig.json",
    ),
)
def test_local_validation_mutation_and_code_loading_options_remain_reviewable(
    tmp_path: Path,
    invocation: str,
) -> None:
    runner = "eslint" if "eslint" in invocation else "tsc"
    home, active, workspace = _workspace(tmp_path, runner)

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": f"cd {workspace} && {invocation}"},
        cwd=active,
        home_dir=home,
    )

    assert match is not None


def test_local_next_runner_symlink_escape_remains_reviewable(tmp_path: Path) -> None:
    home, active, workspace = _workspace(tmp_path, "next")
    outside = home / "outside-next"
    _write(outside, "#!/usr/bin/env node\n", executable=True)
    binary = workspace / "node_modules" / ".bin" / "next"
    binary.unlink()
    binary.symlink_to(outside)

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": f"cd {workspace} && ./node_modules/.bin/next build --webpack"},
        cwd=active,
        home_dir=home,
    )

    assert match is not None


def test_locally_modified_runner_with_consistent_metadata_remains_reviewable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, active, workspace = _workspace(tmp_path, "next")
    _trust_fixture_package(monkeypatch, workspace, "next")
    executable = workspace / "node_modules" / "next" / "dist" / "bin" / "next"
    _write(executable, "#!/usr/bin/env node\nrequire('./payload.js')\n", executable=True)

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": f"cd {workspace} && ./node_modules/.bin/next build --webpack"},
        cwd=active,
        home_dir=home,
    )

    assert match is not None


@pytest.mark.parametrize(
    "command",
    (
        "cp .env .env.backup",
        "bun install --frozen-lockfile",
        "./deploy.sh production",
    ),
)
def test_unrelated_sensitive_workflows_remain_reviewable(tmp_path: Path, command: str) -> None:
    home, active, workspace = _workspace(tmp_path, "next")

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": f"cd {workspace} && {command}"},
        cwd=active,
        home_dir=home,
    )

    assert match is not None
