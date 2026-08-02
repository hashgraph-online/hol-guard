from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.runtime import routine_local_node as routine_module
from codex_plugin_scanner.guard.runtime import routine_node_identity as identity_module
from codex_plugin_scanner.guard.runtime.routine_local_node import routine_package_tree_digest
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request
from codex_plugin_scanner.guard.trusted_local_tools import local_tool_approval_eligibility


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

    assert match is not None
    eligibility = local_tool_approval_eligibility(
        f"cd {workspace} && ./node_modules/.bin/next build --webpack",
        cwd=active,
        home_dir=home,
    )
    assert eligibility is not None
    assert eligibility.capability == "build"


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
def test_dependency_bound_local_routine_offers_reusable_capability_approval(
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

    assert match is not None
    eligibility = local_tool_approval_eligibility(
        f"cd {workspace} && {invocation}",
        cwd=active,
        home_dir=home,
    )
    assert eligibility is not None
    approval = eligibility.to_payload()
    assert approval["allowed_targets"] == ["capability"]
    durations = cast(list[object], approval["allowed_durations"])
    assert "5h" in durations
    assert "always" not in durations


@pytest.mark.parametrize(
    "invocation",
    (
        "NODE_OPTIONS=--require=./bootstrap.js ./node_modules/.bin/next build --webpack 2>&1 | tail -30",
        "./node_modules/.bin/next dev 2>&1 | tail -30",
        "./node_modules/.bin/next build --webpack > build.log",
        "./node_modules/.bin/next build --webpack 2>&1 | tail -1001",
        "./node_modules/.bin/next build --webpack 2>&1 | sh",
        "./node_modules/.bin/next build --webpack 2>&1 | ./payload/tail -30",
        "./node_modules/.bin/next build --webpack $(touch marker)",
    ),
)
def test_local_next_variants_with_execution_or_write_risk_remain_reviewable(
    tmp_path: Path,
    invocation: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, active, workspace = _workspace(tmp_path, "next")
    _trust_fixture_package(monkeypatch, workspace, "next")

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": f"cd {workspace} && {invocation}"},
        cwd=active,
        home_dir=home,
    )

    assert match is not None
    assert (
        local_tool_approval_eligibility(
            f"cd {workspace} && {invocation}",
            cwd=active,
            home_dir=home,
        )
        is None
    )


@pytest.mark.parametrize(
    "invocation",
    (
        "./node_modules/.bin/eslint --fix src/example.ts",
        "./node_modules/.bin/eslint --config ./attacker.js src/example.ts",
        "./node_modules/.bin/eslint --plugin attacker src/example.ts",
        "./node_modules/.bin/eslint src > output.txt",
        "./node_modules/.bin/eslint src/*.ts",
        "./node_modules/.bin/tsc --emitDeclarationOnly",
        "./node_modules/.bin/tsc --noEmit --project ../tsconfig.json",
        "./node_modules/.bin/tsc --noEmit --project tsconfig.build.json",
        "./node_modules/.bin/tsc --noEmit --project $HOME/tsconfig.json",
    ),
)
def test_local_validation_mutation_and_code_loading_options_remain_reviewable(
    tmp_path: Path,
    invocation: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = "eslint" if "eslint" in invocation else "tsc"
    home, active, workspace = _workspace(tmp_path, runner)
    _trust_fixture_package(monkeypatch, workspace, runner)

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": f"cd {workspace} && {invocation}"},
        cwd=active,
        home_dir=home,
    )

    assert match is not None
    assert (
        local_tool_approval_eligibility(
            f"cd {workspace} && {invocation}",
            cwd=active,
            home_dir=home,
        )
        is None
    )


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
    assert (
        local_tool_approval_eligibility(
            f"cd {workspace} && ./node_modules/.bin/next build --webpack",
            cwd=active,
            home_dir=home,
        )
        is None
    )


def test_dependency_change_invalidates_existing_approval_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, active, workspace = _workspace(tmp_path, "next")
    next_package_path = workspace / "node_modules" / "next" / "package.json"
    next_package = cast(dict[str, object], json.loads(next_package_path.read_text(encoding="utf-8")))
    next_package["dependencies"] = {"helper": "1.0.0"}
    _write(next_package_path, json.dumps(next_package))
    _write(
        workspace / "node_modules" / "helper" / "package.json",
        json.dumps({"name": "helper", "version": "1.0.0", "main": "index.js"}),
    )
    helper = workspace / "node_modules" / "helper" / "index.js"
    _write(helper, "module.exports = 1\n")
    _trust_fixture_package(monkeypatch, workspace, "next")
    command = f"cd {workspace} && ./node_modules/.bin/next build --webpack"

    before = local_tool_approval_eligibility(command, cwd=active, home_dir=home)
    assert before is not None
    _write(helper, "module.exports = 2\n")
    after = local_tool_approval_eligibility(command, cwd=active, home_dir=home)

    assert after is not None
    assert after.tool_identity_hash != before.tool_identity_hash


def test_configuration_closure_change_invalidates_existing_approval_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, active, workspace = _workspace(tmp_path, "next")
    config = workspace / "next.config.js"
    helper = workspace / "config" / "build.js"
    _write(config, "module.exports = require('./config/build.js')\n")
    _write(helper, "module.exports = {}\n")
    _trust_fixture_package(monkeypatch, workspace, "next")
    command = f"cd {workspace} && ./node_modules/.bin/next build --webpack"

    before = local_tool_approval_eligibility(command, cwd=active, home_dir=home)
    assert before is not None
    _write(helper, "module.exports = { reactStrictMode: true }\n")
    after = local_tool_approval_eligibility(command, cwd=active, home_dir=home)

    assert after is not None
    assert after.tool_identity_hash != before.tool_identity_hash


def test_configuration_package_change_invalidates_existing_approval_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, active, workspace = _workspace(tmp_path, "next")
    _write(workspace / "next.config.mjs", "import 'config-helper'; export default {}\n")
    _write(
        workspace / "node_modules" / "config-helper" / "package.json",
        json.dumps({"name": "config-helper", "version": "1.0.0", "main": "index.js"}),
    )
    helper = workspace / "node_modules" / "config-helper" / "index.js"
    _write(helper, "module.exports = 1\n")
    _trust_fixture_package(monkeypatch, workspace, "next")
    command = f"cd {workspace} && ./node_modules/.bin/next build --webpack"

    before = local_tool_approval_eligibility(command, cwd=active, home_dir=home)
    assert before is not None
    _write(helper, "module.exports = 2\n")
    after = local_tool_approval_eligibility(command, cwd=active, home_dir=home)

    assert after is not None
    assert after.tool_identity_hash != before.tool_identity_hash


def test_json_configuration_plugin_change_invalidates_existing_approval_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, active, workspace = _workspace(tmp_path, "eslint")
    _write(workspace / ".eslintrc.json", json.dumps({"extends": ["plugin:react/recommended"]}))
    _write(
        workspace / "node_modules" / "eslint-plugin-react" / "package.json",
        json.dumps({"name": "eslint-plugin-react", "version": "1.0.0", "main": "index.js"}),
    )
    plugin = workspace / "node_modules" / "eslint-plugin-react" / "index.js"
    _write(plugin, "module.exports = {}\n")
    _trust_fixture_package(monkeypatch, workspace, "eslint")
    command = f"cd {workspace} && ./node_modules/.bin/eslint src"

    before = local_tool_approval_eligibility(command, cwd=active, home_dir=home)
    assert before is not None
    _write(plugin, "module.exports = { rules: {} }\n")
    after = local_tool_approval_eligibility(command, cwd=active, home_dir=home)

    assert after is not None
    assert after.tool_identity_hash != before.tool_identity_hash


def test_scoped_json_plugin_change_invalidates_existing_approval_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, active, workspace = _workspace(tmp_path, "eslint")
    _write(workspace / ".eslintrc.json", json.dumps({"plugins": ["@scope/name"]}))
    package = workspace / "node_modules" / "@scope" / "eslint-plugin-name"
    _write(
        package / "package.json",
        json.dumps({"name": "@scope/eslint-plugin-name", "version": "1.0.0", "main": "index.js"}),
    )
    plugin = package / "index.js"
    _write(plugin, "module.exports = {}\n")
    _trust_fixture_package(monkeypatch, workspace, "eslint")
    command = f"cd {workspace} && ./node_modules/.bin/eslint src"

    before = local_tool_approval_eligibility(command, cwd=active, home_dir=home)
    assert before is not None
    _write(plugin, "module.exports = { rules: {} }\n")
    after = local_tool_approval_eligibility(command, cwd=active, home_dir=home)

    assert after is not None
    assert after.tool_identity_hash != before.tool_identity_hash


def test_computed_configuration_module_remains_reviewable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, active, workspace = _workspace(tmp_path, "next")
    _write(workspace / "next.config.js", "module.exports = require(process.env.BUILD_CONFIG)\n")
    _trust_fixture_package(monkeypatch, workspace, "next")

    eligibility = local_tool_approval_eligibility(
        f"cd {workspace} && ./node_modules/.bin/next build --webpack",
        cwd=active,
        home_dir=home,
    )

    assert eligibility is None


def test_create_require_configuration_remains_reviewable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, active, workspace = _workspace(tmp_path, "next")
    _write(
        workspace / "next.config.mjs",
        "".join(
            (
                "import { createRequire } from 'node:module'; const load = createRequire(import.meta.url); ",
                "export default load('./config.js')\n",
            )
        ),
    )
    _trust_fixture_package(monkeypatch, workspace, "next")

    eligibility = local_tool_approval_eligibility(
        f"cd {workspace} && ./node_modules/.bin/next build --webpack",
        cwd=active,
        home_dir=home,
    )

    assert eligibility is None


def test_dependency_directory_symlink_remains_reviewable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, active, workspace = _workspace(tmp_path, "next")
    package_path = workspace / "node_modules" / "next" / "package.json"
    package = cast(dict[str, object], json.loads(package_path.read_text(encoding="utf-8")))
    package["dependencies"] = {"helper": "1.0.0"}
    _write(package_path, json.dumps(package))
    helper = workspace / "node_modules" / "helper"
    _write(helper / "package.json", json.dumps({"name": "helper", "version": "1.0.0"}))
    outside = home / "outside"
    outside.mkdir()
    (helper / "dynamic").symlink_to(outside, target_is_directory=True)
    _trust_fixture_package(monkeypatch, workspace, "next")

    eligibility = local_tool_approval_eligibility(
        f"cd {workspace} && ./node_modules/.bin/next build --webpack",
        cwd=active,
        home_dir=home,
    )

    assert eligibility is None


def test_dependency_closure_uses_one_aggregate_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, active, workspace = _workspace(tmp_path, "next")
    _trust_fixture_package(monkeypatch, workspace, "next")
    monkeypatch.setattr(identity_module, "_MAX_CLOSURE_FILES", 1)

    eligibility = local_tool_approval_eligibility(
        f"cd {workspace} && ./node_modules/.bin/next build --webpack",
        cwd=active,
        home_dir=home,
    )

    assert eligibility is None


def test_approval_identity_is_scoped_to_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, active, workspace = _workspace(tmp_path / "first", "next")
    other_home, other_active, other_workspace = _workspace(tmp_path / "second", "next")
    _trust_fixture_package(monkeypatch, workspace, "next")
    _trust_fixture_package(monkeypatch, other_workspace, "next")
    first = local_tool_approval_eligibility(
        f"cd {workspace} && ./node_modules/.bin/next build --webpack",
        cwd=active,
        home_dir=home,
    )
    second = local_tool_approval_eligibility(
        f"cd {other_workspace} && ./node_modules/.bin/next build --webpack",
        cwd=other_active,
        home_dir=other_home,
    )

    assert first is not None
    assert second is not None
    assert first.tool_identity_hash != second.tool_identity_hash


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
