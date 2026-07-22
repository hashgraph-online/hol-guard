from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.local_node_runner_evidence import build_local_node_runner_evidence
from codex_plugin_scanner.guard.runtime.package_intent_parser import parse_package_intent

_INTEGRITY = "sha512-" + base64.b64encode(bytes(64)).decode("ascii")


def _write(path: Path, content: str, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(content, encoding="utf-8")
    if executable:
        _ = path.chmod(0o755)


def _workspace(root: Path, runner: str) -> Path:
    workspace = (root / "workspace").resolve()
    version = "1.2.3"
    _write(workspace / "package.json", json.dumps({"devDependencies": {runner: f"^{version}"}}))
    _write(
        workspace / "package-lock.json",
        json.dumps({"packages": {f"node_modules/{runner}": _lock_entry(runner, version)}}),
    )
    target = workspace / "node_modules" / runner / "bin" / f"{runner}.mjs"
    _write(target, "process.exit(0);\n", executable=True)
    _write(
        workspace / "node_modules" / runner / "package.json",
        json.dumps({"name": runner, "version": version, "bin": {runner: f"bin/{runner}.mjs"}}),
    )
    link = workspace / "node_modules" / ".bin" / runner
    link.parent.mkdir(parents=True)
    link.symlink_to(Path("..") / runner / "bin" / f"{runner}.mjs")
    _write(workspace / "src" / "example.ts", "export const value = 1;\n")
    _write(workspace / "src" / "example.test.ts", "test('value', () => {});\n")
    return workspace


def _lock_entry(runner: str, version: str) -> dict[str, str]:
    return {
        "version": version,
        "resolved": f"https://registry.npmjs.org/{runner}/-/{runner}-{version}.tgz",
        "integrity": _INTEGRITY,
    }


def _evidence(workspace: Path, argv: tuple[str, ...]):
    intent = parse_package_intent(" ".join(("npx", *argv)), workspace=workspace)
    assert intent is not None
    assert len(intent.local_executions) == 1
    return build_local_node_runner_evidence("npx", argv, intent.local_executions[0], workspace=workspace)


@pytest.fixture
def manager_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = (tmp_path / "bin").resolve()
    _write(directory / "npx", "#!/bin/sh\nexit 99\n", executable=True)
    monkeypatch.setenv("PATH", str(directory))
    return directory


@pytest.mark.parametrize(
    ("runner", "argv", "operation"),
    (
        ("vitest", ("--no-install", "vitest", "run", "src/example.test.ts"), "test"),
        ("eslint", ("--no-install", "eslint", "--no-cache", "src/example.ts"), "lint"),
    ),
)
def test_exact_local_runner_evidence_is_complete(
    tmp_path: Path,
    manager_path: Path,
    runner: str,
    argv: tuple[str, ...],
    operation: str,
) -> None:
    del manager_path
    workspace = _workspace(tmp_path, runner)

    evidence = _evidence(workspace, argv)

    assert evidence is not None
    assert evidence.status == "complete"
    assert evidence.reasons == ()
    assert evidence.operation_id == operation
    assert evidence.review_disposition == "review_required"
    assert evidence.direct_silent_verification is False


@pytest.mark.parametrize(
    "argv",
    (
        ("vitest", "run", "src/example.test.ts"),
        ("--no-install", "--package", "vitest", "vitest", "run", "src/example.test.ts"),
        ("--no-install", "vitest", "run"),
        ("--no-install", "vitest", "run", "--coverage", "src/example.test.ts"),
        ("--no-install", "eslint", "src/example.ts"),
        ("--no-install", "eslint", "--no-cache", "--fix", "src/example.ts"),
        ("--no-install", "eslint", "--no-cache", "src"),
        ("--no-install", "eslint", "--no-cache", "src/../src/example.ts"),
        ("--no-install", "eslint", "--no-cache", "../outside.ts"),
    ),
)
def test_argument_deltas_are_never_complete(
    tmp_path: Path,
    manager_path: Path,
    argv: tuple[str, ...],
) -> None:
    del manager_path
    runner = "eslint" if "eslint" in argv else "vitest"
    workspace = _workspace(tmp_path, runner)
    _write(tmp_path / "outside.ts", "export {};\n")

    evidence = _evidence(workspace, argv)

    assert evidence is None or evidence.status == "incomplete"


@pytest.mark.parametrize(
    "drift",
    (
        "manifest",
        "lock",
        "installed",
        "installed-name",
        "bin-escape",
        "semver-range",
        "registry-source",
        "integrity",
    ),
)
def test_identity_drift_is_never_complete(
    tmp_path: Path,
    manager_path: Path,
    drift: str,
) -> None:
    del manager_path
    workspace = _workspace(tmp_path, "eslint")
    if drift == "manifest":
        _write(workspace / "package.json", json.dumps({"devDependencies": {"eslint": "file:../eslint"}}))
    elif drift == "lock":
        _write(
            workspace / "package-lock.json",
            json.dumps({"packages": {"node_modules/eslint": _lock_entry("eslint", "1.2.4")}}),
        )
    elif drift == "installed":
        _write(
            workspace / "node_modules" / "eslint" / "package.json",
            json.dumps({"name": "eslint", "version": "9.9.9", "bin": {"eslint": "bin/eslint.mjs"}}),
        )
    elif drift == "installed-name":
        _write(
            workspace / "node_modules" / "eslint" / "package.json",
            json.dumps({"name": "not-eslint", "version": "1.2.3", "bin": {"eslint": "bin/eslint.mjs"}}),
        )
    elif drift == "bin-escape":
        _write(
            workspace / "node_modules" / "eslint" / "package.json",
            json.dumps({"name": "eslint", "version": "1.2.3", "bin": {"eslint": "../../escape.mjs"}}),
        )
    elif drift == "semver-range":
        _write(workspace / "package.json", json.dumps({"devDependencies": {"eslint": "^0.2.3"}}))
        _write(
            workspace / "package-lock.json",
            json.dumps({"packages": {"node_modules/eslint": _lock_entry("eslint", "0.9.0")}}),
        )
        _write(
            workspace / "node_modules" / "eslint" / "package.json",
            json.dumps({"name": "eslint", "version": "0.9.0", "bin": {"eslint": "bin/eslint.mjs"}}),
        )
    elif drift == "registry-source":
        entry = _lock_entry("eslint", "1.2.3")
        entry["resolved"] = "https://packages.example.invalid/eslint-1.2.3.tgz"
        _write(workspace / "package-lock.json", json.dumps({"packages": {"node_modules/eslint": entry}}))
    elif drift == "integrity":
        entry = _lock_entry("eslint", "1.2.3")
        entry["integrity"] = "sha512-invalid"
        _write(workspace / "package-lock.json", json.dumps({"packages": {"node_modules/eslint": entry}}))
    evidence = _evidence(workspace, ("--no-install", "eslint", "--no-cache", "src/example.ts"))

    assert evidence is not None
    assert evidence.status == "incomplete"


def test_growing_or_oversized_json_identity_is_never_complete(
    tmp_path: Path,
    manager_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del manager_path
    workspace = _workspace(tmp_path, "eslint")
    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.local_node_runner_evidence._MAX_JSON_BYTES", 1)

    evidence = _evidence(workspace, ("--no-install", "eslint", "--no-cache", "src/example.ts"))

    assert evidence is not None
    assert evidence.status == "incomplete"
