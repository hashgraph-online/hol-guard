from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard import contained_package_script_execution as execution_module
from codex_plugin_scanner.guard.contained_package_script_execution import (
    try_execute_contained_package_script,
)
from codex_plugin_scanner.guard.package_shim_gate import package_shim_command_requires_guard
from codex_plugin_scanner.guard.runtime import local_package_script_evidence as evidence_module
from codex_plugin_scanner.guard.runtime.effect_contract import ProofRequirement, ProofRoute
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition
from codex_plugin_scanner.guard.runtime.local_package_script_evidence import (
    build_local_package_script_evidence,
)
from tests.guard_command_corpus import iter_adversarial_corpus, iter_benign_corpus
from tests.guard_command_corpus_oracle import iter_adversarial_oracle, iter_benign_oracle
from tests.native_command_test_support import iter_native_command_evaluations

_INTEGRITY = "sha512-" + base64.b64encode(bytes(64)).decode("ascii")
_OPERATIONS = {
    "test": ("vitest", "vitest", "vitest run src/example.test.ts"),
    "lint": ("eslint", "eslint", "eslint --no-cache src/example.ts"),
    "build": ("vite", "vite", "vite build"),
    "typecheck": ("typescript", "tsc", "tsc --noEmit --pretty"),
}
_CORPUS_PARTITIONS = 32


def _write(path: Path, content: str, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(content, encoding="utf-8")
    if executable:
        _ = path.chmod(0o755)


def _workspace(root: Path, operation: str) -> Path:
    workspace = (root / "workspace").resolve()
    package, runner, script = _OPERATIONS[operation]
    version = "1.2.3"
    _write(
        workspace / "package.json",
        json.dumps({"scripts": {operation: script}, "devDependencies": {package: version}}),
    )
    _write(
        workspace / "package-lock.json",
        json.dumps(
            {
                "packages": {
                    f"node_modules/{package}": {
                        "version": version,
                        "resolved": f"https://registry.npmjs.org/{package}/-/{package}-{version}.tgz",
                        "integrity": _INTEGRITY,
                    }
                }
            }
        ),
    )
    target = workspace / "node_modules" / package / "bin" / f"{runner}.mjs"
    _write(target, "process.exit(0);\n", executable=True)
    _write(
        workspace / "node_modules" / package / "package.json",
        json.dumps({"name": package, "version": version, "bin": {runner: f"bin/{runner}.mjs"}}),
    )
    _write(workspace / "src" / "example.ts", "export const value = 1;\n")
    _write(workspace / "src" / "example.test.ts", "test('value', () => {});\n")
    _write(workspace / "vite.config.ts", "export default {};\n")
    _write(workspace / "tsconfig.json", '{"compilerOptions":{"noEmit":true}}\n')
    return workspace


def _requires_containment_proof(evaluation: object) -> bool:
    reasons = evaluation.decision_plane.reasons
    return any(reason.reason_code == "contained-routine-proof-required" for reason in reasons)


@pytest.mark.parametrize("partition", range(_CORPUS_PARTITIONS))
def test_every_cdx_061_corpus_case_requires_owned_containment_proof(partition: int) -> None:
    # Keep every case and oracle assertion, but amortize native process startup
    # through the existing bounded evaluator rather than spawning per command.
    benign = list(
        zip(
            iter_benign_corpus(shard_index=partition, shard_count=_CORPUS_PARTITIONS),
            iter_benign_oracle(shard_index=partition, shard_count=_CORPUS_PARTITIONS),
            strict=True,
        )
    )
    evaluations = iter_native_command_evaluations(
        (case.command for case, _oracle in benign), cwd=Path("workspace"), home_dir=Path("home")
    )
    for (case, oracle), reviewed in zip(benign, evaluations, strict=True):
        assert case.case_id == oracle.case_id
        evaluation = reviewed.evaluation
        owned = _requires_containment_proof(evaluation)
        if oracle.owner != "CDX-061":
            assert not owned
            continue
        assert owned
        assert evaluation.minimum_action == "review"
        # Intrinsic Git-context reapproval strengthens, never replaces, the
        # independently required containment proof.
        expected_floor = "require-reapproval" if reviewed.native_minimum_action == "require-reapproval" else "review"
        assert evaluation.decision_plane.action == expected_floor
        assert evaluation.decision_plane.proof_routes == frozenset()
    adversarial = list(
        zip(
            iter_adversarial_corpus(shard_index=partition, shard_count=_CORPUS_PARTITIONS),
            iter_adversarial_oracle(shard_index=partition, shard_count=_CORPUS_PARTITIONS),
            strict=True,
        )
    )
    evaluations = iter_native_command_evaluations(
        (case.command for case, _oracle in adversarial), cwd=Path("workspace"), home_dir=Path("home")
    )
    for (case, oracle), reviewed in zip(adversarial, evaluations, strict=True):
        assert case.case_id == oracle.case_id
        assert oracle.owner != "CDX-061"
        assert not _requires_containment_proof(reviewed.evaluation)


def test_cdx_061_corpus_owned_count_and_operations_remain_complete() -> None:
    owned = [
        (case, oracle)
        for case, oracle in zip(iter_benign_corpus(), iter_benign_oracle(), strict=True)
        if oracle.owner == "CDX-061"
    ]
    evaluations = iter_native_command_evaluations(
        (case.command for case, _oracle in owned), cwd=Path("workspace"), home_dir=Path("home")
    )
    count = 0
    for (case, oracle), reviewed in zip(owned, evaluations, strict=True):
        assert case.case_id == oracle.case_id
        count += 1
        assert _requires_containment_proof(reviewed.evaluation)
    assert count == 275


@pytest.mark.parametrize(
    ("operation", "scripts", "reason"),
    (
        ("build", {"build": "vite build && cat /etc/passwd"}, "script_not_exact"),
        ("build", {"prebuild": "node prepare.js"}, "lifecycle_script_present"),
        (
            "typecheck",
            {"typecheck": "tsc --noEmit --project ../x"},
            "script_arguments_not_result_only",
        ),
        ("lint", {"lint": "eslint --fix src/example.ts"}, "script_arguments_not_result_only"),
        (
            "test",
            {"test": "vitest run --coverage src/example.test.ts"},
            "script_arguments_not_result_only",
        ),
    ),
)
def test_workspace_code_abuse_cannot_complete_launch_evidence(
    tmp_path: Path,
    operation: str,
    scripts: dict[str, str],
    reason: str,
) -> None:
    workspace = _workspace(tmp_path, operation)
    raw_manifest = cast(object, json.loads((workspace / "package.json").read_text(encoding="utf-8")))
    assert isinstance(raw_manifest, dict)
    manifest = cast(dict[str, object], raw_manifest)
    raw_scripts = manifest.get("scripts")
    assert isinstance(raw_scripts, dict)
    cast(dict[str, object], raw_scripts).update(scripts)
    _write(workspace / "package.json", json.dumps(manifest))

    evidence = build_local_package_script_evidence("bun", ("run", operation), workspace=workspace)

    assert evidence is not None
    assert evidence.status == "incomplete"
    assert reason in evidence.reasons


@pytest.mark.parametrize("name", ("bun.lock", "pnpm-lock.yaml", "yarn.lock"))
def test_ambiguous_lock_sources_fail_closed(tmp_path: Path, name: str) -> None:
    workspace = _workspace(tmp_path, "build")
    _write(workspace / name, "untrusted-lock")

    evidence = build_local_package_script_evidence("bun", ("run", "build"), workspace=workspace)

    assert evidence is not None
    assert evidence.status == "incomplete"
    assert "lock_source_ambiguous" in evidence.reasons


@pytest.mark.parametrize(
    ("specifier", "version", "expected"),
    (("^1.2.3", "1.9.0", True), ("^0.12.0", "0.12.3", True), ("^0.0.3", "0.0.4", False)),
)
def test_caret_version_matching_follows_semver(specifier: str, version: str, expected: bool) -> None:
    assert (
        evidence_module.version_spec_matches(
            specifier, version, version_re=evidence_module._VERSION, caret_pins_zero_major=True
        )
        is expected
    )


def test_scoped_registry_tarball_omits_scope_from_filename() -> None:
    resolved = "https://registry.npmjs.org/@scope/tool/-/tool-1.2.3.tgz"
    assert evidence_module._canonical_resolution("@scope/tool", "1.2.3", resolved)  # pyright: ignore[reportPrivateUsage]


def test_all_bun_execution_enters_guard_but_only_exact_scripts_have_evidence(tmp_path: Path) -> None:
    for operation in _OPERATIONS:
        assert package_shim_command_requires_guard("bun", ("run", operation), workspace=tmp_path)
    for argv in (("run", "dev"), ("run", "build", "--watch"), ("script.ts",)):
        assert package_shim_command_requires_guard("bun", argv, workspace=tmp_path)
        assert build_local_package_script_evidence("bun", argv, workspace=tmp_path) is None
    assert not package_shim_command_requires_guard("bun", ("--version",), workspace=tmp_path)


def _manager(root: Path) -> Path:
    directory = (root / "bin").resolve()
    _write(directory / "bun", "#!/bin/sh\nexit 99\n", executable=True)
    return directory


@pytest.fixture
def native_home(package_intent_native: Path) -> Path:
    return package_intent_native


def test_native_request_carries_environment_and_timeout_without_python_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _workspace(tmp_path, "test")
    shim = _manager(tmp_path)
    captured: dict[str, object] = {}

    def native(workspace_arg: Path, manager: str, argv: tuple[str, ...], **kwargs: object) -> None:
        captured.update(workspace=workspace_arg, manager=manager, argv=argv, **kwargs)

    monkeypatch.setattr(execution_module._native_execution, "contained_package_script_execute_native", native)
    environment = {"PATH": str(shim), "GITHUB_TOKEN": "left-to-the-resident"}
    result = try_execute_contained_package_script(
        "bun",
        ("run", "test"),
        workspace=workspace,
        guard_home=tmp_path,
        shim_directory=shim,
        environment=environment,
        timeout_seconds=45.0,
    )

    assert result is None
    assert captured["workspace"] == workspace
    assert captured["manager"] == "bun"
    assert captured["argv"] == ("run", "test")
    assert captured["environment"] == environment
    assert captured["timeout_seconds"] == 45.0
    # The resident rebuilds the script evidence; Python never supplies it.
    assert "evidence" not in captured


@pytest.mark.parametrize("manager", ("npm", "pnpm", "yarn", "bunx", "npx"))
def test_only_bun_reaches_the_resident(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, manager: str) -> None:
    def native(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("resident must only see bun")

    monkeypatch.setattr(execution_module._native_execution, "contained_package_script_execute_native", native)
    assert (
        try_execute_contained_package_script(
            manager,
            ("run", "test"),
            workspace=tmp_path,
            guard_home=tmp_path,
            shim_directory=tmp_path,
            environment={},
        )
        is None
    )


@pytest.mark.parametrize("operation", tuple(_OPERATIONS))
def test_exact_bun_script_is_contained_by_the_resident_or_returns_to_review(
    native_home: Path, tmp_path: Path, operation: str
) -> None:
    workspace = _workspace(tmp_path, operation)
    shim = _manager(tmp_path)
    result = try_execute_contained_package_script(
        "bun",
        ("run", operation),
        workspace=workspace,
        guard_home=native_home,
        shim_directory=shim,
        environment={"PATH": str(shim), "GITHUB_TOKEN": "must-not-cross"},
    )

    # Hosts without an enforcing backend or an immutable bun return to review.
    if result is None:
        return
    assert result.operation_id == operation
    assert result.proof.route is ProofRoute.CONTAINED
    assert ProofRequirement.DEPENDENCY_PROVENANCE not in result.proof.satisfied_requirements
    assert result.decision.disposition is FinalDisposition.SILENT_CONTAINED
    assert result.exit_code != 99, "the live package manager must never run"
    assert "must-not-cross" not in result.stdout + result.stderr


@pytest.mark.parametrize(
    ("operation", "scripts"),
    (
        ("build", {"build": "vite build && cat /etc/passwd"}),
        ("build", {"prebuild": "node prepare.js"}),
        ("typecheck", {"typecheck": "tsc --noEmit --project ../x"}),
        ("lint", {"lint": "eslint --fix src/example.ts"}),
        ("test", {"test": "vitest run --coverage src/example.test.ts"}),
    ),
)
def test_workspace_code_abuse_returns_to_review(
    native_home: Path, tmp_path: Path, operation: str, scripts: dict[str, str]
) -> None:
    workspace = _workspace(tmp_path, operation)
    manifest = cast(dict[str, object], json.loads((workspace / "package.json").read_text(encoding="utf-8")))
    cast(dict[str, object], manifest["scripts"]).update(scripts)
    _write(workspace / "package.json", json.dumps(manifest))
    shim = _manager(tmp_path)
    assert (
        try_execute_contained_package_script(
            "bun",
            ("run", operation),
            workspace=workspace,
            guard_home=native_home,
            shim_directory=shim,
            environment={"PATH": str(shim)},
        )
        is None
    )


@pytest.mark.parametrize("relative", (".env", "src/linked.ts"))
def test_protected_or_linked_workspace_returns_to_review(native_home: Path, tmp_path: Path, relative: str) -> None:
    workspace = _workspace(tmp_path, "test")
    shim = _manager(tmp_path)
    target = workspace / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if relative == ".env":
        target.write_text("TOKEN=secret\n", encoding="utf-8")
    else:
        target.symlink_to("/usr/bin/true")
    assert (
        try_execute_contained_package_script(
            "bun",
            ("run", "test"),
            workspace=workspace,
            guard_home=native_home,
            shim_directory=shim,
            environment={"PATH": str(shim)},
        )
        is None
    )
