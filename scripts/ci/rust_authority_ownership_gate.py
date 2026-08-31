#!/usr/bin/env python3
"""Enforce HOL Guard's permanent Rust runtime authority boundary."""

from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Final

if __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci.hook_data_plane_ownership_contract import (
    SCHEMA,
    load_manifest,
    registered_harnesses,
)
from scripts.ci.rust_pretool_no_python_gate import _graph_failures

MANIFEST = Path("docs/guard/contracts/hook-data-plane-ownership.v2.json")
SELF_PROTECTED_PATHS: Final = frozenset(
    {
        ".github/workflows/native-wheel-ci.yml",
        ".github/workflows/rust-authority-ownership.yml",
        "docs/guard/contracts/hook-data-plane-ownership.v2.json",
        "scripts/ci/hook_data_plane_ownership_contract.py",
        "scripts/ci/rust_authority_ownership_gate.py",
    }
)

TEMPORARY_PATHS: Final = (
    Path(".github/workflows/rust-local-toolchain-export.yml"),
    Path(".github/workflows/rust-pretool-authority-bootstrap.yml"),
    Path(".github/workflows/rust-pretool-authority-orchestrator.yml"),
    Path(".github/workflows/rust-authority-batch1-finalize.yml"),
    Path(".github/workflows/rust-authority-batch1-merge-gate.yml"),
    Path(".github/workflows/rust-posttool-authority-bootstrap.yml"),
    Path(".github/workflows/rust-posttool-authority-orchestrator.yml"),
    Path(".github/workflows/rust-posttool-authority-lint-fix.yml"),
    Path(".github/workflows/rust-authority-batch2-merge-gate.yml"),
    Path(".github/workflows/rust-authority-batch2-retry-merge-v2.yml"),
    Path(".github/workflows/rust-authority-batch2-converge-v3.yml"),
    Path(".github/workflows/rust-authority-batch2-converge-v4.yml"),
    Path(".github/workflows/rust-authority-final-orchestrator.yml"),
    Path(".github/workflows/rust-authority-final-lint-fix.yml"),
    Path(".github/workflows/rust-authority-final-merge-gate.yml"),
    Path(".github/workflows/rust-authority-final-retry-merge-v2.yml"),
    Path(".github/workflows/rust-authority-batch3-converge-v3.yml"),
    Path("scripts/ci/bootstrap_rust_pretool_authority.sh"),
    Path("scripts/ci/bootstrap_rust_posttool_authority.sh"),
    Path("scripts/ci/fallback_rust_posttool_authority.py"),
    Path("scripts/ci/converge_rust_posttool_authority_v2.py"),
    Path("scripts/ci/harden_rust_policy_snapshot_v3.py"),
    Path("scripts/ci/select_rust_posttool_authority_candidate_v2.sh"),
    Path("scripts/ci/rust_authority_ownership_gate_v2.py"),
    Path("scripts/ci/rust_authority_ownership_gate_v3.py"),
    Path("scripts/ci/finalize_rust_authority_migration.py"),
    Path("scripts/ci/finalize_rust_authority_migration_v2.py"),
    Path("docs/guard/.batch1-merge-probe"),
    Path("docs/guard/rust-authority-batch-2-bootstrap.md"),
    Path("rust/AUTHORITY_BATCH_1"),
    Path("rust/AUTHORITY_BATCH_1_FINAL"),
    Path("rust/AUTHORITY_BATCH_2"),
    Path("rust/AUTHORITY_BATCH_2_FINAL"),
    Path("rust/AUTHORITY_FINAL"),
)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RuntimeError(f"required authority source is missing: {path}") from exc


def _python_imports_function(path: Path, module_suffix: str, name: str) -> bool:
    tree = ast.parse(_read(path), filename=str(path))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and (node.module or "").endswith(module_suffix)
            and any(alias.name == name for alias in node.names)
        ):
            return True
    return False


def _registered_harnesses() -> frozenset[str]:
    return registered_harnesses()


def _manifest() -> dict[str, object]:
    value = load_manifest(MANIFEST)
    protected_patterns, owner_patterns = _manifest_patterns(value)
    for path in _repository_matches(protected_patterns):
        if not any(_matches(path, pattern) for pattern in owner_patterns):
            raise RuntimeError(f"protected hook data-plane path has no ownership mapping: {path}")
    return value


def _matches(path: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(path, pattern)


def _node_patterns(manifest: dict[str, object]) -> tuple[str, ...]:
    nodes = manifest.get("nodes")
    if not isinstance(nodes, list):
        return ()
    return tuple(
        pattern
        for node in nodes
        if isinstance(node, dict) and isinstance(node.get("paths"), list)
        for pattern in node["paths"]
        if isinstance(pattern, str)
    )


def _manifest_patterns(manifest: dict[str, object]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    protected = manifest.get("protected_change_globs")
    protected_patterns = (
        tuple(pattern for pattern in protected if isinstance(pattern, str)) if isinstance(protected, list) else ()
    )
    owner_patterns = _node_patterns(manifest)
    return tuple(dict.fromkeys((*protected_patterns, *owner_patterns, *SELF_PROTECTED_PATHS))), owner_patterns


def _repository_matches(patterns: tuple[str, ...]) -> tuple[str, ...]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        check=True,
        capture_output=True,
        text=True,
    )
    tracked_paths = result.stdout.split("\0")
    return tuple(
        sorted(path for path in tracked_paths if path and any(_matches(path, pattern) for pattern in patterns))
    )


def _manifest_at_ref(base_ref: str | None) -> dict[str, object] | None:
    if not base_ref or set(base_ref) == {"0"}:
        return None
    result = subprocess.run(
        ["git", "show", f"{base_ref}:{MANIFEST.as_posix()}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        return None
    return payload


def _changed_files(base_ref: str | None) -> tuple[str, ...]:
    if not base_ref or set(base_ref) == {"0"}:
        return ()
    result = subprocess.run(
        ["git", "diff", "--name-only", "--no-renames", "--diff-filter=ACMRD", f"{base_ref}...HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return tuple(line.strip() for line in result.stdout.splitlines() if line.strip())


def _changed_path_gate(manifest: dict[str, object], base_ref: str | None) -> tuple[str, ...]:
    changed = _changed_files(base_ref)
    head_protected, head_owners = _manifest_patterns(manifest)
    base_manifest = _manifest_at_ref(base_ref)
    if base_manifest is None:
        base_protected: tuple[str, ...] = ()
        base_owners: tuple[str, ...] = ()
    else:
        base_protected, base_owners = _manifest_patterns(base_manifest)
        _coverage_narrowing_gate(
            base_protected=base_protected,
            base_owners=base_owners,
            head_protected=head_protected,
            head_owners=head_owners,
        )
    protected = tuple(dict.fromkeys((*base_protected, *head_protected, *SELF_PROTECTED_PATHS)))
    for path in changed:
        if not any(_matches(path, pattern) for pattern in protected):
            continue
        owners = head_owners if Path(path).exists() else tuple(dict.fromkeys((*base_owners, *head_owners)))
        if not any(_matches(path, pattern) for pattern in owners):
            raise RuntimeError(f"changed hook data-plane path has no ownership mapping: {path}")
    return changed


def _coverage_narrowing_gate(
    *,
    base_protected: tuple[str, ...],
    base_owners: tuple[str, ...],
    head_protected: tuple[str, ...],
    head_owners: tuple[str, ...],
) -> None:
    for path in _repository_matches(base_protected):
        if not any(_matches(path, pattern) for pattern in head_protected):
            raise RuntimeError(f"live hook data-plane protection was removed: {path}")
    for path in _repository_matches(base_owners):
        if not any(_matches(path, pattern) for pattern in head_owners):
            raise RuntimeError(f"live hook data-plane ownership was removed: {path}")


def _pretool_gate() -> None:
    graph_failures = _graph_failures(Path("."))
    if graph_failures:
        raise RuntimeError("; ".join(graph_failures))

    pretool = Path("src/codex_plugin_scanner/guard/native_pretool.py")
    if _python_imports_function(pretool, "command_evaluation", "evaluate_command"):
        raise RuntimeError("native PreToolUse transport imports the Python command evaluator")
    if "evaluate_command(" in _read(pretool):
        raise RuntimeError("native PreToolUse transport calls the Python command evaluator")
    _assert_policy_floor_fail_closed(pretool)

    hook = _read(Path("src/codex_plugin_scanner/guard/daemon/hook_worker.py"))
    if "review_pre_tool_native" not in hook:
        raise RuntimeError("PreToolUse hook path is not bound to the native runtime")
    region = re.search(
        r'if event_name\s*==\s*"PreToolUse":[\s\S]*?(?=\n\s*if event_name\s*!=\s*"PostToolUse")',
        hook,
    )
    if region is None:
        raise RuntimeError("daemon has no Rust PreToolUse authority route")
    if "self.engine.review(" in region.group(0):
        raise RuntimeError("PreToolUse can reach the Python HookReviewEngine")
    if "native_pre_tool_unavailable" not in region.group(0):
        raise RuntimeError("PreToolUse does not fail closed when native is unavailable")
    if 'status.mode == "shadow"' not in region.group(0):
        raise RuntimeError("PreToolUse does not isolate shadow Python rollback")
    if 'raise HookWorkerUnsupported("native PreToolUse runtime is unavailable")' in region.group(0):
        shadow_only = re.search(
            r'if status\.mode == "shadow":\s*raise HookWorkerUnsupported\("native PreToolUse runtime is unavailable"\)',
            region.group(0),
        )
        if shadow_only is None:
            raise RuntimeError("PreToolUse unavailable path still falls through to Python")

    command_model = Path("src/codex_plugin_scanner/guard/native_command_model.py")
    if command_model.exists():
        model = _read(command_model)
        if 'status.mode not in {"shadow", "force"}' not in model:
            raise RuntimeError("command-model bridge is not confined to shadow or force")
        if "Python remains authoritative" in model:
            raise RuntimeError("command-model bridge still declares Python authority")

    runtime = "\n".join(
        _read(path)
        for path in (
            Path("rust/crates/guard-runtime/src/main.rs"),
            Path("rust/crates/guard-runtime/src/resident_protocol.rs"),
        )
    )
    command = _read(Path("rust/crates/guard-command/src/lib.rs"))
    combined = runtime + "\n" + command
    if not re.search(r"PreToolUse|pre_tool|pre-tool", combined):
        raise RuntimeError("Rust runtime does not implement PreToolUse authority")


def _posttool_gate() -> None:
    hook = _read(Path("src/codex_plugin_scanner/guard/daemon/hook_worker.py"))
    if re.search(
        r"if response is None:\s*response = self\.engine\.review\(request\)",
        hook,
    ):
        raise RuntimeError("supported PostToolUse still spills into Python semantic evaluation")
    if 'native_required = mode in {"auto", "force"}' not in hook:
        raise RuntimeError("PostToolUse auto path is not native-required")
    if re.search(r'mode == "auto" and native_runtime_status\(\)\.available', hook):
        raise RuntimeError("PostToolUse still availability-gates native authority")

    native = _read(Path("src/codex_plugin_scanner/guard/native_runtime.py"))
    if "currently supported Python reference backend remains authoritative" in native:
        raise RuntimeError("native runtime still declares Python PostToolUse authority")

    core = _read(Path("rust/crates/guard-hook-core/src/lib.rs"))
    for required in ("review_post_tool", "read_bounded", "scan_text"):
        if required not in core:
            raise RuntimeError(f"Rust PostToolUse core is missing {required}")


def _mode_gate() -> None:
    relevant = [
        Path("src/codex_plugin_scanner/guard/native_runtime.py"),
        Path("src/codex_plugin_scanner/guard/native_command_model.py"),
        Path("docs/guard/all-harness-hook-review.md"),
        Path("docs/guard/harness-support.md"),
    ]
    strict_mode = re.compile(r"(?i)(native|rust|runtime)[-_ ]strict|strict[-_ ]mode|mode[=: ]+strict")
    found: list[str] = []
    for path in relevant:
        if path.exists() and strict_mode.search(_read(path)):
            found.append(str(path))
    if found:
        raise RuntimeError(f"retired strict-mode terminology remains: {found}")


def _policy_and_identity_gate() -> None:
    cargo = _read(Path("rust/crates/guard-runtime/Cargo.toml"))
    runtime = "\n".join(
        _read(path)
        for path in (
            Path("rust/crates/guard-runtime/src/main.rs"),
            Path("rust/crates/guard-runtime/src/resident_protocol.rs"),
        )
    )
    native = _read(Path("src/codex_plugin_scanner/guard/native_runtime.py"))
    release = _read(Path("scripts/verify_native_runtime_release.py"))
    if "guard-policy-snapshot" not in cargo:
        raise RuntimeError("hol-guard-runtime does not link guard-policy-snapshot")
    if "PolicySnapshot" not in runtime and "policy_snapshot" not in runtime:
        raise RuntimeError("hol-guard-runtime does not consume policy snapshots")
    if "rule_digest" not in runtime:
        raise RuntimeError("native policy snapshot is not rule-digest bound")
    for required in (
        "native_manifest_runtime_mismatch",
        "native_manifest_version_mismatch",
        "native_manifest_rule_mismatch",
        "runtime_sha256",
    ):
        if required not in native and required not in release:
            raise RuntimeError(f"bundled runtime identity guard is missing: {required}")


def _workflow_gate() -> None:
    path = Path(".github/workflows/rust-authority-ownership.yml")
    source = _read(path)
    trigger = source.split("permissions:", maxsplit=1)[0]
    if "paths:" in trigger or "paths-ignore:" in trigger:
        raise RuntimeError("authority workflow must be selected for every pull request to main")
    for required in ("pull_request:\n    branches: [main]", "fetch-depth: 0", "--base-ref"):
        if required not in source:
            raise RuntimeError(f"authority workflow is missing its always-selected diff gate: {required}")
    required_commands = (
        "rust_pretool_authority_integration.py",
        "rust_posttool_failclosed_integration.py",
        "test_guard_native_runtime_differential.py",
        "test_guard_native_runtime_mutation_differential.py",
        "bench_guard_native_release_gate.py",
        "test_native_hol_guard_wheel.py",
    )
    missing_commands = [value for value in required_commands if value not in source]
    if missing_commands:
        raise RuntimeError(f"authority workflow integration coverage is incomplete: {missing_commands}")

    native_wheel = _read(Path(".github/workflows/native-wheel-ci.yml"))
    native_trigger = native_wheel.split("permissions:", maxsplit=1)[0]
    if "paths:" in native_trigger or "paths-ignore:" in native_trigger:
        raise RuntimeError("installed native-wheel proof must be selected for every pull request to main")
    for required in (
        "HOL_GUARD_NATIVE HOL_GUARD_NATIVE_BINARY HOL_GUARD_HOOK_FAST_PATH",
        "Remove-Item Env:HOL_GUARD_HOOK_FAST_PATH",
        "probe_native_default_auto.py --json native-default-auto.json",
    ):
        if required not in native_wheel:
            raise RuntimeError(f"installed no-env workflow is incomplete: {required}")


def _docs_gate() -> None:
    architecture = _read(Path("docs/guard/all-harness-hook-review.md"))
    support = _read(Path("docs/guard/harness-support.md"))
    forbidden = (
        "PreToolUse, UserPromptSubmit, and PermissionRequest events raise",
        "causing the server to fall through to the legacy CLI path",
        "Python remains authoritative",
    )
    for value in forbidden:
        if value in architecture or value in support:
            raise RuntimeError(f"legacy Python authority documentation remains: {value}")
    if "Rust Authority Boundary" not in architecture or "Rust Authority Boundary" not in support:
        raise RuntimeError("Rust authority boundary is not documented on both harness pages")


def _hygiene_gate() -> None:
    residue = [str(path) for path in TEMPORARY_PATHS if path.exists()]
    if residue:
        raise RuntimeError(f"temporary Rust migration delivery residue remains: {residue}")


def _ordered_call_names(node: ast.AST) -> list[str]:
    names: list[str] = []
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
            names.append(child.func.id)
        names.extend(_ordered_call_names(child))
    return names


def _assert_policy_floor_fail_closed(path: Path) -> None:
    tree = ast.parse(_read(path), filename=str(path))
    fn = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "native_pre_tool_policy_floor"
        ),
        None,
    )
    if fn is None:
        raise RuntimeError("native PreToolUse policy floor is missing")
    for node in ast.walk(fn):
        if isinstance(node, ast.Attribute) and node.attr == "available":
            raise RuntimeError("PreToolUse policy floor still inspects native availability")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "native_mode":
            raise RuntimeError("PreToolUse policy floor still calls native_mode")
    returns_block = any(
        isinstance(node, ast.Return) and isinstance(node.value, ast.Constant) and node.value.value == "block"
        for node in ast.walk(fn)
    )
    if not returns_block:
        raise RuntimeError("PreToolUse policy floor does not fail closed")


def _cli_gate() -> None:
    hook = _read(Path("src/codex_plugin_scanner/guard/cli/commands_hook.py"))
    if "try_native_or_source_ref_hook" not in hook:
        raise RuntimeError("CLI hook path does not consult native authority")
    path = Path("src/codex_plugin_scanner/guard/cli/commands_hook_native_authority.py")
    tree = ast.parse(_read(path), filename=str(path))
    fn = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "try_native_or_source_ref_hook"
        ),
        None,
    )
    if fn is None:
        raise RuntimeError("CLI native authority helper is missing")
    calls = _ordered_call_names(fn)
    try:
        native_idx = calls.index("try_native_hook_authority")
        source_idx = calls.index("_try_source_ref_fast_path")
    except ValueError as exc:
        raise RuntimeError("CLI hook path is missing native authority or source-ref routing") from exc
    if native_idx > source_idx:
        raise RuntimeError("CLI hook path consults Python source-ref review before native authority")
    native_cli = _read(path)
    if "HookReviewEngine" in native_cli or "evaluate_command(" in native_cli:
        raise RuntimeError("CLI native authority path still imports a Python semantic replica")


def run(root: Path, *, base_ref: str | None = None) -> dict[str, object]:
    original = Path.cwd()
    try:
        if root != original:
            import os

            os.chdir(root)
        manifest = _manifest()
        changed = _changed_path_gate(manifest, base_ref)
        _pretool_gate()
        _posttool_gate()
        _mode_gate()
        _policy_and_identity_gate()
        _workflow_gate()
        _docs_gate()
        _hygiene_gate()
        _cli_gate()
        return {
            "schema": SCHEMA,
            "status": "passed",
            "manifest": manifest,
            "changed_files_checked": list(changed),
        }
    finally:
        if Path.cwd() != original:
            import os

            os.chdir(original)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--json", type=Path)
    parser.add_argument("--base-ref")
    parsed = parser.parse_args()
    payload = run(parsed.root.resolve(), base_ref=parsed.base_ref)
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    print(rendered)
    if parsed.json is not None:
        parsed.json.parent.mkdir(parents=True, exist_ok=True)
        parsed.json.write_text(rendered + "\n", encoding="utf-8")
    raise SystemExit(0)
