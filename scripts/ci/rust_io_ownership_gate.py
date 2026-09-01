#!/usr/bin/env python3
"""Prove that decision-critical hook I/O is owned by the native runtime.

The hook transport is Python, but source bytes, path classification, file
identity, and content equivalence are Rust responsibilities.  This gate keeps
the boundary executable: it inventories synchronous Python I/O and hashes,
walks the supported hook call graph, and rejects a new Python operation on a
native decision branch.  The compatibility oracle remains observable in the
inventory, but is explicitly limited to ``off``/``shadow`` and differential
tests.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Final

if __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci.rust_io_ownership_resolver import resolve_call

SCHEMA: Final = "hol-guard.decision-critical-io.v1"
NATIVE_MODES: Final = frozenset({"auto", "force"})
COMPATIBILITY_MODES: Final = frozenset({"off", "shadow"})

_FS_METHODS: Final = frozenset(
    {
        "open",
        "read",
        "read_bytes",
        "read_text",
        "stat",
        "lstat",
        "readlink",
        "iterdir",
        "glob",
        "rglob",
        "resolve",
        "exists",
        "is_file",
        "is_dir",
        "is_symlink",
        "realpath",
    }
)
_FS_FUNCTIONS: Final = frozenset({"open", "readlink", "stat", "lstat", "listdir", "scandir"})
_HASH_FUNCTIONS: Final = frozenset({"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s"})
_ARCHIVE_MODULES: Final = frozenset({"tarfile", "zipfile", "gzip", "bz2", "lzma", "shutil"})
_DECODE_FUNCTIONS: Final = frozenset({"b64decode", "loads", "decode", "unpack", "decompress"})
_EQUIVALENCE_FUNCTIONS: Final = frozenset({"output_equivalent", "parity_signature", "sha256_text"})

_COMPATIBILITY_PATHS: Final = frozenset(
    {
        "src/codex_plugin_scanner/guard/runtime/hook_source_read.py",
        "src/codex_plugin_scanner/guard/runtime/hook_content_scanner.py",
        "src/codex_plugin_scanner/guard/runtime/hook_decision_cache.py",
        "src/codex_plugin_scanner/guard/runtime/hook_review_engine.py",
        "src/codex_plugin_scanner/guard/runtime/source_paths.py",
        "src/codex_plugin_scanner/guard/native_command_model.py",
    }
)
_TRANSPORT_IDENTITY_PATHS: Final = frozenset(
    {
        "src/codex_plugin_scanner/guard/native_runtime.py",
        "src/codex_plugin_scanner/guard/native_runtime_resident.py",
        "src/codex_plugin_scanner/guard/native_runtime_resilience.py",
        "src/codex_plugin_scanner/guard/codex_hook_launch_runtime.py",
    }
)
_TRANSPORT_DECODE_PATHS: Final = frozenset(
    {
        "src/codex_plugin_scanner/guard/native_hook_edge.py",
        "src/codex_plugin_scanner/guard/native_pretool.py",
        "src/codex_plugin_scanner/guard/native_resident_client.py",
        "src/codex_plugin_scanner/guard/native_runtime.py",
    }
)
_ASYNC_POLICY_PATHS: Final = frozenset(
    {
        "src/codex_plugin_scanner/guard/mdm/policy.py",
        "src/codex_plugin_scanner/guard/mdm/contracts.py",
        "src/codex_plugin_scanner/guard/native_policy_snapshot_publisher.py",
        "src/codex_plugin_scanner/guard/native_policy_snapshot_publisher_inputs.py",
        "src/codex_plugin_scanner/guard/native_policy_snapshot_storage.py",
        "src/codex_plugin_scanner/guard/config.py",
        "src/codex_plugin_scanner/guard/runtime/command_activity_correlation.py",
    }
)
_PERSISTENCE_PATH_PREFIXES: Final = (
    "src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_writer.py",
    "src/codex_plugin_scanner/guard/runtime/hook_enrichment_queue.py",
    "src/codex_plugin_scanner/guard/daemon/hook_metrics.py",
)


@dataclass(frozen=True, slots=True)
class RootSpec:
    path: str
    name: str
    class_name: str | None = None


@dataclass(frozen=True, slots=True)
class FunctionRecord:
    path: str
    name: str
    qualname: str
    node: ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True, slots=True)
class IoObservation:
    path: str
    line: int
    operation: str
    kind: str
    category: str
    reachable: bool


ROOTS: Final = (
    RootSpec(
        "src/codex_plugin_scanner/guard/daemon/hook_worker.py",
        "review_http_payload",
        "HookWorker",
    ),
    RootSpec(
        "src/codex_plugin_scanner/guard/daemon/hook_worker.py",
        "_review_post_tool_http",
        "HookWorker",
    ),
    RootSpec("src/codex_plugin_scanner/guard/native_hook_edge.py", "review_raw_hook_native"),
    RootSpec("src/codex_plugin_scanner/guard/native_runtime.py", "review_post_tool_native"),
    RootSpec("src/codex_plugin_scanner/guard/native_resident_client.py", "native_resident_client_request"),
    RootSpec(
        "src/codex_plugin_scanner/guard/cli/commands_hook_native_authority.py",
        "try_native_hook_authority",
    ),
    RootSpec(
        "src/codex_plugin_scanner/guard/cli/commands_hook_native_authority.py",
        "try_native_or_source_ref_hook",
    ),
)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"could not inspect {path}") from exc


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _call_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _attribute_chain(value: ast.AST) -> tuple[str, ...]:
    if isinstance(value, ast.Name):
        return (value.id,)
    if isinstance(value, ast.Attribute):
        return (*_attribute_chain(value.value), value.attr)
    return ()


def _functions(tree: ast.AST, path: str) -> Iterable[FunctionRecord]:
    def visit(body: list[ast.stmt], prefix: str = "") -> Iterable[FunctionRecord]:
        for item in body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualname = f"{prefix}.{item.name}" if prefix else item.name
                yield FunctionRecord(path, item.name, qualname, item)
                yield from visit(item.body, qualname)
            elif isinstance(item, ast.ClassDef):
                class_prefix = f"{prefix}.{item.name}" if prefix else item.name
                yield from visit(item.body, class_prefix)

    if isinstance(tree, ast.Module):
        yield from visit(tree.body)


def _function_map(root: Path) -> dict[tuple[str, str], list[FunctionRecord]]:
    result: dict[tuple[str, str], list[FunctionRecord]] = {}
    source_root = root / "src/codex_plugin_scanner/guard"
    for path in sorted(source_root.rglob("*.py")):
        relative = _relative(path, root)
        tree = ast.parse(_read(path), filename=relative)
        for record in _functions(tree, relative):
            result.setdefault((relative, record.name), []).append(record)
    return result


def _root_record(root: Path, spec: RootSpec, records: dict[tuple[str, str], list[FunctionRecord]]) -> FunctionRecord:
    candidates = records.get((spec.path, spec.name), [])
    if spec.class_name is not None:
        candidates = [item for item in candidates if item.qualname.startswith(f"{spec.class_name}.")]
    if len(candidates) != 1:
        raise RuntimeError(f"expected one {spec.class_name or 'module'}.{spec.name} in {root / spec.path}")
    return candidates[0]


def _calls(record: FunctionRecord) -> tuple[str, ...]:
    names: list[str] = []
    for node in ast.walk(record.node):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            names.append(node.func.id)
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        chain = _attribute_chain(node.func)
        if len(chain) == 2 and chain[0] in {"self", "cls"}:
            names.append(node.func.attr)
        elif len(chain) >= 2:
            # Keep qualified calls so the resolver can follow repository-module
            # aliases instead of silently dropping decision-critical helpers.
            names.append(".".join(chain))
    return tuple(names)


def _category(path: str, kind: str) -> str:
    if path in _COMPATIBILITY_PATHS:
        return "compatibility_only"
    if path in _TRANSPORT_IDENTITY_PATHS:
        return "transport_identity"
    if path in _TRANSPORT_DECODE_PATHS and kind == "decode":
        return "transport_decode"
    if path in _ASYNC_POLICY_PATHS:
        return "asynchronous_policy"
    if path.startswith(_PERSISTENCE_PATH_PREFIXES):
        return "persistence_only"
    if kind in {"archive", "decode"}:
        return "unclassified_python_content_io"
    return "unclassified_python_io"


def _observations(record: FunctionRecord) -> Iterable[IoObservation]:
    path = record.path
    if record.name in _EQUIVALENCE_FUNCTIONS:
        yield IoObservation(path, record.node.lineno, record.name, "equivalence", _category(path, "equivalence"), True)
    for node in ast.walk(record.node):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            chain = _attribute_chain(node.func)
            kind: str | None = None
            operation: str | None = None
            if chain and chain[0] in _ARCHIVE_MODULES:
                kind, operation = "archive", name
            elif name in _FS_FUNCTIONS or name in _FS_METHODS:
                kind, operation = "filesystem", name
            elif name in _HASH_FUNCTIONS or (chain and chain[-2:] == ("hashlib", name)):
                kind, operation = "hash", name
            elif name in _DECODE_FUNCTIONS:
                kind, operation = "decode", name
            elif name in _ARCHIVE_MODULES:
                kind, operation = "archive", name
            if kind is not None and operation is not None:
                yield IoObservation(path, node.lineno, operation, kind, _category(path, kind), True)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                module = alias.name.split(".", maxsplit=1)[0]
                if module in _ARCHIVE_MODULES:
                    yield IoObservation(path, node.lineno, module, "archive", _category(path, "archive"), True)
                elif module == "hashlib":
                    yield IoObservation(path, node.lineno, module, "hash", _category(path, "hash"), True)
        elif isinstance(node, ast.ImportFrom):
            module = (node.module or "").split(".", maxsplit=1)[0]
            if module in _ARCHIVE_MODULES:
                yield IoObservation(path, node.lineno, module, "archive", _category(path, "archive"), True)
            elif module == "hashlib":
                yield IoObservation(path, node.lineno, module, "hash", _category(path, "hash"), True)


def _reachable_records(
    root: Path,
    records: dict[tuple[str, str], list[FunctionRecord]],
) -> tuple[FunctionRecord, ...]:
    pending = [_root_record(root, spec, records) for spec in ROOTS]
    seen: set[tuple[str, str]] = set()
    result: list[FunctionRecord] = []
    while pending:
        record = pending.pop()
        identity = (record.path, record.qualname)
        if identity in seen:
            continue
        seen.add(identity)
        result.append(record)
        for name in _calls(record):
            resolved = resolve_call(root, record, name, records)
            if resolved is not None:
                pending.append(resolved)
    return tuple(result)


def _call_in(node: ast.AST, name: str) -> bool:
    return any(isinstance(child, ast.Call) and _call_name(child) == name for child in ast.walk(node))


def _call_in_branch(node: ast.If, name: str) -> bool:
    """Inspect only the guarded body, never the compatibility ``else``."""
    return any(
        isinstance(child, ast.Call) and _call_name(child) == name
        for statement in node.body
        for child in ast.walk(statement)
    )


def _native_branch(record: FunctionRecord, marker: str) -> ast.If | None:
    for node in ast.walk(record.node):
        if not isinstance(node, ast.If):
            continue
        names = {child.id for child in ast.walk(node.test) if isinstance(child, ast.Name)}
        constants = {child.value for child in ast.walk(node.test) if isinstance(child, ast.Constant)}
        if marker in names or marker in constants:
            return node
    return None


def _branch_failures(root: Path, records: dict[tuple[str, str], list[FunctionRecord]]) -> list[str]:
    failures: list[str] = []
    review = _root_record(root, ROOTS[0], records)
    native = _native_branch(review, "auto")
    if native is None or not _call_in_branch(native, "_review_native_edge"):
        failures.append("HookWorker.review_http_payload has no direct auto/force native edge return")
    elif any(
        _call_in_branch(native, forbidden) for forbidden in ("load_guard_config", "review", "evaluate_source_file_ref")
    ):
        failures.append("HookWorker native PostTool branch reaches Python semantic evaluation")

    post = _root_record(root, ROOTS[1], records)
    required = _native_branch(post, "native_required")
    if required is None or not _call_in_branch(required, "review_post_tool_native"):
        failures.append("HookWorker PostTool native-required branch is incomplete")
    elif _call_in_branch(required, "review"):
        failures.append("HookWorker native-required branch calls Python review")

    publisher_path = "src/codex_plugin_scanner/guard/native_policy_snapshot_publisher.py"
    publisher = records.get((publisher_path, "start"), [])
    if len(publisher) != 1:
        failures.append("native policy publisher start function is missing")
    else:
        forbidden = (
            "_publication_context",
            "_compiled_effective_policy",
            "load_guard_config",
        )
        if any(_call_in(publisher[0].node, name) for name in forbidden):
            failures.append("policy publisher start performs decision-time config or secret I/O")
    return failures


def _inventory(root: Path, reachable: tuple[FunctionRecord, ...]) -> list[IoObservation]:
    reachable_ids = {(record.path, record.qualname) for record in reachable}
    observations: list[IoObservation] = []
    source_root = root / "src/codex_plugin_scanner/guard"
    for path in sorted(source_root.rglob("*.py")):
        relative = _relative(path, root)
        tree = ast.parse(_read(path), filename=relative)
        module_records = tuple(_functions(tree, relative))
        for record in module_records:
            for observation in _observations(record):
                observations.append(
                    IoObservation(
                        observation.path,
                        observation.line,
                        observation.operation,
                        observation.kind,
                        observation.category,
                        (record.path, record.qualname) in reachable_ids or relative in _COMPATIBILITY_PATHS,
                    )
                )
    return sorted(
        set(observations),
        key=lambda item: (item.path, item.line, item.operation, item.kind),
    )


def _capability_contract() -> list[dict[str, object]]:
    return [
        {
            "id": "post_tool_source_read",
            "authority": "rust",
            "rust_symbols": ["guard_secure_fs::read_bounded", "guard_hook_core::review_post_tool"],
            "python_semantic_fallback": False,
            "compatibility_modes": sorted(COMPATIBILITY_MODES),
            "failure": "fail_closed",
        },
        {
            "id": "sensitive_path_and_symlink_classification",
            "authority": "rust",
            "rust_symbols": ["guard_secure_fs::classify_source_path", "guard_secure_fs::contains_symlink_component"],
            "python_semantic_fallback": False,
            "compatibility_modes": sorted(COMPATIBILITY_MODES),
            "failure": "fail_closed",
        },
        {
            "id": "pre_post_identity_and_equivalence",
            "authority": "rust",
            "rust_symbols": ["guard_secure_fs::FileIdentity", "guard_hook_core::review_post_tool"],
            "python_semantic_fallback": False,
            "compatibility_modes": sorted(COMPATIBILITY_MODES),
            "failure": "fail_closed",
        },
        {
            "id": "archive_decode_package_inspection",
            "authority": "rust_when_hook_reachable",
            "rust_symbols": [
                "guard_command::pretool::evaluate_pre_tool_envelope",
                "guard_runtime::strict_json::parse",
                "guard_hook_core::extract_payload_output",
            ],
            "python_semantic_fallback": False,
            "compatibility_modes": sorted(COMPATIBILITY_MODES),
            "failure": "fail_closed",
        },
        {
            "id": "policy_snapshot_admission",
            "authority": "rust",
            "rust_symbols": [
                "guard_runtime::policy_store::PolicySnapshotStore",
                "guard_runtime::edge::evaluate_envelope_with_store",
            ],
            "python_semantic_fallback": False,
            "python_decision_time_disk_io": False,
            "failure": "fail_closed",
        },
    ]


def validate(root: Path) -> dict[str, object]:
    root = root.resolve()
    records = _function_map(root)
    reachable = _reachable_records(root, records)
    failures = _branch_failures(root, records)
    inventory = _inventory(root, reachable)
    reachable_bad = [item for item in inventory if item.reachable and item.category.startswith("unclassified_python")]
    if reachable_bad:
        failures.extend(
            f"reachable unclassified Python I/O: {item.path}:{item.line} {item.operation}" for item in reachable_bad
        )
    if failures:
        raise RuntimeError("; ".join(failures))
    reachable_inventory = [item for item in inventory if item.reachable]
    inventory_counts = Counter(item.category for item in inventory)
    return {
        "schema": SCHEMA,
        "status": "passed",
        "native_modes": sorted(NATIVE_MODES),
        "compatibility_modes": sorted(COMPATIBILITY_MODES),
        "capabilities": _capability_contract(),
        "roots": [f"{item.path}:{item.name}" for item in (_root_record(root, spec, records) for spec in ROOTS)],
        "reachable_function_count": len(reachable),
        "inventory_total": len(inventory),
        "inventory_by_category": dict(sorted(inventory_counts.items())),
        "inventory": [
            {
                "path": item.path,
                "line": item.line,
                "operation": item.operation,
                "kind": item.kind,
                "category": item.category,
                "reachable": item.reachable,
            }
            for item in reachable_inventory
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    payload = validate(args.root)
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    print(rendered)
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
