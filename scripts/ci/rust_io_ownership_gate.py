#!/usr/bin/env python3
"""Prove that decision-critical hook I/O is owned by the native runtime.

The hook transport is Python, but source bytes, path classification, file
identity, and content equivalence are Rust responsibilities.  This gate keeps
the boundary executable: it inventories synchronous Python I/O and hashes,
walks the supported hook call graph, and rejects a new Python operation on a
native decision branch.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Final, cast

if __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci.rust_io_ownership_contract import capability_contract
from scripts.ci.rust_io_ownership_resolver import FunctionRecordLike, resolve_call

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
        "src/codex_plugin_scanner/guard/runtime/source_paths.py",
        "src/codex_plugin_scanner/guard/native_command_model.py",
    }
)
_TRANSPORT_IDENTITY_PATHS: Final = frozenset(
    {
        # Payload-reference metadata validation; the native edge reads bytes.
        "src/codex_plugin_scanner/guard/daemon/hook_request_parsing.py",
        # Archive-inspection transport: lease, request binding, and the
        # bounded native worker invocation; all archive semantics are Rust.
        "src/codex_plugin_scanner/guard/native_archive_inspection.py",
        "src/codex_plugin_scanner/guard/native_runtime.py",
        "src/codex_plugin_scanner/guard/native_context.py",
        "src/codex_plugin_scanner/guard/native_resident_client.py",
        "src/codex_plugin_scanner/guard/native_runtime_resilience.py",
        "src/codex_plugin_scanner/guard/codex_hook_launch_runtime.py",
        "src/codex_plugin_scanner/guard/daemon/discovery.py",
        "src/codex_plugin_scanner/guard/daemon/manager.py",
        # Interpreter bootstrap identity only; no policy or command decisions.
        "src/codex_plugin_scanner/guard/daemon/pipx_import_paths.py",
        "src/codex_plugin_scanner/guard/frozen_runtime_commands.py",
    }
)
_TRANSPORT_INTEGRITY_PATHS: Final = frozenset(
    {
        "src/codex_plugin_scanner/guard/native_decision_receipt.py",
        "src/codex_plugin_scanner/guard/native_command_observations.py",
        "src/codex_plugin_scanner/guard/native_context.py",
        # Execution-environment digest binds transport context without carrying
        # the environment values themselves.
        "src/codex_plugin_scanner/guard/hook_execution_environment.py",
        "src/codex_plugin_scanner/guard/native_hook_edge.py",
        "src/codex_plugin_scanner/guard/daemon/hook_native_review_approval.py",
        # Retry lineage is local diagnostic metadata. Its digests protect
        # reattachment integrity but never authorize or evaluate an action.
        "src/codex_plugin_scanner/guard/retry_lineage.py",
    }
)
_TRANSPORT_AUTHORITY_PATHS: Final = frozenset(
    {
        # Strict owner-checked native command-control lock and marker transport.
        "src/codex_plugin_scanner/guard/native_command_control_authority_io.py",
    }
)
_TRANSPORT_DECODE_PATHS: Final = frozenset(
    {
        "src/codex_plugin_scanner/guard/native_hook_edge.py",
        "src/codex_plugin_scanner/guard/native_pretool.py",
        "src/codex_plugin_scanner/guard/native_resident_client.py",
        "src/codex_plugin_scanner/guard/native_runtime.py",
        "src/codex_plugin_scanner/guard/native_context.py",
    }
)
_STRUCTURED_OUTPUT_MEDIATION_PATHS: Final = frozenset(
    {
        "src/codex_plugin_scanner/guard/runtime/secret_sensitivity.py",
        "src/codex_plugin_scanner/guard/runtime/structured_data_sensitivity.py",
        "src/codex_plugin_scanner/guard/runtime/structured_output_mediation.py",
    }
)
_ASYNC_POLICY_PATHS: Final = frozenset(
    {
        "src/codex_plugin_scanner/guard/mdm/policy.py",
        "src/codex_plugin_scanner/guard/mdm/managed_file_trust.py",
        "src/codex_plugin_scanner/guard/mdm/contracts.py",
        "src/codex_plugin_scanner/guard/native_policy_snapshot_publisher.py",
        "src/codex_plugin_scanner/guard/native_policy_snapshot_publisher_inputs.py",
        "src/codex_plugin_scanner/guard/native_policy_snapshot_storage.py",
        "src/codex_plugin_scanner/guard/config.py",
        "src/codex_plugin_scanner/guard/config_file_io.py",
        "src/codex_plugin_scanner/guard/directory_path_authority.py",
        "src/codex_plugin_scanner/guard/runtime/command_activity_correlation.py",
        "src/codex_plugin_scanner/guard/runtime/command_native_factors.py",
    }
)
_PERSISTENCE_PATH_PREFIXES: Final = (
    "src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_writer.py",
    "src/codex_plugin_scanner/guard/runtime/hook_enrichment_queue.py",
    "src/codex_plugin_scanner/guard/daemon/hook_metrics.py",
    "src/codex_plugin_scanner/guard/private_file_io.py",
    "src/codex_plugin_scanner/guard/local_dashboard_session.py",
    "src/codex_plugin_scanner/guard/guard_home_state.py",
    "src/codex_plugin_scanner/guard/store_base.py",
    "src/codex_plugin_scanner/guard/store_mcp_catalog.py",
)
_PRESENTATION_PATHS: Final = frozenset(
    {
        # Retained Python: approval presentation, harness adapters, and
        # continuation surfaces. These render or forward decisions; they
        # never compute them.
        "src/codex_plugin_scanner/guard/adapters/cursor_native_approval.py",
        "src/codex_plugin_scanner/guard/adapters/zcode_contained_tests.py",
        "src/codex_plugin_scanner/guard/approval_scope_support.py",
        "src/codex_plugin_scanner/guard/approvals.py",
        "src/codex_plugin_scanner/guard/codex_app_server.py",
        "src/codex_plugin_scanner/guard/daemon/hook_pretool_rendering.py",
        "src/codex_plugin_scanner/guard/continuation_runtime.py",
        "src/codex_plugin_scanner/guard/edge_events.py",
        "src/codex_plugin_scanner/guard/harness_usage.py",
        "src/codex_plugin_scanner/guard/local_authority_integrity.py",
        "src/codex_plugin_scanner/guard/mcp_tool_calls.py",
        "src/codex_plugin_scanner/guard/temporary_mcp_approvals.py",
    }
)
_SERVICE_PATHS: Final = frozenset(
    {
        # Retained Python: daemon supervision/lifecycle, cloud/OAuth/network
        # services, publication, and install support.
        "src/codex_plugin_scanner/guard/daemon/discovery.py",
        "src/codex_plugin_scanner/guard/daemon/lifecycle_journal.py",
        "src/codex_plugin_scanner/guard/daemon/manager.py",
        "src/codex_plugin_scanner/guard/daemon/runtime_peer.py",
        "src/codex_plugin_scanner/guard/daemon/start_classification.py",
        "src/codex_plugin_scanner/guard/frozen_daemon_runtime.py",
        "src/codex_plugin_scanner/guard/runtime/mcp_connection_identity.py",
        "src/codex_plugin_scanner/guard/extension_builder/io.py",
        "src/codex_plugin_scanner/guard/frozen_runtime_commands.py",
        "src/codex_plugin_scanner/guard/live_process_identity.py",
        "src/codex_plugin_scanner/guard/mdm/acl.py",
        "src/codex_plugin_scanner/guard/mdm/network_credentials.py",
        "src/codex_plugin_scanner/guard/mdm/network_transport.py",
        "src/codex_plugin_scanner/guard/mdm/network_trust.py",
        "src/codex_plugin_scanner/guard/native_policy_snapshot_windows_key.py",
        "src/codex_plugin_scanner/guard/native_policy_snapshot_windows_support.py",
        "src/codex_plugin_scanner/guard/oauth_token_claims.py",
        "src/codex_plugin_scanner/guard/stable_guard_cli.py",
    }
)
_PENDING_AUTHORITY_PATHS: Final = frozenset(
    {
        # Decision-adjacent Python that remains authoritative until the
        # package/archive, guarded-launch, command-authority, and local-MCP
        # migration legs land. Each leg must shrink this set; it may only
        # grow through an explicit contract change.
        "src/codex_plugin_scanner/guard/cli/commands_hook_native_eval.py",
        "src/codex_plugin_scanner/guard/cli/commands_hook_native_floor.py",
        "src/codex_plugin_scanner/guard/cli/commands_hook_native_generic.py",
        "src/codex_plugin_scanner/guard/cli/commands_hook_native_prepare.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_apply_patch_policy.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_codex_commands.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_codex_git.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_codex_git_config.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_codex_paths.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_codex_prompt_attachments.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_codex_reads.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_codex_tool_output.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_hook_state.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_native_search.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_runtime_artifacts.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_runtime_policy.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_runtime_resolution.py",
        "src/codex_plugin_scanner/guard/package_execution_context.py",
        "src/codex_plugin_scanner/guard/package_execution_context_configuration.py",
        "src/codex_plugin_scanner/guard/package_execution_context_inputs.py",
        "src/codex_plugin_scanner/guard/package_shim_frozen.py",
        "src/codex_plugin_scanner/guard/package_shim_status.py",
        "src/codex_plugin_scanner/guard/runtime/_shell_execution_context_support.py",
        "src/codex_plugin_scanner/guard/runtime/_shell_secret_read_support.py",
        "src/codex_plugin_scanner/guard/runtime/actions.py",
        "src/codex_plugin_scanner/guard/runtime/approval_context.py",
        "src/codex_plugin_scanner/guard/runtime/browser_mcp_intent.py",
        "src/codex_plugin_scanner/guard/runtime/command_decision_adapter.py",
        "src/codex_plugin_scanner/guard/runtime/command_evaluation.py",
        "src/codex_plugin_scanner/guard/runtime/compound_git_inspection.py",
        "src/codex_plugin_scanner/guard/runtime/contained_execution_common.py",
        "src/codex_plugin_scanner/guard/runtime/containment_executor.py",
        "src/codex_plugin_scanner/guard/runtime/direct_typescript_diagnostics.py",
        "src/codex_plugin_scanner/guard/runtime/direct_vitest.py",
        "src/codex_plugin_scanner/guard/runtime/effect_decision.py",
        "src/codex_plugin_scanner/guard/runtime/embedded_script_evidence.py",
        "src/codex_plugin_scanner/guard/runtime/extension_contribution.py",
        "src/codex_plugin_scanner/guard/runtime/extension_control_runtime.py",
        "src/codex_plugin_scanner/guard/runtime/extension_trust.py",
        "src/codex_plugin_scanner/guard/runtime/false_positive_rules.py",
        "src/codex_plugin_scanner/guard/runtime/git_execution_safety.py",
        "src/codex_plugin_scanner/guard/runtime/git_index_inspection.py",
        "src/codex_plugin_scanner/guard/runtime/github_actions_read_workflow.py",
        "src/codex_plugin_scanner/guard/runtime/github_workflow_approval_record.py",
        "src/codex_plugin_scanner/guard/runtime/github_workflow_authorization.py",
        "src/codex_plugin_scanner/guard/runtime/github_workflow_context.py",
        "src/codex_plugin_scanner/guard/runtime/github_workflow_operations.py",
        "src/codex_plugin_scanner/guard/runtime/github_workflow_runtime.py",
        "src/codex_plugin_scanner/guard/runtime/jsonc.py",
        "src/codex_plugin_scanner/guard/runtime/local_cli_commands.py",
        "src/codex_plugin_scanner/guard/runtime/local_cli_compound.py",
        "src/codex_plugin_scanner/guard/runtime/local_cli_identity.py",
        "src/codex_plugin_scanner/guard/runtime/local_package_script_evidence.py",
        "src/codex_plugin_scanner/guard/runtime/lockfile_evaluation_support.py",
        "src/codex_plugin_scanner/guard/runtime/lockfile_parse_result.py",
        "src/codex_plugin_scanner/guard/runtime/mcp_protection.py",
        "src/codex_plugin_scanner/guard/runtime/mcp_server_contribution.py",
        "src/codex_plugin_scanner/guard/runtime/mcp_skill_firewall.py",
        "src/codex_plugin_scanner/guard/runtime/npm_source_spec.py",
        "src/codex_plugin_scanner/guard/runtime/package_evidence_common.py",
        "src/codex_plugin_scanner/guard/runtime/package_intent_common.py",
        "src/codex_plugin_scanner/guard/runtime/package_intent_parser.py",
        "src/codex_plugin_scanner/guard/runtime/package_json_scripts.py",
        "src/codex_plugin_scanner/guard/runtime/package_manifest_diff.py",
        "src/codex_plugin_scanner/guard/runtime/prompt_injection.py",
        "src/codex_plugin_scanner/guard/runtime/read_only_git_audit.py",
        "src/codex_plugin_scanner/guard/runtime/restricted_archive_destination.py",
        "src/codex_plugin_scanner/guard/runtime/restricted_archive_stream.py",
        "src/codex_plugin_scanner/guard/runtime/routine_local_node.py",
        "src/codex_plugin_scanner/guard/runtime/routine_node_identity.py",
        "src/codex_plugin_scanner/guard/runtime/routine_setup_commands.py",
        "src/codex_plugin_scanner/guard/runtime/runner.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/agent_guidance_reads.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/benign_requests.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/credential_exfiltration.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/developer_inspection.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/developer_routines.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/git_routines.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/interpreter_launch.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/interpreter_observers.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/interpreter_trust.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/local_read_operands.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/request_artifacts.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/routine_directory_creation.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/sensitive_read_pipeline.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/shell_quote_parsing.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/shell_static_safety.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/source_edit_context.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/tool_action_requests.py",
        "src/codex_plugin_scanner/guard/runtime/shell_command_wrappers.py",
        "src/codex_plugin_scanner/guard/runtime/shell_secret_reads.py",
        "src/codex_plugin_scanner/guard/runtime/skill_paths.py",
        "src/codex_plugin_scanner/guard/runtime/supply_chain_bundle_runtime.py",
        "src/codex_plugin_scanner/guard/runtime/supply_chain_package_eval.py",
        "src/codex_plugin_scanner/guard/runtime/typescript_launch_evidence.py",
        "src/codex_plugin_scanner/guard/runtime/workspace_path_guard.py",
        "src/codex_plugin_scanner/guard/shims.py",
        "src/codex_plugin_scanner/guard/trusted_local_tools.py",
        "src/codex_plugin_scanner/guard/trusted_package_tools.py",
    }
)
_PERSISTENCE_ONLY_PATHS: Final = frozenset(
    {
        # Opt-in sealed diagnostics; these helpers never authorize a decision.
        "src/codex_plugin_scanner/guard/codex_binding_capture.py",
        "src/codex_plugin_scanner/guard/codex_binding_capture_bounds.py",
        "src/codex_plugin_scanner/guard/codex_binding_capture_crypto.py",
        "src/codex_plugin_scanner/guard/codex_binding_capture_fs.py",
        "src/codex_plugin_scanner/guard/codex_binding_capture_join.py",
        "src/codex_plugin_scanner/guard/codex_binding_capture_writer.py",
    }
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
        "route_native_hook",
    ),
)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"could not inspect {path}") from exc


@cache
def _parsed_module(path: Path) -> ast.Module:
    """Parse a source file once per process; inputs are read-only while validating."""

    return ast.parse(_read(path), filename=str(path))


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
        tree = _parsed_module(path)
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
    if path in _STRUCTURED_OUTPUT_MEDIATION_PATHS and kind in {"hash", "decode"}:
        return "adapter_output_mediation"
    if path in _PERSISTENCE_ONLY_PATHS:
        return "persistence_only"
    if path in _TRANSPORT_IDENTITY_PATHS:
        return "transport_identity"
    if path in _TRANSPORT_DECODE_PATHS and kind == "decode":
        return "transport_decode"
    if path in _TRANSPORT_INTEGRITY_PATHS and kind == "hash":
        return "transport_integrity"
    if path in _TRANSPORT_AUTHORITY_PATHS and kind == "filesystem":
        return "transport_authority"
    if path in _ASYNC_POLICY_PATHS:
        return "asynchronous_policy"
    if path.startswith(_PERSISTENCE_PATH_PREFIXES):
        return "persistence_only"
    if path in _PRESENTATION_PATHS:
        return "approval_presentation"
    if path in _SERVICE_PATHS:
        return "python_service"
    if path in _PENDING_AUTHORITY_PATHS:
        return "pending_authority_migration"
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
    records_view = cast(Mapping[tuple[str, str], list[FunctionRecordLike]], records)
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
            resolved = resolve_call(root, cast(FunctionRecordLike, cast(object, record)), name, records_view)
            if resolved is not None:
                pending.append(cast(FunctionRecord, cast(object, resolved)))
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
        tree = _parsed_module(path)
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
    return capability_contract(COMPATIBILITY_MODES)


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
