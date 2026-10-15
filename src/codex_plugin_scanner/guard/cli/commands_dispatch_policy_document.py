"""Canonical Guard policy document CLI commands."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, TextIO, cast

from ...version import __version__
from ..approval_gate import ApprovalGateError, require_high_risk
from ..business_policy_document_import import (
    compile_document_for_import,
    has_business_rules,
    plan_document_for_import,
    read_business_document_for_store,
)
from ..native_policy_document import NativePolicyDocumentError
from ..native_policy_snapshot_constants import NativePolicySnapshotError
from ..policy_authority import PolicyAuthorityError
from ..policy_decision_explain import active_policy_document
from ..policy_document import policy_document_digest
from ..policy_document_authority import policy_import_approval_binding
from ..policy_document_io import (
    PolicyCompilationError,
    PolicyDocumentDiff,
    PolicyFileTrustError,
    build_policy_document_from_rows,
    diff_policy_documents,
    load_trusted_policy_document,
    read_trusted_policy_text,
    write_private_policy_text,
)
from ..policy_document_yaml import PolicyDocumentError, format_policy_document_yaml
from ..policy_starters import with_modeline
from ..runtime.command_policy import compile_command_policy_rules, evaluate_command_policy_rules
from ..store import GuardStore
from ..store_policy_document import PolicyImportMode
from .approval_gate_prompt import prompt_for_approval_gate
from .commands_dispatch_policy_dx import (
    confirm_policy_import,
    run_policy_explain_decision,
    run_policy_status,
    wants_json,
)


class PolicyDocumentCommandArgs(Protocol):
    policy_command: str
    file: str
    check: bool
    include_provenance: bool
    mode: str
    dry_run: bool
    command_text: str
    json: bool


def _write_payload(
    command: str,
    payload: dict[str, object],
    *,
    as_json: bool,
    output_stream: TextIO | None,
) -> None:
    stream = output_stream or sys.stdout
    if as_json:
        stream.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
        return
    summary = payload.get("message")
    stream.write(f"{summary if isinstance(summary, str) else command}\n")


def _write_document(text: str, output_stream: TextIO | None) -> None:
    stream = output_stream or sys.stdout
    stream.write(text)
    if not text.endswith("\n"):
        stream.write("\n")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_and_compile(path: Path):
    document = load_trusted_policy_document(path)
    return document, compile_document_for_import(document)


def _compile_for_local_store(path: Path):
    document = load_trusted_policy_document(path)
    try:
        return document, compile_document_for_import(document), None
    except PolicyCompilationError as error:
        if error.code != "command_expression_requires_guard_3_1_runtime":
            raise
        return document, (), error


def _run_guard_policy_document_command(
    args: PolicyDocumentCommandArgs,
    *,
    store: GuardStore | None = None,
    input_text: str | None = None,
    output_stream: TextIO | None = None,
    **_kwargs: object,
) -> int:
    command = str(args.policy_command)
    as_json = wants_json(args)
    try:
        if command == "capabilities":
            _write_payload(
                "policy capabilities",
                {
                    "guard_version": __version__,
                    "policy_schema": "guard.hashgraphonline.com/v1alpha1",
                    "capabilities": ["command-pattern-expressions.v1"],
                    "command_pattern_expressions": {
                        "combinators": ["all", "any"],
                        "operators": [
                            "exact",
                            "startsWith",
                            "contains",
                            "endsWith",
                            "glob",
                            "regex",
                        ],
                        "regex_timeout_ms": 50,
                    },
                    "message": "Command-pattern policy expressions are supported.",
                },
                as_json=as_json,
                output_stream=output_stream,
            )
            return 0

        if command == "evaluate-command":
            document = load_trusted_policy_document(Path(args.file))
            evaluation = evaluate_command_policy_rules(
                compile_command_policy_rules(document),
                str(args.command_text),
            )
            _write_payload(
                "policy evaluate-command",
                {
                    "action": evaluation.action,
                    "matching_rule_ids": list(evaluation.matching_rule_ids),
                    "message": (
                        "No command expression matched; default allow."
                        if not evaluation.matching_rule_ids
                        else f"Command matched {len(evaluation.matching_rule_ids)} policy rule(s): {evaluation.action}."
                    ),
                },
                as_json=as_json,
                output_stream=output_stream,
            )
            return 0

        if command == "fmt":
            path = Path(args.file)
            original = read_trusted_policy_text(path)
            document = load_trusted_policy_document(path)
            canonical = format_policy_document_yaml(document)
            formatted = with_modeline(canonical)
            # A file formatted before the modeline existed is still canonical, so --check accepts it.
            changed = original not in (canonical, formatted) if bool(args.check) else original != formatted
            if bool(args.check):
                _write_payload(
                    "policy fmt",
                    {
                        "changed": changed,
                        "message": "Policy formatting differs." if changed else "Policy is canonically formatted.",
                    },
                    as_json=as_json,
                    output_stream=output_stream,
                )
                return 1 if changed else 0
            write_private_policy_text(path, formatted)
            _write_payload(
                "policy fmt",
                {"changed": changed, "message": "Policy formatted canonically."},
                as_json=as_json,
                output_stream=output_stream,
            )
            return 0

        if store is None:
            raise RuntimeError("Guard policy command requires a policy store.")

        if command == "recover-business-source":
            from ..native_business_source_recovery import recover_committed_business_source

            document, _ = _load_and_compile(Path(args.file))
            gate_input = prompt_for_approval_gate(
                store.guard_home,
                use_cooldown=False,
                summary="Approve recovery of this exact interrupted business source installation.",
            )
            grant = require_high_risk(
                store.guard_home,
                purpose="policy_import",
                **policy_import_approval_binding(document, "replace"),
                approval_gate_input=gate_input,
            )
            source = recover_committed_business_source(store, document, approval_gate_grant=grant)
            _write_payload(
                "policy recover-business-source",
                {"digest": source.source_digest, "message": "Recovered the business policy installation."},
                as_json=as_json,
                output_stream=output_stream,
            )
            return 0

        if command == "diff":
            candidate, _ = _load_and_compile(Path(args.file))
            difference = diff_policy_documents(active_policy_document(store), candidate)
            semantic_payload = _semantic_diff_payload(difference)
            if as_json:
                _write_payload(
                    "policy diff",
                    semantic_payload,
                    as_json=True,
                    output_stream=output_stream,
                )
            else:
                summary = (
                    "Comparing the file against the policy that is Live on this device.\n"
                    f"Semantic changes: {len(difference.additions)} additions, "
                    f"{len(difference.modifications)} modifications, "
                    f"{len(difference.removals)} removals.\n"
                    f"Impacted scopes: {', '.join(difference.impacted_scopes) or 'none'}.\n"
                    f"Impacted harnesses: {', '.join(difference.impacted_harnesses) or 'none'}.\n"
                    "Impacted artifact families: "
                    f"{', '.join(difference.impacted_artifact_families) or 'none'}.\n"
                    f"Conflict warnings: {', '.join(difference.conflict_warnings) or 'none'}.\n\n"
                    f"Broadened rules: {', '.join(difference.broadened_rules) or 'none'}.\n"
                    f"Narrowed rules: {', '.join(difference.narrowed_rules) or 'none'}.\n"
                    "Effective action changes: "
                    f"{', '.join(difference.effective_action_changes) or 'none'}.\n"
                    "Broad relaxing changes: "
                    f"{', '.join(difference.broad_relaxing_changes) or 'none'}.\n\n"
                )
                _write_document(summary + (difference.text or "No policy changes."), output_stream)
            return 1 if difference.changed else 0

        if command in {"export", "show"}:
            include_provenance = bool(args.include_provenance)
            if include_provenance:
                gate_input = prompt_for_approval_gate(store.guard_home, use_cooldown=False)
                require_high_risk(
                    store.guard_home,
                    purpose="policy_export_provenance",
                    approval_gate_input=gate_input,
                )
            rows = store.list_policy_decisions()
            business_document = read_business_document_for_store(store)
            if business_document is not None and not include_provenance:
                from ..business_policy_document_view import without_provenance

                business_document = without_provenance(business_document)
            document = business_document or build_policy_document_from_rows(rows, include_provenance=include_provenance)
            formatted = with_modeline(format_policy_document_yaml(document))
            output_value = getattr(args, "output", None) if command == "export" else None
            payload: dict[str, object] = {
                "rules": len(document.rules),
                "digest": policy_document_digest(document),
                "include_provenance": include_provenance,
                "provenance_redacted": not include_provenance,
            }
            if output_value is None:
                if as_json:
                    payload["yaml"] = formatted
                    payload["message"] = f"Exported {len(document.rules)} policy rules."
                    _write_payload(
                        "policy export",
                        payload,
                        as_json=True,
                        output_stream=output_stream,
                    )
                else:
                    _write_document(formatted, output_stream)
            else:
                output = Path(output_value)
                write_private_policy_text(output, formatted)
                payload["written"] = str(output)
                payload["message"] = f"Exported {len(document.rules)} policy rules."
                _write_payload(
                    "policy export",
                    payload,
                    as_json=as_json,
                    output_stream=output_stream,
                )
            return 0
        if command == "status":
            return run_policy_status(args, store, output_stream)
        if command == "explain" and getattr(args, "decision_id", None):
            return run_policy_explain_decision(args, store, output_stream)
        if command == "explain":
            document = active_policy_document(store)
            compiled = compile_document_for_import(document)
            actions: dict[str, int] = {}
            scopes: dict[str, int] = {}
            for row in compiled:
                action = row.decision.action
                scope = row.decision.scope
                actions[action] = actions.get(action, 0) + 1
                scopes[scope] = scopes.get(scope, 0) + 1
            message = (
                f"Active policy has {len(document.rules)} canonical rules compiled into {len(compiled)} local rows."
            )
            if has_business_rules(document):
                for rule in document.rules:
                    if rule.enabled:
                        actions[rule.effect] = actions.get(rule.effect, 0) + 1
                scopes["business"] = sum(rule.enabled for rule in document.rules)
                message = (
                    f"Active policy has {len(document.rules)} business rules in the authenticated complete source."
                )
            _write_payload(
                "policy explain",
                {
                    "document_id": document.metadata.id,
                    "digest": policy_document_digest(document),
                    "rules": len(document.rules),
                    "compiled_rows": len(compiled),
                    "actions": dict(sorted(actions.items())),
                    "scopes": dict(sorted(scopes.items())),
                    "message": message,
                },
                as_json=as_json,
                output_stream=output_stream,
            )
            return 0

        if command == "import":
            document, compiled = _load_and_compile(Path(args.file))
            mode = cast(PolicyImportMode, args.mode)
            current_document = active_policy_document(store)
            difference = diff_policy_documents(current_document, document)
            plan = plan_document_for_import(store, document, compiled, mode)
            dry_run = bool(args.dry_run)
            if dry_run:
                _write_payload(
                    "policy import",
                    {
                        "dry_run": True,
                        "document_id": document.metadata.id,
                        "digest": policy_document_digest(document),
                        "compiled_rows": len(compiled),
                        "import_additions": list(plan.additions),
                        "import_replacements": list(plan.replacements),
                        "import_removals": list(plan.removals),
                        **_semantic_diff_payload(difference),
                        "message": (
                            f"Dry run: {len(plan.additions)} additions, "
                            f"{len(plan.replacements)} replacements, "
                            f"{len(plan.removals)} removals; no changes written."
                        ),
                    },
                    as_json=as_json,
                    output_stream=output_stream,
                )
                return 0

            declined = confirm_policy_import(args, difference.text, output_stream, input_text)
            if declined is not None:
                _write_payload("policy import", declined, as_json=as_json, output_stream=output_stream)
                return 4
            gate_input = prompt_for_approval_gate(
                store.guard_home,
                use_cooldown=False,
                summary=(
                    f"Approve policy import: {len(plan.additions)} additions, "
                    f"{len(plan.replacements)} replacements, "
                    f"{len(plan.removals)} removals; "
                    f"{len(difference.broad_relaxing_changes)} broad relaxing changes."
                ),
            )
            grant = require_high_risk(
                store.guard_home,
                purpose="policy_import",
                **policy_import_approval_binding(document, mode),
                approval_gate_input=gate_input,
            )
            result = store.import_policy_document(
                document,
                compiled,
                mode=mode,
                now=_now(),
                approval_gate_grant=grant,
            )
            _write_payload(
                "policy import",
                {
                    "dry_run": False,
                    "document_id": result.document_id,
                    "digest": result.digest,
                    "inserted": result.inserted,
                    "replaced": result.replaced,
                    "additions": list(plan.additions),
                    "replacements": list(plan.replacements),
                    "removals": list(plan.removals),
                    "message": f"Imported {result.inserted} policy rules.",
                },
                as_json=as_json,
                output_stream=output_stream,
            )
            return 0

        raise ValueError("unknown_policy_document_command")
    except (
        ApprovalGateError,
        PolicyAuthorityError,
        PolicyCompilationError,
        PolicyDocumentError,
        PolicyFileTrustError,
        NativePolicySnapshotError,
        NativePolicyDocumentError,
    ) as error:
        code = getattr(error, "code", error.__class__.__name__)
        _write_payload(
            f"policy {command}",
            {"error": str(code), "message": str(error)},
            as_json=as_json,
            output_stream=output_stream,
        )
        return 4


def _semantic_diff_payload(difference: PolicyDocumentDiff) -> dict[str, object]:
    return {
        "changed": difference.changed,
        "diff": difference.text,
        "additions": list(difference.additions),
        "modifications": list(difference.modifications),
        "removals": list(difference.removals),
        "impacted_scopes": list(difference.impacted_scopes),
        "impacted_harnesses": list(difference.impacted_harnesses),
        "impacted_artifact_families": list(difference.impacted_artifact_families),
        "conflict_warnings": list(difference.conflict_warnings),
        "broadened_rules": list(difference.broadened_rules),
        "narrowed_rules": list(difference.narrowed_rules),
        "unchanged_rules": list(difference.unchanged_rules),
        "effective_action_changes": list(difference.effective_action_changes),
        "broad_relaxing_changes": list(difference.broad_relaxing_changes),
        "requires_high_risk_approval": bool(difference.broad_relaxing_changes),
    }


__all__ = ["_run_guard_policy_document_command"]
