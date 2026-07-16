"""Canonical Guard policy document CLI commands."""

from __future__ import annotations

import json
import os
import sys
from argparse import Namespace
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO, cast

from ..approval_gate import ApprovalGateError, require_high_risk
from ..policy_document import policy_document_digest
from ..policy_document_io import (
    PolicyCompilationError,
    PolicyFileTrustError,
    build_policy_document_from_rows,
    compile_policy_document,
    diff_policy_documents,
    load_trusted_policy_document,
    read_trusted_policy_text,
    write_private_policy_text,
)
from ..policy_document_yaml import PolicyDocumentError, format_policy_document_yaml
from ..store import GuardStore
from ..store_policy_document import PolicyImportMode
from .approval_gate_prompt import prompt_for_approval_gate

_POLICY_IMPORT_FLAG = "HOL_GUARD_POLICY_YAML_IMPORT"


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
    return document, compile_policy_document(document)


def _run_guard_policy_document_command(
    args: Namespace,
    *,
    store: GuardStore | None = None,
    output_stream: TextIO | None = None,
    **_kwargs: object,
) -> int:
    command = str(args.policy_command)
    as_json = bool(getattr(args, "json", False))
    try:
        if command == "validate":
            document, compiled = _load_and_compile(Path(args.file))
            _write_payload(
                "policy validate",
                {
                    "valid": True,
                    "document_id": document.metadata.id,
                    "digest": policy_document_digest(document),
                    "compiled_rows": len(compiled),
                    "message": f"Valid Guard policy: {document.metadata.id} ({len(compiled)} rows)",
                },
                as_json=as_json,
                output_stream=output_stream,
            )
            return 0

        if command == "fmt":
            path = Path(args.file)
            original = read_trusted_policy_text(path)
            document, _compiled = _load_and_compile(path)
            formatted = format_policy_document_yaml(document)
            changed = original != formatted
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

        if command == "diff":
            candidate, _ = _load_and_compile(Path(args.file))
            base = build_policy_document_from_rows(store.list_policy_decisions(), include_provenance=True)
            difference = diff_policy_documents(base, candidate)
            if as_json:
                _write_payload(
                    "policy diff",
                    {"changed": difference.changed, "diff": difference.text},
                    as_json=True,
                    output_stream=output_stream,
                )
            else:
                _write_document(difference.text or "No policy changes.", output_stream)
            return 1 if difference.changed else 0

        if command == "export":
            include_provenance = bool(args.include_provenance)
            if include_provenance:
                gate_input = prompt_for_approval_gate(store.guard_home, use_cooldown=False)
                require_high_risk(
                    store.guard_home,
                    purpose="policy_export_provenance",
                    approval_gate_input=gate_input,
                )
            rows = store.list_policy_decisions()
            document = build_policy_document_from_rows(rows, include_provenance=include_provenance)
            formatted = format_policy_document_yaml(document)
            output_value = getattr(args, "output", None)
            payload: dict[str, object] = {
                "rules": len(document.rules),
                "digest": policy_document_digest(document),
                "include_provenance": include_provenance,
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

        if command == "import":
            if os.environ.get(_POLICY_IMPORT_FLAG) != "1":
                _write_payload(
                    "policy import",
                    {
                        "error": "policy_import_disabled",
                        "message": f"Policy import requires {_POLICY_IMPORT_FLAG}=1.",
                    },
                    as_json=as_json,
                    output_stream=output_stream,
                )
                return 4
            document, compiled = _load_and_compile(Path(args.file))
            mode = cast(PolicyImportMode, args.mode)
            plan = store.plan_policy_document_import(compiled, mode=mode)
            dry_run = bool(args.dry_run)
            if dry_run:
                _write_payload(
                    "policy import",
                    {
                        "dry_run": True,
                        "document_id": document.metadata.id,
                        "digest": policy_document_digest(document),
                        "compiled_rows": len(compiled),
                        "additions": list(plan.additions),
                        "replacements": list(plan.replacements),
                        "removals": list(plan.removals),
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

            gate_input = prompt_for_approval_gate(store.guard_home, use_cooldown=False)
            grant = require_high_risk(
                store.guard_home,
                purpose="policy_import",
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
                    "message": f"Imported {result.inserted} policy rows.",
                },
                as_json=as_json,
                output_stream=output_stream,
            )
            return 0

        raise ValueError("unknown_policy_document_command")
    except (ApprovalGateError, PolicyCompilationError, PolicyDocumentError, PolicyFileTrustError) as error:
        code = getattr(error, "code", error.__class__.__name__)
        _write_payload(
            f"policy {command}",
            {"error": str(code), "message": str(error)},
            as_json=as_json,
            output_stream=output_stream,
        )
        return 4


__all__ = ["_run_guard_policy_document_command"]
