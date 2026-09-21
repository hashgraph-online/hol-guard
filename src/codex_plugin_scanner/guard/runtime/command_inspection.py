"""Command inspection from native evidence, without executing the target."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.config import resolve_guard_home
from codex_plugin_scanner.guard.risk import artifact_risk_signals_v2
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    COMMAND_EXTENSION_SCHEMA_VERSION,
)
from codex_plugin_scanner.guard.runtime.command_model import CanonicalCommand, parse_shell_command
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from codex_plugin_scanner.guard.runtime.native_command_evaluation import review_command_native
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    build_tool_action_request_artifact,
    extract_sensitive_tool_action_request,
)


def unavailable_command_inspection(
    command: str,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    canonical_command: CanonicalCommand | None = None,
    native_evaluation_failed: bool = False,
) -> dict[str, object]:
    """Return an explicit unavailable result without contacting a runtime."""

    command_text = command.strip()
    if not command_text:
        raise ValueError("Command text cannot be empty")
    if canonical_command is None:
        preview = parse_shell_command(command_text, cwd=cwd, home_dir=home_dir)
        normalized_command = command_text
        wrapper_chain: list[str] = []
    else:
        preview = canonical_command
        normalized_command = preview.normalized_text
        wrapper_chain = list(preview.wrapper_chain)
    return {
        "schema_version": COMMAND_EXTENSION_SCHEMA_VERSION,
        "status": "native_unavailable",
        "command": command_text,
        "classification": {
            "matched": False,
            "explicitly_benign": False,
            "action_class": None,
            "reason": (
                "Native command evaluation failed. The command remains blocked."
                if native_evaluation_failed
                else "Native inspection is unavailable. Check native runtime and command-control status."
            ),
            "normalized_command": normalized_command,
            "wrapper_chain": wrapper_chain,
        },
        "risk_classes": [],
        "minimum_action": "block" if native_evaluation_failed else "review",
        "controlling_rule_id": None,
        "signals": [],
        "extensions": [],
        "rules": [],
        "command_model": preview.to_dict(),
        "trace": [
            {
                "step": "native-command-evidence",
                "result": "failed" if native_evaluation_failed else "unavailable",
                "detail": (
                    "Native command evaluation failed; the bound native model and terminal block are preserved."
                    if native_evaluation_failed
                    else "No Python matcher fallback or target execution was performed."
                ),
            }
        ],
        "policy_evaluation": "not_run",
        "side_effects": "none",
    }


def inspect_command(
    command: str,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    guard_home: Path | None = None,
    extension_control_snapshot: ExtensionControlRuntimeSnapshot | None = None,
) -> dict[str, object]:
    """Classify one command without executing it or persisting Guard state."""

    command_text = command.strip()
    if not command_text:
        raise ValueError("Command text cannot be empty")
    workspace = (cwd or Path.cwd()).resolve()
    home = (home_dir or Path.home()).resolve()
    reviewed = review_command_native(
        command_text,
        guard_home=guard_home or resolve_guard_home(),
        cwd=workspace,
        home_dir=home,
        extension_control_snapshot=extension_control_snapshot,
    )
    if reviewed is None:
        return unavailable_command_inspection(command_text, cwd=workspace, home_dir=home)
    evaluation = reviewed.evaluation
    canonical_command = evaluation.command
    native_extensions = reviewed.payload.get("command_extensions")
    if isinstance(native_extensions, dict) and native_extensions.get("evaluation_error") is not None:
        return unavailable_command_inspection(
            command_text,
            canonical_command=canonical_command,
            native_evaluation_failed=True,
        )
    arguments = {"command": command_text}
    benign = reviewed.payload["explicitly_benign"] is True
    match = extract_sensitive_tool_action_request(
        "Shell",
        arguments,
        cwd=workspace,
        home_dir=home,
        canonical_command=canonical_command,
        native_evaluation=evaluation,
    )
    if match is not None:
        # Preserve the classifier's more specific diagnostic label, using the
        # same request-bound native observations and authenticated controls.
        # Compatibility metadata cannot add native rule ownership or remove a
        # native block; this is the projection used for the matching artifact.
        evaluation = evaluate_command(
            command_text,
            canonical_command=canonical_command,
            compatibility_action_class=match.action_class,
            compatibility_reason=match.reason,
            cwd=workspace,
            home_dir=home,
            extension_control_snapshot=reviewed.snapshot,
            native_extension_evidence=reviewed.payload,
        )
    trace: list[dict[str, object]] = [
        {
            "step": "canonical-parse",
            "result": canonical_command.confidence,
            "detail": "Validated the request-bound native command model.",
        },
        {
            "step": "benign-classification",
            "result": "matched" if benign else "not-matched",
            "detail": "Used the native command decision's explicit benign classification.",
        },
        {
            "step": "sensitive-action-classification",
            "result": "matched" if match is not None else "not-matched",
            "detail": "Ran the same sensitive command parser used by Guard harness hooks.",
        },
    ]
    trace.append(
        {
            "step": "structured-rule-matching",
            "result": str(len(evaluation.matches)),
            "detail": "Projected native observations onto versioned command rule metadata.",
        }
    )
    if not evaluation.matched or (evaluation.minimum_action == "allow" and match is None):
        return {
            "schema_version": COMMAND_EXTENSION_SCHEMA_VERSION,
            "status": "no_match",
            "command": command_text,
            "classification": {
                "matched": False,
                "explicitly_benign": benign,
                "action_class": None,
                "reason": (
                    "No built-in command safety extension matched. Other Guard protections and final policy were not "
                    "evaluated."
                ),
                "normalized_command": command_text,
                "wrapper_chain": [],
            },
            "risk_classes": [],
            "minimum_action": evaluation.minimum_action,
            "controlling_rule_id": evaluation.controlling_rule_id,
            "signals": [],
            "extensions": [],
            "rules": [],
            "command_model": canonical_command.to_dict(),
            "trace": trace,
            "policy_evaluation": "not_run",
            "side_effects": "none",
        }

    signals = ()
    if match is not None:
        artifact = build_tool_action_request_artifact(
            "guard-cli",
            match,
            config_path="command-inspection",
            source_scope="inspection",
            native_extension_evidence=reviewed.payload,
            extension_control_snapshot=reviewed.snapshot,
            native_evaluation=evaluation,
        )
        signals = artifact_risk_signals_v2(artifact)
    extensions_by_id = {owned.extension.extension_id: owned.extension for owned in evaluation.matches}
    trace.extend(
        (
            {
                "step": "extension-ownership",
                "result": ",".join(sorted(extensions_by_id)) or "unowned",
                "detail": "Selected extension ownership from validated native observations.",
            },
            {
                "step": "rule-ownership",
                "result": ",".join(owned.match.rule.rule_id for owned in evaluation.matches) or "unowned",
                "detail": "Selected every matching structured rule without making a policy decision.",
            },
            {
                "step": "risk-signal-derivation",
                "result": "completed",
                "detail": f"Derived {len(signals)} existing Guard risk signal(s) from the classified artifact.",
            },
        )
    )
    classification_reason = evaluation.controlling_reason or (
        "Sensitive command matched without registered rule metadata."
    )
    wrapper_chain = list(dict.fromkeys((*canonical_command.wrapper_chain, *(match.wrapper_chain if match else ()))))
    return {
        "schema_version": COMMAND_EXTENSION_SCHEMA_VERSION,
        "status": "review",
        "command": command_text,
        "classification": {
            "matched": True,
            "explicitly_benign": benign,
            "action_class": evaluation.controlling_action_class,
            "reason": classification_reason,
            "normalized_command": match.command_text if match is not None else canonical_command.normalized_text,
            "wrapper_chain": wrapper_chain,
        },
        "risk_classes": list(evaluation.risk_classes),
        "minimum_action": evaluation.minimum_action,
        "controlling_rule_id": evaluation.controlling_rule_id,
        "signals": [signal.to_dict() for signal in signals],
        "extensions": [extensions_by_id[extension_id].to_dict() for extension_id in sorted(extensions_by_id)],
        "rules": [owned.to_dict() for owned in evaluation.matches],
        "command_model": canonical_command.to_dict(),
        "trace": trace,
        "policy_evaluation": "not_run",
        "side_effects": "none",
    }


def command_extensions_payload(extension_id: str | None = None) -> dict[str, object]:
    """Return deterministic metadata for built-in command safety extensions."""

    if extension_id is not None:
        extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(extension_id)
        if extension is None:
            raise ValueError(f"Unknown command safety extension: {extension_id}")
        extensions = (extension,)
    else:
        extensions = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
    return {
        "schema_version": COMMAND_EXTENSION_SCHEMA_VERSION,
        "source": "built-in",
        "count": len(extensions),
        "extensions": [extension.to_dict() for extension in extensions],
    }
