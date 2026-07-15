"""Side-effect-free command inspection using Guard's runtime command parser."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.risk import artifact_risk_signals_v2
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    COMMAND_EXTENSION_SCHEMA_VERSION,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    build_tool_action_request_artifact,
    extract_sensitive_tool_action_request,
    is_explicitly_benign_tool_action_request,
)


def inspect_command(
    command: str,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> dict[str, object]:
    """Classify one command without executing it or persisting Guard state."""

    command_text = command.strip()
    if not command_text:
        raise ValueError("Command text cannot be empty")
    workspace = (cwd or Path.cwd()).resolve()
    home = (home_dir or Path.home()).resolve()
    canonical_command = parse_shell_command(command_text, cwd=workspace, home_dir=home)
    arguments = {"command": command_text}
    benign = is_explicitly_benign_tool_action_request("Shell", arguments, cwd=workspace, home_dir=home)
    match = extract_sensitive_tool_action_request(
        "Shell",
        arguments,
        cwd=workspace,
        home_dir=home,
        canonical_command=canonical_command,
    )
    evaluation = evaluate_command(
        command_text,
        canonical_command=canonical_command,
        compatibility_action_class=match.action_class if match is not None else None,
        compatibility_reason=match.reason if match is not None else None,
        cwd=workspace,
        home_dir=home,
    )
    trace: list[dict[str, object]] = [
        {
            "step": "canonical-parse",
            "result": canonical_command.confidence,
            "detail": "Built Guard's side-effect-free canonical command model.",
        },
        {
            "step": "benign-classification",
            "result": "matched" if benign else "not-matched",
            "detail": "Checked Guard's explicit read-only and observer command classifications.",
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
            "detail": "Matched versioned command rules against the canonical command model.",
        }
    )
    if not evaluation.matched:
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
        )
        signals = artifact_risk_signals_v2(artifact)
    extensions_by_id = {owned.extension.extension_id: owned.extension for owned in evaluation.matches}
    trace.extend(
        (
            {
                "step": "extension-ownership",
                "result": ",".join(sorted(extensions_by_id)) or "unowned",
                "detail": "Selected structured extension ownership with compatibility fallback.",
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
