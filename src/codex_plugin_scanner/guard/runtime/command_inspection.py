"""Side-effect-free command inspection using Guard's runtime command parser."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.risk import artifact_risk_signals_v2
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    COMMAND_EXTENSION_SCHEMA_VERSION,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.command_rules import CommandRuleMatch
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
    match = extract_sensitive_tool_action_request("Shell", arguments, cwd=workspace, home_dir=home)
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
    structured_matches = BUILT_IN_COMMAND_EXTENSION_REGISTRY.matching_rules(canonical_command)
    trace.append(
        {
            "step": "structured-rule-matching",
            "result": str(len(structured_matches)),
            "detail": "Matched versioned command rules against the canonical command model.",
        }
    )
    if match is None and not structured_matches:
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
            "signals": [],
            "extensions": [],
            "rules": [],
            "command_model": canonical_command.to_dict(),
            "trace": trace,
            "policy_evaluation": "not_run",
            "side_effects": "none",
        }

    compatibility_extension = (
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.for_action_class(match.action_class) if match is not None else None
    )
    compatibility_rule = (
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.rule_for_action_class(match.action_class) if match is not None else None
    )
    selected_matches = list(structured_matches)
    selected_rule_ids = {rule.rule_id for _extension, rule, _evidence in selected_matches}
    if (
        compatibility_extension is not None
        and compatibility_rule is not None
        and compatibility_rule.rule_id not in selected_rule_ids
        and not selected_matches
    ):
        selected_matches.append((compatibility_extension, compatibility_rule, ()))

    signals = ()
    if match is not None:
        artifact = build_tool_action_request_artifact(
            "guard-cli",
            match,
            config_path="command-inspection",
            source_scope="inspection",
        )
        signals = artifact_risk_signals_v2(artifact)
    extensions_by_id = {extension.extension_id: extension for extension, _rule, _evidence in selected_matches}
    rule_matches = [
        CommandRuleMatch(
            rule=rule,
            action_class=match.action_class if match is not None else None,
            reason=match.reason if match is not None else rule.description,
            command=canonical_command,
            matcher_evidence=evidence,
        )
        for _extension, rule, evidence in selected_matches
    ]
    risk_classes = sorted({risk for rule_match in rule_matches for risk in rule_match.rule.risk_classes})
    trace.extend(
        (
            {
                "step": "extension-ownership",
                "result": ",".join(sorted(extensions_by_id)) or "unowned",
                "detail": "Selected structured extension ownership with compatibility fallback.",
            },
            {
                "step": "rule-ownership",
                "result": ",".join(rule_match.rule.rule_id for rule_match in rule_matches) or "unowned",
                "detail": "Selected every matching structured rule without making a policy decision.",
            },
            {
                "step": "risk-signal-derivation",
                "result": "completed",
                "detail": f"Derived {len(signals)} existing Guard risk signal(s) from the classified artifact.",
            },
        )
    )
    primary_rule_match = rule_matches[0]
    classification_reason = match.reason if match is not None else primary_rule_match.rule.description
    return {
        "schema_version": COMMAND_EXTENSION_SCHEMA_VERSION,
        "status": "review",
        "command": command_text,
        "classification": {
            "matched": True,
            "explicitly_benign": benign,
            "action_class": match.action_class if match is not None else None,
            "reason": classification_reason,
            "normalized_command": match.command_text if match is not None else canonical_command.normalized_text,
            "wrapper_chain": list(match.wrapper_chain) if match is not None else list(canonical_command.wrapper_chain),
        },
        "risk_classes": risk_classes,
        "signals": [signal.to_dict() for signal in signals],
        "extensions": [extensions_by_id[extension_id].to_dict() for extension_id in sorted(extensions_by_id)],
        "rules": [rule_match.to_dict() for rule_match in rule_matches],
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
