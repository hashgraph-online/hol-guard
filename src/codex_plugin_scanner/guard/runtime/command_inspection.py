"""Command inspection from native evidence, without executing the target."""

from __future__ import annotations

import shlex
from collections.abc import Mapping
from pathlib import Path

from codex_plugin_scanner.guard.config import resolve_guard_home
from codex_plugin_scanner.guard.native_context import bound_context_digest_home
from codex_plugin_scanner.guard.native_pretool import REVIEW_TIER_ACTIONS
from codex_plugin_scanner.guard.native_rich_command_model import NativeCommandModelError
from codex_plugin_scanner.guard.native_sensitive_request import NativeSensitiveRequestError
from codex_plugin_scanner.guard.native_tool_action_identity import NativeToolActionIdentityError
from codex_plugin_scanner.guard.risk import artifact_risk_signals_v2
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    COMMAND_EXTENSION_SCHEMA_VERSION,
)
from codex_plugin_scanner.guard.runtime.command_model import CanonicalCommand
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command as parse_shell_command
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from codex_plugin_scanner.guard.runtime.native_command_evaluation import review_command_native
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    build_tool_action_request_artifact,
    extract_sensitive_tool_action_request,
)

# Reason codes a caller can see on an inspection that produced no verdict.
# None of them is a safe answer: the command keeps at least a review.
UNAVAILABLE_REASON_CODES = frozenset(
    {
        "native_review_unavailable",
        "native_evaluation_failed",
        "daemon_not_running",
        "daemon_start_failed",
        "daemon_start_timeout",
        "daemon_request_failed",
    }
)
FAILED_REASON_CODES = frozenset({"native_evaluation_failed"})
UNAVAILABLE_RECOVERY_COMMANDS = ("hol-guard daemon status", "hol-guard daemon repair")
# Inspection enforces nothing, so it can wait for a native runtime that is still
# warming up. A hook keeps the short default; this stays under the CLI's
# five-second daemon request timeout.
INSPECTION_NATIVE_TIMEOUT_SECONDS = 3.0
# Native reason codes that say only that evaluation failed. Any other reason a
# native block carries is a decision, and inspection reports it as one.
_NATIVE_FAILURE_REASON_CODES = frozenset(
    {"native_command_evaluation_failed", "native_command_extension_evaluation_failed"}
)


def recovery_commands(guard_home: Path | None = None) -> list[str]:
    """The recovery commands, naming ``guard_home`` when the caller knows it."""

    if guard_home is None:
        return list(UNAVAILABLE_RECOVERY_COMMANDS)
    quoted = shlex.quote(str(guard_home))
    return [f"{command} --guard-home {quoted}" for command in UNAVAILABLE_RECOVERY_COMMANDS]


def inspection_readiness(
    reason_code: str, *, failed: bool = False, guard_home: Path | None = None
) -> dict[str, object]:
    """Describe why an inspection has no verdict, without command text."""

    code = reason_code if reason_code in UNAVAILABLE_REASON_CODES else "native_review_unavailable"
    # The state follows the code, as `native-readiness.v1.json` declares it, so
    # a failed evaluation is never reported as a cold runtime worth retrying.
    return {
        "state": "failed" if failed or code in FAILED_REASON_CODES else "unavailable",
        "reason_code": code,
        "verdict": "not_evaluated",
        "safe_verdict": False,
        "recovery_commands": recovery_commands(guard_home),
    }


def unavailable_command_inspection(
    command: str,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    canonical_command: CanonicalCommand | None = None,
    native_evaluation_failed: bool = False,
    reason_code: str | None = None,
) -> dict[str, object]:
    """Return an explicit unavailable result without contacting a runtime."""

    command_text = command.strip()
    if not command_text:
        raise ValueError("Command text cannot be empty")
    if canonical_command is None:
        preview = None
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
            "recovery": (
                "Re-run the Guard scan or repair the native runtime; the command stays blocked "
                "until evaluation succeeds."
                if native_evaluation_failed
                else "Verify the native runtime is installed and command control is healthy, then retry."
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
        "command_model": preview.to_dict() if preview is not None else None,
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
        "readiness": inspection_readiness(
            "native_evaluation_failed" if native_evaluation_failed else (reason_code or "native_review_unavailable"),
            failed=native_evaluation_failed,
        ),
    }


def _native_hold(native: Mapping[str, object]) -> dict[str, object] | None:
    """Return the native hook decision when it would hold the command."""

    if native.get("decision") != "deny":
        return None
    # Only a reapproval or containment floor is reported here. A plain native
    # review with no extension match keeps the catalog's no_match answer.
    # The decoder reads the same fallback, so a floor named only as
    # ``policy_action`` is reported too.
    native_action = native.get("minimum_action") or native.get("policy_action")
    if native_action not in REVIEW_TIER_ACTIONS:
        return None
    reason_code = native.get("reason_code")
    reason = native.get("reason")
    if not isinstance(reason_code, str) or not reason_code or not isinstance(reason, str) or not reason:
        return None
    return {
        "decision": "deny",
        "minimum_action": "review",
        "native_minimum_action": native_action,
        "reason_code": reason_code,
        "reason": reason,
    }


def _named_native_block(native: Mapping[str, object]) -> dict[str, object] | None:
    """Return the native block when it names a reason other than a failed evaluation."""

    if native.get("decision") != "deny" or native.get("minimum_action") != "block":
        return None
    reason_code = native.get("reason_code")
    reason = native.get("reason")
    if not isinstance(reason_code, str) or not reason_code or not isinstance(reason, str) or not reason:
        return None
    if reason_code in _NATIVE_FAILURE_REASON_CODES:
        return None
    return {"decision": "deny", "minimum_action": "block", "reason_code": reason_code, "reason": reason}


def _native_block_inspection(
    command_text: str, canonical_command: CanonicalCommand, native_block: Mapping[str, object]
) -> dict[str, object]:
    """Report a native block whose reason is known, without reparsing the command.

    Extension matching could not run, but the native runtime still decided:
    ``curl ... | sh`` is blocked as remote code execution. That decision is the
    answer, not an evaluation failure.
    """

    reason_code = str(native_block["reason_code"])
    return {
        "schema_version": COMMAND_EXTENSION_SCHEMA_VERSION,
        "status": "review",
        "command": command_text,
        "classification": {
            "matched": True,
            "explicitly_benign": False,
            "action_class": None,
            "reason": native_block["reason"],
            "normalized_command": canonical_command.normalized_text,
            "wrapper_chain": list(canonical_command.wrapper_chain),
        },
        "risk_classes": [],
        "minimum_action": "block",
        "controlling_rule_id": reason_code,
        "native_decision": dict(native_block),
        "signals": [],
        "extensions": [],
        "rules": [],
        "command_model": canonical_command.to_dict(),
        "trace": [
            {
                "step": "native-command-evidence",
                "result": "not-matched",
                "detail": "Extension rules could not be matched; the native pre-tool decision still applies.",
            },
            {
                "step": "native-hook-decision",
                "result": reason_code,
                "detail": "The native pre-execution decision blocks this command.",
            },
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

    with bound_context_digest_home(guard_home or resolve_guard_home()):
        try:
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
                timeout_seconds=INSPECTION_NATIVE_TIMEOUT_SECONDS,
                timeout_ceiling_seconds=INSPECTION_NATIVE_TIMEOUT_SECONDS,
            )
            if reviewed is None:
                return unavailable_command_inspection(command_text, cwd=workspace, home_dir=home)
            evaluation = reviewed.evaluation
            canonical_command = evaluation.command
            native_extensions = reviewed.payload.get("command_extensions")
            if isinstance(native_extensions, dict) and native_extensions.get("evaluation_error") is not None:
                native_block = _named_native_block(reviewed.payload)
                if native_block is not None:
                    return _native_block_inspection(command_text, canonical_command, native_block)
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
                    # The resident's own floor, before host policy. Inspection
                    # composes only extension coverage, so a containment or
                    # reapproval floor a hook would apply shows here.
                    "step": "native-pre-tool-floor",
                    "result": str(reviewed.payload.get("minimum_action") or "unknown"),
                    "detail": "The native runtime's pre-tool floor; Guard hooks apply it before final policy.",
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
            native_hold = _native_hold(reviewed.payload)
            if native_hold is not None and (
                not evaluation.matched or (evaluation.minimum_action == "allow" and match is None)
            ):
                # No extension rule matched, but the native hook decision would
                # still hold this command. Report that decision, never no_match.
                trace.append(
                    {
                        "step": "native-hook-decision",
                        "result": str(native_hold["reason_code"]),
                        "detail": "The native pre-execution decision holds this command for review.",
                    }
                )
                return {
                    "schema_version": COMMAND_EXTENSION_SCHEMA_VERSION,
                    "status": "review",
                    "command": command_text,
                    "classification": {
                        "matched": True,
                        "explicitly_benign": False,
                        "action_class": None,
                        "reason": native_hold["reason"],
                        "normalized_command": canonical_command.normalized_text,
                        "wrapper_chain": list(canonical_command.wrapper_chain),
                    },
                    "risk_classes": [],
                    "minimum_action": native_hold["minimum_action"],
                    "controlling_rule_id": native_hold["reason_code"],
                    "native_decision": native_hold,
                    "signals": [],
                    "extensions": [],
                    "rules": [],
                    "command_model": canonical_command.to_dict(),
                    "trace": trace,
                    "policy_evaluation": "not_run",
                    "side_effects": "none",
                }
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
                            "No built-in command safety extension matched. Other Guard protections and final policy "
                            "were not evaluated."
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
            wrapper_chain = list(
                dict.fromkeys((*canonical_command.wrapper_chain, *(match.wrapper_chain if match else ())))
            )
            return {
                "schema_version": COMMAND_EXTENSION_SCHEMA_VERSION,
                "status": "review",
                "command": command_text,
                "classification": {
                    "matched": True,
                    "explicitly_benign": benign,
                    "action_class": evaluation.controlling_action_class,
                    "reason": classification_reason,
                    "normalized_command": match.command_text
                    if match is not None
                    else canonical_command.normalized_text,
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

        except (NativeCommandModelError, NativeSensitiveRequestError, NativeToolActionIdentityError):
            return unavailable_command_inspection(command, native_evaluation_failed=True)


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
