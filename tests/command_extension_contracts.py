"""Shared assertions for declarative command-extension security contracts."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request
from tests.native_command_test_support import real_native_command_evaluation

ReviewedCommandCase = tuple[str, str, str]


def enable_local_admin_extension_layer(*extension_ids: str) -> ExtensionControlLayer:
    """Build a local-admin layer that enables the named command extensions."""

    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=tuple(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, extension_id),
                state=ControlState.ENABLED,
            )
            for extension_id in extension_ids
        ),
    )


def assert_reviewed_command_cases(cases: tuple[ReviewedCommandCase, ...], tmp_path: Path) -> None:
    """Prove every destructive command reaches both inspection and runtime review.

    This deliberately evaluates every case before failing, so a single pytest
    node retains the same diagnostic signal as the former repeated test bodies.
    """
    failures: list[str] = []
    for command, action_class, rule_id in cases:
        reviewed = real_native_command_evaluation(command, cwd=tmp_path)
        with patch(
            "codex_plugin_scanner.guard.runtime.command_inspection.review_command_native",
            return_value=reviewed,
        ):
            payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
        classification = payload.get("classification")
        actual_action_class = classification.get("action_class") if isinstance(classification, dict) else None
        raw_rules = payload.get("rules")
        rule_ids: set[str] = set()
        if isinstance(raw_rules, list):
            for rule in raw_rules:
                if isinstance(rule, dict) and isinstance(rule_id_value := rule.get("rule_id"), str):
                    rule_ids.add(rule_id_value)
        runtime_match = extract_sensitive_tool_action_request(
            "Shell",
            {"command": command},
            cwd=tmp_path,
            home_dir=tmp_path,
            canonical_command=reviewed.evaluation.command,
            native_evaluation=reviewed.evaluation,
        )
        actual_runtime_action = runtime_match.action_class if runtime_match is not None else None
        if (
            payload.get("status") != "review"
            or actual_action_class != action_class
            or rule_id not in rule_ids
            or payload.get("controlling_rule_id") != rule_id
            or actual_runtime_action != action_class
        ):
            failures.append(
                f"{command!r}: status={payload.get('status')!r}, "
                f"inspection_action={actual_action_class!r}, "
                f"rules={sorted(rule_ids)!r}, controlling_rule={payload.get('controlling_rule_id')!r}, "
                f"runtime_action={actual_runtime_action!r}; expected "
                f"action={action_class!r}, rule={rule_id!r}"
            )
    assert not failures, "\n".join(failures)


def assert_review_required_cases(cases: tuple[str, ...], tmp_path: Path) -> None:
    """Prove a command remains reviewable without duplicating its rule contract."""
    failures: list[str] = []
    for command in cases:
        reviewed = real_native_command_evaluation(command, cwd=tmp_path)
        with patch(
            "codex_plugin_scanner.guard.runtime.command_inspection.review_command_native",
            return_value=reviewed,
        ):
            payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
        runtime_match = extract_sensitive_tool_action_request(
            "Shell",
            {"command": command},
            cwd=tmp_path,
            home_dir=tmp_path,
            canonical_command=reviewed.evaluation.command,
            native_evaluation=reviewed.evaluation,
        )
        if payload.get("status") != "review" or runtime_match is None:
            failures.append(
                f"{command!r}: status={payload.get('status')!r}, "
                f"runtime_action={runtime_match.action_class if runtime_match is not None else None!r}; expected review"
            )
    assert not failures, "\n".join(failures)


def assert_safe_command_cases(cases: tuple[str, ...], tmp_path: Path) -> None:
    """Prove preview, help, and observer cases remain non-reviewable."""
    failures: list[str] = []
    for command in cases:
        reviewed = real_native_command_evaluation(command, cwd=tmp_path)
        with patch(
            "codex_plugin_scanner.guard.runtime.command_inspection.review_command_native",
            return_value=reviewed,
        ):
            payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
        runtime_match = extract_sensitive_tool_action_request(
            "Shell",
            {"command": command},
            cwd=tmp_path,
            home_dir=tmp_path,
            canonical_command=reviewed.evaluation.command,
            native_evaluation=reviewed.evaluation,
        )
        if payload.get("status") != "no_match" or runtime_match is not None:
            failures.append(
                f"{command!r}: status={payload.get('status')!r}, "
                f"runtime_action={runtime_match.action_class if runtime_match is not None else None!r}; "
                "expected no_match"
            )
    assert not failures, "\n".join(failures)
