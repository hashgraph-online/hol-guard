"""Guard wrapper-mode runtime execution."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from ...version import __version__
from ..action_lattice import is_guard_action, most_restrictive_guard_action
from ..adapters.base import HarnessAdapter, HarnessContext
from ..approval_gate import ApprovalGateError
from ..cli.oauth_client import (
    GuardDpopKeyMaterial,
    resolve_guard_oauth_client_config,
    validate_guard_sync_endpoint,
)
from ..cloud_exceptions import (
    build_cloud_exceptions_from_policy_bundle,
    cloud_exception_to_dict,
    dedupe_cloud_exceptions,
)
from ..config import VALID_RECEIPT_REDACTION_LEVELS, GuardConfig, load_guard_config
from ..edge_events import build_runtime_session_event
from ..mdm.network import managed_urlopen
from ..models import GuardAction, GuardArtifact, HarnessDetection, PolicyDecision
from ..package_firewall_defaults import extract_cloud_user_profile
from ..package_firewall_entitlement import (
    build_oauth_package_firewall_entitlement,
    reconcile_connect_state_with_oauth_entitlement,
)
from ..policy_bundle_decisions import build_policy_bundle_decisions as _materialize_policy_bundle_decisions
from ..policy_bundle_parser import (
    POLICY_BUNDLE_RULE_MATCHER_FAMILIES,
    computed_policy_bundle_hash,
    non_empty_string,
    policy_bundle_acceptance_checkpoint,
    policy_bundle_is_enforceable,
    policy_bundle_is_version_downgrade,
    policy_bundle_rejection_message,
)
from ..policy_bundle_parser import (
    policy_bundle_daemon_version_supported as _daemon_version_supported,
)
from ..policy_bundle_trusted_keys import (
    MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY,
    PolicyBundleVerificationKey,
    policy_bundle_keyring_payload,
    validate_synced_policy_bundle,
)
from ..redaction import redact_sensitive_text
from ..shims import package_shim_cloud_coverage
from ..store import GuardStore
from ..synced_policy import cached_policy_bundle_validation, validated_synced_policy_bundle
from ..types import PromptRequest, RemediationAction
from .actions import GuardActionEnvelope, redacted_workspace_label
from .approval_context import (
    build_runtime_launch_identity,
    parse_approval_context_token,
    resolved_runtime_launch_argv,
    runtime_launch_identity_is_reusable,
)
from .approval_reuse import (
    APPROVAL_REUSE_CLAIM_FAILED,
    APPROVAL_REUSE_LAUNCH_IDENTITY_UNVERIFIED,
)
from .composition_rules import compose_action_from_signals
from .decisions import (
    AUTHORITATIVE_DECISION_INCONSISTENT,
    build_authoritative_decision,
    evaluation_authority_error,
    rebuild_artifact_authority,
)
from .detectors import DetectorContext, DetectorRegistry, DetectorRunResult, register_default_detectors
from .prompt_injection import detect_prompt_injection_requests
from .signals import RiskSignalV2
from .supply_chain_bundle import (
    SupplyChainBundleError,
    load_supply_chain_bundle_response,
    load_supply_chain_verification_keys,
    verify_supply_chain_bundle_response,
)
from .supply_chain_bundle_models import SupplyChainVerificationKey
from .supply_chain_support import ecosystem_support_matrix


def detect_harness(harness: str, context: HarnessContext) -> HarnessDetection:
    from ..consumer import detect_harness as _detect_harness

    return _detect_harness(harness, context)


def evaluate_detection(
    detection: HarnessDetection,
    store: GuardStore,
    config: GuardConfig,
    *,
    default_action: str | None = None,
    persist: bool = True,
    trusted_request_overrides: Mapping[str, str] | None = None,
    trusted_request_override_labels: Mapping[str, str] | None = None,
    pending_approval_claims: list[tuple[Mapping[str, object], str, str]] | None = None,
    claimed_saved_approval_overrides: Mapping[str, str] | None = None,
    retained_saved_approval_overrides: Mapping[str, str] | None = None,
    runtime_detector_context: Mapping[str, object] | None = None,
    runtime_detector_block_reason: str | None = None,
):
    from ..consumer.service import evaluate_detection as _evaluate_detection

    return _evaluate_detection(
        detection,
        store,
        config,
        default_action=default_action,
        persist=persist,
        trusted_request_overrides=trusted_request_overrides,
        trusted_request_override_labels=trusted_request_override_labels,
        pending_approval_claims=pending_approval_claims,
        claimed_saved_approval_overrides=claimed_saved_approval_overrides,
        retained_saved_approval_overrides=retained_saved_approval_overrides,
        runtime_detector_context=runtime_detector_context,
        runtime_detector_block_reason=runtime_detector_block_reason,
    )


def get_adapter(harness: str) -> HarnessAdapter:
    from ..adapters import get_adapter as _get_adapter

    return _get_adapter(harness)


def _computed_policy_bundle_hash(policy_bundle: dict[str, object]) -> str:
    return computed_policy_bundle_hash(policy_bundle)


_APPROVAL_METADATA_KEYS = (
    "approval_center_url",
    "approval_delivery",
    "approval_requests",
    "approval_wait",
    "review_hint",
)

_RUNTIME_DETECTOR_REVIEW_REASON = "runtime_detector_review"
_RUNTIME_DETECTOR_WARN_REASON = "runtime_detector_warn"
_APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM = "approval_reuse_context_changed_after_claim"
# Every prepared launch-environment entry is authority-hashed except this
# explicit execution-boundary credential. Inherited values are removed before
# hashing; only Guard's freshly resolved Hermes credential may be added later.
_HERMES_GUARD_TOKEN_ENV_KEY = "HERMES_GUARD_TOKEN"
_GUARD_RUN_LATE_CREDENTIAL_ENV_KEYS = frozenset({_HERMES_GUARD_TOKEN_ENV_KEY})


def _resolved_exact_request_overrides(evaluation: Mapping[str, object]) -> dict[str, str]:
    """Extract trusted allow results bound to the exact queued context token."""

    wait_result = evaluation.get("approval_wait")
    if not isinstance(wait_result, Mapping) or wait_result.get("resolved") is not True:
        return {}
    raw_items = wait_result.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        return {}
    items = [item for item in raw_items if isinstance(item, Mapping)]
    if len(items) != len(raw_items) or any(
        item.get("status") != "resolved" or item.get("resolution_action") != "allow" for item in items
    ):
        return {}
    overrides: dict[str, str] = {}
    for item in items:
        artifact_id = item.get("artifact_id")
        artifact_hash = item.get("artifact_hash")
        if (
            not isinstance(artifact_id, str)
            or not artifact_id
            or not isinstance(artifact_hash, str)
            or parse_approval_context_token(artifact_hash) is None
        ):
            return {}
        overrides[artifact_id] = artifact_hash
    return overrides


_INTERACTIVE_ALLOW_OVERRIDE_LABELS = frozenset({"allow-once", "allow-artifact", "allow-publisher", "allow-harness"})


def _resolved_interactive_request_overrides(
    evaluation: Mapping[str, object],
) -> tuple[dict[str, str], dict[str, str]]:
    """Extract exact allow intents returned by the trusted terminal resolver."""

    raw_items = evaluation.get("artifacts")
    if not isinstance(raw_items, list):
        return {}, {}
    overrides: dict[str, str] = {}
    labels: dict[str, str] = {}
    for item in raw_items:
        if not isinstance(item, Mapping) or item.get("policy_action") != "allow":
            continue
        user_override = item.get("user_override")
        artifact_id = item.get("artifact_id")
        artifact_hash = item.get("approval_context_hash")
        if (
            not isinstance(user_override, str)
            or user_override not in _INTERACTIVE_ALLOW_OVERRIDE_LABELS
            or not isinstance(artifact_id, str)
            or not artifact_id
            or not isinstance(artifact_hash, str)
            or parse_approval_context_token(artifact_hash) is None
        ):
            continue
        overrides[artifact_id] = artifact_hash
        labels[artifact_id] = user_override
    return overrides, labels


def _runtime_detector_authority(evaluation: Mapping[str, object]) -> tuple[GuardAction | None, str | None]:
    composition = evaluation.get("runtime_detector_composition")
    if not isinstance(composition, Mapping):
        return None, None
    action = composition.get("action")
    reason = composition.get("reason")
    if not is_guard_action(action) or action not in {"allow", "warn", "review", "block"}:
        return None, None
    return action, reason if isinstance(reason, str) and reason else None


def _runtime_detector_context(evaluation: Mapping[str, object]) -> dict[str, object] | None:
    """Return timing-free detector authority suitable for exact context hashing."""

    raw_composition = evaluation.get("runtime_detector_composition")
    composition = (
        {
            "action": raw_composition.get("action"),
            "reason": raw_composition.get("reason"),
            "downgraded": raw_composition.get("downgraded") is True,
            "upgraded": raw_composition.get("upgraded") is True,
        }
        if isinstance(raw_composition, Mapping)
        else {}
    )
    raw_signals = evaluation.get("runtime_detector_signals_v2")
    signals = (
        [dict(signal) for signal in raw_signals if isinstance(signal, Mapping)] if isinstance(raw_signals, list) else []
    )
    telemetry = _normalized_runtime_detector_telemetry(evaluation)
    if not composition and not signals and not telemetry:
        return None
    return {"composition": composition, "signals_v2": signals, "telemetry": telemetry}


def _normalized_runtime_detector_telemetry(evaluation: Mapping[str, object]) -> list[dict[str, object]]:
    """Bind semantic detector outcomes while excluding nondeterministic duration."""

    raw_telemetry = evaluation.get("runtime_detector_telemetry")
    if not isinstance(raw_telemetry, list):
        return []
    telemetry: list[dict[str, object]] = []
    for raw_item in raw_telemetry:
        if not isinstance(raw_item, Mapping):
            continue
        item = {str(key): value for key, value in raw_item.items() if isinstance(key, str) and key != "elapsed_ms"}
        categories = item.get("categories")
        if isinstance(categories, (list, tuple)):
            item["categories"] = sorted({category for category in categories if isinstance(category, str)})
        telemetry.append(item)
    return sorted(
        telemetry,
        key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
    )


def _runtime_detector_nonterminal_evidence(
    action: GuardAction | None,
    reason: str | None,
) -> dict[str, object] | None:
    if action == "warn":
        return {
            "source": "runtime_detector_registry",
            "status": "warning",
            "reason_code": _RUNTIME_DETECTOR_WARN_REASON,
            "reason": reason or "runtime detector signals require a warning",
        }
    if action == "review":
        return {
            "source": "runtime_detector_registry",
            "status": "review-required",
            "reason_code": _RUNTIME_DETECTOR_REVIEW_REASON,
            "reason": reason or "runtime detector signals require review",
        }
    return None


def _config_with_current_authority(
    config: GuardConfig,
    evaluation: Mapping[str, object],
    authority_action: GuardAction,
    *,
    artifact_ids: set[str] | None = None,
) -> GuardConfig:
    """Bind runner-only authority into each artifact's current policy context.

    Runtime detector composition happens outside the consumer service.  A
    synthetic per-artifact override makes that current authority participate
    in approval-context hashing and saved-decision composition before any
    one-shot claim. Existing stronger current actions remain authoritative.
    """

    raw_artifacts = evaluation.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        return config
    artifact_actions = dict(config.artifact_actions or {})
    changed = False
    for item in raw_artifacts:
        if not isinstance(item, Mapping):
            continue
        artifact_id = item.get("artifact_id")
        if not isinstance(artifact_id, str) or not artifact_id:
            continue
        if artifact_ids is not None and artifact_id not in artifact_ids:
            continue
        composition = item.get("policy_composition")
        current_action = composition.get("current_action") if isinstance(composition, Mapping) else None
        if not is_guard_action(current_action):
            current_action = item.get("policy_action")
        composed = most_restrictive_guard_action(current_action, authority_action, unknown_action="block")
        if artifact_actions.get(artifact_id) != composed:
            artifact_actions[artifact_id] = composed
            changed = True
    return replace(config, artifact_actions=artifact_actions) if changed else config


@dataclass(frozen=True, slots=True)
class _GuardRunLaunchPlan:
    """The exact adapter launch vector resolved at an authority boundary."""

    adapter_command: tuple[str, ...]
    execution_command: tuple[str, ...]
    environment: Mapping[str, str]
    environment_sha256: str
    identity: Mapping[str, object]
    launch_cwd: Path
    reusable: bool


def _guard_run_launch_environment(
    adapter: HarnessAdapter,
    context: HarnessContext,
) -> tuple[dict[str, str], Path]:
    environment = os.environ.copy()
    environment["HOME"] = str(context.home_dir)
    if os.name == "nt":
        environment["USERPROFILE"] = str(context.home_dir)
    environment = adapter.prepare_launch_environment(context, environment)
    for credential_key in _GUARD_RUN_LATE_CREDENTIAL_ENV_KEYS:
        environment.pop(credential_key, None)
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in environment.items()):
        raise ValueError("Harness launch environment must contain only string keys and values.")
    launch_cwd = (context.workspace_dir or Path.cwd()).expanduser().resolve(strict=True)
    if not launch_cwd.is_dir():
        raise NotADirectoryError(f"Harness launch cwd is not a directory: {launch_cwd}")
    return dict(environment), launch_cwd


def _guard_run_launch_environment_hash(environment: Mapping[str, str]) -> str:
    """Return a canonical, non-reversible digest of the full prepared environment."""

    material = json.dumps(
        sorted(environment.items()),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(b"hol.guard.guard-run-launch-environment:v1\x00" + material).hexdigest()


def _guard_run_plan_for_command(
    adapter_command: Sequence[str],
    *,
    environment: Mapping[str, str],
    launch_cwd: Path,
) -> _GuardRunLaunchPlan | None:
    normalized_command = tuple(adapter_command)
    if not normalized_command or any(not isinstance(part, str) or not part for part in normalized_command):
        return None
    identity = build_runtime_launch_identity(
        normalized_command[0],
        args=normalized_command[1:],
        structured_command=True,
        direct_executable=True,
        search_path=environment.get("PATH"),
        cwd=launch_cwd,
        launch_env=environment,
    )
    pinned_command = resolved_runtime_launch_argv(identity, args=normalized_command[1:])
    reusable = pinned_command is not None and runtime_launch_identity_is_reusable(identity)
    return _GuardRunLaunchPlan(
        adapter_command=normalized_command,
        execution_command=pinned_command if reusable and pinned_command is not None else normalized_command,
        environment=dict(environment),
        environment_sha256=_guard_run_launch_environment_hash(environment),
        identity=identity,
        launch_cwd=launch_cwd,
        reusable=reusable,
    )


def _guard_run_launch_previews(
    harness: str,
    context: HarnessContext,
    passthrough_args: list[str],
) -> tuple[_GuardRunLaunchPlan, ...]:
    """Content-bind every launch argv without performing adapter setup."""

    adapter = get_adapter(harness)
    raw_commands: Sequence[Sequence[str]] = adapter.preview_launch_commands(context, passthrough_args)
    environment, launch_cwd = _guard_run_launch_environment(adapter, context)
    plans: list[_GuardRunLaunchPlan] = []
    seen_commands: set[tuple[str, ...]] = set()
    for raw_command in raw_commands:
        plan = _guard_run_plan_for_command(
            raw_command,
            environment=environment,
            launch_cwd=launch_cwd,
        )
        if plan is None or plan.adapter_command in seen_commands:
            continue
        seen_commands.add(plan.adapter_command)
        plans.append(plan)
    return tuple(plans)


def _guard_run_executable_prefix(launch_plan: _GuardRunLaunchPlan) -> tuple[str, ...] | None:
    """Recover the canonical prefix prepended while pinning a preview argv."""

    adapter_arguments = launch_plan.adapter_command[1:]
    prefix_length = len(launch_plan.execution_command) - len(adapter_arguments)
    if prefix_length < 1:
        return None
    if adapter_arguments and launch_plan.execution_command[prefix_length:] != adapter_arguments:
        return None
    return launch_plan.execution_command[:prefix_length]


def _guard_run_finalize_authorized_launch_plan(
    harness: str,
    context: HarnessContext,
    passthrough_args: list[str],
    authorized_plans: Sequence[_GuardRunLaunchPlan],
) -> _GuardRunLaunchPlan | None:
    """Run authorized setup without re-resolving previewed launch identity."""

    if not authorized_plans or not all(plan.reusable for plan in authorized_plans):
        return None
    environment = authorized_plans[0].environment
    environment_sha256 = authorized_plans[0].environment_sha256
    if any(
        plan.environment_sha256 != environment_sha256 or dict(plan.environment) != dict(environment)
        for plan in authorized_plans[1:]
    ):
        return None
    resolved_prefixes = [_guard_run_executable_prefix(plan) for plan in authorized_plans]
    if any(prefix is None for prefix in resolved_prefixes):
        return None
    prefixes = tuple(dict.fromkeys(cast(tuple[str, ...], prefix) for prefix in resolved_prefixes))
    adapter = get_adapter(harness)
    actual_command = adapter.launch_command_from_authorized_plan(
        context,
        passthrough_args,
        authorized_executable_prefixes=prefixes,
        launch_environment=dict(environment),
    )
    normalized_actual = tuple(actual_command)
    for plan in authorized_plans:
        if normalized_actual in {plan.adapter_command, plan.execution_command}:
            return plan
    return None


def _guard_run_launch_plan_signature(launch_plan: _GuardRunLaunchPlan) -> str | None:
    if not launch_plan.reusable:
        return None
    return json.dumps(
        {
            "adapter_command": list(launch_plan.adapter_command),
            "environment_sha256": launch_plan.environment_sha256,
            "identity": launch_plan.identity,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _guard_run_authority_signature(
    detection: HarnessDetection,
    evaluation: Mapping[str, object],
    launch_previews: Sequence[_GuardRunLaunchPlan] = (),
) -> tuple[object, ...] | None:
    """Return the exact launch authority checked on both sides of a claim."""

    raw_artifacts = evaluation.get("artifacts")
    if not isinstance(raw_artifacts, list):
        return None
    contexts: dict[str, tuple[str, str]] = {}
    for item in raw_artifacts:
        if not isinstance(item, Mapping):
            return None
        artifact_id = item.get("artifact_id")
        approval_context_hash = item.get("approval_context_hash")
        policy_action = item.get("policy_action")
        if (
            not isinstance(artifact_id, str)
            or not artifact_id
            or artifact_id in contexts
            or not isinstance(approval_context_hash, str)
            or parse_approval_context_token(approval_context_hash) is None
            or not is_guard_action(policy_action)
        ):
            return None
        contexts[artifact_id] = (approval_context_hash, policy_action)
    detector_payload = _runtime_detector_context(evaluation)
    return (
        detection.harness,
        detection.installed,
        detection.command_available,
        tuple(detection.config_paths),
        tuple(sorted(contexts.items())),
        json.dumps(detector_payload, sort_keys=True, separators=(",", ":"), default=str),
        tuple(_guard_run_launch_plan_signature(plan) for plan in launch_previews),
    )


def _receipt_rowid_cursor(store: GuardStore) -> int:
    with store._connect() as connection:
        row = connection.execute("select coalesce(max(rowid), 0) as cursor from runtime_receipts").fetchone()
    return int(row["cursor"]) if row is not None else 0


def _saved_decision_is_retained(decision: Mapping[str, object]) -> bool:
    """Return whether a successful claim leaves the authority row in place."""

    approval_id = decision.get("approval_id")
    if isinstance(approval_id, str) and approval_id:
        artifact_id = decision.get("artifact_id")
        return isinstance(artifact_id, str) and ":package-request:" in artifact_id
    decision_id = decision.get("decision_id")
    if isinstance(decision_id, int) and not isinstance(decision_id, bool):
        return not (decision.get("source") == "approval-gate" and decision.get("expires_at") is not None)
    # The store rejects unknown claim identities. Classifying them as retained
    # is the conservative fallback if an alternate store implementation ever
    # accepts one: absence may not be treated as proof of consumption.
    return True


def _append_authority_evidence_to_receipts(
    store: GuardStore,
    *,
    after_rowid: int,
    evaluation: Mapping[str, object],
    evidence: Mapping[str, object],
    approval_source: str,
    source_actions: frozenset[str],
    replace_existing_source: bool = False,
) -> None:
    """Attach runner-composed authority to receipts emitted by one evaluation."""

    raw_artifacts = evaluation.get("artifacts")
    if not isinstance(raw_artifacts, list):
        return
    artifact_ids = {
        artifact_id
        for item in raw_artifacts
        if isinstance(item, Mapping)
        for artifact_id in (item.get("artifact_id"),)
        if isinstance(artifact_id, str) and artifact_id
    }
    if not artifact_ids:
        return
    reason_code = evidence.get("reason_code")
    # Runtime detector authority is composed in this aggregate, so its receipt
    # evidence is amended in the same local transaction boundary.
    with store._connect() as connection:
        rows = connection.execute(
            """
            select rowid, artifact_id, policy_decision, scanner_evidence_json, approval_source
            from runtime_receipts
            where rowid > ?
            order by rowid asc
            """,
            (after_rowid,),
        ).fetchall()
        for row in rows:
            if str(row["artifact_id"]) not in artifact_ids:
                continue
            try:
                raw_evidence = json.loads(str(row["scanner_evidence_json"]))
            except (TypeError, ValueError):
                raw_evidence = []
            scanner_evidence = list(raw_evidence) if isinstance(raw_evidence, list) else []
            if replace_existing_source:
                scanner_evidence = [
                    item
                    for item in scanner_evidence
                    if not isinstance(item, Mapping) or item.get("source") != evidence.get("source")
                ]
            if not any(
                isinstance(item, Mapping)
                and item.get("source") == evidence.get("source")
                and item.get("reason_code") == reason_code
                for item in scanner_evidence
            ):
                scanner_evidence.append(dict(evidence))
            current_source = row["approval_source"]
            next_source = approval_source if str(row["policy_decision"]) in source_actions else current_source
            connection.execute(
                """
                update runtime_receipts
                set scanner_evidence_json = ?, approval_source = ?
                where rowid = ?
                """,
                (json.dumps(scanner_evidence, sort_keys=True), next_source, int(row["rowid"])),
            )


_DEFAULT_DETECTOR_REGISTRY: tuple[Callable[[], tuple[Any, ...]], DetectorRegistry] | None = None
_DEFAULT_DETECTOR_REGISTRY_LOCK = threading.Lock()


def _get_default_detector_registry() -> DetectorRegistry:
    factory = register_default_detectors
    cached = _DEFAULT_DETECTOR_REGISTRY
    if cached is not None and cached[0] is factory:
        return cached[1]
    with _DEFAULT_DETECTOR_REGISTRY_LOCK:
        cached = _DEFAULT_DETECTOR_REGISTRY
        if cached is None or cached[0] is not factory:
            cached = (factory, DetectorRegistry(factory()))
            globals()["_DEFAULT_DETECTOR_REGISTRY"] = cached
    return cached[1]


@contextmanager
def _guard_sync_auth_lock(store: GuardStore):
    with store.hold_oauth_refresh_lock():
        yield


_INSTALL_TIME_STOP_EVENTS = frozenset(
    {
        "install_time_block",
        "install_time_review",
        "install_time_require-reapproval",
        "install_time_sandbox-required",
    }
)
_PAIN_SIGNAL_EVENTS = frozenset(
    {
        "changed_artifact_caught",
        *_INSTALL_TIME_STOP_EVENTS,
        "install_time_warn",
        "supply_chain_bundle_refresh_requested",
        "approval_gate/remote_policy_sync_blocked",
    }
)
_EXCEPTION_EXPIRY_ALERT_WINDOW_HOURS = 7 * 24
_SECRET_REQUEST_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?<![\w-])\.env(?!\.example\b)(?:\.[\w.-]+)?\b"), "local .env file"),
    (re.compile(r"(?:^|[\s'\"`])~?/.ssh(?:/|\b)"), "SSH material"),
    (re.compile(r"(?:^|[\s'\"`])~?/.aws/(?:credentials|config)\b"), "AWS credentials"),
    (re.compile(r"(?:^|[\s'\"`])~?/.kube/config\b"), "kubeconfig"),
    (re.compile(r"(?:^|[\s'\"`])~?/.docker/config\.json\b"), "Docker credentials"),
    (re.compile(r"(?<![\w-])\.npmrc\b"), "npm registry credentials"),
    (re.compile(r"(?<![\w-])\.pypirc\b"), "Python package credentials"),
    (re.compile(r"(?<![\w-])\.git-credentials\b"), "Git credential store"),
)
_SECRET_ABSOLUTE_HINTS: tuple[tuple[str, str], ...] = (
    ("/.ssh/", "SSH material"),
    ("/.aws/credentials", "AWS credentials"),
    ("/.aws/config", "AWS credentials"),
    ("/.kube/config", "kubeconfig"),
    ("/.docker/config.json", "Docker credentials"),
)
_SECRET_READ_INTENT_PATTERN = re.compile(
    r"\b("
    r"read|open|print|show|dump|cat|head|tail|less|copy|cp|scp|reveal|display|summari[sz]e|inspect|extract|"
    r"use|include|grab|"
    r"contain(?:s)?|contents?\s+of|what(?:'s| is)\s+in"
    r")\b",
    re.IGNORECASE,
)
_NEGATED_SECRET_READ_PATTERN = re.compile(
    r"\b(?:never|do\s+not|don't|dont|must\s+not|should\s+not|cannot|can't)\b[^.!?;\n]{0,80}"
    r"\b(?:read|open|print|show|dump|cat|head|tail|less|copy|cp|scp|reveal|display|summari[sz]e|inspect|extract|"
    r"use|include|grab)\b",
    re.IGNORECASE,
)
_FOLLOWING_SECRET_REFERENCE_PATTERN = re.compile(
    r"\b(?:it|them|these|those|file|files|secret|secrets|contents?|credentials?|token|tokens?|key|keys)\b",
    re.IGNORECASE,
)
_EXFIL_ACTIONS = r"(?:send|post|upload|transfer|paste|sync)"
_EXFIL_ARTIFACTS = r"(?:contents?|data|payload|file|secret|token|key|credential|credentials|config|output)"
_EXFIL_DESTINATIONS = r"(?:to|into|onto|via|through|over|at)"
_EXFIL_NAMED_REMOTE_TARGETS = r"(?:webhook|gist|pastebin|slack|discord|telegram|server|endpoint|url)"
_EXFIL_REMOTE_TARGETS = (
    r"(?:(?:[a-z][a-z0-9+.-]*://)|(?:[a-z0-9-]+\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3}|"
    rf"{_EXFIL_NAMED_REMOTE_TARGETS})"
)
_SAME_SENTENCE_80 = r"[^.!?;\n]{0,80}"
_SAME_SENTENCE_40 = r"[^.!?;\n]{0,40}"
_EXFIL_PROMPT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        rf"\b(?:upload|exfiltrate|transfer|paste|gist|webhook)\b{_SAME_SENTENCE_80}\b"
        rf"{_EXFIL_ARTIFACTS}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{_EXFIL_ACTIONS}\b{_SAME_SENTENCE_80}\b"
        rf"{_EXFIL_ARTIFACTS}\b"
        rf"{_SAME_SENTENCE_40}\b{_EXFIL_DESTINATIONS}\b{_SAME_SENTENCE_40}\b"
        rf"{_EXFIL_REMOTE_TARGETS}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{_EXFIL_ACTIONS}\b{_SAME_SENTENCE_80}\b"
        rf"{_EXFIL_DESTINATIONS}\b{_SAME_SENTENCE_40}\b"
        rf"{_EXFIL_NAMED_REMOTE_TARGETS}\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:send|post|upload|transfer|paste|sync)\b.{0,120}"
        r"(?:"
        r"(?<![\w-])\.env(?:\.[\w.-]+)?\b|"
        r"(?:^|[\s'\"`])~?/.ssh(?:/|\b)|"
        r"(?:^|[\s'\"`])~?/.aws/(?:credentials|config)\b|"
        r"(?:^|[\s'\"`])~?/.kube/config\b|"
        r"(?:^|[\s'\"`])~?/.docker/config\.json\b|"
        r"(?<![\w-])\.npmrc\b|"
        r"(?<![\w-])\.pypirc\b|"
        r"(?<![\w-])\.git-credentials\b|"
        r"/.ssh/|"
        r"/.aws/credentials|"
        r"/.aws/config|"
        r"/.kube/config|"
        r"/.docker/config\.json"
        r")"
        r".{0,80}\b(?:to|into|onto|via|through)\b.{0,80}"
        r"(?:[a-z][a-z0-9+.-]*://|webhook|gist|pastebin|slack|discord|telegram|server|endpoint|url)\b",
        re.IGNORECASE,
    ),
)
_DESTRUCTIVE_PROMPT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:run|execute|use|call|invoke)\b.{0,40}\b(?:rm\s+-rf|rm\s+|del\s+|truncate\s+|chmod\s+|chown\s+|mv\s+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:^|[\s'\"`(])(?:rm\s+-rf|rm\s+\S|del\s+\S|truncate\s+\S|chmod\s+\S|chown\s+\S|mv\s+\S)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:delete|remove|overwrite|truncate)\b.{0,60}\b(?:file|directory|repo|workspace|contents?)\b",
        re.IGNORECASE,
    ),
)
_SUBPROCESS_PROMPT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:run|execute|use|call|invoke|launch|spawn)\b.{0,60}\b"
        r"(?:bash\s+-c|sh\s+-c|zsh\s+-c|powershell|cmd\s+/c|subprocess|exec\(|spawn\()",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:^|[\s'\"`(])(?:bash\s+-c\b|sh\s+-c\b|zsh\s+-c\b|powershell(?:\.exe)?(?:\s|$)|cmd\s+/c(?:\s|$)|subprocess\.(?:run|Popen|call|check_call|check_output)\b|exec\(|spawn\()",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:use|call|invoke)\b.{0,40}\bsubprocess\b",
        re.IGNORECASE,
    ),
)
_GUARD_BYPASS_PROMPT_PATTERN = re.compile(
    r"\b(hol-guard\s+(?:disable|off|uninstall)|disable\s+hol-guard|approval_policy\s*=\s*\"never\"|guard[_-]?bypass)\b",
    re.IGNORECASE,
)
_DOCUMENT_PROMPT_ACTION_PATTERN = re.compile(
    r"\b(?:create|draft|document|generate|outline|plan|update|write)\b",
    re.IGNORECASE,
)
_DOCUMENT_PROMPT_TARGET_PATTERN = re.compile(
    r"\b(?:checklist|docs?|documentation|file|files|guide|markdown|notes?|plan(?:ning)?|prd|prompt|report|runbook|spec|todo)\b",
    re.IGNORECASE,
)
_DOCUMENT_PROMPT_CONTEXT_PATTERN = re.compile(
    r"\b(?:checklist|command|commands|document|documentation|example|examples|regression|test|tests|validate|verify)\b",
    re.IGNORECASE,
)
_DOCUMENT_PROMPT_GUARDRAIL_PATTERN = re.compile(
    r"\b(?:approval|block(?:ed)?|guard|guardrail|policy|protection|require(?:s|d)?\s+approval)\b",
    re.IGNORECASE,
)
_DOCUMENT_PROMPT_STRONG_GUARDRAIL_PATTERN = re.compile(
    r"(?:do\s+not|must\s+not|must\s+stay\s+blocked|must\s+remain\s+blocked|never|"
    r"require(?:s|d)?\s+approval|should\s+stay\s+blocked|should\s+remain\s+blocked|stay\s+blocked)",
    re.IGNORECASE,
)
_PROMPT_SENTENCE_BOUNDARY_PATTERN = re.compile(r"[!?;]|[.](?=\s|$)")
_GUARD_SYNC_USER_AGENT = f"hol-guard/{__version__}"
_SYNC_HTTP_TIMEOUT_SECONDS = 20
_SYNC_HTTP_RETRY_TIMEOUT_SECONDS = 120
_SYNC_RETRYABLE_GATEWAY_STATUS_CODES = frozenset({502, 503, 504, 522, 524})
_SYNC_RETRYABLE_GATEWAY_MAX_ATTEMPTS = 2
_RUNTIME_SYNC_TIMEOUT_SECONDS = 10
_RUNTIME_SYNC_RETRY_TIMEOUT_SECONDS = 90
_RECEIPT_SYNC_BATCH_SIZE = 50
_RECEIPT_SYNC_CURSOR_PAGE_SIZE = 200
_RECEIPT_SYNC_CURSOR_BACKFILL_ROWS = 200
_RECEIPT_COMMAND_DETAIL_BACKFILL_DAYS = 30
_RECEIPT_COMMAND_DETAIL_BACKFILL_LIMIT = 200
_PAIN_SIGNAL_TIMEOUT_SECONDS = 10
_PAIN_SIGNAL_RETRY_TIMEOUT_SECONDS = 90
_GUARD_EVENTS_ENDPOINT_UNAVAILABLE_RETRY_MINUTES = 5  # single 404 shouldn't disable sync for a full day


class GuardSyncNotConfiguredError(RuntimeError):
    """Raised when Guard Cloud sync is requested before the machine is paired."""


class GuardSyncNotAvailableError(RuntimeError):
    """Raised when Guard Cloud sync is blocked by plan limits or temporary outages."""

    retryable: bool

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


class GuardSyncAuthorizationExpiredError(GuardSyncNotConfiguredError):
    """Raised when local OAuth material can no longer mint a runtime access token."""


def _prompt_sentence_start(text: str, index: int) -> int:
    matches = list(_PROMPT_SENTENCE_BOUNDARY_PATTERN.finditer(text, 0, index))
    return matches[-1].end() if matches else 0


def _prompt_sentence_end(text: str, index: int) -> int:
    match = _PROMPT_SENTENCE_BOUNDARY_PATTERN.search(text, index)
    return match.end() if match is not None else len(text)


def _prompt_secret_intent_region(text: str, *, start: int, end: int) -> str:
    current_sentence_start = _prompt_sentence_start(text, start)
    region_start = _prompt_sentence_start(text, max(0, current_sentence_start - 1))
    first_sentence_end = _prompt_sentence_end(text, end)
    second_sentence_end = (
        _prompt_sentence_end(text, first_sentence_end) if first_sentence_end < len(text) else first_sentence_end
    )
    return text[region_start:second_sentence_end]


def _prompt_has_secret_read_intent(prompt_text: str, *, start: int, end: int) -> bool:
    if _prompt_match_is_documented_example(prompt_text, start=start, end=end):
        return False
    sentence = _secret_match_sentence(prompt_text, start=start, end=end)
    sentence_end = _prompt_sentence_end(prompt_text, end)
    sentence_intents = tuple(_SECRET_READ_INTENT_PATTERN.finditer(sentence))
    if sentence_intents:
        if any(not _secret_read_intent_is_negated(sentence, match.start(), match.end()) for match in sentence_intents):
            return True
        return _following_sentence_has_secret_read_intent(prompt_text, sentence_end)
    if _NEGATED_SECRET_READ_PATTERN.search(sentence) is not None:
        return _following_sentence_has_secret_read_intent(prompt_text, sentence_end)
    region = _prompt_secret_intent_region(prompt_text, start=start, end=end)
    for match in _SECRET_READ_INTENT_PATTERN.finditer(region):
        if not _secret_read_intent_is_negated(region, match.start(), match.end()):
            return True
    return False


def _secret_match_sentence(prompt_text: str, *, start: int, end: int) -> str:
    sentence_start = _prompt_sentence_start(prompt_text, start)
    sentence_end = _prompt_sentence_end(prompt_text, end)
    return prompt_text[sentence_start:sentence_end]


def _following_sentence_has_secret_read_intent(prompt_text: str, sentence_end: int) -> bool:
    if sentence_end >= len(prompt_text):
        return False
    next_end = _prompt_sentence_end(prompt_text, sentence_end)
    following = prompt_text[sentence_end:next_end]
    has_positive_intent = any(
        not _secret_read_intent_is_negated(following, match.start(), match.end())
        for match in _SECRET_READ_INTENT_PATTERN.finditer(following)
    )
    if not has_positive_intent:
        return False
    return _FOLLOWING_SECRET_REFERENCE_PATTERN.search(following) is not None


def _secret_read_intent_is_negated(region: str, intent_start: int, intent_end: int) -> bool:
    window_start = max(0, intent_start - 90)
    prefix = region[window_start:intent_start]
    clause_start = window_start
    for boundary in (".", "!", "?", ";", ",", " and ", " but ", " then "):
        boundary_index = prefix.rfind(boundary)
        if boundary_index >= 0:
            clause_start = max(clause_start, window_start + boundary_index + len(boundary))
    scoped_start = clause_start
    scoped_region = region[scoped_start:intent_end]
    return _NEGATED_SECRET_READ_PATTERN.search(scoped_region) is not None


def _prompt_match_is_documented_example(prompt_text: str, *, start: int, end: int) -> bool:
    region = _prompt_secret_intent_region(prompt_text, start=start, end=end)
    if _DOCUMENT_PROMPT_ACTION_PATTERN.search(region) is None:
        return False
    if _DOCUMENT_PROMPT_TARGET_PATTERN.search(region) is None:
        return False
    if _DOCUMENT_PROMPT_GUARDRAIL_PATTERN.search(region) is None:
        return False
    if _DOCUMENT_PROMPT_CONTEXT_PATTERN.search(region) is None and not _prompt_match_is_wrapped_literal(
        prompt_text,
        start=start,
        end=end,
    ):
        return False
    return _DOCUMENT_PROMPT_STRONG_GUARDRAIL_PATTERN.search(region) is not None or _prompt_match_is_wrapped_literal(
        prompt_text,
        start=start,
        end=end,
    )


def _prompt_match_is_wrapped_literal(prompt_text: str, *, start: int, end: int) -> bool:
    if start < len(prompt_text) and prompt_text[start] in {"`", "'", '"'}:
        delimiter = prompt_text[start]
        return _next_non_whitespace_character(prompt_text, end) == delimiter
    delimiter = _previous_non_whitespace_character(prompt_text, start)
    if delimiter not in {"`", "'", '"'}:
        return False
    return _next_non_whitespace_character(prompt_text, end) == delimiter


def _previous_non_whitespace_character(text: str, index: int) -> str | None:
    for position in range(index - 1, -1, -1):
        if not text[position].isspace():
            return text[position]
    return None


def _next_non_whitespace_character(text: str, index: int) -> str | None:
    for position in range(index, len(text)):
        if not text[position].isspace():
            return text[position]
    return None


def _first_match(patterns: tuple[re.Pattern[str], ...], text: str) -> re.Match[str] | None:
    for pattern in patterns:
        match = pattern.search(text)
        if match is not None:
            return match
    return None


def _iter_hint_occurrences(text: str, hint: str) -> list[tuple[int, int]]:
    occurrences: list[tuple[int, int]] = []
    current_pos = 0
    while True:
        start = text.find(hint, current_pos)
        if start == -1:
            return occurrences
        end = start + len(hint)
        occurrences.append((start, end))
        current_pos = start + 1


def _resolve_hermes_guard_access_token(store: GuardStore) -> str | None:
    """Best-effort retrieval of the current Guard OAuth access token for Hermes runtime.

    Returns ``None`` if credentials are not configured or the token cannot be resolved.
    Hermes's ``guard_runtime_policy.py`` defaults to ``fail_open=True`` when no token
    is available, so this is non-fatal.
    """
    try:
        auth_context = _resolve_guard_sync_auth_context(store)
    except Exception:
        return None
    token = auth_context.get("access_token")
    if isinstance(token, str) and token:
        return token
    return None


def guard_run(
    harness: str,
    context: HarnessContext,
    store: GuardStore,
    config: GuardConfig,
    dry_run: bool,
    passthrough_args: list[str],
    default_action: str | None = None,
    interactive_resolver: Callable[[HarnessDetection, dict[str, Any]], dict[str, Any]] | None = None,
    blocked_resolver: Callable[[HarnessDetection, dict[str, Any]], dict[str, Any]] | None = None,
    current_config_provider: Callable[[], GuardConfig] | None = None,
) -> dict[str, Any]:
    """Evaluate local harness state and optionally launch the harness."""

    detection = _detection_with_prompt_artifacts(detect_harness(harness, context), context, passthrough_args)
    launch_plan: _GuardRunLaunchPlan | None = None
    pending_approval_claims: list[tuple[Mapping[str, object], str, str]] = []
    base_evaluation = evaluate_detection(
        detection,
        store,
        config,
        default_action=default_action,
        persist=False,
        pending_approval_claims=pending_approval_claims,
    )

    action_envelope = _guard_run_action_envelope(harness, context, passthrough_args)
    detector_evaluation = _evaluation_with_detector_registry(
        base_evaluation,
        action_envelope,
        context,
        config,
    )
    detector_action, _detector_reason = _runtime_detector_authority(detector_evaluation)
    detector_context = _runtime_detector_context(detector_evaluation)
    authority_config = config
    if detector_action in {"warn", "review"}:
        # The first evaluation is deliberately non-consuming and exists only
        # to recover each artifact's current policy action. Re-evaluate with
        # nonterminal detector authority bound into the current authority
        # before trusting or scheduling any saved approval claim.
        authority_config = _config_with_current_authority(config, base_evaluation, detector_action)
    if detector_context is not None:
        pending_approval_claims = []
        evaluation = evaluate_detection(
            detection,
            store,
            authority_config,
            default_action=default_action,
            persist=False,
            pending_approval_claims=pending_approval_claims,
            runtime_detector_context=detector_context,
        )
        evaluation = _evaluation_with_recorded_detector_result(evaluation, detector_evaluation)
    else:
        evaluation = detector_evaluation
    detector_block_reason = detector_evaluation.get("blocked_by_detector")
    authoritative_detector_block = (
        detector_block_reason if isinstance(detector_block_reason, str) and detector_block_reason else None
    )
    if evaluation["blocked"]:
        evaluation = _evaluation_with_action_envelope(evaluation, action_envelope)

    resolved_evaluation: dict[str, Any] | None = None
    trusted_request_overrides: dict[str, str] = {}
    trusted_request_override_labels: dict[str, str] = {}
    if (
        not dry_run
        and authoritative_detector_block is None
        and interactive_resolver is not None
        and evaluation["blocked"]
    ):
        resolved_evaluation = interactive_resolver(detection, evaluation)
        trusted_request_overrides, trusted_request_override_labels = _resolved_interactive_request_overrides(
            resolved_evaluation
        )
    elif (
        not dry_run and authoritative_detector_block is None and blocked_resolver is not None and evaluation["blocked"]
    ):
        resolved_evaluation = blocked_resolver(detection, evaluation)
        trusted_request_overrides = _resolved_exact_request_overrides(resolved_evaluation)
        trusted_request_override_labels = {artifact_id: "approval-center" for artifact_id in trusted_request_overrides}
    if resolved_evaluation is not None:
        # A terminal prompt or browser wait is an authority boundary even when
        # the user chose the unpersisted ``allow-once`` path. Reload policy
        # before applying that exact request override; post-claim refresh below
        # cannot protect an approval that intentionally created no stored row.
        resolution_config_refresh_failed = False
        if current_config_provider is not None:
            try:
                provided_config = current_config_provider()
            except Exception:
                resolution_config_refresh_failed = True
            else:
                if isinstance(provided_config, GuardConfig):
                    config = provided_config
                else:
                    resolution_config_refresh_failed = True
        if resolution_config_refresh_failed:
            trusted_request_overrides = {}
            trusted_request_override_labels = {}
        detection = _detection_with_prompt_artifacts(detect_harness(harness, context), context, passthrough_args)
        base_evaluation = evaluate_detection(
            detection,
            store,
            config,
            default_action=default_action,
            persist=False,
        )
        detector_evaluation = _evaluation_with_detector_registry(
            base_evaluation,
            action_envelope,
            context,
            config,
        )
        detector_action, _detector_reason = _runtime_detector_authority(detector_evaluation)
        detector_context = _runtime_detector_context(detector_evaluation)
        authority_config = config
        if detector_action in {"warn", "review"}:
            authority_config = _config_with_current_authority(config, base_evaluation, detector_action)
        pending_approval_claims = []
        evaluation = evaluate_detection(
            detection,
            store,
            authority_config,
            default_action=default_action,
            persist=False,
            trusted_request_overrides=trusted_request_overrides,
            trusted_request_override_labels=trusted_request_override_labels,
            pending_approval_claims=pending_approval_claims,
            runtime_detector_context=detector_context,
        )
        evaluation = _evaluation_with_recorded_detector_result(evaluation, detector_evaluation)
        detector_block_reason = detector_evaluation.get("blocked_by_detector")
        authoritative_detector_block = (
            detector_block_reason if isinstance(detector_block_reason, str) and detector_block_reason else None
        )
        if evaluation["blocked"]:
            evaluation = _evaluation_with_action_envelope(evaluation, action_envelope)
        for key in _APPROVAL_METADATA_KEYS:
            if key in resolved_evaluation:
                evaluation[key] = resolved_evaluation[key]
    if evaluation["blocked"] or dry_run:
        receipt_cursor = _receipt_rowid_cursor(store)
        persisted = evaluate_detection(
            detection,
            store,
            authority_config,
            default_action=default_action,
            persist=True,
            trusted_request_overrides=trusted_request_overrides,
            trusted_request_override_labels=trusted_request_override_labels,
            runtime_detector_context=detector_context,
            runtime_detector_block_reason=authoritative_detector_block,
        )
        if persisted["blocked"]:
            persisted = _evaluation_with_action_envelope(persisted, action_envelope)
        persisted = _evaluation_with_recorded_detector_result(persisted, detector_evaluation)
        detector_evidence = _runtime_detector_nonterminal_evidence(detector_action, _detector_reason)
        if detector_evidence is not None and detector_action is not None:
            _append_authority_evidence_to_receipts(
                store,
                after_rowid=receipt_cursor,
                evaluation=persisted,
                evidence=detector_evidence,
                approval_source="runtime-detector",
                source_actions=frozenset({detector_action}),
            )
        if resolved_evaluation is not None:
            for key in _APPROVAL_METADATA_KEYS:
                if key in resolved_evaluation:
                    persisted[key] = resolved_evaluation[key]
        evaluation = persisted
    else:
        decisions_to_claim = [decision for decision, _artifact_id, _artifact_hash in pending_approval_claims]
        preclaim_launch_previews: tuple[_GuardRunLaunchPlan, ...] = ()
        preclaim_signature: tuple[object, ...] | None = None
        preclaim_failure_reason: str | None = None
        if decisions_to_claim:
            try:
                preclaim_launch_previews = _guard_run_launch_previews(harness, context, passthrough_args)
            except Exception:
                preclaim_launch_previews = ()
            if preclaim_launch_previews and all(plan.reusable for plan in preclaim_launch_previews):
                preclaim_signature = _guard_run_authority_signature(
                    detection,
                    evaluation,
                    preclaim_launch_previews,
                )
            if preclaim_signature is None:
                preclaim_failure_reason = APPROVAL_REUSE_LAUNCH_IDENTITY_UNVERIFIED
            else:
                try:
                    claim_succeeded = store.claim_approval_reuse_decisions(decisions_to_claim, now=_now())
                except Exception:
                    claim_succeeded = False
                if not claim_succeeded:
                    preclaim_failure_reason = APPROVAL_REUSE_CLAIM_FAILED
        if decisions_to_claim and preclaim_failure_reason is not None:
            failed_ids = {artifact_id for _decision, artifact_id, _artifact_hash in pending_approval_claims}
            failure_config = _config_with_current_authority(
                authority_config,
                evaluation,
                "require-reapproval",
                artifact_ids=failed_ids,
            )
            if preclaim_failure_reason == APPROVAL_REUSE_LAUNCH_IDENTITY_UNVERIFIED:
                failure_reason = (
                    "saved approval could not be reused because the harness launch identity was not stable "
                    "and path-pinned"
                )
                claim_status = "rejected"
                revalidation_status = "unverified"
            else:
                failure_reason = "saved approval could not be atomically claimed"
                claim_status = "failed"
                revalidation_status = "claim-failed"
            receipt_cursor = _receipt_rowid_cursor(store)
            evaluation = evaluate_detection(
                detection,
                store,
                failure_config,
                default_action=default_action,
                persist=True,
                trusted_request_overrides=trusted_request_overrides,
                trusted_request_override_labels=trusted_request_override_labels,
                runtime_detector_context=detector_context,
                runtime_detector_block_reason=authoritative_detector_block,
            )
            evaluation = _evaluation_with_recorded_detector_result(evaluation, detector_evaluation)
            evaluation = _evaluation_with_preclaim_failure(
                evaluation,
                affected_artifact_ids=failed_ids,
                reason_code=preclaim_failure_reason,
                reason=failure_reason,
                claim_status=claim_status,
                revalidation_status=revalidation_status,
            )
            detector_evidence = _runtime_detector_nonterminal_evidence(detector_action, _detector_reason)
            if detector_evidence is not None and detector_action is not None:
                _append_authority_evidence_to_receipts(
                    store,
                    after_rowid=receipt_cursor,
                    evaluation=evaluation,
                    evidence=detector_evidence,
                    approval_source="runtime-detector",
                    source_actions=frozenset({detector_action}),
                )
            _append_authority_evidence_to_receipts(
                store,
                after_rowid=receipt_cursor,
                evaluation=evaluation,
                evidence={
                    "source": "approval_reuse",
                    "status": "rejected",
                    "reason_code": preclaim_failure_reason,
                    "reason": failure_reason,
                },
                approval_source="approval-reuse",
                source_actions=frozenset({"review", "require-reapproval", "sandbox-required", "block"}),
                replace_existing_source=True,
            )
            if resolved_evaluation is not None:
                for key in _APPROVAL_METADATA_KEYS:
                    if key in resolved_evaluation:
                        evaluation[key] = resolved_evaluation[key]
            evaluation = _evaluation_with_action_envelope(evaluation, action_envelope)
        else:
            consumed_claim_overrides = {
                artifact_id: artifact_hash
                for decision, artifact_id, artifact_hash in pending_approval_claims
                if not _saved_decision_is_retained(decision)
            }
            retained_claim_overrides = {
                artifact_id: artifact_hash
                for decision, artifact_id, artifact_hash in pending_approval_claims
                if _saved_decision_is_retained(decision)
            }
            if decisions_to_claim:
                config_refresh_failed = False
                fresh_config = config
                if current_config_provider is not None:
                    try:
                        provided_config = current_config_provider()
                    except Exception:
                        config_refresh_failed = True
                    else:
                        if isinstance(provided_config, GuardConfig):
                            fresh_config = provided_config
                        else:
                            config_refresh_failed = True
                detection = _detection_with_prompt_artifacts(
                    detect_harness(harness, context),
                    context,
                    passthrough_args,
                )
                fresh_base_evaluation = evaluate_detection(
                    detection,
                    store,
                    fresh_config,
                    default_action=default_action,
                    persist=False,
                )
                fresh_detector_evaluation = _evaluation_with_detector_registry(
                    fresh_base_evaluation,
                    action_envelope,
                    context,
                    fresh_config,
                )
                fresh_detector_action, fresh_detector_reason = _runtime_detector_authority(fresh_detector_evaluation)
                fresh_detector_context = _runtime_detector_context(fresh_detector_evaluation)
                fresh_authority_config = fresh_config
                if fresh_detector_action in {"warn", "review"}:
                    fresh_authority_config = _config_with_current_authority(
                        fresh_config,
                        fresh_base_evaluation,
                        fresh_detector_action,
                    )
                fresh_evaluation = evaluate_detection(
                    detection,
                    store,
                    fresh_authority_config,
                    default_action=default_action,
                    persist=False,
                    trusted_request_overrides=trusted_request_overrides,
                    trusted_request_override_labels=trusted_request_override_labels,
                    claimed_saved_approval_overrides=consumed_claim_overrides,
                    retained_saved_approval_overrides=retained_claim_overrides,
                    runtime_detector_context=fresh_detector_context,
                )
                fresh_evaluation = _evaluation_with_recorded_detector_result(
                    fresh_evaluation,
                    fresh_detector_evaluation,
                )
                try:
                    fresh_launch_previews = _guard_run_launch_previews(harness, context, passthrough_args)
                except Exception:
                    fresh_launch_previews = ()
                postclaim_signature = (
                    _guard_run_authority_signature(detection, fresh_evaluation, fresh_launch_previews)
                    if fresh_launch_previews and all(plan.reusable for plan in fresh_launch_previews)
                    else None
                )
                finalized_launch_plan: _GuardRunLaunchPlan | None = None
                if (
                    not config_refresh_failed
                    and preclaim_signature is not None
                    and postclaim_signature == preclaim_signature
                ):
                    try:
                        finalized_launch_plan = _guard_run_finalize_authorized_launch_plan(
                            harness,
                            context,
                            passthrough_args,
                            fresh_launch_previews,
                        )
                    except Exception:
                        finalized_launch_plan = None
                if (
                    config_refresh_failed
                    or preclaim_signature is None
                    or postclaim_signature != preclaim_signature
                    or finalized_launch_plan is None
                ):
                    stale_config = _config_with_current_authority(
                        fresh_authority_config,
                        fresh_evaluation,
                        "require-reapproval",
                    )
                    fresh_block_reason = fresh_detector_evaluation.get("blocked_by_detector")
                    authoritative_fresh_block = (
                        fresh_block_reason if isinstance(fresh_block_reason, str) and fresh_block_reason else None
                    )
                    receipt_cursor = _receipt_rowid_cursor(store)
                    evaluation = evaluate_detection(
                        detection,
                        store,
                        stale_config,
                        default_action=default_action,
                        persist=True,
                        runtime_detector_context=fresh_detector_context,
                        runtime_detector_block_reason=authoritative_fresh_block,
                    )
                    evaluation = _evaluation_with_recorded_detector_result(
                        evaluation,
                        fresh_detector_evaluation,
                    )
                    evaluation = _evaluation_with_claim_context_failure(
                        evaluation,
                        claimed_artifact_ids={
                            artifact_id for _decision, artifact_id, _artifact_hash in pending_approval_claims
                        },
                    )
                    fresh_detector_evidence = _runtime_detector_nonterminal_evidence(
                        fresh_detector_action,
                        fresh_detector_reason,
                    )
                    if fresh_detector_evidence is not None:
                        _append_authority_evidence_to_receipts(
                            store,
                            after_rowid=receipt_cursor,
                            evaluation=evaluation,
                            evidence=fresh_detector_evidence,
                            approval_source="runtime-detector",
                            source_actions=frozenset(),
                        )
                    _append_authority_evidence_to_receipts(
                        store,
                        after_rowid=receipt_cursor,
                        evaluation=evaluation,
                        evidence={
                            "source": "approval_reuse",
                            "status": "rejected",
                            "reason_code": _APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
                            "reason": "launch authority changed after the saved approval was claimed",
                        },
                        approval_source="approval-reuse",
                        source_actions=frozenset({"review", "require-reapproval", "sandbox-required", "block"}),
                        replace_existing_source=True,
                    )
                    evaluation = _evaluation_with_action_envelope(evaluation, action_envelope)
                else:
                    detector_evaluation = fresh_detector_evaluation
                    detector_action = fresh_detector_action
                    _detector_reason = fresh_detector_reason
                    detector_context = fresh_detector_context
                    authority_config = fresh_authority_config
                    evaluation = fresh_evaluation
                    launch_plan = finalized_launch_plan

            if not evaluation["blocked"]:
                receipt_cursor = _receipt_rowid_cursor(store)
                evaluation = evaluate_detection(
                    detection,
                    store,
                    authority_config,
                    default_action=default_action,
                    persist=True,
                    trusted_request_overrides=trusted_request_overrides,
                    trusted_request_override_labels=trusted_request_override_labels,
                    claimed_saved_approval_overrides=consumed_claim_overrides,
                    retained_saved_approval_overrides=retained_claim_overrides,
                    runtime_detector_context=detector_context,
                )
                if evaluation["blocked"]:
                    evaluation = _evaluation_with_action_envelope(evaluation, action_envelope)
                evaluation = _evaluation_with_recorded_detector_result(evaluation, detector_evaluation)
                detector_evidence = _runtime_detector_nonterminal_evidence(detector_action, _detector_reason)
                if detector_evidence is not None and detector_action is not None:
                    _append_authority_evidence_to_receipts(
                        store,
                        after_rowid=receipt_cursor,
                        evaluation=evaluation,
                        evidence=detector_evidence,
                        approval_source="runtime-detector",
                        source_actions=frozenset({detector_action}),
                    )
                if resolved_evaluation is not None:
                    for key in _APPROVAL_METADATA_KEYS:
                        if key in resolved_evaluation:
                            evaluation[key] = resolved_evaluation[key]
    if "config_paths" not in evaluation:
        evaluation["config_paths"] = list(detection.config_paths) or _guard_run_config_paths(
            detection=detection,
            context=context,
            passthrough_args=passthrough_args,
        )
    authority_error = evaluation_authority_error(
        evaluation,
        require_launch_permitted=not dry_run and evaluation.get("blocked") is False,
    )
    if authority_error is not None:
        evaluation["blocked"] = True
        evaluation["launched"] = False
        evaluation["launch_command"] = []
        evaluation["authority_error"] = AUTHORITATIVE_DECISION_INCONSISTENT
        evaluation["authority_error_message"] = (
            "Guard detected contradictory decision fields and refused to launch. "
            "Re-run the Guard scan or repair the local Guard installation before retrying."
        )
        return evaluation
    if evaluation["blocked"] or dry_run:
        evaluation["launched"] = False
        evaluation["launch_command"] = []
        return evaluation

    if launch_plan is None:
        try:
            launch_previews = _guard_run_launch_previews(harness, context, passthrough_args)
            launch_plan = (
                _guard_run_finalize_authorized_launch_plan(
                    harness,
                    context,
                    passthrough_args,
                    launch_previews,
                )
                if launch_previews and all(plan.reusable for plan in launch_previews)
                else None
            )
        except Exception as error:
            evaluation["launched"] = False
            evaluation["launch_command"] = []
            evaluation["return_code"] = 127
            evaluation["launch_error"] = str(error)
            return evaluation
    if launch_plan is None or not launch_plan.reusable:
        evaluation["launched"] = False
        evaluation["launch_command"] = []
        evaluation["return_code"] = 127
        evaluation["launch_error"] = "Guard could not resolve a stable, path-pinned harness launch command."
        return evaluation
    command = list(launch_plan.execution_command)
    evaluation["launch_command"] = command
    environment = dict(launch_plan.environment)
    if harness == "hermes":
        _hermes_token = _resolve_hermes_guard_access_token(store)
        if _hermes_token is not None:
            # This is the sole intentional environment addition after the
            # prepared environment was authority-hashed. It is a short-lived
            # Guard credential resolved only at the execution boundary, not
            # user-controlled launch configuration. It must NOT leak to
            # user-configured MCP subprocesses; the proxy layer scrubs it
            # before launch (see proxy._build_scrubbed_env).
            environment[_HERMES_GUARD_TOKEN_ENV_KEY] = _hermes_token
    try:
        result = subprocess.run(command, cwd=launch_plan.launch_cwd, check=False, env=environment)
    except FileNotFoundError as error:
        evaluation["launched"] = False
        evaluation["return_code"] = 127
        evaluation["launch_error"] = str(error)
        return evaluation
    evaluation["launched"] = True
    evaluation["return_code"] = result.returncode
    return evaluation


def _guard_run_action_envelope(
    harness: str,
    context: HarnessContext,
    passthrough_args: list[str],
) -> GuardActionEnvelope:
    workspace = context.workspace_dir
    workspace_hash = None
    if workspace is not None:
        workspace_path = workspace.expanduser()
        with suppress(OSError):
            workspace_path = workspace_path.resolve()
        workspace_hash = hashlib.sha256(str(workspace_path).encode("utf-8")).hexdigest()
    return GuardActionEnvelope(
        schema_version=1,
        action_id="",
        harness=harness,
        event_name="HarnessStart",
        action_type="harness_start",
        workspace=redacted_workspace_label(workspace, home_dir=context.home_dir),
        workspace_hash=workspace_hash,
        tool_name=None,
        command=None,
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        script_name=None,
        raw_payload_redacted={"passthrough_arg_count": len(passthrough_args)},
    )


def _evaluation_with_action_envelope(
    evaluation: dict[str, Any],
    action_envelope: GuardActionEnvelope,
) -> dict[str, Any]:
    artifacts = evaluation.get("artifacts")
    if not isinstance(artifacts, list):
        return evaluation
    action_payload = action_envelope.to_dict()
    normalized_artifacts: list[object] = []
    changed = False
    for item in artifacts:
        if isinstance(item, dict) and "action_envelope_json" not in item:
            normalized_artifacts.append({**item, "action_envelope_json": action_payload})
            changed = True
        else:
            normalized_artifacts.append(item)
    if not changed:
        return evaluation
    return {**evaluation, "artifacts": normalized_artifacts}


def _evaluation_with_detector_registry(
    evaluation: dict[str, Any],
    action_envelope: GuardActionEnvelope,
    context: HarnessContext,
    config: GuardConfig,
) -> dict[str, Any]:
    if not config.runtime_detector_registry:
        return evaluation
    detector_context = DetectorContext(
        config=config,
        workspace=context.workspace_dir,
        prior_decisions={},
        threat_intel={},
        redaction_settings={},
    )
    result = _get_default_detector_registry().run(
        action_envelope,
        detector_context,
        timeout_ms=config.runtime_detector_timeout_ms,
        disabled_detector_ids=config.runtime_detector_disabled_ids,
    )
    trace_error = (
        _write_detector_debug_trace(config, action_envelope, result) if config.runtime_detector_debug_trace else None
    )
    if not result.signals and not result.telemetry:
        if trace_error is None:
            return evaluation
        return {**evaluation, "runtime_detector_trace_error": trace_error}
    next_evaluation = {
        **evaluation,
        "runtime_detector_signals_v2": [signal.to_dict() for signal in result.signals],
        "runtime_detector_telemetry": [item.to_dict() for item in result.telemetry],
    }
    # Compose detector authority independently from the base artifact result.
    # Otherwise an already-reviewable artifact makes every detector result
    # appear to be a block and prevents us from identifying a genuine terminal
    # detector block before entering the approval flow.
    composition = compose_action_from_signals(result.signals, "allow")
    next_evaluation["runtime_detector_composition"] = {
        "action": composition.action,
        "reason": composition.reason,
        "downgraded": composition.downgraded,
        "upgraded": composition.upgraded,
    }
    if composition.action == "block":
        next_evaluation["blocked"] = True
        next_evaluation["blocked_by_detector"] = composition.reason
    if trace_error is not None:
        next_evaluation["runtime_detector_trace_error"] = trace_error
    return next_evaluation


_RUNTIME_DETECTOR_RESULT_KEYS = (
    "runtime_detector_signals_v2",
    "runtime_detector_telemetry",
    "runtime_detector_composition",
    "runtime_detector_trace_error",
)


def _artifact_with_authority_updates(
    item: Mapping[str, object],
    *,
    reason: str | None,
    composition_updates: Mapping[str, object],
    additional_signals: Sequence[RiskSignalV2] = (),
) -> dict[str, object]:
    """Apply runner trace changes without allowing serialized aliases to drift."""

    try:
        return rebuild_artifact_authority(
            item,
            reason=reason,
            composition_updates=composition_updates,
            additional_signals=additional_signals,
        )
    except (TypeError, ValueError):
        # Preserve evidence for the final gate. The malformed decision remains
        # intentionally unmodified so evaluation_authority_error fails closed.
        return {**dict(item), "decision_contract_error": AUTHORITATIVE_DECISION_INCONSISTENT}


def _runtime_detector_signals_from_evaluation(
    evaluation: Mapping[str, object],
) -> tuple[RiskSignalV2, ...]:
    raw_signals = evaluation.get("runtime_detector_signals_v2")
    if raw_signals is None:
        return ()
    if not isinstance(raw_signals, list):
        raise ValueError("runtime_detector_signals_v2 must be a list")
    signals: list[RiskSignalV2] = []
    for raw_signal in raw_signals:
        if not isinstance(raw_signal, Mapping):
            raise ValueError("runtime detector signal must be an object")
        signals.append(RiskSignalV2.from_dict(raw_signal))
    return tuple(signals)


def _evaluation_with_recorded_detector_result(
    evaluation: dict[str, Any],
    detector_evaluation: Mapping[str, object],
) -> dict[str, Any]:
    """Carry one pre-launch detector result across persistence without rerunning it."""

    next_evaluation = dict(evaluation)
    for key in _RUNTIME_DETECTOR_RESULT_KEYS:
        if key in detector_evaluation:
            next_evaluation[key] = detector_evaluation[key]
    blocked_by_detector = detector_evaluation.get("blocked_by_detector")
    if isinstance(blocked_by_detector, str) and blocked_by_detector:
        next_evaluation["blocked"] = True
        next_evaluation["blocked_by_detector"] = blocked_by_detector
    detector_action, detector_reason = _runtime_detector_authority(detector_evaluation)
    try:
        detector_signals = _runtime_detector_signals_from_evaluation(detector_evaluation)
    except (TypeError, ValueError):
        next_evaluation["decision_contract_error"] = AUTHORITATIVE_DECISION_INCONSISTENT
        return next_evaluation
    evidence = _runtime_detector_nonterminal_evidence(detector_action, detector_reason)

    raw_artifacts = next_evaluation.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        if detector_action is not None:
            authority_reason = detector_reason or (
                str(evidence["reason"]) if evidence is not None else "runtime detector blocked this launch"
            )
            run_decision = build_authoritative_decision(
                detector_action,
                reason=authority_reason,
                composition_trace={"runtime_detector_action": detector_action},
                signals=detector_signals,
                authority_finalized=detector_action != "review",
                source="runtime-detector-registry",
            )
            next_evaluation["run_authoritative_decision"] = run_decision.to_dict()
            next_evaluation["blocked"] = bool(next_evaluation.get("blocked")) or run_decision.enforcement.blocking
            if run_decision.enforcement.blocking:
                next_evaluation["blocked_by_detector"] = authority_reason
        return next_evaluation
    artifacts: list[object] = []
    for raw_item in raw_artifacts:
        if not isinstance(raw_item, Mapping):
            artifacts.append(raw_item)
            continue
        item = dict(raw_item)
        raw_scanner_evidence = item.get("scanner_evidence")
        scanner_evidence: list[object] = (
            [
                dict(raw_evidence) if isinstance(raw_evidence, Mapping) else raw_evidence
                for raw_evidence in raw_scanner_evidence
            ]
            if isinstance(raw_scanner_evidence, list)
            else []
        )
        if evidence is not None and not any(
            isinstance(raw_evidence, Mapping)
            and raw_evidence.get("source") == evidence["source"]
            and raw_evidence.get("reason_code") == evidence["reason_code"]
            for raw_evidence in scanner_evidence
        ):
            scanner_evidence.append(evidence)
        item["scanner_evidence"] = scanner_evidence
        composition_updates: dict[str, object] = {}
        if detector_action is not None:
            composition_updates = {
                "runtime_detector_action": detector_action,
                "runtime_detector_reason": detector_reason
                or (str(evidence["reason"]) if evidence is not None else "runtime detector authority"),
            }
        item = _artifact_with_authority_updates(
            item,
            reason=(
                str(evidence["reason_code"])
                if evidence is not None and item.get("policy_action") == detector_action
                else None
            ),
            composition_updates=composition_updates,
            additional_signals=detector_signals,
        )
        artifacts.append(item)
    next_evaluation["artifacts"] = artifacts
    return next_evaluation


def _evaluation_with_preclaim_failure(
    evaluation: dict[str, Any],
    *,
    affected_artifact_ids: set[str],
    reason_code: str,
    reason: str,
    claim_status: str,
    revalidation_status: str,
) -> dict[str, Any]:
    """Record a terminal, auditable failure before approval authority is claimed."""

    evidence = {
        "source": "approval_reuse",
        "status": "rejected",
        "reason_code": reason_code,
        "reason": reason,
    }
    artifacts: list[object] = []
    for raw_item in evaluation.get("artifacts", []):
        if not isinstance(raw_item, Mapping) or raw_item.get("artifact_id") not in affected_artifact_ids:
            artifacts.append(raw_item)
            continue
        item = dict(raw_item)
        raw_scanner_evidence = item.get("scanner_evidence")
        scanner_evidence: list[object] = (
            [
                dict(raw_evidence)
                for raw_evidence in raw_scanner_evidence
                if isinstance(raw_evidence, Mapping) and raw_evidence.get("source") != "approval_reuse"
            ]
            if isinstance(raw_scanner_evidence, list)
            else []
        )
        scanner_evidence.append(evidence)
        item["scanner_evidence"] = scanner_evidence
        item["approval_reuse_status"] = "rejected"
        item["approval_reuse_reason_code"] = reason_code
        approval_reuse = item.get("approval_reuse")
        item["approval_reuse"] = {
            **(dict(approval_reuse) if isinstance(approval_reuse, Mapping) else {}),
            "action": item.get("policy_action"),
            "status": "rejected",
            "reason_code": reason_code,
            "should_claim": False,
        }
        item = _artifact_with_authority_updates(
            item,
            reason=reason_code,
            composition_updates={
                "claim_revalidation": revalidation_status,
                "claim_revalidation_reason": reason_code,
            },
        )
        artifacts.append(item)
    return {
        **evaluation,
        "artifacts": artifacts,
        "blocked": True,
        "approval_claim": {
            "status": claim_status,
            "reason_code": reason_code,
            "artifact_ids": sorted(affected_artifact_ids),
        },
    }


def _evaluation_with_claim_context_failure(
    evaluation: dict[str, Any],
    *,
    claimed_artifact_ids: set[str],
) -> dict[str, Any]:
    """Make a changed post-claim authority terminal and auditable."""

    evidence = {
        "source": "approval_reuse",
        "status": "rejected",
        "reason_code": _APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
        "reason": "launch authority changed after the saved approval was claimed",
    }
    artifacts: list[object] = []
    for raw_item in evaluation.get("artifacts", []):
        if not isinstance(raw_item, Mapping):
            artifacts.append(raw_item)
            continue
        item = dict(raw_item)
        raw_scanner_evidence = item.get("scanner_evidence")
        scanner_evidence: list[object] = (
            [
                dict(raw_evidence)
                for raw_evidence in raw_scanner_evidence
                if isinstance(raw_evidence, Mapping) and raw_evidence.get("source") != "approval_reuse"
            ]
            if isinstance(raw_scanner_evidence, list)
            else []
        )
        scanner_evidence.append(evidence)
        item["scanner_evidence"] = scanner_evidence
        item["approval_reuse_status"] = "rejected"
        item["approval_reuse_reason_code"] = _APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM
        approval_reuse = item.get("approval_reuse")
        item["approval_reuse"] = {
            **(dict(approval_reuse) if isinstance(approval_reuse, Mapping) else {}),
            "action": item.get("policy_action"),
            "status": "rejected",
            "reason_code": _APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
            "should_claim": False,
        }
        item = _artifact_with_authority_updates(
            item,
            reason=_APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
            composition_updates={
                "claim_revalidation": "changed",
                "claim_revalidation_reason": _APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
            },
        )
        artifacts.append(item)
    next_evaluation = {
        **evaluation,
        "artifacts": artifacts,
        "blocked": True,
        "approval_claim": {
            "status": "rejected",
            "reason_code": _APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
            "artifact_ids": sorted(claimed_artifact_ids),
        },
    }
    return next_evaluation


def _write_detector_debug_trace(
    config: GuardConfig,
    action_envelope: GuardActionEnvelope,
    result: DetectorRunResult,
) -> dict[str, object] | None:
    created_at = datetime.now(timezone.utc)
    action_payload = action_envelope.to_dict()
    trace_payload = {
        "schema_version": 1,
        "created_at": created_at.isoformat(),
        "action": _redact_detector_debug_payload(action_payload),
        "signals": [signal.to_dict() for signal in result.signals],
        "telemetry": [item.to_dict() for item in result.telemetry],
    }
    trace_dir = config.guard_home / "debug" / "detectors"
    action_digest = hashlib.sha256(
        json.dumps(action_payload, sort_keys=True, default=str).encode("utf-8"),
    ).hexdigest()[:12]
    trace_path = trace_dir / f"{created_at.strftime('%Y%m%dT%H%M%S%fZ')}-{action_digest}.json"
    try:
        trace_dir.mkdir(parents=True, exist_ok=True)
        trace_path.write_text(json.dumps(trace_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as error:
        return {"error_type": type(error).__name__, "message": str(error)}
    return None


def _redact_detector_debug_payload(value: object) -> object:
    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        for key, item in value.items():
            key_text = str(key)
            if "prompt" in key_text.lower():
                redacted[key_text] = "[redacted]"
            else:
                redacted[key_text] = _redact_detector_debug_payload(item)
        return redacted
    if isinstance(value, (tuple, list)):
        return [_redact_detector_debug_payload(item) for item in value]
    return value


def _guard_run_config_paths(
    *,
    detection: HarnessDetection,
    context: HarnessContext,
    passthrough_args: list[str],
) -> list[str]:
    if detection.config_paths:
        return list(detection.config_paths)
    prompt_text = " ".join(value.strip() for value in passthrough_args if value.strip())
    if prompt_text:
        return [str(_prompt_policy_path(detection, context))]
    return []


def _detection_with_prompt_artifacts(
    detection: HarnessDetection,
    context: HarnessContext,
    passthrough_args: list[str],
) -> HarnessDetection:
    prompt_text = " ".join(value.strip() for value in passthrough_args if value.strip())
    prompt_requests = extract_prompt_requests(prompt_text)
    if not prompt_requests:
        return detection
    prompt_artifacts = prompt_requests_to_artifacts(
        detection=detection,
        context=context,
        requests=prompt_requests,
    )
    return HarnessDetection(
        harness=detection.harness,
        installed=detection.installed,
        command_available=detection.command_available,
        config_paths=detection.config_paths,
        artifacts=(*detection.artifacts, *prompt_artifacts),
        warnings=detection.warnings,
    )


def extract_prompt_requests(prompt_text: str) -> list[PromptRequest]:
    """Extract structured prompt intent requests from passthrough arguments."""

    normalized_prompt = " ".join(prompt_text.split())
    lowered = normalized_prompt.lower()
    if not lowered:
        return []
    requests: list[PromptRequest] = []
    seen_secret_labels: set[str] = set()

    def add_secret_request(*, label: str, matched: str) -> None:
        if label in seen_secret_labels:
            return
        seen_secret_labels.add(label)
        summary = (
            "Prompt asks the harness to read a local .env file directly."
            if label == "local .env file"
            else f"Prompt asks for direct access to {label}."
        )
        requests.append(
            PromptRequest(
                request_id=_prompt_request_id("secret_read", matched, lowered),
                request_class="secret_read",
                summary=summary,
                matched_text=matched,
                severity=8,
                confidence=0.9,
                remediation=(
                    RemediationAction(kind="approve_once", label="Approve once", detail="Allow a one-time access."),
                    RemediationAction(
                        kind="rotate_exposed_secret",
                        label="Rotate secret",
                        detail="Rotate credentials if this read is unexpected.",
                    ),
                ),
            )
        )

    for pattern, label in _SECRET_REQUEST_PATTERNS:
        for match in pattern.finditer(normalized_prompt):
            if not _prompt_has_secret_read_intent(normalized_prompt, start=match.start(), end=match.end()):
                continue
            add_secret_request(label=label, matched=match.group(0).strip())
            break
    for hint, label in _SECRET_ABSOLUTE_HINTS:
        for start, end in _iter_hint_occurrences(lowered, hint):
            if _prompt_has_secret_read_intent(normalized_prompt, start=start, end=end):
                add_secret_request(label=label, matched=hint)
                break
    exfil_match = _first_match(_EXFIL_PROMPT_PATTERNS, normalized_prompt)
    if exfil_match is not None:
        matched_text = exfil_match.group(0).strip()
        requests.append(
            PromptRequest(
                request_id=_prompt_request_id("exfil_intent", matched_text, lowered),
                request_class="exfil_intent",
                summary="Prompt includes exfiltration-oriented transfer intent.",
                matched_text=matched_text,
                severity=8,
                confidence=0.84,
                remediation=(
                    RemediationAction(
                        kind="review_network_destination",
                        label="Review destination",
                        detail="Validate destination before data transfer.",
                    ),
                    RemediationAction(kind="defer_and_notify_team", label="Notify team", detail="Escalate for review."),
                ),
            )
        )
    destructive_match = _first_match(_DESTRUCTIVE_PROMPT_PATTERNS, normalized_prompt)
    if destructive_match is not None:
        matched_text = destructive_match.group(0).strip()
        requests.append(
            PromptRequest(
                request_id=_prompt_request_id(
                    "destructive_intent",
                    matched_text,
                    lowered,
                ),
                request_class="destructive_intent",
                summary="Prompt includes destructive filesystem mutation intent.",
                matched_text=matched_text,
                severity=8,
                confidence=0.87,
                remediation=(
                    RemediationAction(
                        kind="approve_once",
                        label="Approve once",
                        detail="Require explicit one-time approval.",
                    ),
                    RemediationAction(
                        kind="open_investigation",
                        label="Open investigation",
                        detail="Track destructive intent.",
                    ),
                ),
            )
        )
    subprocess_match = _first_match(_SUBPROCESS_PROMPT_PATTERNS, normalized_prompt)
    if subprocess_match is not None:
        matched_text = subprocess_match.group(0).strip()
        requests.append(
            PromptRequest(
                request_id=_prompt_request_id(
                    "subprocess_intent",
                    matched_text,
                    lowered,
                ),
                request_class="subprocess_intent",
                summary="Prompt asks for subprocess or shell-wrapper execution.",
                matched_text=matched_text,
                severity=7,
                confidence=0.8,
                remediation=(
                    RemediationAction(
                        kind="approve_once",
                        label="Approve once",
                        detail="Constrain this run to one approval.",
                    ),
                    RemediationAction(
                        kind="run_in_sandbox",
                        label="Run in sandbox",
                        detail="Execute in isolated mode.",
                    ),
                ),
            )
        )
    if _GUARD_BYPASS_PROMPT_PATTERN.search(normalized_prompt):
        requests.append(
            PromptRequest(
                request_id=_prompt_request_id("guard_bypass_intent", "guard-bypass", lowered),
                request_class="guard_bypass_intent",
                summary="Prompt includes Guard bypass or disable intent.",
                matched_text="guard-bypass",
                severity=10,
                confidence=0.93,
                remediation=(
                    RemediationAction(
                        kind="block_and_remove",
                        label="Block",
                        detail="Do not allow bypass behavior.",
                    ),
                    RemediationAction(
                        kind="open_investigation",
                        label="Investigate",
                        detail="Escalate bypass attempt.",
                    ),
                ),
            )
        )
    existing_classes = {request.request_class for request in requests}
    for request in detect_prompt_injection_requests(normalized_prompt):
        if request.request_class in existing_classes:
            continue
        requests.append(request)
        existing_classes.add(request.request_class)
    deduped: dict[str, PromptRequest] = {}
    for request in requests:
        deduped[request.request_id] = request
    return list(deduped.values())


def prompt_requests_to_artifacts(
    *,
    detection: HarnessDetection,
    context: HarnessContext,
    requests: list[PromptRequest],
) -> list[GuardArtifact]:
    """Convert typed prompt requests into pseudo-artifacts for policy evaluation."""

    config_path = str(_prompt_policy_path(detection, context))
    artifacts: list[GuardArtifact] = []
    for request in requests:
        if request.request_class == "secret_read" and ".env" in request.matched_text.lower():
            artifact_id = f"{detection.harness}:session:prompt-env-read:{request.request_id[:24]}"
        else:
            artifact_id = f"{detection.harness}:session:prompt:{request.request_class}:{request.request_id[:24]}"
        artifacts.append(
            GuardArtifact(
                artifact_id=artifact_id,
                name=f"prompt {request.request_class.replace('_', ' ')}",
                harness=detection.harness,
                artifact_type="prompt_request",
                source_scope="session",
                config_path=config_path,
                metadata={
                    "prompt_signals": [request.summary],
                    "prompt_summary": request.summary,
                    "prompt_matched_text": request.matched_text,
                    "prompt_request_class": request.request_class,
                    "prompt_confidence": request.confidence,
                    "prompt_severity": request.severity,
                },
            )
        )
    return artifacts


def should_force_reapproval(prompt_reqs: list[PromptRequest], prior_policy: dict[str, object] | None) -> bool:
    """Return whether current prompt requests exceed prior approved scope."""

    if not prompt_reqs:
        return False
    if prior_policy is None:
        return True
    approved_classes = prior_policy.get("approved_prompt_classes")
    approved = (
        {str(item) for item in approved_classes if isinstance(item, str)}
        if isinstance(approved_classes, list)
        else set()
    )
    return any(request.request_class not in approved or request.severity >= 8 for request in prompt_reqs)


def _prompt_request_id(request_class: str, matched_text: str, normalized_prompt: str) -> str:
    fingerprint = hashlib.sha256(f"{request_class}:{matched_text}:{normalized_prompt}".encode()).hexdigest()
    return fingerprint


def _prompt_policy_path(detection: HarnessDetection, context: HarnessContext) -> Path:
    from ..adapters import get_adapter

    config_candidates = _prompt_config_candidates(detection, context)
    if context.workspace_dir is not None:
        for config_path in config_candidates:
            candidate = Path(config_path)
            if candidate.is_relative_to(context.workspace_dir):
                return candidate
    if config_candidates:
        return Path(config_candidates[0])
    return get_adapter(detection.harness).policy_path(context)


def _prompt_config_candidates(detection: HarnessDetection, context: HarnessContext) -> tuple[str, ...]:
    if detection.harness == "opencode":
        configured_path = os.getenv("OPENCODE_CONFIG")
        configured_candidate = None
        if configured_path:
            candidate = Path(configured_path).expanduser()
            if not candidate.is_absolute():
                if context.workspace_dir is not None:
                    candidate = context.workspace_dir / candidate
                else:
                    candidate = Path.cwd() / candidate
            configured_candidate = str(candidate)
        return tuple(
            config_path
            for config_path in detection.config_paths
            if Path(config_path).name in {"opencode.json", "opencode.jsonc"} or config_path == configured_candidate
        )
    return detection.config_paths


def _policy_bundle_acknowledgement_payload(
    *,
    device_id: str,
    device_name: str,
    policy_bundle: dict[str, object],
    synced_at: str,
) -> dict[str, object]:
    return {
        "appliedAt": synced_at,
        "bundleHash": policy_bundle["bundleHash"],
        "bundleVersion": policy_bundle["bundleVersion"],
        "deviceId": device_id,
        "deviceName": device_name,
        "status": "synced",
    }


def _policy_bundle_is_version_downgrade(
    existing_bundle: dict[str, object] | None,
    next_bundle: dict[str, object],
) -> bool:
    return policy_bundle_is_version_downgrade(existing_bundle, next_bundle)


def _policy_bundle_utc_datetime(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _policy_bundle_numeric_version(value: str) -> tuple[int, ...] | None:
    tokens = tuple(int(token) for token in re.findall(r"\d+", value))
    return tokens or None


def _policy_bundle_acceptance_checkpoint(policy_bundle: Mapping[str, object]) -> dict[str, object]:
    return policy_bundle_acceptance_checkpoint(dict(policy_bundle))


def _policy_bundle_downgrade_reference(
    store: GuardStore,
    existing_bundle: dict[str, object] | None,
) -> dict[str, object] | None:
    checkpoint = store.get_sync_payload("policy_bundle_acceptance_checkpoint")
    workspace_id = store.get_cloud_workspace_id()
    candidates = [
        item
        for item in (
            checkpoint,
            existing_bundle,
            store.get_sync_payload("policy_bundle_last_good"),
        )
        if isinstance(item, dict) and non_empty_string(item.get("issuedAt")) is not None
        if (workspace_id is None or non_empty_string(item.get("workspaceId")) in {None, workspace_id})
    ]
    if not candidates:
        return None

    def _sort_key(item: dict[str, object]) -> tuple[datetime, tuple[int, ...], str, bool]:
        issued_at = non_empty_string(item.get("issuedAt"))
        assert issued_at is not None
        try:
            timestamp = _policy_bundle_utc_datetime(issued_at)
        except ValueError:
            timestamp = datetime.max.replace(tzinfo=timezone.utc)
        version = non_empty_string(item.get("bundleVersion")) or ""
        return (
            timestamp,
            _policy_bundle_numeric_version(version) or (),
            version,
            non_empty_string(item.get("payloadHash")) is not None,
        )

    return max(candidates, key=_sort_key)


def _validate_cached_policy_bundle(
    store: GuardStore,
    policy_bundle: object,
) -> tuple[dict[str, object] | None, str | None]:
    """Revalidate cached policy authority before any rule is made effective."""

    return cached_policy_bundle_validation(store, policy_bundle)


def _policy_bundle_rejection_payload(reason: str | None) -> dict[str, object]:
    resolved_reason = reason or "invalid_policy_bundle"
    payload: dict[str, object] = {"reason": resolved_reason}
    remediation = policy_bundle_rejection_message(resolved_reason)
    if remediation is not None:
        payload["message"] = remediation
    return payload


def _build_policy_bundle_decisions(
    policy_bundle: dict[str, object],
    *,
    device_id: str,
    device_name: str,
) -> list[PolicyDecision]:
    return _materialize_policy_bundle_decisions(
        policy_bundle,
        device_id=device_id,
        device_name=device_name,
    )


def _parse_policy_simulation_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _receipt_policy_bundle_matcher_family(receipt: dict[str, object]) -> str | None:
    artifact_id = non_empty_string(receipt.get("artifact_id"))
    if artifact_id is None:
        return None
    for family in POLICY_BUNDLE_RULE_MATCHER_FAMILIES:
        if f":{family}:" in artifact_id:
            return family
    return None


def simulate_policy_bundle_receipts(
    store: GuardStore,
    policy_bundle: dict[str, object],
    *,
    limit: int = 50,
    now: str | None = None,
) -> dict[str, object]:
    receipts = store.list_receipts(limit=limit)
    device_id, device_name = _guard_device_metadata(store)
    decisions = _build_policy_bundle_decisions(policy_bundle, device_id=device_id, device_name=device_name)
    generated_at = now or _now()
    generated_at_dt = _parse_policy_simulation_timestamp(generated_at)
    latest_receipt_at: str | None = None
    oldest_receipt_at: str | None = None
    latest_dt: datetime | None = None
    oldest_dt: datetime | None = None
    matches: list[dict[str, object]] = []
    summary = {"allow": 0, "block": 0, "review": 0, "ignore": 0, "matched": 0, "unchanged": 0}
    for receipt in receipts:
        receipt_dt = _parse_policy_simulation_timestamp(receipt.get("timestamp"))
        if receipt_dt is not None and (latest_dt is None or receipt_dt > latest_dt):
            latest_dt = receipt_dt
            latest_receipt_at = str(receipt.get("timestamp"))
        if receipt_dt is not None and (oldest_dt is None or receipt_dt < oldest_dt):
            oldest_dt = receipt_dt
            oldest_receipt_at = str(receipt.get("timestamp"))
        family = _receipt_policy_bundle_matcher_family(receipt)
        if family is None:
            continue
        harness = non_empty_string(receipt.get("harness")) or "*"
        matched = next(
            (item for item in decisions if item.artifact_id == f"family:{family}" and item.harness in {harness, "*"}),
            None,
        )
        simulated_action = matched.action if matched is not None else str(receipt.get("policy_decision") or "review")
        if simulated_action not in {"allow", "block", "review", "ignore"}:
            simulated_action = "review"
        summary[simulated_action] = summary.get(simulated_action, 0) + 1
        if matched is not None:
            summary["matched"] += 1
        else:
            summary["unchanged"] += 1
        matches.append(
            {
                "receipt_id": receipt.get("receipt_id"),
                "artifact_id": receipt.get("artifact_id"),
                "harness": harness,
                "matcher_family": family,
                "observed_action": receipt.get("policy_decision"),
                "simulated_action": simulated_action,
                "matched_rule_id": matched.owner if matched is not None else None,
                "policy_version": non_empty_string(policy_bundle.get("bundleHash")),
                "timestamp": receipt.get("timestamp"),
            }
        )
    stale = False
    if generated_at_dt is not None and latest_dt is not None:
        stale = (generated_at_dt - latest_dt).total_seconds() > 24 * 60 * 60
    return {
        "generated_at": generated_at,
        "policy_bundle_version": non_empty_string(policy_bundle.get("bundleVersion")),
        "policy_version": non_empty_string(policy_bundle.get("bundleHash")),
        "receipt_count": len(receipts),
        "summary": summary,
        "matches": matches,
        "event_freshness": {
            "latest_receipt_at": latest_receipt_at,
            "oldest_receipt_at": oldest_receipt_at,
            "sampled_receipts": len(receipts),
            "stale": stale,
        },
    }


def sync_receipts(
    store: GuardStore,
    *,
    persist_sync_summary: bool = True,
    persist_connect_state: bool = True,
    auth_context: dict[str, object] | None = None,
    home_dir: Path | None = None,
    workspace_dir: Path | None = None,
    include_aibom: bool = False,
    force_aibom: bool = False,
) -> dict[str, object]:
    """Push local receipts to the configured sync endpoint."""

    resolved_auth_context = auth_context if auth_context is not None else _resolve_guard_sync_auth_context(store)
    sync_url = _normalized_receipts_sync_url(_validate_guard_sync_url(_auth_context_sync_url(resolved_auth_context)))
    local_guard_online_at = _now()
    redaction_level = _resolve_cloud_receipt_redaction_level(store)
    _ensure_relaxed_receipt_redaction_resync(store, level=redaction_level, synced_at=local_guard_online_at)
    prior_receipt_cursor = _receipt_sync_cursor_rowid(store)
    receipts = _receipt_sync_rows_for_upload(store, cursor_rowid=prior_receipt_cursor)
    cursor_receipt_ids = {item.get("receipt_id") for item in receipts if isinstance(item.get("receipt_id"), str)}
    receipts, command_detail_backfill_marker = _receipt_sync_rows_with_command_detail_backfill(
        store,
        receipts=receipts,
        redaction_level=redaction_level,
        synced_at=local_guard_online_at,
    )
    inventory = store.list_inventory()
    payload: dict[str, object] = {}
    receipts_stored_total = 0
    advisories_payload: list[dict[str, object]] = []
    policy_bundle_payload: dict[str, object] | None = None
    policy_bundle_sync_payload: dict[str, object] | None = None
    policy_bundle_field_provided = False
    policy_bundle_field_malformed = False
    alert_preferences_payload: dict[str, object] | None = None
    remote_decisions: set[PolicyDecision] = set()
    device_id, device_name = _guard_device_metadata(store)
    sync_context = _receipt_sync_context(
        store=store,
        local_guard_online_at=local_guard_online_at,
        device_id=device_id,
        device_name=device_name,
    )
    latest_uploaded_rowid: int | None = None
    auth_refresh_retried = False
    persisted_command_detail_backfill_marker = command_detail_backfill_marker
    for receipt_batch in _iter_receipt_sync_batches(receipts):
        body = json.dumps(
            {
                "receipts": _cloud_sync_receipts_payload(
                    receipt_batch,
                    device_id=device_id,
                    device_name=device_name,
                    redaction_level=redaction_level,
                ),
                "syncContext": sync_context,
            }
        ).encode("utf-8")
        request = _guard_sync_request(
            resolved_auth_context,
            request_url=sync_url,
            method="POST",
            data=body,
            extra_headers=None,
        )
        try:
            payload = _urlopen_json_with_timeout_retry(
                request=request,
                timeout_seconds=_SYNC_HTTP_TIMEOUT_SECONDS,
                retry_timeout_seconds=_SYNC_HTTP_RETRY_TIMEOUT_SECONDS,
            )
        except urllib.error.HTTPError as error:
            if error.code == 401:
                if auth_context is None and not auth_refresh_retried:
                    auth_refresh_retried = True
                    resolved_auth_context = _resolve_guard_sync_auth_context(store, force_refresh=True)
                    sync_url = _normalized_receipts_sync_url(
                        _validate_guard_sync_url(_auth_context_sync_url(resolved_auth_context))
                    )
                    request = _guard_sync_request(
                        resolved_auth_context,
                        request_url=sync_url,
                        method="POST",
                        data=body,
                        extra_headers=None,
                    )
                    try:
                        payload = _urlopen_json_with_timeout_retry(
                            request=request,
                            timeout_seconds=_SYNC_HTTP_TIMEOUT_SECONDS,
                            retry_timeout_seconds=_SYNC_HTTP_RETRY_TIMEOUT_SECONDS,
                        )
                    except urllib.error.HTTPError as retry_error:
                        if retry_error.code == 401:
                            raise GuardSyncAuthorizationExpiredError(
                                _guard_oauth_reauthorization_message()
                            ) from retry_error
                        if retry_error.code == 403:
                            _is_plan, _msg = _check_plan_restriction_403(retry_error)
                            if _is_plan:
                                raise GuardSyncNotAvailableError(_msg) from retry_error
                            raise RuntimeError(_msg) from retry_error
                        raise RuntimeError(_sync_http_error_message(retry_error)) from retry_error
                    except OSError as retry_error:
                        raise RuntimeError(_sync_url_error_message(retry_error)) from retry_error
                else:
                    raise GuardSyncAuthorizationExpiredError(_guard_oauth_reauthorization_message()) from error
            elif error.code == 403:
                _is_plan, _msg = _check_plan_restriction_403(error)
                if _is_plan:
                    raise GuardSyncNotAvailableError(_msg) from error
                raise RuntimeError(_msg) from error
            else:
                raise RuntimeError(_sync_http_error_message(error)) from error
        except OSError as error:
            raise RuntimeError(_sync_url_error_message(error)) from error
        cursor_batch_rowids = _receipt_sync_cursor_rowids_from_batch(
            receipt_batch,
            cursor_receipt_ids=cursor_receipt_ids,
        )
        for rowid in cursor_batch_rowids:
            if isinstance(rowid, int) and (latest_uploaded_rowid is None or rowid > latest_uploaded_rowid):
                latest_uploaded_rowid = rowid
        batch_synced_at = _sync_timestamp(payload)
        updated_command_detail_backfill_marker = _advance_command_detail_backfill_marker(
            persisted_command_detail_backfill_marker,
            receipt_batch=receipt_batch,
            synced_at=batch_synced_at,
        )
        if updated_command_detail_backfill_marker is not None:
            persisted_command_detail_backfill_marker = updated_command_detail_backfill_marker
            store.set_sync_payload(
                _RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER,
                persisted_command_detail_backfill_marker,
                batch_synced_at,
            )
        if latest_uploaded_rowid is not None:
            _persist_receipt_sync_cursor(
                store=store,
                latest_uploaded_rowid=latest_uploaded_rowid,
                synced_at=batch_synced_at,
            )
        batch_receipts_stored = payload.get("receiptsStored")
        if isinstance(batch_receipts_stored, int):
            receipts_stored_total += batch_receipts_stored
        advisories = payload.get("advisories")
        if isinstance(advisories, list):
            advisories_payload.extend(item for item in advisories if isinstance(item, dict))
        if "policyBundle" in payload:
            policy_bundle_field_provided = True
            policy_bundle = payload.get("policyBundle")
            if isinstance(policy_bundle, dict):
                if policy_bundle or policy_bundle_payload is None:
                    policy_bundle_payload = policy_bundle
                    policy_bundle_sync_payload = payload
            else:
                policy_bundle_field_malformed = True
        alert_preferences = payload.get("alertPreferences")
        if isinstance(alert_preferences, dict) and (alert_preferences or alert_preferences_payload is None):
            alert_preferences_payload = alert_preferences
    now = _sync_timestamp(payload)
    aibom_context: dict[str, object] = {}
    if home_dir is not None:
        aibom_context["home_dir"] = str(home_dir)
    if workspace_dir is not None:
        aibom_context["workspace_dir"] = str(workspace_dir)
        workspace_id = store.get_cloud_workspace_id()
        if workspace_id is not None:
            aibom_context["workspace_id"] = workspace_id
    if aibom_context:
        store.set_sync_payload("aibom_inventory_context", aibom_context, now)
    if persisted_command_detail_backfill_marker is not None:
        store.set_sync_payload(
            _RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER,
            persisted_command_detail_backfill_marker,
            now,
        )
    persisted_cursor_rowid = latest_uploaded_rowid if latest_uploaded_rowid is not None else prior_receipt_cursor
    _persist_receipt_sync_cursor(
        store=store,
        latest_uploaded_rowid=persisted_cursor_rowid,
        synced_at=now,
    )
    deduped_advisories = _dedupe_sync_payload_items(advisories_payload)
    # Top-level ``policy``, ``teamPolicyPack``, and ``exceptions`` fields are
    # legacy unsigned siblings. They may be present on an authenticated HTTPS
    # response, but they are not covered by the pinned policy-bundle signature
    # and therefore cannot be persisted or materialized as local authority.
    # Only decisions and exceptions inside a validated signed bundle are used.
    deduped_exceptions: list[dict[str, object]] = []
    advisories_stored = 0
    if deduped_advisories:
        advisories_stored = store.cache_advisories(deduped_advisories, now)
    validated_policy_bundle: dict[str, object] | None = None
    effective_policy_bundle: dict[str, object] | None = None
    activation_last_error: dict[str, object] = {}
    trusted_policy_bundle_keys: tuple[PolicyBundleVerificationKey, ...] = ()
    update_last_good = False
    existing_policy_bundle_payload = store.get_sync_payload("policy_bundle")
    existing_policy_bundle, existing_policy_bundle_error = _validate_cached_policy_bundle(
        store,
        existing_policy_bundle_payload,
    )
    if policy_bundle_field_provided:
        policy_bundle_rejection_reason: str | None
        if policy_bundle_field_malformed or policy_bundle_payload is None:
            policy_bundle_rejection_reason = "invalid_policy_bundle"
        else:
            validated_policy_bundle, policy_bundle_rejection_reason, trusted_policy_bundle_keys = (
                validate_synced_policy_bundle(
                    policy_bundle_payload,
                    stored_keyring=store.get_sync_payload("policy_bundle_keyring"),
                    sync_payload=policy_bundle_sync_payload,
                    supply_chain_keyring=store.get_sync_payload("supply_chain_bundle_keyring"),
                    managed_keyring_provenance=store.get_sync_payload(
                        MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY
                    ),
                    expected_workspace_id=store.get_cloud_workspace_id(),
                )
            )
        if validated_policy_bundle is not None and not _daemon_version_supported(validated_policy_bundle):
            validated_policy_bundle = None
            policy_bundle_rejection_reason = "unsupported_daemon_version"
        if validated_policy_bundle is not None and not policy_bundle_is_enforceable(validated_policy_bundle):
            validated_policy_bundle = None
            policy_bundle_rejection_reason = "inactive_rollout_state"
        if validated_policy_bundle is not None and _policy_bundle_is_version_downgrade(
            _policy_bundle_downgrade_reference(store, existing_policy_bundle),
            validated_policy_bundle,
        ):
            validated_policy_bundle = None
            policy_bundle_rejection_reason = "bundle_version_downgrade"
        if validated_policy_bundle is not None:
            effective_policy_bundle = validated_policy_bundle
            update_last_good = True
        else:
            # A response that claims signed-bundle authority cannot route the
            # same policy through unsigned sibling fields after verification
            # fails. Keep only a still-valid signed current/LKG bundle.
            remote_decisions.clear()
            last_good_bundle_payload = store.get_sync_payload("policy_bundle_last_good")
            last_good_bundle, _last_good_error = _validate_cached_policy_bundle(
                store,
                last_good_bundle_payload,
            )
            # A valid current bundle may be newer than last-good when a prior
            # sync stopped after persisting current but before advancing the
            # checkpoint. Prefer current so a rejected refresh cannot roll
            # policy authority back to an older signed bundle.
            effective_policy_bundle = existing_policy_bundle or last_good_bundle
            activation_last_error = _policy_bundle_rejection_payload(policy_bundle_rejection_reason)
            store.add_event(
                "policy_bundle/rejected",
                activation_last_error,
                now,
            )
    else:
        effective_policy_bundle = existing_policy_bundle
        if effective_policy_bundle is None:
            last_good_bundle_payload = store.get_sync_payload("policy_bundle_last_good")
            effective_policy_bundle, last_good_error = _validate_cached_policy_bundle(
                store,
                last_good_bundle_payload,
            )
            if (
                effective_policy_bundle is None
                and isinstance(existing_policy_bundle_payload, dict)
                and existing_policy_bundle_payload
            ):
                rejection_reason = existing_policy_bundle_error or last_good_error or "invalid_policy_bundle"
                activation_last_error = _policy_bundle_rejection_payload(rejection_reason)
                store.add_event("policy_bundle/rejected", activation_last_error, now)
        if not activation_last_error:
            stored_last_error = store.get_sync_payload("policy_bundle_last_error")
            if isinstance(stored_last_error, dict):
                activation_last_error = stored_last_error
    if alert_preferences_payload is not None:
        store.set_sync_payload("alert_preferences", alert_preferences_payload, now)
    else:
        store.set_sync_payload("alert_preferences", {}, now)
    cloud_exception_items: list[dict[str, object]] = []
    remote_policies_stored = 0
    remote_policy_sync_blocked = False
    if effective_policy_bundle is not None:
        activation_bundle, activation_reason, activation_keys = validate_synced_policy_bundle(
            effective_policy_bundle,
            stored_keyring=store.get_sync_payload("policy_bundle_keyring"),
            supply_chain_keyring=store.get_sync_payload("supply_chain_bundle_keyring"),
            managed_keyring_provenance=store.get_sync_payload(MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY),
            expected_workspace_id=store.get_cloud_workspace_id(),
        )
        if activation_bundle is not None and not policy_bundle_is_enforceable(activation_bundle):
            activation_bundle = None
            activation_reason = "inactive_rollout_state"
        acceptance_checkpoint = store.get_sync_payload("policy_bundle_acceptance_checkpoint")
        if (
            activation_bundle is not None
            and isinstance(acceptance_checkpoint, dict)
            and _policy_bundle_is_version_downgrade(
                acceptance_checkpoint,
                activation_bundle,
            )
        ):
            activation_bundle = None
            activation_reason = "bundle_version_downgrade"
        if activation_bundle is None:
            activation_last_error = _policy_bundle_rejection_payload(activation_reason)
            store.add_event("policy_bundle/rejected", activation_last_error, now)
            effective_policy_bundle = None
        else:
            # Use exactly the payload and anchor set from the final live trust
            # check for materialization and atomic activation. A key rotation
            # or revocation between initial selection and this check therefore
            # cannot leave the previously selected current/LKG bundle active.
            effective_policy_bundle = activation_bundle
            trusted_policy_bundle_keys = activation_keys
    if effective_policy_bundle is None:
        store.clear_policy_bundle_authority(
            now,
            policy_bundle_last_error=activation_last_error,
        )
        _reset_cloud_receipt_redaction_authority(store, synced_at=now)
    else:
        remote_decisions.update(
            _build_policy_bundle_decisions(
                effective_policy_bundle,
                device_id=device_id,
                device_name=device_name,
            )
        )
        policy_bundle_ack = _policy_bundle_acknowledgement_payload(
            device_id=device_id,
            device_name=device_name,
            policy_bundle=effective_policy_bundle,
            synced_at=now,
        )
        cloud_exception_items = _policy_bundle_cloud_exception_items(
            store,
            device_id=device_id,
            sync_exceptions=[],
            policy_bundle=effective_policy_bundle,
            policy_bundle_ack=policy_bundle_ack,
        )
        checkpoint = _policy_bundle_downgrade_reference(store, effective_policy_bundle)
        if validated_policy_bundle is not None:
            checkpoint = _policy_bundle_acceptance_checkpoint(validated_policy_bundle)
        try:
            activated = store.apply_policy_bundle_authority(
                list(remote_decisions),
                now,
                policy_bundle=effective_policy_bundle,
                policy_bundle_keyring=policy_bundle_keyring_payload(
                    trusted_policy_bundle_keys,
                    workspace_id=store.get_cloud_workspace_id(),
                ),
                cloud_exceptions=cloud_exception_items,
                policy_bundle_ack=policy_bundle_ack,
                policy_bundle_checkpoint=(
                    _policy_bundle_acceptance_checkpoint(checkpoint)
                    if isinstance(checkpoint, dict)
                    else _policy_bundle_acceptance_checkpoint(effective_policy_bundle)
                ),
                update_last_good=update_last_good,
                policy_bundle_last_error=activation_last_error,
                remote_write_authorized=True,
            )
            if not activated:
                cloud_exception_items = []
                activation_last_error = _policy_bundle_rejection_payload("bundle_version_downgrade")
                store.add_event(
                    "policy_bundle/rejected",
                    activation_last_error,
                    now,
                )
            else:
                remote_policies_stored = len(remote_decisions)
                cloud_redaction_level = non_empty_string(effective_policy_bundle.get("receiptRedactionLevel"))
                if cloud_redaction_level in VALID_RECEIPT_REDACTION_LEVELS:
                    _persist_cloud_receipt_redaction_level(
                        store,
                        level=cloud_redaction_level,
                        synced_at=now,
                    )
                else:
                    _reset_cloud_receipt_redaction_authority(store, synced_at=now)
        except ApprovalGateError as error:
            cloud_exception_items = []
            remote_policy_sync_blocked = True
            store.add_event(
                "approval_gate/remote_policy_sync_blocked",
                {
                    "error": error.code,
                    "remote_policies_count": len(remote_decisions),
                },
                now,
            )
    _record_synced_alert_events(
        store=store,
        advisories=deduped_advisories,
        alert_preferences=alert_preferences_payload,
        exceptions=deduped_exceptions,
        now=now,
    )
    try:
        pain_signals_uploaded = sync_pain_signals(store, auth_context=resolved_auth_context)
    except RuntimeError as pain_signal_error:
        if "429" in str(pain_signal_error):
            pain_signals_uploaded = 0
        else:
            raise
    value_metrics = _build_value_metrics(store)
    weekly_digest = _build_weekly_firewall_digest(metrics=value_metrics, now=now)
    summary: dict[str, object] = {
        "synced_at": payload.get("syncedAt"),
        "receipts_stored": receipts_stored_total,
        "advisories_stored": advisories_stored,
        "exceptions_stored": len(deduped_exceptions),
        "cloud_exceptions_stored": len(cloud_exception_items),
        "remote_policies_stored": remote_policies_stored,
        "pain_signals_uploaded": pain_signals_uploaded,
        "receipts": len(receipts),
        "receipt_cursor_rowid": persisted_cursor_rowid,
        "receipt_cursor_backfill": bool(
            prior_receipt_cursor is not None
            and len(receipts) > 0
            and not any(
                (receipt_rowid := _int_value(item.get("receipt_rowid"))) is not None
                and receipt_rowid > prior_receipt_cursor
                for item in receipts
            )
        ),
        "inventory": 0,
        "inventory_tracked": len(inventory),
        "value_metrics": value_metrics,
        "weekly_digest": weekly_digest,
    }
    if remote_policy_sync_blocked:
        summary["remote_policy_sync_blocked"] = True
    summary["guard_events_v1"] = sync_guard_events(store, auth_context=resolved_auth_context)
    if include_aibom:
        from ..aibom_cli import sync_aibom_snapshots_if_due

        summary["aibom_inventory"] = sync_aibom_snapshots_if_due(
            store,
            generated_at=now,
            auth_context=resolved_auth_context,
            force=force_aibom,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
        )
    else:
        summary["aibom_inventory"] = {
            "synced": False,
            "skipped": True,
            "reason": "background_deferred",
            "message": (
                "AIBOM inventory refresh is deferred to the Guard daemon background lane; "
                "run hol-guard guard sync --deep to refresh now."
            ),
        }
    if persist_sync_summary:
        store.set_sync_payload("sync_summary", summary, now)
    if persist_connect_state:
        store.record_latest_guard_connect_sync_success(sync_payload=summary, now=now)
    return summary


def _guard_cloud_http_error_details(error: urllib.error.HTTPError) -> tuple[str, bool]:
    try:
        raw_body = error.read().decode("utf-8", errors="replace")
    except OSError:
        raw_body = ""
    retryable = error.code in {429, 503, 524}
    payload: object = None
    if raw_body:
        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError:
            payload = None
    message: str | None = None
    if isinstance(payload, dict):
        message = _read_guard_cloud_error_message(payload)
        guard_error = payload.get("guardError")
        if isinstance(guard_error, dict):
            if guard_error.get("retryable") is True:
                retryable = True
            guard_code = guard_error.get("code")
            unavailable_codes = {"guard_unavailable", "guard_cloud_unavailable"}
            if isinstance(guard_code, str) and guard_code.strip().lower() in unavailable_codes:
                retryable = True
    if message is None:
        normalized_body = raw_body.strip()
        message = normalized_body or f"HTTP Error {error.code}: {error.reason}"
    return message, retryable


def _fetch_supply_chain_bundle_payload(request: urllib.request.Request) -> dict[str, object]:
    try:
        return _urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=_SYNC_HTTP_TIMEOUT_SECONDS,
            retry_timeout_seconds=_SYNC_HTTP_RETRY_TIMEOUT_SECONDS,
        )
    except urllib.error.HTTPError as error:
        if error.code == 403:
            is_plan_restricted, message = _check_plan_restriction_403(error)
            if is_plan_restricted:
                raise GuardSyncNotAvailableError(message) from error
            raise RuntimeError(message) from error
        message, retryable = _guard_cloud_http_error_details(error)
        if retryable:
            raise GuardSyncNotAvailableError(message, retryable=True) from error
        raise RuntimeError(message) from error
    except OSError as error:
        raise RuntimeError(_sync_url_error_message(error)) from error


def _normalized_supply_chain_bundle_index_url(bundle_url: str) -> str:
    parsed = urllib.parse.urlsplit(bundle_url)
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path.rstrip("/") + "/index",
            parsed.query,
            "",
        )
    )


def _supply_chain_partition_bundle_url(bundle_url: str, *, ecosystem: str, partition: int) -> str:
    parsed = urllib.parse.urlsplit(bundle_url)
    query_pairs = [
        (key, value)
        for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if key not in {"ecosystem", "partition"}
    ]
    query_pairs.extend((("ecosystem", ecosystem), ("partition", str(partition))))
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urllib.parse.urlencode(query_pairs),
            "",
        )
    )


def _sync_supply_chain_bundle_incremental(
    *,
    bundle_url: str,
    cached_bundle_version: str | None,
    auth_context: dict[str, object],
    store: GuardStore,
    trusted_keys: tuple[SupplyChainVerificationKey, ...],
    workspace_id: str,
) -> dict[str, object] | None:
    index_request = _guard_sync_request(
        auth_context,
        request_url=_normalized_supply_chain_bundle_index_url(bundle_url),
        method="GET",
        data=None,
        extra_headers={"Accept-Encoding": "identity"},
    )
    try:
        index_payload = _fetch_supply_chain_bundle_payload(index_request)
    except RuntimeError:
        return None
    if not isinstance(index_payload, dict):
        return None
    raw_partitions = index_payload.get("partitions")
    if not isinstance(raw_partitions, list) or len(raw_partitions) == 0:
        return None
    cached_partition_payload = store.get_sync_payload("supply_chain_bundle_partition_cache")
    cached_partitions = {}
    if isinstance(cached_partition_payload, dict):
        raw_cached_partitions = cached_partition_payload.get("partitions")
        if isinstance(raw_cached_partitions, dict):
            cached_partitions = raw_cached_partitions
    next_partition_cache: dict[str, object] = {}
    refreshed_partitions = 0
    for descriptor in raw_partitions:
        if not isinstance(descriptor, dict):
            continue
        ecosystem = descriptor.get("ecosystem")
        partition = descriptor.get("partition")
        payload_hash = descriptor.get("payloadHash")
        if not isinstance(ecosystem, str) or not isinstance(partition, int) or not isinstance(payload_hash, str):
            continue
        cache_key = f"{ecosystem}:{partition}"
        cached_partition = cached_partitions.get(cache_key)
        response = None
        if isinstance(cached_partition, dict) and cached_partition.get("payload_hash") == payload_hash:
            raw_cached_response = cached_partition.get("response")
            if isinstance(raw_cached_response, dict):
                try:
                    response = load_supply_chain_bundle_response(raw_cached_response)
                    verify_supply_chain_bundle_response(
                        response,
                        trusted_keys=trusted_keys or None,
                        cached_bundle_version=cached_bundle_version,
                    )
                except SupplyChainBundleError:
                    response = None
        if response is None:
            try:
                partition_request = _guard_sync_request(
                    auth_context,
                    request_url=_supply_chain_partition_bundle_url(
                        bundle_url, ecosystem=ecosystem, partition=partition
                    ),
                    method="GET",
                    data=None,
                    extra_headers={"Accept-Encoding": "identity"},
                )
                partition_payload = _fetch_supply_chain_bundle_payload(partition_request)
                response = load_supply_chain_bundle_response(partition_payload)
                verify_supply_chain_bundle_response(
                    response,
                    trusted_keys=trusted_keys or None,
                    cached_bundle_version=cached_bundle_version,
                )
            except (RuntimeError, SupplyChainBundleError):
                return None
            refreshed_partitions += 1
        next_partition_cache[cache_key] = {
            "payload_hash": payload_hash,
            "response": response.to_dict(),
        }
    if not next_partition_cache:
        return None
    bundle_version = index_payload.get("bundleVersion")
    resolved_bundle_version = bundle_version if isinstance(bundle_version, str) and bundle_version else None
    if resolved_bundle_version is None:
        resolved_bundle_version = cached_bundle_version or ""
    return {
        "cache_payload": {
            "bundle_version": resolved_bundle_version,
            "partitions": next_partition_cache,
            "workspace_id": workspace_id,
        },
        "refreshed_partitions": refreshed_partitions,
        "total_partitions": len(next_partition_cache),
    }


def sync_supply_chain_bundle(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    """Fetch, verify, and persist the active supply-chain bundle for the cloud workspace."""

    resolved_auth_context = auth_context if auth_context is not None else _resolve_guard_sync_auth_context(store)
    workspace_id = store.get_cloud_workspace_id()
    if workspace_id is None:
        raise GuardSyncNotConfiguredError("Guard Cloud workspace is not connected.")
    bundle_url = _normalized_supply_chain_bundle_url(str(resolved_auth_context["sync_url"]), workspace_id)
    cached_bundle = store.get_cached_supply_chain_bundle(workspace_id)
    cached_bundle_version = None
    if isinstance(cached_bundle, dict):
        cached_payload = cached_bundle.get("bundle")
        if isinstance(cached_payload, dict):
            existing_version = cached_payload.get("bundleVersion")
            if isinstance(existing_version, str) and existing_version:
                cached_bundle_version = existing_version
    trusted_keys = load_supply_chain_verification_keys(store.get_sync_payload("supply_chain_bundle_keyring"))
    try:
        partition_sync: dict[str, object] | None = _sync_supply_chain_bundle_incremental(
            bundle_url=bundle_url,
            cached_bundle_version=cached_bundle_version,
            auth_context=resolved_auth_context,
            store=store,
            trusted_keys=trusted_keys,
            workspace_id=workspace_id,
        )
    except (RuntimeError, SupplyChainBundleError):
        partition_sync = None
    if (
        partition_sync is not None
        and partition_sync.get("refreshed_partitions") == 0
        and isinstance(cached_bundle, dict)
    ):
        try:
            response = load_supply_chain_bundle_response(cached_bundle)
            verify_supply_chain_bundle_response(
                response,
                trusted_keys=trusted_keys or None,
                cached_bundle_version=cached_bundle_version,
            )
        except SupplyChainBundleError:
            try:
                request = _guard_sync_request(
                    resolved_auth_context,
                    request_url=bundle_url,
                    method="GET",
                    data=None,
                    extra_headers={"Accept-Encoding": "identity"},
                )
                payload = _fetch_supply_chain_bundle_payload(request)
                response = load_supply_chain_bundle_response(payload)
                verify_supply_chain_bundle_response(
                    response,
                    trusted_keys=trusted_keys or None,
                    cached_bundle_version=cached_bundle_version,
                )
            except (RuntimeError, SupplyChainBundleError) as error:
                raise RuntimeError(f"Guard supply-chain bundle sync failed: {error}") from error
    else:
        request = _guard_sync_request(
            resolved_auth_context,
            request_url=bundle_url,
            method="GET",
            data=None,
            extra_headers={"Accept-Encoding": "identity"},
        )
        payload = _fetch_supply_chain_bundle_payload(request)
        try:
            response = load_supply_chain_bundle_response(payload)
            verify_supply_chain_bundle_response(
                response,
                trusted_keys=trusted_keys or None,
                cached_bundle_version=cached_bundle_version,
            )
        except SupplyChainBundleError as error:
            raise RuntimeError(f"Guard supply-chain bundle sync failed: {error}") from error
    synced_at = _now()
    store.cache_supply_chain_bundle(workspace_id, response.to_dict(), synced_at)
    store.set_sync_payload(
        "supply_chain_bundle_keyring",
        {
            "workspace_id": workspace_id,
            "keys": [item.to_dict() for item in response.verification_keys],
        },
        synced_at,
    )
    store.set_sync_payload(
        "supply_chain_bundle_entitlement",
        {
            "bundle_version": response.bundle.bundle_version,
            "key_id": response.bundle.key_id,
            "policy_hash": response.bundle.policy_hash,
            "tier": response.bundle.tier,
            "workspace_id": workspace_id,
        },
        synced_at,
    )
    if partition_sync is not None:
        cache_payload = partition_sync.get("cache_payload")
        if isinstance(cache_payload, dict):
            store.set_sync_payload(
                "supply_chain_bundle_partition_cache",
                cache_payload,
                synced_at,
            )
    summary: dict[str, object] = {
        "advisory_count": len(response.bundle.advisories),
        "bundle_version": response.bundle.bundle_version,
        "ecosystem_support": list(ecosystem_support_matrix()),
        "feed_snapshot_hash": response.bundle.feed_snapshot_hash,
        "package_count": len(response.bundle.packages),
        "policy_hash": response.bundle.policy_hash,
        "status": "synced",
        "synced_at": synced_at,
        "tier": response.bundle.tier,
        "workspace_id": workspace_id,
    }
    if partition_sync is not None:
        summary["partition_sync"] = {
            "enabled": True,
            "refreshed": _int_value(partition_sync.get("refreshed_partitions")) or 0,
            "total": _int_value(partition_sync.get("total_partitions")) or 0,
        }
    store.set_sync_payload("supply_chain_bundle_summary", summary, synced_at)
    return summary


def sync_guard_events(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    """Push pending GuardEventV1 envelopes to Guard Cloud."""

    resolved_auth_context = auth_context if auth_context is not None else _resolve_guard_sync_auth_context(store)
    sync_url = _guard_events_sync_url(_validate_guard_sync_url(_auth_context_sync_url(resolved_auth_context)))
    previous_summary = store.get_sync_payload("guard_events_v1_summary")
    total_events = 0
    total_accepted = 0
    synced_at = _now()
    while True:
        pending_events = store.list_guard_events_v1(uploaded=False, limit=200)
        if not pending_events:
            if (
                total_events == 0
                and isinstance(previous_summary, dict)
                and previous_summary.get("sync_reason") == "guard_events_endpoint_unavailable"
                and _guard_events_endpoint_unavailable_recently(store)
            ):
                return previous_summary
            break
        body = json.dumps({"events": [event["payload"] for event in pending_events]}).encode("utf-8")
        request = _guard_sync_request(
            resolved_auth_context,
            request_url=sync_url,
            method="POST",
            data=body,
            extra_headers=None,
        )
        try:
            payload = _urlopen_json_with_timeout_retry(
                request=request,
                timeout_seconds=_SYNC_HTTP_TIMEOUT_SECONDS,
                retry_timeout_seconds=_SYNC_HTTP_RETRY_TIMEOUT_SECONDS,
            )
        except urllib.error.HTTPError as error:
            if error.code == 404:
                pending_count = len(pending_events)
                summary: dict[str, object] = {
                    "synced_at": synced_at,
                    "events": total_events,
                    "accepted": total_accepted,
                    "skipped": 0,
                    "sync_skipped": True,
                    "sync_reason": "guard_events_endpoint_unavailable",
                    "pending_count": pending_count,
                }
                store.set_sync_payload("guard_events_v1_summary", summary, synced_at)
                return summary
            if error.code == 429:
                retry_after_seconds = _parse_retry_after_header(error)
                summary: dict[str, object] = {
                    "synced_at": synced_at,
                    "events": total_events,
                    "accepted": total_accepted,
                    "skipped": 0,
                    "sync_skipped": True,
                    "sync_reason": "guard_events_rate_limited",
                    "pending_count": len(pending_events),
                    "retry_after_seconds": retry_after_seconds,
                }
                store.set_sync_payload("guard_events_v1_summary", summary, synced_at)
                return summary
            if error.code == 403:
                is_plan, message = _check_plan_restriction_403(error)
                if is_plan:
                    raise GuardSyncNotAvailableError(message) from error
                _record_guard_events_sync_failure(
                    store,
                    total_events=total_events,
                    total_accepted=total_accepted,
                    pending_count=len(pending_events),
                    error_type=type(error).__name__,
                    message=message,
                )
                raise RuntimeError(message) from error
            message = _sync_http_error_message(error)
            _record_guard_events_sync_failure(
                store,
                total_events=total_events,
                total_accepted=total_accepted,
                pending_count=len(pending_events),
                error_type=type(error).__name__,
                message=message,
            )
            raise RuntimeError(_redact_sync_text(message)) from error
        except OSError as error:
            message = _sync_url_error_message(error)
            _record_guard_events_sync_failure(
                store,
                total_events=total_events,
                total_accepted=total_accepted,
                pending_count=len(pending_events),
                error_type=type(error).__name__,
                message=message,
            )
            raise RuntimeError(_redact_sync_text(message)) from error
        completed_ids = _completed_guard_event_ids(payload)
        synced_at = _sync_timestamp(payload)
        uploaded = store.mark_guard_events_v1_uploaded(completed_ids, synced_at)
        total_events += len(pending_events)
        total_accepted += uploaded
        if uploaded == 0 or len(pending_events) < 200:
            break
    summary: dict[str, object] = {"synced_at": synced_at, "events": total_events, "accepted": total_accepted}
    store.set_sync_payload("guard_events_v1_summary", summary, synced_at)
    return summary


def _parse_retry_after_header(error: urllib.error.HTTPError) -> int:
    """Parse the Retry-After header from a 429 response. Returns seconds to wait."""
    retry_after = error.headers.get("Retry-After") if error.headers else None
    if not retry_after:
        return 60  # Default: 60 seconds
    try:
        return max(1, int(retry_after))
    except ValueError:
        pass
    try:
        retry_date = datetime.fromisoformat(retry_after.replace("Z", "+00:00"))
        delta = (retry_date - datetime.now(timezone.utc)).total_seconds()
        return max(1, int(delta))
    except (ValueError, TypeError):
        return 60


def _retryable_gateway_http_error(error: urllib.error.HTTPError) -> bool:
    return error.code in _SYNC_RETRYABLE_GATEWAY_STATUS_CODES


def _retry_after_sleep_seconds(error: urllib.error.HTTPError, retry_timeout_seconds: int) -> int:
    return min(_parse_retry_after_header(error), retry_timeout_seconds)


def _request_for_gateway_retry(request: urllib.request.Request) -> urllib.request.Request:
    return _refresh_guard_sync_request(request) or request


def _record_guard_events_sync_failure(
    store: GuardStore,
    *,
    total_events: int,
    total_accepted: int,
    pending_count: int,
    error_type: str,
    message: str,
) -> None:
    recorded_at = _now()
    next_retry_after = (datetime.now(timezone.utc) + timedelta(seconds=_SYNC_HTTP_RETRY_TIMEOUT_SECONDS)).isoformat()
    summary: dict[str, object] = {
        "synced_at": None,
        "status": "failed",
        "events": total_events,
        "accepted": total_accepted,
        "pending_events": pending_count,
        "error_type": error_type,
        "message": _redact_sync_text(message),
        "retry_after_seconds": _SYNC_HTTP_RETRY_TIMEOUT_SECONDS,
        "next_retry_after": next_retry_after,
    }
    store.set_sync_payload("guard_events_v1_summary", summary, recorded_at)


def _guard_events_endpoint_unavailable_recently(store: GuardStore) -> bool:
    summary = store.get_sync_payload("guard_events_v1_summary")
    if not isinstance(summary, dict):
        return False
    if summary.get("sync_reason") not in ("guard_events_endpoint_unavailable", "guard_events_rate_limited"):
        return False
    synced_at = summary.get("synced_at")
    if not isinstance(synced_at, str):
        return True
    parsed = _parse_iso_timestamp(synced_at)
    if parsed is None:
        return True
    return datetime.now(timezone.utc) - parsed < timedelta(minutes=_GUARD_EVENTS_ENDPOINT_UNAVAILABLE_RETRY_MINUTES)


def sync_runtime_session(
    store: GuardStore,
    *,
    session: dict[str, object],
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    """Publish the active Guard runtime session so the dashboard can show the machine immediately."""

    resolved_auth_context = auth_context or _resolve_guard_sync_auth_context(store)
    sync_url = _normalized_runtime_sessions_sync_url(
        _validate_guard_sync_url(_auth_context_sync_url(resolved_auth_context))
    )
    session_payload = _cloud_runtime_session_payload(store, session)
    body = json.dumps({"session": session_payload}).encode("utf-8")
    request = _guard_sync_request(
        resolved_auth_context,
        request_url=sync_url,
        method="POST",
        data=body,
        extra_headers=None,
    )
    try:
        payload = _urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=_RUNTIME_SYNC_TIMEOUT_SECONDS,
            retry_timeout_seconds=_RUNTIME_SYNC_RETRY_TIMEOUT_SECONDS,
        )
    except urllib.error.HTTPError as error:
        if error.code == 404:
            recorded_at = _now()
            summary = {
                "synced_at": None,
                "runtime_session_synced_at": None,
                "runtime_session_id": session_payload["sessionId"],
                "runtime_sessions_visible": 0,
                "runtime_session_sync_skipped": True,
                "runtime_session_sync_reason": "runtime_session_endpoint_unavailable",
                "local_guard_online_at": recorded_at,
                "runtime_harness": session_payload["harness"],
                "runtime_surface": session_payload["surface"],
                "runtime_workspace": session_payload["workspace"],
                "runtime_device_id": session_payload["deviceId"],
            }
            store.set_sync_payload("runtime_session_summary", summary, recorded_at)
            return summary
        if error.code == 429:
            retry_after_seconds = _parse_retry_after_header(error)
            recorded_at = _now()
            summary = {
                "synced_at": None,
                "runtime_session_synced_at": None,
                "runtime_session_id": session_payload["sessionId"],
                "runtime_sessions_visible": 0,
                "runtime_session_sync_skipped": True,
                "runtime_session_sync_reason": "runtime_session_rate_limited",
                "local_guard_online_at": recorded_at,
                "runtime_harness": session_payload["harness"],
                "runtime_surface": session_payload["surface"],
                "runtime_workspace": session_payload["workspace"],
                "runtime_device_id": session_payload["deviceId"],
                "retry_after_seconds": retry_after_seconds,
            }
            store.set_sync_payload("runtime_session_summary", summary, recorded_at)
            return summary
        raise RuntimeError(_sync_http_error_message(error)) from error
    except OSError as error:
        raise RuntimeError(_sync_url_error_message(error)) from error
    if not isinstance(payload, dict):
        raise RuntimeError("Invalid sync response")
    synced_at = _sync_timestamp(payload)
    synced_items = payload.get("items")
    summary: dict[str, object] = {
        "synced_at": synced_at,
        "runtime_session_synced_at": synced_at,
        "runtime_session_id": session_payload["sessionId"],
        "runtime_sessions_visible": len(synced_items) if isinstance(synced_items, list) else 0,
        "local_guard_online_at": synced_at,
        "runtime_harness": session_payload["harness"],
        "runtime_surface": session_payload["surface"],
        "runtime_workspace": session_payload["workspace"],
        "runtime_device_id": session_payload["deviceId"],
    }
    store.set_sync_payload("runtime_session_summary", summary, synced_at)
    workspace_id = store.get_cloud_workspace_id()
    device_id = store.get_or_create_installation_id()
    if not _guard_events_endpoint_unavailable_recently(store):
        store.add_guard_event_v1(
            build_runtime_session_event(
                session_id=str(session_payload["sessionId"]),
                occurred_at=synced_at,
                payload=session_payload,
                workspace_id=workspace_id,
                device_id=device_id,
            )
        )
    return summary


def _local_guard_runtime_session() -> dict[str, object]:
    return {
        "harness": "hol-guard",
        "surface": "cli",
        "status": "active",
        "client_name": "hol-guard",
        "client_title": "HOL Guard CLI",
        "client_version": __version__,
        "workspace": "local-machine",
        "capabilities": ["approval-center", "guard-cloud-sync", "local-daemon"],
    }


def sync_local_guard_cloud_proof(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
    now: str | None = None,
    home_dir: Path | None = None,
    workspace_dir: Path | None = None,
    include_aibom: bool = False,
) -> dict[str, object]:
    """Publish the local Guard runtime session before syncing receipts."""
    resolved_now = now or _now()
    with store.hold_cloud_sync_lock():
        reconcile_connect_state_with_oauth_entitlement(store, now=resolved_now)
        resolved_auth_context = auth_context if auth_context is not None else _resolve_guard_sync_auth_context(store)
        runtime_summary = sync_runtime_session(
            store,
            session=_local_guard_runtime_session(),
            auth_context=resolved_auth_context,
        )
        receipts_summary = sync_receipts(
            store,
            persist_sync_summary=False,
            persist_connect_state=False,
            auth_context=resolved_auth_context,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            include_aibom=include_aibom,
        )
        summary = dict(receipts_summary)
        summary.update(
            {
                "runtime_session_id": runtime_summary.get("runtime_session_id"),
                "runtime_session_synced_at": runtime_summary.get("runtime_session_synced_at"),
                "runtime_sessions_visible": runtime_summary.get("runtime_sessions_visible"),
                "local_guard_online_at": runtime_summary.get("local_guard_online_at")
                or receipts_summary.get("local_guard_online_at"),
                "runtime_harness": runtime_summary.get("runtime_harness"),
                "runtime_surface": runtime_summary.get("runtime_surface"),
                "runtime_workspace": runtime_summary.get("runtime_workspace"),
                "runtime_device_id": runtime_summary.get("runtime_device_id"),
                "runtime": runtime_summary,
                "receipts": dict(receipts_summary),
            }
        )
        recorded_at = str(summary.get("synced_at") or summary.get("runtime_session_synced_at") or _now())
        store.set_sync_payload("sync_summary", summary, recorded_at)
        store.record_latest_guard_connect_sync_success(sync_payload=summary, now=recorded_at)
        return summary


def sync_pain_signals(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
) -> int:
    try:
        resolved_auth_context = auth_context or _resolve_guard_sync_auth_context(store)
    except GuardSyncAuthorizationExpiredError:
        raise
    except GuardSyncNotConfiguredError:
        return 0
    normalized_sync_url = _normalized_receipts_sync_url(
        _validate_guard_sync_url(_auth_context_sync_url(resolved_auth_context))
    )
    cursor_payload = store.get_sync_payload("pain_signal_cursor")
    last_event_id = _last_uploaded_event_id(cursor_payload)
    uploaded_count = 0
    current_event_id = last_event_id
    warn_occurrences: dict[tuple[str, str], int] = {}
    while True:
        candidates = store.list_events_after(
            current_event_id,
            limit=500,
            event_names=tuple(sorted(_PAIN_SIGNAL_EVENTS)),
        )
        if not candidates:
            break
        last_processed_event_id = _int_value(candidates[-1].get("event_id")) or current_event_id
        signal_items: list[dict[str, object]] = []
        for item in candidates:
            event_name = _optional_string(item.get("event_name"))
            payload = item.get("payload")
            if event_name == "install_time_warn" and isinstance(payload, dict):
                warn_key = _warning_occurrence_key(payload)
                if warn_key is not None:
                    warn_occurrences[warn_key] = warn_occurrences.get(warn_key, 0) + 1
            pain_signal = _pain_signal_item(item, warn_occurrences=warn_occurrences)
            if pain_signal is not None:
                signal_items.append(pain_signal)
        if signal_items:
            request = _guard_sync_request(
                resolved_auth_context,
                request_url=_pain_signal_sync_url(normalized_sync_url),
                method="POST",
                data=json.dumps({"items": signal_items}).encode("utf-8"),
                extra_headers=None,
            )
            try:
                _urlopen_with_timeout_retry(
                    request=request,
                    timeout_seconds=_PAIN_SIGNAL_TIMEOUT_SECONDS,
                    retry_timeout_seconds=_PAIN_SIGNAL_RETRY_TIMEOUT_SECONDS,
                )
            except urllib.error.HTTPError as error:
                if error.code == 404:
                    return uploaded_count
                if error.code == 429:
                    return uploaded_count
                raise RuntimeError(_sync_http_error_message(error)) from error
            except OSError as error:
                raise RuntimeError(_sync_url_error_message(error)) from error
            uploaded_count += len(signal_items)
        current_event_id = last_processed_event_id
        store.set_sync_payload(
            "pain_signal_cursor",
            {"event_id": current_event_id},
            _now(),
        )
        if len(candidates) < 500:
            break
    return uploaded_count


def _persist_cloud_exceptions(
    store: GuardStore,
    *,
    device_id: str | None = None,
    sync_exceptions: list[dict[str, object]] | None = None,
    policy_bundle: dict[str, object] | None = None,
    now: str,
) -> list[dict[str, object]]:
    serialized = _policy_bundle_cloud_exception_items(
        store,
        device_id=device_id,
        sync_exceptions=sync_exceptions,
        policy_bundle=policy_bundle,
    )
    store.set_cloud_exceptions(serialized, now)
    return serialized


def _policy_bundle_cloud_exception_items(
    store: GuardStore,
    *,
    device_id: str | None = None,
    sync_exceptions: list[dict[str, object]] | None = None,
    policy_bundle: dict[str, object] | None = None,
    policy_bundle_ack: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    """Build bundle-derived exceptions without mutating activation state."""

    resolved_device_id = device_id
    if resolved_device_id is None:
        resolved_device_id, _device_name = _guard_device_metadata(store)
    bundle_ack = policy_bundle_ack
    if bundle_ack is None:
        bundle_ack_payload = store.get_sync_payload("policy_bundle_ack")
        bundle_ack = bundle_ack_payload if isinstance(bundle_ack_payload, dict) else None
    items = []
    # ``sync_exceptions`` is retained as an explicit compatibility boundary so
    # callers can demonstrate that legacy unsigned siblings were considered
    # and rejected. It must never contribute enforcement authority.
    del sync_exceptions
    if isinstance(policy_bundle, dict):
        items.extend(
            build_cloud_exceptions_from_policy_bundle(
                policy_bundle,
                device_id=resolved_device_id,
                policy_bundle_ack=bundle_ack,
            )
        )
    serialized = [cloud_exception_to_dict(item) for item in dedupe_cloud_exceptions(items)]
    return serialized


def _base64url_encode(data: bytes) -> str:
    return urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _encode_jwt_segment(payload: Mapping[str, object]) -> str:
    return _base64url_encode(json.dumps(dict(payload), separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _dpop_access_token_confirmation_claim(access_token: str) -> str:
    # RFC 9449 requires the DPoP `ath` claim to be the SHA-256 hash of the access token.
    # codeql[py/weak-sensitive-data-hashing]
    digest = hashes.Hash(hashes.SHA256())
    digest.update(access_token.encode("ascii"))
    return _base64url_encode(digest.finalize())


def _sign_guard_dpop_proof(
    *,
    request_url: str,
    method: str,
    dpop_key_material: GuardDpopKeyMaterial,
    access_token: str | None = None,
    nonce: str | None = None,
    now: datetime | None = None,
) -> str:
    issued_at = int((now or datetime.now(timezone.utc)).timestamp())
    header = {
        "alg": dpop_key_material.algorithm,
        "jwk": dpop_key_material.public_jwk,
        "typ": "dpop+jwt",
    }
    claims: dict[str, object] = {
        "htu": request_url,
        "htm": method.upper(),
        "iat": issued_at,
        "jti": str(uuid4()),
    }
    if isinstance(access_token, str) and access_token:
        claims["ath"] = _dpop_access_token_confirmation_claim(access_token)
    if isinstance(nonce, str):
        normalized_nonce = nonce.strip()
        if normalized_nonce:
            claims["nonce"] = normalized_nonce
    signing_input = f"{_encode_jwt_segment(header)}.{_encode_jwt_segment(claims)}".encode("ascii")
    try:
        private_key = serialization.load_pem_private_key(
            dpop_key_material.private_key_pem.encode("ascii"),
            password=None,
        )
    except (TypeError, ValueError) as exc:
        raise GuardSyncAuthorizationExpiredError(
            "Guard Cloud authorization key is invalid. Reconnect Guard Cloud."
        ) from exc
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP256R1):
        raise RuntimeError("Guard DPoP key must be a P-256 (SECP256R1) EC private key.")
    der_signature = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r_value, s_value = decode_dss_signature(der_signature)
    jose_signature = _base64url_encode(r_value.to_bytes(32, byteorder="big") + s_value.to_bytes(32, byteorder="big"))
    return f"{signing_input.decode('ascii')}.{jose_signature}"


def _guard_http_header_value(response: object, header_name: str) -> str | None:
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    value = headers.get(header_name)
    if value is None:
        header_items = getattr(headers, "items", None)
        if callable(header_items):
            target_header = header_name.lower()
            raw_header_items = header_items()
            if not isinstance(raw_header_items, Iterable):
                raw_header_items = ()
            for header_item in raw_header_items:
                if not isinstance(header_item, tuple) or len(header_item) != 2:
                    continue
                current_name, current_value = header_item
                if isinstance(current_name, str) and current_name.lower() == target_header:
                    value = current_value
                    break
    if not isinstance(value, str):
        return None
    normalized_value = value.strip()
    return normalized_value or None


def _http_error_payload(error: urllib.error.HTTPError) -> object:
    try:
        raw_body = error.read()
    except OSError:
        raw_body = b""
    error.fp = io.BytesIO(raw_body)
    if not raw_body:
        return None
    try:
        return json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _dpop_nonce_from_http_error(error: urllib.error.HTTPError, payload: object) -> str | None:
    if error.code not in {400, 401}:
        return None
    nonce = _guard_http_header_value(error, "DPoP-Nonce")
    if nonce is None:
        return None
    if isinstance(payload, dict):
        oauth_error = str(payload.get("error") or "").strip()
        if oauth_error and oauth_error not in {"use_dpop_nonce", "invalid_dpop_proof"}:
            return None
    return nonce


_GUARD_DPOP_REQUEST_CONTEXTS: dict[str, dict[str, object]] = {}
_GUARD_DPOP_REQUEST_CONTEXT_LIMIT = 1000


def _remember_guard_dpop_request_context(dpop_header: str, context: dict[str, object]) -> None:
    if len(_GUARD_DPOP_REQUEST_CONTEXTS) >= _GUARD_DPOP_REQUEST_CONTEXT_LIMIT:
        oldest_header = next(iter(_GUARD_DPOP_REQUEST_CONTEXTS), None)
        if isinstance(oldest_header, str):
            _GUARD_DPOP_REQUEST_CONTEXTS.pop(oldest_header, None)
    _GUARD_DPOP_REQUEST_CONTEXTS[dpop_header] = context


def _guard_sync_request(
    auth_context: dict[str, object],
    *,
    request_url: str,
    method: str,
    data: bytes | None = None,
    extra_headers: dict[str, str] | None = None,
    dpop_nonce: str | None = None,
) -> urllib.request.Request:
    headers = _guard_sync_headers(
        auth_context,
        request_url=request_url,
        method=method,
        extra_headers=extra_headers,
        dpop_nonce=dpop_nonce,
    )
    request = urllib.request.Request(
        request_url,
        data=data,
        method=method,
        headers=headers,
    )
    object.__setattr__(
        request,
        "_guard_dpop_retry_context",
        {
            "auth_context": auth_context,
            "request_url": request_url,
            "method": method,
            "extra_headers": None if extra_headers is None else dict(extra_headers),
            "dpop_nonce": dpop_nonce,
        },
    )
    return request


def _oauth_refresh_error_message(error: urllib.error.HTTPError) -> str:
    try:
        raw_body = error.read().decode("utf-8")
    except OSError:
        raw_body = ""
    try:
        payload = json.loads(raw_body) if raw_body else None
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        description = _optional_string(payload.get("error_description"))
        if description is not None:
            return description
        error_code = _optional_string(payload.get("error"))
        if error_code is not None:
            return error_code
    normalized_body = raw_body.strip()
    if normalized_body:
        return normalized_body
    return f"HTTP Error {error.code}: {error.reason}"


def _guard_oauth_reauthorization_message() -> str:
    return "Guard authorization expired. Run `hol-guard connect` to sign in again."


def _guard_oauth_reconnect_after_revoked_message() -> str:
    return (
        "Guard Cloud sign-in on this device is no longer valid. "
        "Run `hol-guard disconnect` then `hol-guard connect` to sign in again."
    )


def _invalid_grant_oauth_payload(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    return _invalid_grant_oauth_error_details(
        _optional_string(payload.get("error")),
        _optional_string(payload.get("error_description")),
    )


def _invalid_grant_oauth_error_details(
    error_code: str | None,
    description: str | None,
) -> bool:
    return error_code == "invalid_grant" or (
        description is not None and "missing, expired, or already consumed" in description.lower()
    )


def _oauth_authorization_error_requires_fresh_sign_in(error: Exception) -> bool:
    message = str(error).strip().lower()
    return (
        "invalid_grant" in message
        or "missing, expired, or already consumed" in message
        or _guard_oauth_reconnect_after_revoked_message().lower() in message
    )


def clear_revoked_guard_oauth_sign_in(store: GuardStore) -> bool:
    """Return True when refresh proves the local OAuth grant was revoked and cleared."""
    try:
        with _guard_sync_auth_lock(store):
            credentials = store.get_oauth_local_credentials(allow_primary=True)
            if credentials is None:
                return False
            try:
                _resolve_guard_sync_auth_context_from_oauth_credentials(store, credentials)
            except GuardSyncAuthorizationExpiredError as error:
                if _oauth_authorization_error_requires_fresh_sign_in(error):
                    store.clear_oauth_local_credentials()
                    return True
                return False
    except (RuntimeError, OSError, TimeoutError):
        return False
    return False


def repair_guard_cloud_connect_storage(store: GuardStore) -> dict[str, object]:
    """Repair local OAuth storage without clearing sign-in state."""
    repaired_storage = store.repair_oauth_local_credential_storage_from_primary()
    existing_sign_in_valid = store.get_oauth_local_credentials(allow_primary=True) is not None
    return {
        "cleared_stale_sign_in": False,
        "existing_sign_in_valid": existing_sign_in_valid,
        "repaired_storage": repaired_storage,
    }


def prepare_guard_cloud_connect_authorization(store: GuardStore) -> dict[str, object]:
    """Repair local OAuth storage and clear revoked sign-in before reconnect."""
    repaired_storage = repair_guard_cloud_connect_storage(store)["repaired_storage"]
    cleared_stale_sign_in = clear_revoked_guard_oauth_sign_in(store)
    existing_sign_in_valid = store.get_oauth_local_credentials(allow_primary=True) is not None
    return {
        "repaired_storage": repaired_storage,
        "cleared_stale_sign_in": cleared_stale_sign_in,
        "existing_sign_in_valid": existing_sign_in_valid,
    }


def _guard_sync_reconnect_message() -> str:
    return "Guard Cloud sync endpoint is not trusted. Run `hol-guard connect` to restore Cloud sync."


def _validate_guard_sync_url(sync_url: str, *, issuer: str | None = None) -> str:
    try:
        return validate_guard_sync_endpoint(sync_url, issuer=issuer)
    except ValueError as error:
        if issuer is not None:
            raise GuardSyncAuthorizationExpiredError(f"{_guard_oauth_reauthorization_message()} {error}") from error
        raise GuardSyncNotConfiguredError(f"{_guard_sync_reconnect_message()} {error}") from error


def _refresh_guard_oauth_access_token(
    *,
    token_endpoint: str,
    client_id: str,
    refresh_token: str,
    dpop_key_material: GuardDpopKeyMaterial,
) -> dict[str, object]:
    request_body = urllib.parse.urlencode(
        {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token,
        }
    ).encode("utf-8")
    dpop_nonce: str | None = None
    nonce_retry_count = 0
    while True:
        try:
            dpop_proof = _sign_guard_dpop_proof(
                request_url=token_endpoint,
                method="POST",
                dpop_key_material=dpop_key_material,
                nonce=dpop_nonce,
            )
        except (RuntimeError, TypeError, ValueError) as error:
            raise GuardSyncAuthorizationExpiredError(f"{_guard_oauth_reauthorization_message()} {error}") from error
        request = urllib.request.Request(
            token_endpoint,
            data=request_body,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "User-Agent": _GUARD_SYNC_USER_AGENT,
                "DPoP": dpop_proof,
            },
        )
        try:
            with managed_urlopen(request, timeout=_SYNC_HTTP_TIMEOUT_SECONDS) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            payload = _http_error_payload(error) if error.code in {400, 401, 403} else None
            challenge_nonce = _dpop_nonce_from_http_error(error, payload)
            if challenge_nonce is not None and challenge_nonce != dpop_nonce and nonce_retry_count < 3:
                dpop_nonce = challenge_nonce
                nonce_retry_count += 1
                continue
            if error.code in {400, 401, 403}:
                if _invalid_grant_oauth_payload(payload):
                    raise GuardSyncAuthorizationExpiredError(_guard_oauth_reconnect_after_revoked_message()) from error
                refresh_error_message = _oauth_refresh_error_message(error)
                raise GuardSyncAuthorizationExpiredError(
                    f"{_guard_oauth_reauthorization_message()} {refresh_error_message}"
                ) from error
            refresh_error_message = _oauth_refresh_error_message(error)
            raise RuntimeError(f"Guard OAuth token refresh failed: {refresh_error_message}") from error
        except OSError as error:
            raise RuntimeError(_sync_url_error_message(error)) from error
        if not isinstance(payload, dict):
            raise GuardSyncAuthorizationExpiredError(_guard_oauth_reauthorization_message())
        access_token = _optional_string(payload.get("access_token"))
        token_type = _optional_string(payload.get("token_type"))
        if access_token is None or token_type is None or token_type.lower() not in {"bearer", "dpop"}:
            raise GuardSyncAuthorizationExpiredError(_guard_oauth_reauthorization_message())
        access_token_expires_at = _oauth_access_token_expires_at(
            access_token,
            payload=payload,
            now=datetime.now(timezone.utc),
        )
        return {
            "access_token": access_token,
            "access_token_expires_at": access_token_expires_at,
            "package_firewall_entitlement": build_oauth_package_firewall_entitlement(
                payload,
                now=datetime.now(timezone.utc),
            ),
            "cloud_user_profile": extract_cloud_user_profile(payload),
            "had_guard_local_entitlement": isinstance(payload.get("guard_local_entitlement"), dict),
            "refresh_token": _optional_string(payload.get("refresh_token")) or refresh_token,
        }


def _oauth_sync_url_from_issuer(issuer: str) -> str:
    oauth_client = resolve_guard_oauth_client_config(issuer)
    return f"{oauth_client.issuer}/api/guard/receipts/sync"


def _oauth_dpop_key_material(credentials: dict[str, object]) -> GuardDpopKeyMaterial:
    dpop_private_key_pem = _optional_string(credentials.get("dpop_private_key_pem"))
    dpop_public_jwk = credentials.get("dpop_public_jwk")
    dpop_public_jwk_thumbprint = _optional_string(credentials.get("dpop_public_jwk_thumbprint"))
    if dpop_private_key_pem is None or not isinstance(dpop_public_jwk, dict) or dpop_public_jwk_thumbprint is None:
        raise GuardSyncAuthorizationExpiredError(_guard_oauth_reauthorization_message())
    return GuardDpopKeyMaterial(
        algorithm="ES256",
        private_key_pem=dpop_private_key_pem,
        public_jwk={str(key): str(value) for key, value in dpop_public_jwk.items()},
        public_jwk_thumbprint=dpop_public_jwk_thumbprint,
    )


_OAUTH_ACCESS_TOKEN_REFRESH_SKEW_SECONDS = 60


def _decode_oauth_access_token_claims(access_token: str) -> dict[str, object]:
    parts = access_token.split(".")
    if len(parts) != 3:
        return {}
    try:
        padding = "=" * (-len(parts[1]) % 4)
        payload = json.loads(urlsafe_b64decode(parts[1] + padding).decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _oauth_access_token_expires_at(
    access_token: str,
    *,
    payload: dict[str, object],
    now: datetime,
) -> str | None:
    claims = _decode_oauth_access_token_claims(access_token)
    exp = claims.get("exp")
    if isinstance(exp, (int, float)) and not isinstance(exp, bool) and float(exp) > 0:
        return datetime.fromtimestamp(float(exp), tz=timezone.utc).isoformat()
    expires_in = payload.get("expires_in")
    parsed_expires_in: int | None
    if isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool):
        parsed_expires_in = int(expires_in)
    elif isinstance(expires_in, str):
        try:
            parsed_expires_in = int(expires_in)
        except ValueError:
            parsed_expires_in = None
    else:
        parsed_expires_in = None
    if parsed_expires_in is None or parsed_expires_in <= 0:
        return None
    return (now + timedelta(seconds=parsed_expires_in)).isoformat()


def _cached_oauth_access_token(credentials: dict[str, object], *, now: datetime) -> str | None:
    access_token = _optional_string(credentials.get("access_token"))
    access_token_expires_at = _optional_string(credentials.get("access_token_expires_at"))
    if access_token is None or access_token_expires_at is None:
        return None
    try:
        expires_at = datetime.fromisoformat(access_token_expires_at)
    except ValueError:
        return None
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    expires_at = expires_at.astimezone(timezone.utc)
    if expires_at <= now + timedelta(seconds=_OAUTH_ACCESS_TOKEN_REFRESH_SKEW_SECONDS):
        return None
    return access_token


def _persist_rotated_oauth_refresh_token(
    *,
    store: GuardStore,
    credentials: dict[str, object],
    package_firewall_entitlement: dict[str, object] | None = None,
    cloud_user_profile: dict[str, str] | None = None,
    refresh_token: str,
    access_token: str | None = None,
    access_token_expires_at: str | None = None,
    force_primary_secret_rewrite: bool = False,
) -> None:
    issuer = _optional_string(credentials.get("issuer"))
    client_id = _optional_string(credentials.get("client_id"))
    dpop_private_key_pem = _optional_string(credentials.get("dpop_private_key_pem"))
    dpop_public_jwk = credentials.get("dpop_public_jwk")
    dpop_public_jwk_thumbprint = _optional_string(credentials.get("dpop_public_jwk_thumbprint"))
    if (
        issuer is None
        or client_id is None
        or dpop_private_key_pem is None
        or not isinstance(dpop_public_jwk, dict)
        or dpop_public_jwk_thumbprint is None
    ):
        raise GuardSyncAuthorizationExpiredError(_guard_oauth_reauthorization_message())
    supply_chain_firewall: bool | None
    if isinstance(package_firewall_entitlement, dict) and isinstance(
        package_firewall_entitlement.get("supply_chain_firewall"), bool
    ):
        supply_chain_firewall = bool(package_firewall_entitlement.get("supply_chain_firewall"))
    else:
        credentials_supply_chain_firewall = credentials.get("supply_chain_firewall")
        supply_chain_firewall = (
            credentials_supply_chain_firewall if isinstance(credentials_supply_chain_firewall, bool) else None
        )
    store.set_oauth_local_credentials(
        issuer=issuer,
        client_id=client_id,
        refresh_token=refresh_token,
        dpop_private_key_pem=dpop_private_key_pem,
        dpop_public_jwk={str(key): str(value) for key, value in dpop_public_jwk.items()},
        dpop_public_jwk_thumbprint=dpop_public_jwk_thumbprint,
        grant_id=_optional_string(credentials.get("grant_id")),
        machine_id=_optional_string(credentials.get("machine_id")),
        supply_chain_entitlement_expires_at=(
            _optional_string(package_firewall_entitlement.get("supply_chain_entitlement_expires_at"))
            if isinstance(package_firewall_entitlement, dict)
            else _optional_string(credentials.get("supply_chain_entitlement_expires_at"))
        ),
        supply_chain_firewall=supply_chain_firewall,
        supply_chain_plan_id=(
            _optional_string(package_firewall_entitlement.get("supply_chain_plan_id"))
            if isinstance(package_firewall_entitlement, dict)
            else _optional_string(credentials.get("supply_chain_plan_id"))
        ),
        workspace_id=_optional_string(credentials.get("workspace_id")),
        cloud_user_profile=cloud_user_profile,
        runtime_id=_optional_string(credentials.get("runtime_id")),
        runtime_label=_optional_string(credentials.get("runtime_label")),
        access_token=access_token,
        access_token_expires_at=access_token_expires_at,
        now=_now(),
        force_primary_secret_rewrite=force_primary_secret_rewrite,
    )


def _resolve_guard_sync_auth_context_from_oauth_credentials(
    store: GuardStore,
    oauth_credentials: dict[str, object],
    *,
    persist_recovered_secret: bool = False,
    force_refresh: bool = False,
) -> dict[str, object]:
    issuer = _optional_string(oauth_credentials.get("issuer"))
    client_id = _optional_string(oauth_credentials.get("client_id"))
    refresh_token = _optional_string(oauth_credentials.get("refresh_token"))
    if issuer is None or client_id is None or refresh_token is None:
        raise GuardSyncAuthorizationExpiredError(_guard_oauth_reauthorization_message())
    dpop_key_material = _oauth_dpop_key_material(oauth_credentials)
    try:
        oauth_client = resolve_guard_oauth_client_config(issuer)
    except ValueError as error:
        raise GuardSyncAuthorizationExpiredError(f"{_guard_oauth_reauthorization_message()} {error}") from error
    cached_access_token = (
        None if force_refresh else _cached_oauth_access_token(oauth_credentials, now=datetime.now(timezone.utc))
    )
    if cached_access_token is not None and not persist_recovered_secret:
        sync_url = _validate_guard_sync_url(
            _oauth_sync_url_from_issuer(oauth_client.issuer),
            issuer=oauth_client.issuer,
        )
        return {
            "sync_url": sync_url,
            "access_token": cached_access_token,
            "dpop_key_material": dpop_key_material,
        }
    refreshed = _refresh_guard_oauth_access_token(
        token_endpoint=oauth_client.token_endpoint,
        client_id=client_id,
        refresh_token=refresh_token,
        dpop_key_material=dpop_key_material,
    )
    rotated_refresh_token = str(refreshed["refresh_token"])
    refreshed_entitlement = refreshed.get("package_firewall_entitlement")
    package_firewall_entitlement: dict[str, object] | None = (
        refreshed_entitlement if isinstance(refreshed_entitlement, dict) else None
    )
    refreshed_cloud_user_profile = refreshed.get("cloud_user_profile")
    if not isinstance(refreshed_cloud_user_profile, dict):
        refreshed_cloud_user_profile = None
    had_entitlement = bool(refreshed.get("had_guard_local_entitlement"))
    # When the refresh response includes a guard_local_entitlement but no
    # user_profile, clear the stale profile rather than preserving it.
    # When there's no guard_local_entitlement at all (old server), keep existing.
    effective_cloud_user_profile: dict[str, str] | None
    if had_entitlement:
        effective_cloud_user_profile = refreshed_cloud_user_profile
    else:
        effective_cloud_user_profile = refreshed_cloud_user_profile or _extract_dict_field(
            oauth_credentials, "cloud_user_profile"
        )
    stored_cloud_user_profile = _extract_dict_field(oauth_credentials, "cloud_user_profile")
    profile_changed = effective_cloud_user_profile != stored_cloud_user_profile
    if (
        force_refresh
        or rotated_refresh_token != refresh_token
        or package_firewall_entitlement is not None
        or profile_changed
        or persist_recovered_secret
    ):
        _persist_rotated_oauth_refresh_token(
            store=store,
            credentials=oauth_credentials,
            package_firewall_entitlement=package_firewall_entitlement,
            cloud_user_profile=effective_cloud_user_profile,
            refresh_token=rotated_refresh_token,
            access_token=_optional_string(refreshed.get("access_token")),
            access_token_expires_at=_optional_string(refreshed.get("access_token_expires_at")),
            force_primary_secret_rewrite=force_refresh,
        )
    sync_url = _validate_guard_sync_url(
        _oauth_sync_url_from_issuer(oauth_client.issuer),
        issuer=oauth_client.issuer,
    )
    return {
        "sync_url": sync_url,
        "access_token": str(refreshed["access_token"]),
        "dpop_key_material": dpop_key_material,
    }


# Test-only override: when set, _resolve_guard_sync_auth_context returns this dict
# directly instead of resolving OAuth credentials (which would refresh tokens over
# the network). Tests seed OAuth credentials for status/connect-state checks and set
# this override to keep sync-path exercises hermetic.
_test_sync_auth_context_override: dict[str, object] | None = None


def _test_sync_auth_context_from_env() -> dict[str, object] | None:
    if not os.environ.get("PYTEST_CURRENT_TEST"):
        return None
    raw = os.environ.get("HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON")
    if raw is None:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    sync_url = payload.get("sync_url")
    access_token = payload.get("access_token")
    if not isinstance(sync_url, str) or not isinstance(access_token, str):
        return None
    sync_url = _validate_guard_sync_url(sync_url)
    return {
        "sync_url": sync_url,
        "access_token": access_token,
        "dpop_key_material": None,
    }


def _resolve_guard_sync_auth_context(
    store: GuardStore,
    *,
    allow_primary_repair: bool = True,
    force_refresh: bool = False,
) -> dict[str, object]:
    if _test_sync_auth_context_override is not None:
        override = dict(_test_sync_auth_context_override)
        override["sync_url"] = _validate_guard_sync_url(_auth_context_sync_url(override))
        return override
    env_override = _test_sync_auth_context_from_env()
    if env_override is not None:
        return env_override
    with _guard_sync_auth_lock(store):
        oauth_health = store.get_oauth_local_credential_health()
        oauth_credentials = store.get_oauth_local_credentials(allow_primary=allow_primary_repair)
        if oauth_credentials is not None:
            return _resolve_guard_sync_auth_context_from_oauth_credentials(
                store,
                oauth_credentials,
                force_refresh=force_refresh,
            )
        if bool(oauth_health.get("configured")):
            recoverable_credentials = store.get_recoverable_oauth_local_credentials()
            if recoverable_credentials is not None:
                return _resolve_guard_sync_auth_context_from_oauth_credentials(
                    store,
                    recoverable_credentials,
                    persist_recovered_secret=allow_primary_repair,
                    force_refresh=force_refresh,
                )
            raise GuardSyncAuthorizationExpiredError(_guard_oauth_reauthorization_message())
        raise GuardSyncNotConfiguredError("Guard is not logged in.")


def _guard_sync_headers(
    auth_context: dict[str, object],
    *,
    request_url: str,
    method: str,
    extra_headers: dict[str, str] | None = None,
    dpop_nonce: str | None = None,
) -> dict[str, str]:
    access_token = str(auth_context["access_token"])
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": _GUARD_SYNC_USER_AGENT,
    }
    dpop_key_material = auth_context.get("dpop_key_material")
    if isinstance(dpop_key_material, GuardDpopKeyMaterial):
        dpop_header = _sign_guard_dpop_proof(
            request_url=request_url,
            method=method,
            dpop_key_material=dpop_key_material,
            access_token=access_token,
            nonce=dpop_nonce,
        )
        headers["DPoP"] = dpop_header
        _remember_guard_dpop_request_context(
            dpop_header,
            {
                "auth_context": auth_context,
                "request_url": request_url,
                "method": method,
                "extra_headers": None if extra_headers is None else dict(extra_headers),
                "dpop_nonce": dpop_nonce,
            },
        )
    if isinstance(extra_headers, dict):
        headers.update(extra_headers)
    return headers


def _guard_sync_request_with_nonce(
    request: urllib.request.Request,
    dpop_nonce: str,
) -> urllib.request.Request | None:
    request_context = _resolve_guard_dpop_retry_context(request)
    if request_context is None:
        return None
    auth_context = request_context.get("auth_context")
    request_url = request_context.get("request_url")
    method = request_context.get("method")
    extra_headers = request_context.get("extra_headers")
    current_dpop_nonce = request_context.get("dpop_nonce")
    if not isinstance(auth_context, dict) or not isinstance(request_url, str) or not isinstance(method, str):
        return None
    if extra_headers is not None and not isinstance(extra_headers, dict):
        return None
    if current_dpop_nonce == dpop_nonce:
        return None
    return _guard_sync_request(
        auth_context,
        request_url=request_url,
        method=method,
        data=_request_data_bytes(request.data),
        extra_headers=None if extra_headers is None else {str(key): str(value) for key, value in extra_headers.items()},
        dpop_nonce=dpop_nonce,
    )


def _resolve_guard_dpop_retry_context(
    request: urllib.request.Request,
) -> dict[str, object] | None:
    request_context = getattr(request, "_guard_dpop_retry_context", None)
    if isinstance(request_context, dict):
        return request_context
    current_dpop = request.get_header("DPoP")
    if not isinstance(current_dpop, str):
        for header_name, header_value in request.header_items():
            if header_name.lower() == "dpop":
                current_dpop = header_value
                break
    if not isinstance(current_dpop, str):
        return None
    request_context = _GUARD_DPOP_REQUEST_CONTEXTS.get(current_dpop)
    if not isinstance(request_context, dict):
        return None
    return request_context


def _refresh_guard_sync_request(
    request: urllib.request.Request,
) -> urllib.request.Request | None:
    """Build a new request with a fresh DPoP proof for timeout retries.

    Reusing the same DPoP proof after a timeout triggers server-side replay
    detection because the original request may have already been consumed.
    Preserves any server-provided DPoP nonce from the current request so
    nonce-challenged endpoints do not lose their nonce state across retries.
    """
    request_context = _resolve_guard_dpop_retry_context(request)
    if request_context is None:
        return None
    auth_context = request_context.get("auth_context")
    request_url = request_context.get("request_url")
    method = request_context.get("method")
    extra_headers = request_context.get("extra_headers")
    current_dpop_nonce = request_context.get("dpop_nonce")
    if not isinstance(auth_context, dict) or not isinstance(request_url, str) or not isinstance(method, str):
        return None
    if extra_headers is not None and not isinstance(extra_headers, dict):
        return None
    return _guard_sync_request(
        auth_context,
        request_url=request_url,
        method=method,
        data=_request_data_bytes(request.data),
        extra_headers=None if extra_headers is None else {str(key): str(value) for key, value in extra_headers.items()},
        dpop_nonce=current_dpop_nonce if isinstance(current_dpop_nonce, str) else None,
    )


def _read_guard_cloud_error_message(payload: dict[str, object]) -> str | None:
    guard_error = payload.get("guardError")
    if isinstance(guard_error, dict):
        for key in ("msg", "message"):
            nested = guard_error.get(key)
            if isinstance(nested, str) and nested.strip():
                return nested.strip()
    for key in ("err", "message", "error"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _sync_http_error_message(error: urllib.error.HTTPError) -> str:
    try:
        raw_body = error.read().decode("utf-8", errors="replace")
    except OSError:
        raw_body = ""
    try:
        payload = json.loads(raw_body) if raw_body else None
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        message = _read_guard_cloud_error_message(payload)
        if message is not None:
            return message
    normalized_body = raw_body.strip()
    if normalized_body:
        return normalized_body
    return f"HTTP Error {error.code}: {error.reason}"


def _redact_sync_text(value: str) -> str:
    return redact_sensitive_text(value)


_PLAN_403_KEYWORDS: frozenset[str] = frozenset(
    {
        "sync_not_available",
        "plan_restriction",
        "requires a pro",
        "requires a team",
        "upgrade your plan",
        "upgrade to",
        "subscription required",
        "not included in your plan",
        "guard sync requires",
    }
)


def _check_plan_restriction_403(
    error: urllib.error.HTTPError,
) -> tuple[bool, str]:
    """Read a 403 response body exactly once.

    Returns (is_plan_restriction, error_message) so callers never
    drain the stream more than once regardless of which branch they take.
    Checks both machine-readable fields (syncEnabled, error, code) and
    human-readable error messages for plan-restriction signals.
    """
    try:
        raw_body = error.read().decode("utf-8", errors="replace")
    except OSError:
        raw_body = ""
    try:
        payload: object = json.loads(raw_body) if raw_body else None
    except json.JSONDecodeError:
        payload = None
    fallback = raw_body.strip() or f"HTTP Error {error.code}: {error.reason}"
    if not isinstance(payload, dict):
        return False, fallback
    message = payload.get("error")
    message_str = message.strip() if isinstance(message, str) and message.strip() else fallback
    if payload.get("syncEnabled") is False:
        return True, message_str
    error_field = str(payload.get("error") or "").lower()
    code_field = str(payload.get("code") or "").lower()
    combined = f"{error_field} {code_field}"
    if any(kw in combined for kw in _PLAN_403_KEYWORDS):
        return True, message_str
    return False, message_str


def _sync_url_error_message(error: OSError) -> str:
    reason = getattr(error, "reason", error)
    if reason is not None:
        reason_text = str(reason).strip()
        if reason_text:
            return f"Guard sync failed: {reason_text}"
    return "Guard sync failed because the remote endpoint could not be reached."


def _is_timeout_error(error: OSError) -> bool:
    if isinstance(error, TimeoutError | socket.timeout):
        return True
    reason = getattr(error, "reason", error)
    if isinstance(reason, TimeoutError | socket.timeout):
        return True
    reason_text = str(reason).strip().lower()
    if not reason_text:
        return False
    return reason_text == "timed out" or reason_text.endswith(" timed out") or "timed out" in reason_text


def _urlopen_json_with_timeout_retry(
    *,
    request: urllib.request.Request,
    timeout_seconds: int,
    retry_timeout_seconds: int,
) -> dict[str, object]:
    current_request = request
    current_timeout_seconds = timeout_seconds
    retried_timeout = False
    nonce_retry_count = 0
    rate_limit_retry_count = 0
    gateway_retry_count = 0
    while True:
        try:
            with managed_urlopen(current_request, timeout=current_timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            if error.code == 429 and rate_limit_retry_count < 2:
                retry_after = _parse_retry_after_header(error)
                time.sleep(min(retry_after, 120))
                rate_limit_retry_count += 1
                refreshed_request = _refresh_guard_sync_request(current_request)
                if refreshed_request is None:
                    raise
                current_request = refreshed_request
                current_timeout_seconds = timeout_seconds
                retried_timeout = False
                continue
            if _retryable_gateway_http_error(error) and gateway_retry_count < _SYNC_RETRYABLE_GATEWAY_MAX_ATTEMPTS:
                retry_after = _retry_after_sleep_seconds(error, retry_timeout_seconds)
                time.sleep(retry_after)
                gateway_retry_count += 1
                current_request = _request_for_gateway_retry(current_request)
                current_timeout_seconds = timeout_seconds
                retried_timeout = False
                continue
            error_payload = _http_error_payload(error) if error.code in {400, 401} else None
            dpop_nonce = _dpop_nonce_from_http_error(error, error_payload)
            retry_request = (
                None
                if dpop_nonce is None or nonce_retry_count >= 3
                else _guard_sync_request_with_nonce(current_request, dpop_nonce)
            )
            if retry_request is not None:
                nonce_retry_count += 1
                current_request = retry_request
                current_timeout_seconds = timeout_seconds
                retried_timeout = False
                continue
            raise
        except OSError as error:
            if not retried_timeout and _is_timeout_error(error):
                refreshed_request = _refresh_guard_sync_request(current_request)
                if refreshed_request is None:
                    raise
                current_request = refreshed_request
                current_timeout_seconds = retry_timeout_seconds
                retried_timeout = True
                continue
            raise
        if not isinstance(payload, dict):
            raise RuntimeError("Guard Cloud sync returned an invalid response payload.")
        return payload


def _urlopen_with_timeout_retry(
    *,
    request: urllib.request.Request,
    timeout_seconds: int,
    retry_timeout_seconds: int,
) -> None:
    current_request = request
    current_timeout_seconds = timeout_seconds
    retried_timeout = False
    nonce_retry_count = 0
    rate_limit_retry_count = 0
    gateway_retry_count = 0
    while True:
        try:
            with managed_urlopen(current_request, timeout=current_timeout_seconds):
                return
        except urllib.error.HTTPError as error:
            if error.code == 401:
                error_payload = _http_error_payload(error)
                dpop_nonce = _dpop_nonce_from_http_error(error, error_payload)
                if dpop_nonce is not None and nonce_retry_count < 3:
                    nonce_retry_count += 1
                    retry_request = _guard_sync_request_with_nonce(current_request, dpop_nonce)
                    if retry_request is not None:
                        current_request = retry_request
                        current_timeout_seconds = timeout_seconds
                        retried_timeout = False
                        continue
            if error.code == 429 and rate_limit_retry_count < 2:
                retry_after = _parse_retry_after_header(error)
                time.sleep(min(retry_after, 120))
                rate_limit_retry_count += 1
                refreshed_request = _refresh_guard_sync_request(current_request)
                if refreshed_request is None:
                    raise
                current_request = refreshed_request
                current_timeout_seconds = timeout_seconds
                retried_timeout = False
                continue
            if _retryable_gateway_http_error(error) and gateway_retry_count < _SYNC_RETRYABLE_GATEWAY_MAX_ATTEMPTS:
                retry_after = _retry_after_sleep_seconds(error, retry_timeout_seconds)
                time.sleep(retry_after)
                gateway_retry_count += 1
                current_request = _request_for_gateway_retry(current_request)
                current_timeout_seconds = timeout_seconds
                retried_timeout = False
                continue
            error_payload = _http_error_payload(error) if error.code in {400, 401} else None
            dpop_nonce = _dpop_nonce_from_http_error(error, error_payload)
            retry_request = (
                None
                if dpop_nonce is None or nonce_retry_count >= 3
                else _guard_sync_request_with_nonce(current_request, dpop_nonce)
            )
            if retry_request is not None:
                nonce_retry_count += 1
                current_request = retry_request
                current_timeout_seconds = timeout_seconds
                retried_timeout = False
                continue
            raise
        except OSError as error:
            if not retried_timeout and _is_timeout_error(error):
                refreshed_request = _refresh_guard_sync_request(current_request)
                if refreshed_request is None:
                    raise
                current_request = refreshed_request
                current_timeout_seconds = retry_timeout_seconds
                retried_timeout = True
                continue
            raise


def _remote_harness(value: object, *, allow_wildcard: bool = True) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return "*" if allow_wildcard else None


def _remote_workspace(item: dict[str, object]) -> str | None:
    return _optional_string(item.get("workspace")) or _optional_string(item.get("workspacePath"))


def _optional_string(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _extract_dict_field(credentials: dict[str, object], key: str) -> dict[str, str] | None:
    value = credentials.get(key)
    if not isinstance(value, dict):
        return None
    return {str(k): str(v) for k, v in value.items()}


def _int_value(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _string_items(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _request_data_bytes(value: object) -> bytes | None:
    if isinstance(value, bytes):
        return value
    return None


def _auth_context_sync_url(auth_context: dict[str, object]) -> str:
    sync_url = _optional_string(auth_context.get("sync_url"))
    if sync_url is None:
        raise RuntimeError("Guard sync URL is unavailable.")
    return sync_url


def _metric_count(metrics: dict[str, dict[str, object]], key: str) -> int:
    metric = metrics.get(key)
    if not isinstance(metric, dict):
        return 0
    return _int_value(metric.get("value")) or 0


def _normalized_timestamp_string(value: object) -> str | None:
    raw_value = _optional_string(value)
    if raw_value is None:
        return None
    parsed = _parse_iso_timestamp(raw_value)
    if parsed is None:
        return None
    return parsed.isoformat()


def _last_uploaded_event_id(payload: dict[str, object] | list[object] | None) -> int:
    if not isinstance(payload, dict):
        return 0
    event_id = payload.get("event_id")
    return event_id if isinstance(event_id, int) and event_id > 0 else 0


def _pain_signal_item(
    event: dict[str, object],
    *,
    warn_occurrences: dict[tuple[str, str], int] | None = None,
) -> dict[str, object] | None:
    event_name = _optional_string(event.get("event_name"))
    payload = event.get("payload")
    occurred_at = _optional_string(event.get("occurred_at"))
    if event_name is None or not isinstance(payload, dict) or occurred_at is None:
        return None
    artifact_id, artifact_name = _pain_signal_artifact_identity(event_name, payload)
    if artifact_id is None or artifact_name is None:
        return None
    if not _should_emit_pain_signal(
        event_name=event_name,
        payload=payload,
        warn_occurrences=warn_occurrences,
    ):
        return None
    harness = _optional_string(payload.get("harness")) or _optional_string(payload.get("executor")) or "unknown"
    artifact_type = _artifact_type_for_signal(payload, artifact_id)
    latest_summary = _pain_signal_summary(event_name, payload)
    return {
        "signalId": f"{event_name}:{harness}:{artifact_id}",
        "signalName": event_name,
        "artifactId": artifact_id,
        "artifactName": artifact_name,
        "artifactType": artifact_type,
        "harness": harness,
        "latestSummary": latest_summary,
        "occurredAt": occurred_at,
        "source": "scanner",
        "publisher": _optional_string(payload.get("publisher")),
    }


def _artifact_type_for_signal(payload: dict[str, object], artifact_id: str) -> str:
    artifact_type = _optional_string(payload.get("artifact_type"))
    if artifact_type in {"plugin", "skill"}:
        return artifact_type
    if artifact_id.startswith("skill:"):
        return "skill"
    return "plugin"


def _pain_signal_summary(event_name: str, payload: dict[str, object]) -> str:
    reason = _optional_string(payload.get("reason"))
    if reason is not None:
        return reason
    changed_fields = payload.get("changed_fields")
    if event_name == "changed_artifact_caught" and isinstance(changed_fields, list):
        changed_labels = [str(item) for item in changed_fields if isinstance(item, str)]
        if changed_labels:
            return f"Artifact changed across: {', '.join(changed_labels)}."
    risk_signals = payload.get("risk_signals")
    if isinstance(risk_signals, list):
        labels = [str(item) for item in risk_signals if isinstance(item, str)]
        if labels:
            return f"Guard flagged install-time risk: {', '.join(labels)}."
    expires_at = _optional_string(payload.get("expires_at"))
    if event_name == "exception_expiring" and expires_at is not None:
        return f"Guard exception expires at {expires_at}."
    return f"Guard recorded {event_name.replace('_', ' ')} for this artifact."


def _build_value_metrics(store: GuardStore) -> dict[str, dict[str, object]]:
    events = store.list_events(limit=5000)
    installs_stopped = 0
    scripts_prevented = 0
    tokens_protected = 0
    for event in events:
        event_name = _optional_string(event.get("event_name")) or ""
        payload = event.get("payload")
        if not isinstance(payload, dict):
            continue
        if event_name in _INSTALL_TIME_STOP_EVENTS:
            installs_stopped += 1
            install_kind = (_optional_string(payload.get("install_kind")) or "").lower()
            risk_signals = payload.get("risk_signals")
            script_signal = isinstance(risk_signals, list) and any(
                "script" in str(signal).lower() for signal in risk_signals
            )
            if "script" in install_kind or script_signal:
                scripts_prevented += 1
        if event_name == "changed_artifact_caught":
            changed_fields = payload.get("changed_fields")
            risk_signals = payload.get("risk_signals")
            touched_launch_surface = isinstance(changed_fields, list) and any(
                str(item) in {"command", "args"} for item in changed_fields
            )
            secret_signal = isinstance(risk_signals, list) and any(
                any(token in str(signal).lower() for token in ("token", "secret", ".env", "credential"))
                for signal in risk_signals
            )
            if touched_launch_surface and secret_signal:
                tokens_protected += 1
    return {
        "installs_stopped_before_execution": {
            "value": installs_stopped,
            "source": "guard_events:install_time_block|review|require-reapproval|sandbox-required",
        },
        "scripts_prevented": {
            "value": scripts_prevented,
            "source": "guard_events:risk_signals|install_kind",
        },
        "tokens_protected": {
            "value": tokens_protected,
            "source": "guard_events:changed_artifact_caught",
        },
    }


def _build_weekly_firewall_digest(*, metrics: dict[str, dict[str, object]], now: str) -> dict[str, object]:
    installs_stopped = _metric_count(metrics, "installs_stopped_before_execution")
    scripts_prevented = _metric_count(metrics, "scripts_prevented")
    tokens_protected = _metric_count(metrics, "tokens_protected")
    headline = (
        "Package firewall summary: "
        f"{installs_stopped} installs stopped before execution, "
        f"{scripts_prevented} scripts prevented, "
        f"{tokens_protected} token-protection incidents."
    )
    return {
        "subject": "HOL Guard weekly package firewall summary",
        "generated_at": now,
        "period_days": 7,
        "headline": headline,
        "body_preview": (
            "HOL Guard weekly digest\n"
            f"{headline}\n"
            "Review the approval queue and sync health to keep package protection current."
        ),
    }


def _pain_signal_artifact_identity(event_name: str, payload: dict[str, object]) -> tuple[str | None, str | None]:
    artifact_id = _optional_string(payload.get("artifact_id"))
    artifact_name = _optional_string(payload.get("artifact_name"))
    if artifact_id is not None and artifact_name is not None:
        return (artifact_id, artifact_name)
    if event_name == "supply_chain_bundle_refresh_requested":
        fallback_id = artifact_id or "guard:supply-chain:feed"
        return (fallback_id, artifact_name or fallback_id)
    if event_name == "approval_gate/remote_policy_sync_blocked":
        return ("guard:policy:disable", "remote policy sync disabled")
    return (None, None)


def _warning_occurrence_key(payload: dict[str, object]) -> tuple[str, str] | None:
    artifact_id = _optional_string(payload.get("artifact_id"))
    harness = _optional_string(payload.get("harness")) or _optional_string(payload.get("executor"))
    if artifact_id is None or harness is None:
        return None
    return (harness, artifact_id)


def _should_emit_pain_signal(
    *,
    event_name: str,
    payload: dict[str, object],
    warn_occurrences: dict[tuple[str, str], int] | None,
) -> bool:
    if event_name in _INSTALL_TIME_STOP_EVENTS:
        return True
    if event_name == "install_time_warn":
        warn_key = _warning_occurrence_key(payload)
        if warn_key is None:
            return False
        if warn_occurrences is None:
            return False
        return warn_occurrences.get(warn_key, 0) >= 2
    if event_name == "changed_artifact_caught":
        policy_action = _optional_string(payload.get("policy_action"))
        return policy_action in {"review", "require-reapproval", "sandbox-required", "block"}
    if event_name == "supply_chain_bundle_refresh_requested":
        reason = _optional_string(payload.get("reason"))
        return reason == "feed_stale"
    return event_name == "approval_gate/remote_policy_sync_blocked"


def _pain_signal_sync_url(sync_url: str) -> str:
    parsed = urllib.parse.urlsplit(sync_url)
    path = parsed.path.rstrip("/")
    segments = [segment for segment in path.split("/") if segment]
    if len(segments) >= 2 and segments[-2:] in (["receipts", "sync"], ["inventory", "sync"]):
        next_segments = [*segments[:-2], "signals", "pain"]
    elif segments and segments[-1] in {"receipts", "inventory"}:
        next_segments = [*segments[:-1], "signals", "pain"]
    else:
        next_segments = [*segments, "signals", "pain"]
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            "/" + "/".join(next_segments),
            parsed.query,
            parsed.fragment,
        )
    )


def _normalized_receipts_sync_url(sync_url: str) -> str:
    parsed = urllib.parse.urlsplit(sync_url)
    if parsed.path.rstrip("/") == "/registry/api/v1":
        return urllib.parse.urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                "/registry/api/v1/guard/receipts/sync",
                parsed.query,
                "",
            )
        )
    return sync_url


def _normalized_runtime_sessions_sync_url(sync_url: str) -> str:
    normalized_receipts_url = _normalized_receipts_sync_url(sync_url)
    parsed = urllib.parse.urlsplit(normalized_receipts_url)
    if parsed.path.rstrip("/") == "/registry/api/v1/guard/receipts/sync":
        return urllib.parse.urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                "/registry/api/v1/guard/runtime/sessions/sync",
                parsed.query,
                "",
            )
        )
    if parsed.path.rstrip("/") == "/api/guard/receipts/sync":
        return urllib.parse.urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                "/api/guard/runtime/sessions/sync",
                parsed.query,
                "",
            )
        )
    if parsed.path.rstrip("/") == "/guard/receipts/sync":
        return urllib.parse.urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                "/guard/runtime/sessions/sync",
                parsed.query,
                "",
            )
        )
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path.rstrip("/") + "/runtime/sessions/sync",
            parsed.query,
            "",
        )
    )


def _normalized_supply_chain_bundle_url(sync_url: str, workspace_id: str) -> str:
    normalized_receipts_url = _normalized_receipts_sync_url(sync_url)
    parsed = urllib.parse.urlsplit(normalized_receipts_url)
    if parsed.path.rstrip("/") == "/registry/api/v1/guard/receipts/sync":
        next_path = "/registry/api/v1/guard/supply-chain/bundle"
    elif parsed.path.rstrip("/") == "/api/guard/receipts/sync":
        next_path = "/api/guard/supply-chain/bundle"
    elif parsed.path.rstrip("/") == "/guard/receipts/sync":
        next_path = "/guard/supply-chain/bundle"
    else:
        next_path = parsed.path.rstrip("/") + "/supply-chain/bundle"
    query_pairs = [
        (key, value)
        for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if key != "workspaceId"
    ]
    query_pairs.append(("workspaceId", workspace_id))
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            next_path,
            urllib.parse.urlencode(query_pairs),
            "",
        )
    )


def _guard_events_sync_url(sync_url: str) -> str:
    parsed = urllib.parse.urlsplit(_normalized_receipts_sync_url(sync_url))
    if parsed.path.rstrip("/").endswith("/api/v1/guard/events"):
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), parsed.query, ""))
    path = parsed.path.rstrip("/")
    for suffix in (
        "/registry/api/v1/guard/receipts/sync",
        "/api/guard/receipts/sync",
        "/guard/receipts/sync",
    ):
        if path.endswith(suffix):
            path = path[: -len(suffix)]
            break
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            path.rstrip("/") + "/api/v1/guard/events",
            parsed.query,
            "",
        )
    )


def _completed_guard_event_ids(payload: dict[str, object]) -> list[str]:
    statuses = payload.get("statuses")
    if not isinstance(statuses, list):
        return []
    completed: list[str] = []
    for item in statuses:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "")
        event_id = item.get("eventId")
        if status in {"accepted", "duplicate", "rejected"} and isinstance(event_id, str):
            completed.append(event_id)
    return completed


def _cloud_sync_receipts_payload(
    receipts: list[dict[str, object]],
    *,
    device_id: str,
    device_name: str,
    redaction_level: str = "full",
) -> list[dict[str, object]]:
    return [
        _cloud_sync_receipt_payload(
            receipt,
            device_id=device_id,
            device_name=device_name,
            redaction_level=redaction_level,
        )
        for receipt in receipts
    ]


def _dedupe_sync_payload_items(items: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[str] = set()
    deduped: list[dict[str, object]] = []
    for item in items:
        fingerprint = json.dumps(item, sort_keys=True)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        deduped.append(item)
    return deduped


def _iter_receipt_sync_batches(receipts: list[dict[str, object]]) -> tuple[list[dict[str, object]], ...]:
    if not receipts:
        return ([],)
    return tuple(
        receipts[index : index + _RECEIPT_SYNC_BATCH_SIZE]
        for index in range(0, len(receipts), _RECEIPT_SYNC_BATCH_SIZE)
    )


def _receipt_sync_cursor_rowid(store: GuardStore) -> int | None:
    payload = store.get_sync_payload("receipt_sync_cursor")
    if not isinstance(payload, dict):
        return None
    value = payload.get("last_rowid")
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            return int(stripped)
    return None


def _receipt_sync_rows_for_upload(store: GuardStore, *, cursor_rowid: int | None) -> list[dict[str, object]]:
    if cursor_rowid is None:
        return store.list_receipts(limit=_RECEIPT_SYNC_CURSOR_PAGE_SIZE)
    latest_rowid = store.latest_receipt_rowid()
    if latest_rowid is None:
        return []
    if cursor_rowid > latest_rowid:
        backfill_after = max(latest_rowid - _RECEIPT_SYNC_CURSOR_BACKFILL_ROWS, 0)
        return store.list_receipts_since_rowid(after_rowid=backfill_after, limit=_RECEIPT_SYNC_CURSOR_PAGE_SIZE)
    return store.list_receipts_since_rowid(after_rowid=cursor_rowid, limit=_RECEIPT_SYNC_CURSOR_PAGE_SIZE)


def _receipt_sync_rows_with_command_detail_backfill(
    store: GuardStore,
    *,
    receipts: list[dict[str, object]],
    redaction_level: str,
    synced_at: str,
) -> tuple[list[dict[str, object]], dict[str, object] | None]:
    if _receipt_redaction_level_rank(redaction_level) <= _receipt_redaction_level_rank("full"):
        return receipts, None
    marker = store.get_sync_payload(_RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER)
    before_rowid = _receipt_command_detail_backfill_before_rowid(marker, redaction_level=redaction_level)
    if isinstance(marker, dict) and marker.get("level") == redaction_level and marker.get("complete") is True:
        return receipts, None
    backfill_rows = store.list_receipts_for_command_detail_backfill(
        limit=_RECEIPT_COMMAND_DETAIL_BACKFILL_LIMIT,
        days=_RECEIPT_COMMAND_DETAIL_BACKFILL_DAYS,
        before_rowid=before_rowid,
    )
    seen_receipt_ids = {item.get("receipt_id") for item in receipts if isinstance(item.get("receipt_id"), str)}
    merged = list(receipts)
    added = 0
    for row in backfill_rows:
        receipt_id = row.get("receipt_id")
        if not isinstance(receipt_id, str) or receipt_id in seen_receipt_ids:
            continue
        merged.append({**row, _RECEIPT_COMMAND_DETAIL_BACKFILL_FLAG: True})
        seen_receipt_ids.add(receipt_id)
        added += 1
    backfill_rowids: list[int] = []
    for row in backfill_rows:
        receipt_rowid = row.get("receipt_rowid")
        if isinstance(receipt_rowid, int):
            backfill_rowids.append(receipt_rowid)
    next_before_rowid = min(backfill_rowids) if backfill_rowids else before_rowid
    complete = len(backfill_rows) < _RECEIPT_COMMAND_DETAIL_BACKFILL_LIMIT
    return merged, {
        "level": redaction_level,
        "updated_at": synced_at,
        "days": _RECEIPT_COMMAND_DETAIL_BACKFILL_DAYS,
        "limit": _RECEIPT_COMMAND_DETAIL_BACKFILL_LIMIT,
        "receipts": added,
        "queried": len(backfill_rows),
        "before_rowid": next_before_rowid,
        "complete": complete,
    }


def _receipt_command_detail_backfill_before_rowid(marker: object, *, redaction_level: str) -> int | None:
    if not isinstance(marker, dict) or marker.get("level") != redaction_level:
        return None
    value = marker.get("before_rowid")
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    if isinstance(value, str) and value.strip().isdigit():
        parsed = int(value.strip())
        return parsed if parsed > 0 else None
    return None


def _advance_command_detail_backfill_marker(
    marker: dict[str, object] | None,
    *,
    receipt_batch: Sequence[Mapping[str, object]],
    synced_at: str,
) -> dict[str, object] | None:
    if marker is None:
        return None
    backfill_rowids = [
        receipt_rowid
        for item in receipt_batch
        if item.get(_RECEIPT_COMMAND_DETAIL_BACKFILL_FLAG) is True
        and isinstance((receipt_rowid := item.get("receipt_rowid")), int)
    ]
    if not backfill_rowids:
        return None
    updated_marker = dict(marker)
    updated_marker["before_rowid"] = min(backfill_rowids)
    updated_marker["updated_at"] = synced_at
    return updated_marker


def _receipt_sync_cursor_rowids_from_batch(
    receipt_batch: Sequence[Mapping[str, object]],
    *,
    cursor_receipt_ids: set[object],
) -> list[object]:
    return [item.get("receipt_rowid") for item in receipt_batch if item.get("receipt_id") in cursor_receipt_ids]


def _validated_policy_bundle_acknowledgement(
    store: GuardStore,
    *,
    device_id: str,
    device_name: str,
) -> dict[str, object] | None:
    policy_bundle = validated_synced_policy_bundle(store)
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    if policy_bundle is None or not isinstance(acknowledgement, dict):
        return None

    bundle_hash = non_empty_string(policy_bundle.get("bundleHash"))
    bundle_version = non_empty_string(policy_bundle.get("bundleVersion"))
    if bundle_hash is None or bundle_version is None:
        return None
    if acknowledgement.get("bundleHash") != bundle_hash:
        return None
    if acknowledgement.get("bundleVersion") != bundle_version:
        return None
    if acknowledgement.get("deviceId") != device_id:
        return None
    if acknowledgement.get("deviceName") != device_name:
        return None
    if acknowledgement.get("status") != "synced":
        return None
    if _normalized_timestamp_string(acknowledgement.get("appliedAt")) is None:
        return None
    return acknowledgement


def _receipt_sync_context(
    store: GuardStore,
    *,
    local_guard_online_at: str,
    device_id: str | None = None,
    device_name: str | None = None,
) -> dict[str, object]:
    resolved_device_id = device_id
    resolved_device_name = device_name
    if resolved_device_id is None or resolved_device_name is None:
        resolved_device_id, resolved_device_name = _guard_device_metadata(store)
    runtime_summary = store.get_sync_payload("runtime_session_summary")
    runtime_synced_at = (
        _optional_string(runtime_summary.get("runtime_session_synced_at"))
        if isinstance(runtime_summary, dict)
        else None
    )
    runtime_harness = (
        _optional_string(runtime_summary.get("runtime_harness")) if isinstance(runtime_summary, dict) else None
    )
    sync_health = "healthy" if runtime_synced_at is not None else "degraded"
    policy_bundle_ack = _validated_policy_bundle_acknowledgement(
        store,
        device_id=resolved_device_id,
        device_name=resolved_device_name,
    )
    context: dict[str, object] = {
        "deviceId": resolved_device_id,
        "deviceName": resolved_device_name,
        "harness": runtime_harness or "hol-guard",
        "localGuardOnlineAt": local_guard_online_at,
        "syncHealth": sync_health,
    }
    if policy_bundle_ack is not None:
        context["policyBundleAcknowledgement"] = policy_bundle_ack
    if runtime_synced_at is not None:
        context["lastRuntimeSyncAt"] = runtime_synced_at
    return context


def _persist_receipt_sync_cursor(
    *,
    store: GuardStore,
    latest_uploaded_rowid: int | None,
    synced_at: str,
) -> None:
    if latest_uploaded_rowid is None:
        return
    payload: dict[str, object] = {
        "last_rowid": latest_uploaded_rowid,
        "synced_at": synced_at,
    }
    store.set_sync_payload("receipt_sync_cursor", payload, synced_at)


_RECEIPT_REDACTION_LEVEL_RANK: dict[str, int] = {
    "full": 0,
    "partial": 1,
    "none": 2,
}
_RELAXED_RECEIPT_REDACTION_RESYNC_MARKER = "cloud_receipt_redaction_relaxed_resync_v1"
_RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER = "cloud_receipt_command_detail_backfill_v2"
_RECEIPT_COMMAND_DETAIL_BACKFILL_FLAG = "__command_detail_backfill"


def _receipt_redaction_level_rank(level: str | None) -> int:
    if level is None:
        return _RECEIPT_REDACTION_LEVEL_RANK["full"]
    return _RECEIPT_REDACTION_LEVEL_RANK.get(level, _RECEIPT_REDACTION_LEVEL_RANK["full"])


def _stored_cloud_receipt_redaction_level(store: GuardStore) -> str | None:
    payload = store.get_sync_payload("cloud_receipt_redaction_level")
    if not isinstance(payload, dict):
        return None
    level = payload.get("level")
    return level if isinstance(level, str) and level in VALID_RECEIPT_REDACTION_LEVELS else None


def _local_receipt_redaction_level(store: GuardStore) -> str:
    try:
        config = load_guard_config(store.guard_home)
        if config.receipt_redaction_level in VALID_RECEIPT_REDACTION_LEVELS:
            return config.receipt_redaction_level
    except Exception:
        pass
    return "full"


def _persist_cloud_receipt_redaction_level(store: GuardStore, *, level: str, synced_at: str) -> None:
    previous_level = _stored_cloud_receipt_redaction_level(store) or _local_receipt_redaction_level(store)
    if _receipt_redaction_level_rank(level) > _receipt_redaction_level_rank(previous_level):
        store.set_sync_payload(
            "receipt_sync_cursor",
            {
                "last_rowid": 0,
                "synced_at": synced_at,
                "reason": "cloud_receipt_redaction_level_relaxed",
                "receipt_redaction_level": level,
            },
            synced_at,
        )
    store.set_sync_payload(
        "cloud_receipt_redaction_level",
        {"level": level, "updated_at": synced_at},
        synced_at,
    )
    if _receipt_redaction_level_rank(level) > _receipt_redaction_level_rank("full"):
        store.set_sync_payload(
            _RELAXED_RECEIPT_REDACTION_RESYNC_MARKER,
            {"level": level, "updated_at": synced_at},
            synced_at,
        )


def _reset_cloud_receipt_redaction_authority(store: GuardStore, *, synced_at: str) -> None:
    """Reset relaxation bookkeeping when no signed override is effective."""

    store.set_sync_payload(
        "cloud_receipt_redaction_level",
        {"level": _local_receipt_redaction_level(store), "updated_at": synced_at},
        synced_at,
    )
    store.delete_sync_payload(_RELAXED_RECEIPT_REDACTION_RESYNC_MARKER)
    store.delete_sync_payload(_RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER)


def _ensure_relaxed_receipt_redaction_resync(
    store: GuardStore,
    *,
    level: str,
    synced_at: str,
) -> None:
    if _receipt_redaction_level_rank(level) <= _receipt_redaction_level_rank("full"):
        return
    marker = store.get_sync_payload(_RELAXED_RECEIPT_REDACTION_RESYNC_MARKER)
    if isinstance(marker, dict) and marker.get("level") == level:
        return
    store.set_sync_payload(
        "receipt_sync_cursor",
        {
            "last_rowid": 0,
            "synced_at": synced_at,
            "reason": "cloud_receipt_redaction_level_relaxed_existing",
            "receipt_redaction_level": level,
        },
        synced_at,
    )
    store.set_sync_payload(
        _RELAXED_RECEIPT_REDACTION_RESYNC_MARKER,
        {"level": level, "updated_at": synced_at},
        synced_at,
    )


def _resolve_cloud_receipt_redaction_level(store: GuardStore) -> str:
    """Resolve the receipt redaction level for cloud sync.

    A cloud relaxation is authoritative only while its signed policy bundle
    remains valid. The separately persisted level is cursor bookkeeping, not
    an authority source, because it can outlive or be detached from a bundle.
    """
    policy_bundle = validated_synced_policy_bundle(store)
    if policy_bundle is not None:
        level = policy_bundle.get("receiptRedactionLevel")
        if isinstance(level, str) and level in VALID_RECEIPT_REDACTION_LEVELS:
            return level
    return _local_receipt_redaction_level(store)


def _cloud_sync_command_display_part(value: str) -> str:
    return " ".join(_cloud_sync_sanitize_text(value, fallback="").split())


def _cloud_sync_transport_encode_text(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")


def _cloud_sync_receipt_action_command(envelope: dict[str, object], *, redaction_level: str) -> str | None:
    tool_name = _optional_string(envelope.get("tool_name"))
    sanitized_tool_name = _cloud_sync_command_display_part(tool_name) if tool_name is not None else ""
    command = _optional_string(envelope.get("command"))
    if command is not None and command not in {"guard_commands_module"}:
        if redaction_level == "full":
            return sanitized_tool_name or None
        return _cloud_sync_command_display_part(command)
    target_paths = envelope.get("target_paths")
    if sanitized_tool_name and isinstance(target_paths, list):
        raw_targets = [target for target in target_paths[:3] if isinstance(target, str) and target.strip()]
        if raw_targets and redaction_level == "full":
            target_placeholder = "[targets withheld]" if len(raw_targets) > 1 else "[target withheld]"
            return " ".join([sanitized_tool_name, target_placeholder])
        targets = [_cloud_sync_command_display_part(target) for target in raw_targets]
        targets = [target for target in targets if target]
        if targets:
            return " ".join([sanitized_tool_name, *targets])
        return sanitized_tool_name
    return None


def _cloud_sync_receipt_payload(
    receipt: dict[str, object],
    *,
    device_id: str,
    device_name: str,
    redaction_level: str = "full",
) -> dict[str, object]:
    receipt_fingerprint = _cloud_sync_receipt_fingerprint(receipt)
    artifact_id = _optional_string(receipt.get("artifact_id")) or f"guard:local-receipt:{receipt_fingerprint[:24]}"
    artifact_name = _optional_string(receipt.get("artifact_name")) or artifact_id
    policy_decision = _optional_string(receipt.get("policy_decision")) or "review"
    capabilities_summary = _optional_string(receipt.get("capabilities_summary"))
    explicit_capabilities = receipt.get("capabilities")
    if isinstance(explicit_capabilities, list):
        capabilities = [
            _cloud_sync_sanitize_text(item, fallback="redacted-capability")
            for item in explicit_capabilities
            if isinstance(item, str)
        ]
    else:
        capabilities = []
    summary_input = (
        _optional_string(receipt.get("provenance_summary"))
        or capabilities_summary
        or f"Guard recorded a {policy_decision} decision."
    )
    summary = _cloud_sync_sanitize_text(summary_input, fallback=f"Guard recorded a {policy_decision} decision.")
    explicit_changed_since_last_approval = receipt.get("changedSinceLastApproval")
    if not isinstance(explicit_changed_since_last_approval, bool):
        explicit_changed_since_last_approval = receipt.get("changed_since_last_approval")
    changed_since_last_approval = explicit_changed_since_last_approval is True
    # Review-tier decisions always remain changed, even if an explicit false is present.
    if policy_decision in {"review", "require-reapproval", "sandbox-required"}:
        changed_since_last_approval = True
    payload: dict[str, object] = {
        "receiptId": _optional_string(receipt.get("receipt_id")) or f"guard-receipt-{receipt_fingerprint}",
        "artifactId": artifact_id,
        "artifactName": artifact_name,
        "artifactType": _cloud_sync_artifact_type(artifact_id),
        "artifactSlug": _cloud_sync_artifact_slug(artifact_name, artifact_id),
        "artifactHash": _optional_string(receipt.get("artifact_hash"))
        or hashlib.sha256(artifact_id.encode("utf-8")).hexdigest(),
        "capabilities": capabilities,
        "capturedAt": _optional_string(receipt.get("timestamp")) or _now(),
        "changedSinceLastApproval": changed_since_last_approval,
        "deviceId": device_id,
        "deviceName": device_name,
        "harness": _optional_string(receipt.get("harness")) or "unknown",
        "policyDecision": policy_decision,
        "recommendation": _cloud_sync_recommendation(policy_decision),
        "summary": summary,
    }
    raw_command_text = _optional_string(receipt.get("raw_command_text"))
    if raw_command_text is not None:
        payload["raw_command_text"] = _cloud_sync_command_display_part(raw_command_text)
    publisher = _optional_string(receipt.get("publisher"))
    if publisher is not None:
        payload["publisher"] = publisher
    redacted_envelope = receipt.get("envelope_redacted_json")
    if isinstance(redacted_envelope, dict) and redacted_envelope:
        full_envelope = receipt.get("action_envelope_json")
        if isinstance(full_envelope, dict):
            enriched = dict(redacted_envelope)
            command = _cloud_sync_receipt_action_command(full_envelope, redaction_level=redaction_level)
            if command is not None:
                enriched.pop("command", None)
                enriched["commandEncoded"] = _cloud_sync_transport_encode_text(command)
                enriched["commandTransport"] = "base64url-v1"
            if redaction_level == "none":
                target_paths = full_envelope.get("target_paths")
                if isinstance(target_paths, list):
                    enriched["target_paths"] = target_paths
                network_hosts = full_envelope.get("network_hosts")
                if isinstance(network_hosts, list):
                    enriched["network_hosts"] = network_hosts
                package_name = full_envelope.get("package_name")
                if isinstance(package_name, str) and package_name:
                    enriched["package_name"] = package_name
            payload["envelopeRedacted"] = enriched
        else:
            payload["envelopeRedacted"] = redacted_envelope
    return payload


def _cloud_runtime_session_payload(store: GuardStore, session: dict[str, object]) -> dict[str, object]:
    device_id, device_name = _guard_device_metadata(store)
    workspace = _optional_string(session.get("workspace")) or os.getcwd()
    session_id = (
        _optional_string(session.get("session_id") or session.get("sessionId"))
        or hashlib.sha256(f"{device_id}:{workspace}".encode()).hexdigest()[:24]
    )
    created_at = _optional_string(session.get("created_at") or session.get("createdAt")) or _now()
    updated_at = _optional_string(session.get("updated_at") or session.get("updatedAt")) or created_at
    capabilities = list(_string_items(session.get("capabilities")))
    package_manager_coverage = _cloud_package_manager_coverage(
        store,
        workspace=workspace,
        generated_at=updated_at,
    )
    local_identity = _cloud_local_identity_payload(observed_at=updated_at)
    return {
        "sessionId": session_id,
        "harness": _optional_string(session.get("harness")) or "hol-guard",
        "surface": _optional_string(session.get("surface")) or "cli",
        "status": _optional_string(session.get("status")) or "active",
        "clientName": _optional_string(session.get("client_name") or session.get("clientName")) or "hol-guard",
        "clientTitle": _optional_string(session.get("client_title") or session.get("clientTitle"))
        or f"HOL Guard on {device_name}",
        "clientVersion": _optional_string(session.get("client_version") or session.get("clientVersion")) or __version__,
        "deviceId": device_id,
        "deviceName": device_name,
        "localIdentity": local_identity,
        "localIdentitySource": _cloud_local_identity_source_payload(local_identity),
        "packageManagerCoverage": package_manager_coverage,
        "workspace": workspace,
        "capabilities": capabilities,
        "operations": [],
        "createdAt": created_at,
        "updatedAt": updated_at,
    }


def _cloud_local_identity_payload(*, observed_at: str) -> dict[str, object]:
    hostname = _safe_hostname()
    private_ip = _safe_private_ip()
    if private_ip is None:
        private_ip = _safe_private_ipv6()
    payload: dict[str, object] = {"lastSyncedAt": observed_at}
    if hostname is not None:
        payload["hostname"] = hostname
    if private_ip is not None:
        payload["ipAddress"] = private_ip
        payload["privateIpAddress"] = private_ip
    return payload


def _cloud_local_identity_source_payload(local_identity: dict[str, object]) -> dict[str, str]:
    source: dict[str, str] = {
        "daemonId": "local-guard",
        "daemonVersion": "local-guard",
        "daemonStatus": "local-guard",
        "relayState": "local-guard",
    }
    if "hostname" in local_identity:
        source["hostname"] = "local-guard"
    if "ipAddress" in local_identity:
        source["ipAddress"] = "local-guard"
    if "privateIpAddress" in local_identity:
        source["privateIpAddress"] = "local-guard"
    if "publicIpAddress" in local_identity:
        source["publicIpAddress"] = "local-guard"
    return source


def _safe_hostname() -> str | None:
    with suppress(OSError):
        hostname = socket.gethostname().strip()
        if hostname:
            return hostname[:255]
    return None


def _safe_private_ip() -> str | None:
    with suppress(OSError), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))
        address = sock.getsockname()[0]
        if isinstance(address, str) and address and not address.startswith("127."):
            return address[:128]
    with suppress(OSError):
        address = socket.gethostbyname(socket.gethostname())
        if address and not address.startswith("127."):
            return address[:128]
    return None


def _safe_private_ipv6() -> str | None:
    with suppress(OSError):
        addresses = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6)
        for entry in addresses:
            candidate = entry[4][0]
            if isinstance(candidate, str) and candidate and candidate != "::1":
                return candidate[:128]
    return None


def _cloud_sync_receipt_fingerprint(receipt: dict[str, object]) -> str:
    encoded_receipt = json.dumps(receipt, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded_receipt.encode("utf-8")).hexdigest()


def _cloud_package_manager_coverage(
    store: GuardStore,
    *,
    workspace: str,
    generated_at: str,
) -> dict[str, object]:
    coverage = package_shim_cloud_coverage(
        HarnessContext(
            home_dir=Path.home(),
            workspace_dir=Path(workspace),
            guard_home=store.guard_home,
        ),
        generated_at=generated_at,
    )
    synced_at = None
    next_refresh_at = None
    synced_timestamp = None
    for source_name, summary in (
        ("sync", store.get_sync_payload("sync_summary")),
        ("runtime", store.get_sync_payload("runtime_session_summary")),
        ("bundle", store.get_sync_payload("supply_chain_bundle_summary")),
    ):
        if not isinstance(summary, dict):
            continue
        candidate_synced_at = _optional_string(
            summary.get("synced_at")
            or summary.get("syncedAt")
            or summary.get("runtime_session_synced_at")
            or summary.get("runtimeSessionSyncedAt")
            or summary.get("local_guard_online_at"),
        )
        candidate_timestamp = _parse_iso_timestamp(candidate_synced_at) if candidate_synced_at is not None else None
        if candidate_timestamp is None:
            continue
        if synced_timestamp is not None and candidate_timestamp <= synced_timestamp:
            continue
        synced_at = candidate_synced_at
        synced_timestamp = candidate_timestamp
        next_refresh_at = (
            _optional_string(summary.get("next_refresh_at") or summary.get("nextRefreshAt"))
            if source_name == "bundle"
            else None
        )
    reference_timestamp = _parse_iso_timestamp(generated_at) or datetime.now(timezone.utc)
    stale_status = "unknown"
    if synced_at is not None:
        stale_status = "fresh"
    next_refresh_timestamp = _parse_iso_timestamp(next_refresh_at) if next_refresh_at is not None else None
    if next_refresh_timestamp is None and synced_at is not None:
        next_refresh_timestamp = _parse_iso_timestamp(synced_at)
        if next_refresh_timestamp is not None:
            next_refresh_timestamp += timedelta(minutes=15)
            next_refresh_at = next_refresh_timestamp.isoformat()
    if next_refresh_timestamp is not None and next_refresh_timestamp <= reference_timestamp:
        stale_status = "stale"
    coverage["staleIntel"] = {
        "status": stale_status,
        "lastSyncedAt": synced_at,
        "nextRefreshAt": next_refresh_at,
    }
    return coverage


def _cloud_sync_artifact_type(artifact_id: str) -> str:
    if artifact_id.startswith("skill:") or ":skill:" in artifact_id:
        return "skill"
    return "plugin"


def _cloud_sync_artifact_slug(artifact_name: str, artifact_id: str) -> str:
    base_value = artifact_name.strip() or artifact_id.strip() or "artifact"
    slug = re.sub(r"[^a-z0-9]+", "-", base_value.lower()).strip("-")
    if slug:
        return slug
    fallback = re.sub(r"[^a-z0-9]+", "-", artifact_id.lower()).strip("-")
    return fallback or "artifact"


def _cloud_sync_recommendation(policy_decision: str) -> str:
    if policy_decision == "block":
        return "block"
    if policy_decision in {"review", "require-reapproval", "sandbox-required"}:
        return "review"
    return "monitor"


def _cloud_sync_sanitize_text(value: str, *, fallback: str) -> str:
    redacted = redact_sensitive_text(value).strip()
    if not redacted:
        return fallback
    if _looks_like_source_excerpt(redacted):
        return fallback
    if len(redacted) > 320:
        return f"{redacted[:317]}..."
    return redacted


def _looks_like_source_excerpt(value: str) -> bool:
    lowered = value.lower()
    suspicious_tokens = (
        "function ",
        "def ",
        "class ",
        "import ",
        "from ",
        " => ",
        "console.log(",
        "<script",
        "#!/bin/",
    )
    has_structured_code_shape = "\n" in value and ("{" in value or "}" in value or ";" in value)
    return has_structured_code_shape or any(token in lowered for token in suspicious_tokens)


def _guard_device_metadata(store: GuardStore) -> tuple[str, str]:
    metadata = store.get_device_metadata()
    return str(metadata["installation_id"]), str(metadata["device_label"])


def _record_synced_alert_events(
    *,
    store: GuardStore,
    advisories: Sequence[dict[str, object]],
    alert_preferences: dict[str, object] | None,
    exceptions: Sequence[dict[str, object]],
    now: str,
) -> None:
    advisories_enabled = not (
        isinstance(alert_preferences, dict) and alert_preferences.get("advisoriesEnabled") is False
    )
    if advisories_enabled:
        for item in advisories:
            artifact_id = _optional_string(item.get("artifactId"))
            if artifact_id is None:
                continue
            store.add_event(
                "premium_advisory",
                {
                    "artifact_id": artifact_id,
                    "artifact_name": _optional_string(item.get("artifactName")) or artifact_id,
                    "severity": _optional_string(item.get("severity")),
                    "reason": _optional_string(item.get("reason")),
                },
                now,
            )
    current_time = _parse_iso_timestamp(now)
    for item in exceptions:
        artifact_id = _optional_string(item.get("artifactId"))
        expires_at = _optional_string(item.get("expiresAt"))
        if artifact_id is None or expires_at is None:
            continue
        expiry_time = _parse_iso_timestamp(expires_at)
        if expiry_time is None or current_time is None:
            continue
        if (
            expiry_time <= current_time
            or (expiry_time - current_time).total_seconds() > _EXCEPTION_EXPIRY_ALERT_WINDOW_HOURS * 60 * 60
        ):
            continue
        store.add_event(
            "exception_expiring",
            {
                "artifact_id": artifact_id,
                "artifact_name": _optional_string(item.get("artifactName")) or artifact_id,
                "expires_at": expires_at,
                "reason": _optional_string(item.get("reason")),
                "owner": _optional_string(item.get("owner")),
            },
            now,
        )


def _sync_timestamp(payload: dict[str, object]) -> str:
    synced_at = _optional_string(payload.get("syncedAt"))
    if synced_at is not None and _parse_iso_timestamp(synced_at) is not None:
        return synced_at
    return _now()


def _parse_iso_timestamp(value: str) -> datetime | None:
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
