"""Shared local supply-chain posture and CLI helpers."""

from __future__ import annotations

import importlib
import inspect
import json
import os
import shlex
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, cast
from uuid import uuid4

from .action_lattice import most_restrictive_guard_action, normalize_guard_action
from .adapters.base import HarnessContext
from .approval_scope_support import package_request_runtime_workspace_scope
from .cloud_audit_request import build_cloud_workspace_audit_request
from .config import GuardConfig
from .mdm.network import managed_urlopen
from .models import GuardAction, GuardArtifact
from .native_mcp_proxy_decision import (
    NativeMcpProxyDecisionError,
    native_external_archive_bind,
    native_external_archive_binding_required,
)
from .native_package_approval_hash import native_package_approval_hash
from .native_package_audit_projection import (
    native_batch_url,
    native_cloud_audit_payload,
    native_managed_workspaces,
)
from .native_package_policy_resolve import native_resolve_stored_package_policy
from .native_package_protect_finalize import native_finalize_package_protect, package_protect_stored_policy
from .native_package_protect_projection import (
    NativePackageProtectProjection,
    native_package_protect_projection,
)
from .native_shim_admin import NativeShimAdminError
from .native_supply_chain_posture import native_local_supply_chain_posture
from .native_workspace_inventory import native_workspace_inventory
from .package_execution_context import PackageExecutionContext, build_package_execution_context
from .redaction import redact_text
from .runtime.approval_context import (
    build_runtime_launch_identity,
    resolved_runtime_launch_argv,
    runtime_launch_identity_is_reusable,
)
from .runtime.approval_reuse import evaluate_approval_reuse
from .runtime.package_execution_policy import is_execution_permitted
from .runtime.package_intent_common import (
    PackageIntent,
    build_package_request_artifact,
    redact_package_request_token,
)
from .runtime.package_protect_projection import (
    LOCAL_SUPPLY_CHAIN_HARNESS as _LOCAL_SUPPLY_CHAIN_HARNESS,
)
from .runtime.package_protect_projection import (
    resolve_local_supply_chain_harness as _resolve_local_supply_chain_harness,
)
from .runtime.restricted_archive_download import RestrictedArchiveDownload
from .shims import package_shim_protection, package_shim_supported_managers
from .store import GuardStore
from .store_guard_home_binding import binds_store_guard_home

_MANIFEST_CANDIDATES = (
    "package.json",
    "requirements.txt",
    "constraints.txt",
    "pyproject.toml",
    "Pipfile",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "Gemfile",
)
_PACKAGE_MANAGER_BY_ECOSYSTEM = {
    "npm": "npm",
    "pypi": "pip",
    "cargo": "cargo",
    "go": "go",
    "maven": "maven",
    "packagist": "composer",
    "rubygems": "bundle",
    "docker": "docker",
    "system": "system",
    "unsupported": "unsupported",
}
_ECOSYSTEM_BY_MANIFEST = {
    "package.json": "npm",
    "requirements.txt": "pypi",
    "constraints.txt": "pypi",
    "pyproject.toml": "pypi",
    "Pipfile": "pypi",
    "Cargo.toml": "cargo",
    "go.mod": "go",
    "pom.xml": "maven",
    "build.gradle": "maven",
    "build.gradle.kts": "maven",
    "composer.json": "packagist",
    "Gemfile": "rubygems",
}
_CLOUD_AUDIT_TIMEOUT_SECONDS = 20
_CLOUD_AUDIT_JOB_PAGE_SIZE = 1
_CLOUD_AUDIT_JOB_POLL_INTERVAL_SECONDS = 0.5
_CLOUD_AUDIT_JOB_POLL_TIMEOUT_SECONDS = 20
_CLOUD_AUDIT_SYNC_PAGE_SIZE = 25
_PACKAGE_FIREWALL_REFRESH_MIN_INTERVAL_SECONDS = 300.0
_PACKAGE_FIREWALL_REFRESH_STATE_FILE = "package-firewall-refresh.json"
_PACKAGE_FIREWALL_REFRESH_LOCK = threading.Lock()


def _runtime_runner_module():
    return importlib.import_module(".runtime.runner", __package__)


_LAZY_RUNTIME_RUNNER_EXPORTS = frozenset(
    {
        "GuardSyncAuthorizationExpiredError",
        "GuardSyncNotAvailableError",
        "GuardSyncNotConfiguredError",
    }
)


def __getattr__(name: str) -> Any:
    if name in _LAZY_RUNTIME_RUNNER_EXPORTS:
        return getattr(_runtime_runner_module(), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _package_firewall_entitlement_module():
    return importlib.import_module(".package_firewall_entitlement", __package__)


def _native_package_authority_module():
    return importlib.import_module(".native_package_authority", __package__)


def _native_supply_chain_eval_module():
    return importlib.import_module(".native_supply_chain_eval", __package__)


def compose_blocking_package_evaluation(kind: str, evaluation: Any, **facts: object) -> Any:
    """Resident-owned rewrite on a blocking path; a resident failure yields a terminal block."""

    module = importlib.import_module(".native_package_evaluation_compose", __package__)
    return module.compose_blocking_package_evaluation(kind, evaluation, **facts)


def sync_local_guard_cloud_proof(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    return _runtime_runner_module().sync_local_guard_cloud_proof(store, auth_context=auth_context)


def sync_supply_chain_bundle(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object] | None:
    return _runtime_runner_module().sync_supply_chain_bundle(store, auth_context=auth_context)


def _resolve_guard_sync_auth_context(store: GuardStore):
    return _runtime_runner_module()._resolve_guard_sync_auth_context(store)


def evaluate_package_request_artifact(
    *,
    artifact: GuardArtifact,
    store: GuardStore,
    workspace_dir: Path | None,
    now: str | None = None,
    external_archive_network_authorized: bool = False,
    retain_external_archive_blob: bool = False,
):
    """Evaluate a package request in the resident, which owns every verdict.

    The signed bundle, synced policy rules, the Cloud service call, the
    external-archive review and the fail-closed ladder are all decided in Rust;
    the caller only moves bytes. With ``retain_external_archive_blob`` the
    evaluation carries the verified blobs the caller keeps for a reviewed launch
    (RTM-029/030).
    """
    return _native_supply_chain_eval_module().evaluate_package_request_native(
        artifact=artifact,
        store=store,
        workspace_dir=workspace_dir,
        now=now,
        external_archive_network_authorized=external_archive_network_authorized,
        retain_external_archive_blob=retain_external_archive_blob,
    )


def _parse_package_intent_native(
    raw_command: str,
    *,
    environment: Mapping[str, str] | None,
    workspace: Path | None,
    guard_home: Path,
) -> PackageIntent | None:
    """Ask the resident ``package_intent_parse`` op for the command's intent.

    ``None`` means the resident found no package intent. An unreachable
    resident or an unusable answer raises ``NativeProtectRequestError``, so
    the wrapped install fails closed instead of skipping the package firewall.
    """
    from .native_protect_request import NativeProtectRequestError

    try:
        intent = _native_package_authority_module().package_intent_parse_native(
            raw_command,
            workspace=workspace,
            environment=dict(environment) if environment is not None else None,
            guard_home=guard_home,
            require_answer=True,
        )
    except Exception as error:
        raise NativeProtectRequestError("native_package_intent_unavailable") from error
    if intent is None or isinstance(intent, PackageIntent):
        return intent
    raise NativeProtectRequestError("native_package_intent_malformed")


def _package_firewall_refresh_state_path(guard_home: Path) -> Path:
    return guard_home / _PACKAGE_FIREWALL_REFRESH_STATE_FILE


def _read_package_firewall_refresh_state(guard_home: Path) -> dict[str, object]:
    path = _package_firewall_refresh_state_path(guard_home)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_package_firewall_refresh_state(guard_home: Path, last_attempt: float) -> None:
    path = _package_firewall_refresh_state_path(guard_home)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        tmp_path.write_text(
            json.dumps({"last_refresh_attempt_at": last_attempt}, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        tmp_path.replace(path)
    finally:
        if tmp_path.exists():
            with suppress(OSError):
                tmp_path.unlink()


def build_local_supply_chain_posture(
    store: Any,
    config: GuardConfig,
    *,
    now: str | None = None,
) -> dict[str, object]:
    return native_local_supply_chain_posture(
        store,
        config,
        now=now,
        package_manager_protection=_build_package_manager_protection(store),
    )


def build_supply_chain_status_payload(
    *,
    store: Any,
    config: GuardConfig,
    now: str,
) -> dict[str, object]:
    posture = build_local_supply_chain_posture(store, config, now=now)
    return {
        "generated_at": now,
        "mode": "status",
        "executed": False,
        "dry_run": True,
        "supply_chain": posture,
    }


def _call_sync_with_optional_auth_context(
    refresh: Any,
    *,
    store: Any,
    auth_context: dict[str, object],
) -> dict[str, object]:
    try:
        parameters = inspect.signature(refresh).parameters
    except (TypeError, ValueError):
        parameters = {}
    if "auth_context" in parameters:
        return refresh(store, auth_context=auth_context)
    return refresh(store)


def resolve_package_firewall_entitlement_with_refresh(store: Any) -> dict[str, object]:
    """Resolve package-firewall access and opportunistically heal stale cloud state."""

    entitlement_module = _package_firewall_entitlement_module()
    runner = _runtime_runner_module()

    entitlement = entitlement_module.package_firewall_entitlement_or_denied(store)
    if bool(entitlement.get("allowed")):
        return entitlement
    if store.get_cloud_sync_profile() is None:
        return entitlement
    if str(entitlement.get("reason") or "") not in {
        "guard_cloud_connect_required",
        "guard_cloud_reconnect_required",
        "paid_guard_cloud_required",
    }:
        return entitlement
    now_iso = datetime.now(timezone.utc).isoformat()
    now = time.time()
    with _PACKAGE_FIREWALL_REFRESH_LOCK:
        state = _read_package_firewall_refresh_state(store.guard_home)
        last_refresh_at = state.get("last_refresh_attempt_at")
        if (
            isinstance(last_refresh_at, (int, float))
            and (now - float(last_refresh_at)) < _PACKAGE_FIREWALL_REFRESH_MIN_INTERVAL_SECONDS
        ):
            return entitlement
        _write_package_firewall_refresh_state(store.guard_home, now)
    auth_context: dict[str, object] | None = None
    try:
        auth_context = _resolve_guard_sync_auth_context(store)
    except (runner.GuardSyncAuthorizationExpiredError, runner.GuardSyncNotAvailableError):
        auth_context = None
    except (runner.GuardSyncNotConfiguredError, OSError, RuntimeError):
        auth_context = None
    for refresh in (sync_local_guard_cloud_proof, sync_supply_chain_bundle):
        try:
            if auth_context is None:
                refresh(store)
            else:
                _call_sync_with_optional_auth_context(
                    refresh,
                    store=store,
                    auth_context=auth_context,
                )
        except runner.GuardSyncAuthorizationExpiredError as error:
            if str(entitlement.get("reason") or "") == "guard_cloud_connect_required":
                store.record_latest_guard_connect_sync_result(
                    status="retry_required",
                    milestone="first_sync_failed",
                    now=now_iso,
                    reason=str(error),
                )
            break
        except (runner.GuardSyncNotAvailableError, runner.GuardSyncNotConfiguredError, OSError, RuntimeError):
            continue
    return entitlement_module.package_firewall_entitlement_or_denied(store)


def _workspace_has_project_markers(workspace_dir: Path) -> bool:
    try:
        resolved = workspace_dir.resolve()
    except OSError:
        return False
    return any((resolved / marker).exists() for marker in _MANIFEST_CANDIDATES)


def managed_install_audit_workspace_dirs(store: Any) -> tuple[str, ...]:
    return native_managed_workspaces(store, candidates=False)


@dataclass(frozen=True, slots=True)
class _PackageProtectAuthority:
    intent: PackageIntent
    artifact: GuardArtifact
    evaluation: Any
    current_action: GuardAction
    execution_context: PackageExecutionContext
    artifact_hash: str
    launch_identity: dict[str, object]
    launch_cwd: Path
    launch_environment: Mapping[str, str]
    additional_current_action: object | None
    additional_policy_context: dict[str, object] | None
    observe_mode: bool
    invoking_harness: str = field(default_factory=_resolve_local_supply_chain_harness)


_PackageApprovalClaimDisposition = Literal["consumed", "retained"]


@dataclass(frozen=True, slots=True)
class _StoredPackagePolicyResolution:
    evaluation: Any
    approval_reuse_decision: Mapping[str, object] | None = None
    claim_disposition: _PackageApprovalClaimDisposition | None = None


def _external_archive_downloads(evaluation: object) -> tuple[RestrictedArchiveDownload, ...]:
    value = getattr(evaluation, "external_archive_downloads", ())
    if not isinstance(value, tuple):
        return ()
    return tuple(item for item in value if isinstance(item, RestrictedArchiveDownload))


def _cleanup_external_archive_downloads(evaluation: object) -> None:
    for download in _external_archive_downloads(evaluation):
        download.cleanup()


def _package_evaluation_requires_external_archive_binding(evaluation: object, *, guard_home: Path) -> bool:
    """Whether this evaluation only permits a request bound to its verified archives."""

    return native_external_archive_binding_required(evaluation, guard_home=guard_home)


def _bound_external_archive_launch_command(
    launch_command: Sequence[str],
    *,
    evaluation: object,
    guard_home: Path,
) -> list[str] | None:
    """The launch argv bound to the resident-verified archives, or ``None`` (deny)."""

    downloads = _external_archive_downloads(evaluation)
    requires_binding = _package_evaluation_requires_external_archive_binding(evaluation, guard_home=guard_home)
    if not downloads:
        return None if requires_binding else list(launch_command)
    try:
        bound = native_external_archive_bind(
            [str(item) for item in launch_command],
            downloads,
            requires_binding=requires_binding,
            guard_home=guard_home,
        )
    except NativeMcpProxyDecisionError:
        return None
    return bound if isinstance(bound, list) else None


def _package_manager_launch_environment(
    environment: Mapping[str, str],
    *,
    guard_home: Path,
    launch_cwd: Path,
) -> dict[str, str]:
    """Exclude Guard's interception shim from the reviewed and executed package-manager path."""

    launch_environment = dict(environment)
    try:
        shim_dir = (guard_home / "package-shims" / "bin").expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        raise ValueError("Guard's package shim path could not be verified") from None
    path_entries = environment.get("PATH", "").split(os.pathsep)
    filtered_entries: list[str] = []
    for entry in path_entries:
        if not entry:
            continue
        try:
            path_entry = Path(entry).expanduser()
            if not path_entry.is_absolute():
                path_entry = launch_cwd / path_entry
            resolved_entry = path_entry.resolve()
        except (OSError, RuntimeError, ValueError):
            raise ValueError("package manager PATH could not be verified") from None
        if resolved_entry != shim_dir:
            filtered_entries.append(entry)
    launch_environment["PATH"] = os.pathsep.join(filtered_entries)
    return launch_environment


@binds_store_guard_home
def _build_package_protect_authority(
    *,
    command: Sequence[str],
    store: Any,
    workspace_dir: Path,
    now: str,
    config: GuardConfig | None,
    additional_current_action: object | None,
    additional_policy_context: dict[str, object] | None,
    external_archive_network_authorized: bool = False,
    invoking_harness: str | None = None,
) -> _PackageProtectAuthority | None:
    try:
        launch_cwd = workspace_dir.expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError("package workspace must resolve to an existing directory") from None
    if not launch_cwd.is_dir():
        raise ValueError("package workspace must resolve to an existing directory")
    from .native_policy_snapshot_publisher import provision_native_verifier_key_for_store

    provision_native_verifier_key_for_store(store)
    launch_environment = _package_manager_launch_environment(
        os.environ,
        guard_home=store.guard_home,
        launch_cwd=launch_cwd,
    )
    intent = _parse_package_intent_native(
        shlex.join(command),
        environment=launch_environment,
        workspace=launch_cwd,
        guard_home=store.guard_home,
    )
    if intent is None:
        return None
    sanitized_intent = replace(intent, redacted_command=shlex.join(redacted_command_tokens(command)))
    artifact = build_package_request_artifact(
        _LOCAL_SUPPLY_CHAIN_HARNESS,
        sanitized_intent,
        config_path="hol-guard.toml",
        source_scope="project",
        guard_home=store.guard_home,
    )
    evaluation = evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=launch_cwd,
        now=now,
        external_archive_network_authorized=external_archive_network_authorized,
        retain_external_archive_blob=external_archive_network_authorized,
    )
    try:
        executable = sanitized_intent.command_tokens[0] if sanitized_intent.command_tokens else None
        executable_args = sanitized_intent.command_tokens[1:] if executable is not None else ()
        if sanitized_intent.command_tokens and ";" in sanitized_intent.command_tokens:
            executable = None
            executable_args = ()
        execution_context = build_package_execution_context(
            workspace_dir=launch_cwd,
            artifact=artifact,
            executable=executable,
            executable_args=executable_args,
            environment=launch_environment,
        )
        launch_identity = build_runtime_launch_identity(
            str(command[0]) if command else None,
            args=tuple(str(item) for item in command[1:]),
            structured_command=True,
            direct_executable=True,
            cwd=launch_cwd,
            launch_env=launch_environment,
        )
        if command and executable is not None and str(command[0]) != executable:
            launch_identity["wrapper_resolution"] = {
                "reason": "package_command_wrapper_unresolved",
                "reuse_nonce": uuid4().hex,
                "status": "unproven",
            }
        current_action, artifact_hash = package_current_action_and_hash(
            artifact,
            workspace_dir=launch_cwd,
            store=store,
            evaluation=evaluation,
            execution_context=execution_context,
            launch_identity=launch_identity,
            config=config,
            additional_current_action=additional_current_action,
            additional_policy_context=additional_policy_context,
        )
        return _PackageProtectAuthority(
            invoking_harness=invoking_harness
            if invoking_harness is not None
            else _resolve_local_supply_chain_harness(),
            intent=sanitized_intent,
            artifact=artifact,
            evaluation=evaluation,
            current_action=current_action,
            execution_context=execution_context,
            artifact_hash=artifact_hash,
            launch_identity=launch_identity,
            launch_cwd=launch_cwd,
            launch_environment=launch_environment,
            additional_current_action=additional_current_action,
            additional_policy_context=additional_policy_context,
            observe_mode=config is not None and config.mode == "observe",
        )
    except BaseException:
        _cleanup_external_archive_downloads(evaluation)
        raise


@binds_store_guard_home
def _final_package_protect_authority(
    *,
    initial: _PackageProtectAuthority,
    initial_saved_evaluation: Any,
    saved_approval_pending: bool,
    command: Sequence[str],
    store: Any,
    workspace_dir: Path,
    now: str,
    config: GuardConfig | None,
    current_config_provider: Callable[[], GuardConfig] | None,
    additional_authority_provider: Callable[[], tuple[object | None, dict[str, object] | None]] | None,
) -> tuple[_PackageProtectAuthority, Any]:
    """Refresh mode, claim required approval, then rebuild authority before spawn."""

    additional_action: object | None = initial.additional_current_action
    additional_context: dict[str, object] | None = initial.additional_policy_context
    current_config = config
    config_refresh_failed = False
    if current_config_provider is not None:
        try:
            current_config = current_config_provider()
            if not isinstance(current_config, GuardConfig):
                raise TypeError("current config provider returned an invalid value")
        except Exception:
            config_refresh_failed = True
    saved_approval_claimed = False
    saved_approval_claim_disposition: _PackageApprovalClaimDisposition | None = None
    saved_approval_claim_failure: Any | None = None
    if (
        saved_approval_pending
        and not config_refresh_failed
        and (current_config is None or current_config.mode != "observe")
    ):
        claimed_resolution = _resolve_stored_package_policy_override(
            initial_saved_evaluation,
            store=store,
            artifact=initial.artifact,
            artifact_hash=initial.artifact_hash,
            workspace_dir=workspace_dir,
            now=now,
            execution_context=initial.execution_context,
            current_action=initial.current_action,
            claim_saved_approval=True,
        )
        claimed_action = _protect_action_for_policy_action(claimed_resolution.evaluation.policy_action)
        if not is_execution_permitted(claimed_action):
            saved_approval_claim_failure = claimed_resolution.evaluation
        else:
            saved_approval_claimed = True
            saved_approval_claim_disposition = claimed_resolution.claim_disposition
    if additional_authority_provider is not None:
        try:
            additional_action, additional_context = additional_authority_provider()
        except Exception as error:
            additional_action = "block"
            additional_context = {
                "available": False,
                "error": type(error).__name__,
                "status": "authority_refresh_failed",
                "version": 1,
            }
    if config_refresh_failed:
        additional_action = most_restrictive_guard_action(
            additional_action,
            "block",
            unknown_action="block",
        )
        additional_context = {
            "additional": additional_context,
            "available": False,
            "reason_code": "package_config_refresh_failed",
            "status": "authority_refresh_failed",
            "version": 1,
        }
    current = _build_package_protect_authority(
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        now=now,
        config=current_config,
        additional_current_action=additional_action,
        additional_policy_context=additional_context,
        external_archive_network_authorized=saved_approval_claimed,
        invoking_harness=initial.invoking_harness,
    )
    stored_policy = None
    if (
        current is not None
        and saved_approval_claim_failure is None
        and not current.observe_mode
        and current.artifact.artifact_id == initial.artifact.artifact_id
    ):
        stored_policy = package_protect_stored_policy(
            store,
            artifact=current.artifact,
            artifact_hash=current.artifact_hash,
            workspace_dir=workspace_dir,
            now=now,
            policy_workspaces=_package_policy_workspace_candidates(
                artifact=current.artifact,
                artifact_hash=current.artifact_hash,
                workspace_dir=workspace_dir,
                execution_context=current.execution_context,
            ),
        )
    final_evaluation = native_finalize_package_protect(
        initial=initial,
        current=current,
        claim_failure=saved_approval_claim_failure,
        saved_approval_claimed=saved_approval_claimed,
        claim_disposition=saved_approval_claim_disposition,
        stored_policy=stored_policy,
        store=store,
    )
    return (initial if current is None else current), final_evaluation


def _persist_projection(*, projection: NativePackageProtectProjection, store: Any, now: str) -> None:
    store.add_receipt(projection.receipt)
    store.set_receipt_action_envelope(
        projection.receipt.receipt_id,
        projection.receipt_policy_metadata,
    )
    store.add_event(
        f"install_time_{projection.verdict_action}",
        projection.event_payload,
        now,
    )


def build_package_protect_payload(
    *,
    command: Sequence[str],
    store: Any,
    workspace_dir: Path,
    dry_run: bool,
    allow_saved_approval_execution: bool = False,
    now: str,
    config: GuardConfig | None,
    unsafe_raw_output: bool,
    timeout_seconds: int,
    additional_current_action: object | None = None,
    additional_policy_context: dict[str, object] | None = None,
    current_config_provider: Callable[[], GuardConfig] | None = None,
    additional_authority_provider: Callable[[], tuple[object | None, dict[str, object] | None]] | None = None,
) -> tuple[dict[str, object], int] | None:
    authority = _build_package_protect_authority(
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        now=now,
        config=config,
        additional_current_action=additional_current_action,
        additional_policy_context=additional_policy_context,
    )
    if authority is None:
        return None
    evaluation = _resolve_stored_package_policy_override(
        authority.evaluation,
        store=store,
        artifact=authority.artifact,
        artifact_hash=authority.artifact_hash,
        workspace_dir=workspace_dir,
        now=now,
        execution_context=authority.execution_context,
        current_action=authority.current_action,
        claim_saved_approval=False,
    ).evaluation
    effective_dry_run = dry_run and not (
        allow_saved_approval_execution and _evaluation_uses_saved_package_approval(evaluation)
    )
    payload: dict[str, object] = {
        "generated_at": now,
        "executed": False,
        "dry_run": dry_run,
    }
    projection = native_package_protect_projection(
        store,
        authority=authority,
        evaluation=evaluation,
        command=command,
        executed=False,
    )
    payload.update(projection.fields)
    execution_permitted = projection.execution_permitted
    if config is not None:
        payload["supply_chain"] = build_local_supply_chain_posture(store, config, now=now)
    if not execution_permitted or effective_dry_run:
        _persist_projection(projection=projection, store=store, now=now)
        return (payload, projection.execution_exit_code)
    final_authority, final_evaluation = _final_package_protect_authority(
        initial=authority,
        initial_saved_evaluation=evaluation,
        saved_approval_pending=_evaluation_uses_saved_package_approval(evaluation),
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        now=now,
        config=config,
        current_config_provider=current_config_provider,
        additional_authority_provider=additional_authority_provider,
    )
    try:
        final_projection = native_package_protect_projection(
            store,
            authority=final_authority,
            evaluation=final_evaluation,
            command=command,
            executed=True,
            blocking=False,
        )
    except BaseException:
        _cleanup_external_archive_downloads(final_evaluation)
        raise

    def deny(denied_evaluation: Any) -> tuple[dict[str, object], int]:
        try:
            projection = native_package_protect_projection(
                store,
                authority=final_authority,
                evaluation=denied_evaluation,
                command=command,
                executed=False,
                blocking=True,
                project_execution_action=False,
            )
            payload.update(projection.fields)
            _persist_projection(projection=projection, store=store, now=now)
            return payload, projection.policy_exit_code
        finally:
            _cleanup_external_archive_downloads(final_evaluation)

    if not final_projection.execution_permitted:
        return deny(final_evaluation)
    launch_command = resolved_runtime_launch_argv(
        final_authority.launch_identity,
        args=tuple(str(item) for item in command[1:]),
    )
    if launch_command is None or not runtime_launch_identity_is_reusable(final_authority.launch_identity):
        reuse = evaluate_approval_reuse(
            final_authority.current_action,
            "require-reapproval",
            saved_decision_present=True,
            validation_reason="approval_reuse_identity_changed",
        )
        denied_evaluation = (
            final_authority.evaluation
            if reuse is None
            else compose_blocking_package_evaluation(
                "rejected_reuse", final_authority.evaluation, approval_reuse=reuse.to_evidence()
            )
        )
        return deny(denied_evaluation)
    bound_launch_command = _bound_external_archive_launch_command(
        launch_command,
        evaluation=final_evaluation,
        guard_home=store.guard_home,
    )
    if bound_launch_command is None:
        return deny(package_external_archive_override(final_evaluation, variant="launch_unbound"))
    payload.update(final_projection.fields)
    try:
        execution = subprocess.run(
            bound_launch_command,
            cwd=final_authority.launch_cwd,
            env=final_authority.launch_environment,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout_seconds,
        )
    except (subprocess.TimeoutExpired, OSError) as error:
        payload["execution"] = _build_command_execution_payload(
            stdout=_coerce_command_output(getattr(error, "stdout", None)),
            stderr=_coerce_command_error_output(error),
            returncode=-1,
            unsafe_raw_output=unsafe_raw_output,
        )
        store.add_event(
            "install_time_execution_failed",
            {**final_projection.event_payload, "error": type(error).__name__},
            now,
        )
        _cleanup_external_archive_downloads(final_evaluation)
        return (payload, 1)
    payload["execution"] = _build_command_execution_payload(
        stdout=execution.stdout,
        stderr=execution.stderr,
        returncode=execution.returncode,
        unsafe_raw_output=unsafe_raw_output,
    )
    if execution.returncode == 0:
        _persist_projection(projection=final_projection, store=store, now=now)
    else:
        store.add_event(
            "install_time_execution_failed",
            {**final_projection.event_payload, "returncode": execution.returncode},
            now,
        )
    _cleanup_external_archive_downloads(final_evaluation)
    return (payload, int(execution.returncode))


def apply_stored_package_policy_override(
    evaluation: Any,
    *,
    store: Any,
    artifact: GuardArtifact,
    artifact_hash: str,
    workspace_dir: Path,
    now: str,
    execution_context: PackageExecutionContext | None = None,
    current_action: object | None = None,
    claim_saved_approval: bool = True,
) -> Any:
    """Apply a saved package approval when the content hash still matches."""

    return _resolve_stored_package_policy_override(
        evaluation,
        store=store,
        artifact=artifact,
        artifact_hash=artifact_hash,
        workspace_dir=workspace_dir,
        now=now,
        execution_context=execution_context,
        current_action=current_action,
        claim_saved_approval=claim_saved_approval,
    ).evaluation


def _resolve_stored_package_policy_override(
    evaluation: Any,
    *,
    store: Any,
    artifact: GuardArtifact,
    artifact_hash: str,
    workspace_dir: Path,
    now: str,
    execution_context: PackageExecutionContext | None = None,
    current_action: object | None = None,
    claim_saved_approval: bool = True,
) -> _StoredPackagePolicyResolution:
    """Hydrate saved-policy facts and let the resident decide the override."""

    resolved_context = execution_context or build_package_execution_context(
        workspace_dir=workspace_dir,
        artifact=artifact,
    )
    policy_workspaces = _package_policy_workspace_candidates(
        artifact=artifact,
        artifact_hash=artifact_hash,
        workspace_dir=workspace_dir,
        execution_context=resolved_context,
    )
    resolved, claim_disposition, reused_decision = native_resolve_stored_package_policy(
        evaluation,
        store=store,
        artifact=artifact,
        artifact_hash=artifact_hash,
        workspace_dir=workspace_dir,
        now=now,
        policy_workspaces=policy_workspaces,
        current_action=current_action,
        claim_saved_approval=claim_saved_approval,
    )
    return _StoredPackagePolicyResolution(
        resolved,
        approval_reuse_decision=reused_decision,
        claim_disposition=cast(_PackageApprovalClaimDisposition | None, claim_disposition),
    )


def package_external_archive_override(evaluation: Any, *, variant: str) -> Any:
    """Resident-owned external-archive binding verdict (block or shim delegation).

    Every variant fails closed: an unavailable resident yields a terminal block.
    """

    return compose_blocking_package_evaluation("external_archive_override", evaluation, variant=variant)


def _package_policy_workspace_candidates(
    *,
    artifact: GuardArtifact,
    artifact_hash: str,
    workspace_dir: Path,
    execution_context: PackageExecutionContext | None = None,
) -> tuple[str, ...]:
    resolved_execution_context = execution_context or build_package_execution_context(
        workspace_dir=workspace_dir,
        artifact=artifact,
    )
    runtime_workspace = package_request_runtime_workspace_scope(
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact_hash,
        artifact_type=artifact.artifact_type,
        execution_context=resolved_execution_context,
    )
    return (runtime_workspace,) if runtime_workspace is not None else ()


@binds_store_guard_home
def package_current_action_and_hash(
    artifact: GuardArtifact,
    *,
    workspace_dir: Path,
    store: Any,
    evaluation: Any,
    execution_context: PackageExecutionContext | None = None,
    launch_identity: Mapping[str, object] | None = None,
    config: GuardConfig | None = None,
    additional_current_action: object | None = None,
    additional_policy_context: dict[str, object] | None = None,
) -> tuple[GuardAction, str]:
    resolved_execution_context = execution_context or build_package_execution_context(
        workspace_dir=workspace_dir,
        artifact=artifact,
    )
    return native_package_approval_hash(
        artifact=artifact,
        store=store,
        workspace_dir=workspace_dir,
        evaluation=evaluation,
        execution_context=resolved_execution_context,
        launch_identity=launch_identity,
        config=config,
        additional_current_action=additional_current_action,
        additional_policy_context=additional_policy_context,
    )


def package_request_policy_hash(
    *,
    artifact: GuardArtifact,
    store: Any,
    workspace_dir: Path,
    evaluation: Any,
    execution_context: PackageExecutionContext | None = None,
    config: GuardConfig | None = None,
) -> str:
    """Hash a package request using manifest and lockfile contents."""

    return package_current_action_and_hash(
        artifact,
        workspace_dir=workspace_dir,
        store=store,
        evaluation=evaluation,
        execution_context=execution_context,
        config=config,
    )[1]


def _evaluation_uses_saved_package_approval(evaluation: Any) -> bool:
    return any(reason.get("code") == "saved_package_approval" for reason in evaluation.reasons)


def redacted_command_tokens(command: Sequence[str]) -> tuple[str, ...]:
    return tuple(_redact_command_token(str(token)) for token in command)


def _build_command_execution_payload(
    *,
    stdout: str,
    stderr: str,
    returncode: int,
    unsafe_raw_output: bool,
) -> dict[str, object]:
    redacted_stdout = redact_text(stdout)
    redacted_stderr = redact_text(stderr)
    return {
        "returncode": returncode,
        "stdout": stdout if unsafe_raw_output else redacted_stdout.text,
        "stderr": stderr if unsafe_raw_output else redacted_stderr.text,
        "stdout_redactions": redacted_stdout.to_dict(),
        "stderr_redactions": redacted_stderr.to_dict(),
        "raw_output_enabled": unsafe_raw_output,
    }


def _coerce_command_output(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    return ""


def _coerce_command_error_output(error: subprocess.TimeoutExpired | OSError) -> str:
    parts = [_coerce_command_output(getattr(error, "stderr", None))]
    message = str(error).strip()
    if message:
        parts.append(message)
    return "\n".join(part for part in parts if part)


def _unavailable_package_manager_protection(store: Any, code: str) -> dict[str, object]:
    """The shape the posture renders when the resident cannot answer.

    No manager is reported as protected or unprotected here; the block only
    says the projection is unavailable and why.
    """

    return {
        "path_status": "unavailable",
        "error": code,
        "path_contains_shim_dir": False,
        "restart_shell_required": False,
        "process_path_status": "missing",
        "process_restart_required": False,
        "shell_profile_configured": False,
        "shell_profile_path": None,
        "shim_dir": str(store.guard_home / "package-shims" / "bin"),
        "supported_managers": list(package_shim_supported_managers(store.guard_home)),
        "detected_managers": [],
        "installed_managers": [],
        "active_managers": [],
        "missing_shims": [],
        "protected_managers": [],
        "unprotected_managers": [],
    }


def _build_package_manager_protection(store: Any) -> dict[str, object]:
    context = HarnessContext(
        home_dir=Path.home().resolve(),
        workspace_dir=None,
        guard_home=store.guard_home,
    )
    try:
        return package_shim_protection(context)
    except NativeShimAdminError as error:
        # Posture still renders when the resident cannot answer; the shim
        # fields read as unavailable instead of failing the whole projection.
        return _unavailable_package_manager_protection(store, error.code)


def _execute_cloud_workspace_audit_request(
    *,
    auth_context: dict[str, object],
    request_url: str,
    method: str,
    payload: dict[str, object] | None = None,
) -> dict[str, object]:
    runner = _runtime_runner_module()
    request = build_cloud_workspace_audit_request(
        auth_context=auth_context,
        request_url=request_url,
        method=method,
        payload=payload,
        build_headers=runner._guard_sync_headers,
    )
    try:
        with managed_urlopen(request, timeout=_CLOUD_AUDIT_TIMEOUT_SECONDS) as response:
            response_payload = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 403:
            is_plan_restricted, message = runner._check_plan_restriction_403(error)
            if is_plan_restricted:
                raise runner.GuardSyncNotAvailableError(message) from error
            raise RuntimeError(message) from error
        message, retryable = runner._guard_cloud_http_error_details(error)
        if retryable:
            raise runner.GuardSyncNotAvailableError(message, retryable=True) from error
        raise RuntimeError(message) from error
    except OSError as error:
        raise RuntimeError(runner._sync_url_error_message(error)) from error
    except (ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("Guard cloud workspace audit returned an invalid response.") from error
    if not isinstance(response_payload, dict):
        raise RuntimeError("Guard cloud workspace audit returned an invalid response.")
    return response_payload


def _enqueue_cloud_workspace_audit_job(
    *,
    store: Any,
    auth_context: dict[str, object],
    request_payload: dict[str, object],
    workspace_id: str,
) -> dict[str, object]:
    sync_url = str(auth_context["sync_url"])
    request_url = native_batch_url(store, sync_url, workspace_id)
    response_payload = _execute_cloud_workspace_audit_request(
        auth_context=auth_context,
        request_url=request_url,
        method="POST",
        payload=request_payload,
    )
    job_id = response_payload.get("jobId")
    if not isinstance(job_id, str) or not job_id.strip():
        raise RuntimeError("Guard cloud workspace audit did not return a batch job id.")
    return response_payload


def _poll_cloud_workspace_audit_job(
    *,
    store: Any,
    auth_context: dict[str, object],
    job_id: str,
    workspace_id: str,
) -> dict[str, object]:
    sync_url = str(auth_context["sync_url"])
    request_url = native_batch_url(
        store,
        sync_url,
        workspace_id,
        job_id=job_id,
        page_size=_CLOUD_AUDIT_JOB_PAGE_SIZE,
    )
    deadline = time.monotonic() + _CLOUD_AUDIT_JOB_POLL_TIMEOUT_SECONDS
    last_response: dict[str, object] = {
        "jobId": job_id,
        "status": "queued",
        "workspaceId": workspace_id,
    }
    while time.monotonic() < deadline:
        response_payload = _execute_cloud_workspace_audit_request(
            auth_context=auth_context,
            request_url=request_url,
            method="GET",
        )
        status = str(response_payload.get("status") or "").strip().lower()
        last_response = response_payload
        if status in {"completed", "failed"}:
            return response_payload
        time.sleep(_CLOUD_AUDIT_JOB_POLL_INTERVAL_SECONDS)
    return last_response


def sync_managed_workspace_audits(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
    workspace_dir: Path | None = None,
) -> dict[str, object]:
    runner = _runtime_runner_module()
    resolved_auth_context = auth_context if auth_context is not None else runner._resolve_guard_sync_auth_context(store)
    workspace_id = store.get_cloud_workspace_id()
    if not isinstance(workspace_id, str) or not workspace_id.strip():
        raise runner.GuardSyncNotConfiguredError(
            "Guard Cloud is not connected yet. Run `hol-guard connect` to sign in and pair this machine, "
            "or use `hol-guard login` as a compatibility alias for the same browser flow."
        )
    synced_at = datetime.now(timezone.utc).isoformat()
    workspaces_payload: list[dict[str, object]] = []
    completed_jobs = 0
    failed_jobs = 0
    incomplete_jobs = 0
    queued_jobs = 0
    skipped_workspaces = 0
    for candidate_path in native_managed_workspaces(store, candidates=True, workspace_dir=workspace_dir):
        candidate = Path(candidate_path)
        workspace_label = candidate.name or str(candidate)
        try:
            workspace_inventory = native_workspace_inventory(store, candidate)
            manifest_paths, lockfile_paths = workspace_inventory.manifest_paths, workspace_inventory.lockfile_paths
            inventory = workspace_inventory.inventory
            if not inventory:
                skipped_workspaces += 1
                workspaces_payload.append(
                    {
                        "workspace": workspace_label,
                        "status": "skipped",
                        "message": "No supported package inventory was detected for workspace audit sync.",
                        "package_count": 0,
                    }
                )
                continue
            request_payload = native_cloud_audit_payload(
                store,
                workspace_dir=candidate,
                workspace_id=workspace_id,
                inventory_digest=workspace_inventory.inventory_digest,
                mode="job",
                page_size=min(_CLOUD_AUDIT_SYNC_PAGE_SIZE, max(len(inventory), 1)),
            )
            enqueue_response = _enqueue_cloud_workspace_audit_job(
                store=store,
                auth_context=resolved_auth_context,
                request_payload=request_payload,
                workspace_id=workspace_id,
            )
            job_id = str(enqueue_response.get("jobId") or "").strip()
            final_response = _poll_cloud_workspace_audit_job(
                store=store,
                auth_context=resolved_auth_context,
                job_id=job_id,
                workspace_id=workspace_id,
            )
            final_status = (
                str(final_response.get("status") or enqueue_response.get("status") or "queued").strip().lower()
            )
            cloud_visible_count = _int_value(final_response.get("totalPackages"))
            cloud_processed_count = _int_value(final_response.get("processedCount"))
            incomplete_cloud_projection = (
                final_status == "completed" and cloud_visible_count is not None and cloud_visible_count < len(inventory)
            )
            if incomplete_cloud_projection:
                incomplete_jobs += 1
                workspace_status = "partial"
            else:
                workspace_status = final_status
                if final_status == "completed":
                    completed_jobs += 1
                elif final_status == "failed":
                    failed_jobs += 1
                else:
                    queued_jobs += 1
            message = final_response.get("error")
            if incomplete_cloud_projection:
                message = (
                    "Guard Cloud accepted fewer package rows than hol-guard discovered "
                    f"({cloud_visible_count} of {len(inventory)} visible)."
                )
            workspaces_payload.append(
                {
                    "workspace": workspace_label,
                    "workspace_fingerprint": request_payload.get("workspaceFingerprint"),
                    "job_id": job_id,
                    "status": workspace_status,
                    "package_count": len(inventory),
                    "cloud_processed_count": cloud_processed_count,
                    "cloud_visible_count": cloud_visible_count,
                    "manifest_paths": list(manifest_paths),
                    "lockfile_paths": list(lockfile_paths),
                    "message": message,
                }
            )
        except (
            runner.GuardSyncAuthorizationExpiredError,
            runner.GuardSyncNotAvailableError,
            runner.GuardSyncNotConfiguredError,
        ):
            raise
        except (OSError, RuntimeError, ValueError) as error:
            failed_jobs += 1
            workspaces_payload.append(
                {
                    "workspace": workspace_label,
                    "status": "failed",
                    "message": str(error),
                    "package_count": 0,
                }
            )
    if failed_jobs > 0 and completed_jobs == 0 and queued_jobs == 0 and incomplete_jobs == 0:
        status = "failed"
    elif failed_jobs > 0 or incomplete_jobs > 0:
        status = "partial"
    elif completed_jobs > 0 or queued_jobs > 0:
        status = "synced"
    else:
        status = "idle"
    summary: dict[str, object] = {
        "synced_at": synced_at,
        "status": status,
        "workspace_count": len(workspaces_payload),
        "completed_jobs": completed_jobs,
        "queued_jobs": queued_jobs,
        "failed_jobs": failed_jobs,
        "incomplete_jobs": incomplete_jobs,
        "skipped_workspaces": skipped_workspaces,
        "workspaces": workspaces_payload,
    }
    store.set_sync_payload("workspace_audits_sync_summary", summary, synced_at)
    return summary


def sync_supply_chain_cloud_state(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
    workspace_dir: Path | None = None,
) -> dict[str, object]:
    resolved_auth_context = auth_context if auth_context is not None else _resolve_guard_sync_auth_context(store)
    bundle_summary = _call_sync_with_optional_auth_context(
        sync_supply_chain_bundle,
        store=store,
        auth_context=resolved_auth_context,
    )
    payload = dict(bundle_summary) if isinstance(bundle_summary, dict) else {}
    workspace_audits = sync_managed_workspace_audits(
        store,
        auth_context=resolved_auth_context,
        workspace_dir=workspace_dir,
    )
    payload["workspace_audits"] = workspace_audits
    payload.setdefault("synced_at", workspace_audits.get("synced_at"))
    return payload


def _package_manager_for_scan(manifest_paths: Sequence[str]) -> str:
    for manifest_path in manifest_paths:
        ecosystem = _ECOSYSTEM_BY_MANIFEST.get(Path(manifest_path).name)
        if ecosystem is not None:
            return _PACKAGE_MANAGER_BY_ECOSYSTEM.get(ecosystem, ecosystem)
    return "workspace"


def _protect_action_for_policy_action(policy_action: object) -> GuardAction:
    return normalize_guard_action(policy_action, unknown_action="block")


def _redact_command_token(token: str) -> str:
    token = redact_package_request_token(token)
    if "=" in token:
        key, _, _ = token.partition("=")
        if any(fragment in key.lower() for fragment in ("token", "secret", "api_key", "api-key", "password")):
            return f"{key}=*****"
    if ":" in token:
        key, _, _ = token.partition(":")
        if any(fragment in key.lower() for fragment in ("token", "secret", "api_key", "api-key", "password")):
            return f"{key}: *****"
    return redact_text(token).text


def _int_value(value: object) -> int | None:
    if isinstance(value, int):
        return value
    return None
