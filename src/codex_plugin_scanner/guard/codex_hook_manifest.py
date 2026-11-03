"""Build and verify authenticated identities for Guard-managed Codex hooks.

This module owns the manifest trust model without importing the Codex adapter.
The adapter supplies one complete expected specification, which keeps command
construction at the harness boundary and prevents a circular dependency.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from .codex_hook_compatibility import compatible_bridge_argv_hashes, retained_bridge_generations
from .codex_hook_events import MANAGED_CODEX_HOOK_EVENTS
from .codex_hook_file_integrity import (
    CodexHookIntegrityError,
    canonical_path,
    check_hook_validation_deadline,
    describe_executable_file,
    describe_regular_file,
    validate_regular_file,
)
from .codex_hook_integrity import (
    HOOK_MANIFEST_SCHEMA_VERSION,
    authenticate_hook_manifest_text,
    canonical_manifest_bytes,
    hook_authority_receipt_path,
    hook_manifest_path,
    hook_secret_path,
    load_authenticated_hook_manifest,
    load_hook_secret,
    load_or_create_hook_secret,
    sign_hook_manifest,
)
from .codex_hook_package_identity import (
    assert_package_reauthentication_is_safe as assert_package_reauthentication_is_safe,
)
from .native_codex_hook_manifest_verify import native_codex_hook_manifest_verify

if TYPE_CHECKING:
    from .native_runtime import NativeRuntimeIdentity
    from .runtime_transition import TransitionFile

CODEX_AUTHORITY_REPAIR_ACTION = "apps.repair.codex-authority"

_TRANSPORT_PACKAGE_ROLES = (
    "bridge",
    "bridge_runtime",
    "launch_runtime",
    "runtime_trust",
    "windows_job",
)


@dataclass(frozen=True, slots=True)
class CodexHookManifestSpec:
    """Complete live identity expected for one Codex hook installation."""

    guard_home: Path
    home_dir: Path
    runtime_guard_home: Path
    workspace_dir: Path | None
    config_path: Path
    interpreter_path: Path
    package_version: str
    packaged_file_paths: tuple[tuple[str, Path], ...]
    fallback_argv: tuple[str, ...]
    daemon_start_argv: tuple[str, ...]
    event_bindings: tuple[Mapping[str, object], ...]
    workspace_rebinding_allowed: bool = False


def build_authenticated_hook_manifest(
    spec: CodexHookManifestSpec,
    *,
    previous_manifest: Mapping[str, object] | None = None,
    create_key: bool = True,
) -> dict[str, object]:
    secret = load_or_create_hook_secret(spec.guard_home) if create_key else load_hook_secret(spec.guard_home)
    interpreter = describe_executable_file(spec.interpreter_path, role="interpreter")
    packaged_files = [
        describe_regular_file(path, role=role, executable_required=False) for role, path in spec.packaged_file_paths
    ]
    packaged_by_role = {
        identity.get("role"): identity for identity in packaged_files if isinstance(identity.get("role"), str)
    }
    transport = {role: packaged_by_role.get(role) for role in _TRANSPORT_PACKAGE_ROLES}
    if any(not isinstance(identity, dict) for identity in transport.values()) or len(packaged_by_role) != len(
        spec.packaged_file_paths
    ):
        raise CodexHookIntegrityError(
            "codex_hook_manifest_packaged_files_invalid",
            "Guard cannot authenticate an incomplete Codex hook package identity.",
        )
    generated_at = datetime.now(timezone.utc).isoformat()
    unsigned_manifest: dict[str, object] = {
        "config": {"scope": "global", "target": canonical_path(spec.config_path)},
        "compatible_bridge_argv_sha256": compatible_bridge_argv_hashes(previous_manifest),
        "retained_bridge_generations": retained_bridge_generations(previous_manifest),
        "context": _expected_context(spec),
        "daemon_start": {
            "argv": list(spec.daemon_start_argv),
            "interpreter": interpreter,
            "package_roles": ["daemon_entrypoint", "daemon_manager"],
        },
        "events": [dict(binding) for binding in spec.event_bindings],
        "fallback": {
            "argv": list(spec.fallback_argv),
            "interpreter": interpreter,
            "package_roles": ["fallback_entrypoint"],
        },
        "generated_at": generated_at,
        "harness": "codex",
        "installation_id": secret.installation_id,
        "interpreter": interpreter,
        "package_version": spec.package_version,
        "packaged_files": packaged_files,
        "schema_version": HOOK_MANIFEST_SCHEMA_VERSION,
        "transport": {**transport, "wrapper": None},
    }
    return sign_hook_manifest(unsigned_manifest, secret)


@dataclass(frozen=True, slots=True)
class PreparedCodexHookPublication:
    """Captured authority pair; this is not a complete Codex adapter install."""

    manifest: dict[str, object]
    rendered_config: str
    config_change: TransitionFile
    manifest_change: TransitionFile
    authority_dependency: TransitionFile
    receipt_change: TransitionFile

    @property
    def files(self) -> tuple[TransitionFile, ...]:
        return (self.authority_dependency, self.manifest_change, self.receipt_change, self.config_change)


def prepare_authenticated_hook_publication(
    spec: CodexHookManifestSpec,
    *,
    rendered_config: str,
    previous_manifest: Mapping[str, object] | None = None,
    create_key: bool = False,
    _manifest_builder: Callable[..., dict[str, object]] | None = None,
) -> PreparedCodexHookPublication:
    """Capture a signed config/manifest generation without enrolling by default."""
    from .codex_hook_recovery import _snapshot, build_hook_authority_receipt
    from .runtime_transition import RuntimeTransition, TransitionError, TransitionFile

    # Enrollment runs under the normal install owner's previously validated
    # baseline. A read-only runtime plan must authenticate that baseline itself.
    baseline = previous_manifest if create_key else load_hook_manifest_baseline(spec)
    if baseline != previous_manifest:
        raise TransitionError("adapter_preparation_generation_conflict")
    config_path = spec.config_path.parent.resolve(strict=False) / spec.config_path.name
    manifest_path = hook_manifest_path(spec.guard_home, spec.config_path)
    before_config = _snapshot(config_path)
    before_manifest = _snapshot(manifest_path)
    receipt_path = hook_authority_receipt_path(spec.guard_home, spec.config_path)
    before_receipt = _snapshot(receipt_path)
    if before_config is not None:
        validate_regular_file(config_path, role="config_target", executable_required=False)
        before_config.decode("utf-8")
    config_mode = config_path.stat().st_mode & 0o777 if before_config is not None else 0o600
    manifest_mode = manifest_path.stat().st_mode & 0o777 if before_manifest is not None else 0o600
    receipt_mode = receipt_path.stat().st_mode & 0o777 if before_receipt is not None else 0o600
    secret_path = hook_secret_path(spec.guard_home)
    authority_before = (
        TransitionFile.identity_dependency(secret_path) if secret_path.exists() or secret_path.is_symlink() else None
    )
    manifest = (_manifest_builder or build_authenticated_hook_manifest)(
        spec, previous_manifest=baseline, create_key=create_key
    )
    assert_package_reauthentication_is_safe(baseline, manifest)
    authority_dependency = (
        authority_before if authority_before is not None else TransitionFile.identity_dependency(secret_path)
    )
    # Recheck the captured key before signing another object with it. A
    # replacement during manifest construction remains a generation conflict.
    RuntimeTransition._compare({"files": [authority_dependency.payload()]}, "before")
    prepared = PreparedCodexHookPublication(
        manifest,
        rendered_config,
        TransitionFile(
            config_path,
            before_config,
            rendered_config.encode("utf-8"),
            before_mode=config_mode,
            after_mode=0o600,
            no_follow=True,
        ),
        TransitionFile(
            manifest_path,
            before_manifest,
            canonical_manifest_bytes(manifest) + b"\n",
            before_mode=manifest_mode,
            after_mode=0o600,
            no_follow=True,
        ),
        authority_dependency,
        TransitionFile(
            receipt_path,
            before_receipt,
            build_hook_authority_receipt(
                spec.guard_home,
                config_path,
                config_bytes=rendered_config.encode("utf-8"),
                manifest_bytes=canonical_manifest_bytes(manifest) + b"\n",
            ),
            before_mode=receipt_mode,
            after_mode=0o600,
            no_follow=True,
        ),
    )
    RuntimeTransition._compare({"files": [change.payload() for change in prepared.files]}, "before")
    return prepared


def load_hook_manifest_baseline(spec: CodexHookManifestSpec) -> dict[str, object] | None:
    """Load a prior authenticated baseline or prove this is a clean install.

    No manifest and no secret is the only unauthenticated state that may create
    a baseline. It covers both a first install and explicit migration of a
    pre-manifest exact legacy hook. If either modern artifact exists, every
    authenticity and ownership check must pass before current package bytes can
    be signed again.
    """

    manifest_path = hook_manifest_path(spec.guard_home, spec.config_path)
    secret_path = hook_secret_path(spec.guard_home)
    manifest_exists = manifest_path.exists() or manifest_path.is_symlink()
    secret_exists = secret_path.exists() or secret_path.is_symlink()
    if not manifest_exists and not secret_exists:
        return None
    try:
        manifest = load_authenticated_hook_manifest(spec.guard_home, spec.config_path)
    except (CodexHookIntegrityError, OSError) as exc:
        raise _untrusted_baseline_error() from exc
    if not _manifest_has_owned_installation_context(manifest, spec):
        raise _untrusted_baseline_error()
    return manifest


@dataclass(frozen=True, slots=True, repr=False)
class PreparedCodexHookRepair:
    """Exact captured repair files, without publication or lifecycle authority."""

    manifest_change: TransitionFile
    files: tuple[TransitionFile, ...]
    guard_home: Path
    config_path: Path
    operation_id: str
    native_runtime: NativeRuntimeIdentity | None = None
    verification_workspace: Path | None = None

    def payload(self) -> dict[str, object]:
        from .runtime_transition import TransitionError

        try:
            if str(uuid.UUID(self.operation_id)) != self.operation_id:
                raise ValueError("noncanonical operation")
        except ValueError as exc:
            raise TransitionError("authority_repair_plan_invalid") from exc
        home = self.guard_home.resolve(strict=False)
        config = self.config_path.parent.resolve(strict=False) / self.config_path.name
        change = self.manifest_change
        if (
            len(self.files) > 128
            or len({item.path for item in self.files}) != len(self.files)
            or change.path != hook_manifest_path(home, config)
            or change.before is not None
            or change.after is None
            or change.expected_digest is not None
            or not change.no_follow
            or change.kind != "binding"
            or change.after_mode != 0o600
            or sum(item == change for item in self.files) != 1
            or any(
                item != change and (item.expected_digest is None or item.before is not None or item.after is not None)
                for item in self.files
            )
        ):
            raise TransitionError("authority_repair_plan_invalid")
        required = {hook_secret_path(home), hook_authority_receipt_path(home, config), config}
        if not required <= {item.path for item in self.files if item.expected_digest is not None}:
            raise TransitionError("authority_repair_plan_invalid")
        payload: dict[str, object] = {
            "schema": "hol-guard.codex-authority-repair-plan.v1",
            "action": CODEX_AUTHORITY_REPAIR_ACTION,
            "guard_home": str(home),
            "config_path": str(config),
            "operation_id": self.operation_id,
            "files": [item.payload() for item in self.files],
        }
        if self.native_runtime is not None or self.verification_workspace is not None:
            native, workspace = self.native_runtime, self.verification_workspace
            if (
                native is None
                or workspace is None
                or not workspace.is_absolute()
                or workspace.resolve(strict=False) != workspace
                or not workspace.is_dir()
                or not native.path.is_absolute()
                or native.path.resolve(strict=False) != native.path
                or type(native.size) is not int
                or native.size <= 0
                or type(native.mtime_ns) is not int
                or len(native.sha256) != 64
                or any(char not in "0123456789abcdef" for char in native.sha256)
                or not any(
                    item.path == native.path
                    and item.expected_digest == native.sha256
                    and item.artifact_identity is not None
                    and item.artifact_identity.get("size") == native.size
                    for item in self.files
                )
            ):
                raise TransitionError("authority_repair_native_binding_invalid")
            try:
                if native.path.stat().st_mtime_ns != native.mtime_ns:
                    raise TransitionError("native_runtime_generation_changed")
            except OSError as exc:
                raise TransitionError("native_runtime_generation_changed") from exc
            payload["native_runtime"] = {
                "path": str(native.path),
                "size": native.size,
                "mtime_ns": native.mtime_ns,
                "sha256": native.sha256,
            }
            payload["verification_workspace"] = str(workspace)
        return payload

    def subject(self) -> str:
        digest = hashlib.sha256(canonical_manifest_bytes(self.payload())).hexdigest()
        return f"codex-authority-repair:{self.operation_id}:{digest}"


def prepare_authenticated_hook_manifest_repair(spec: CodexHookManifestSpec) -> PreparedCodexHookRepair:
    """Prepare only restoration of a missing manifest from retained authority."""
    from .codex_hook_compatibility import retained_launch_generations
    from .codex_hook_recovery import _snapshot, load_hook_authority_receipt
    from .codex_hook_runtime_trust import verify_captured_launch_generation
    from .codex_hook_sources import parse_toml_object
    from .runtime_transition import RuntimeTransition, TransitionError, TransitionFile, merge_transition_dependency

    check_hook_validation_deadline()
    config = spec.config_path.parent.resolve(strict=False) / spec.config_path.name
    manifest_path = hook_manifest_path(spec.guard_home, config)
    if _snapshot(manifest_path) is not None:
        raise TransitionError("authority_repair_manifest_present")
    dependencies = []
    for path in (
        hook_secret_path(spec.guard_home),
        hook_authority_receipt_path(spec.guard_home, config),
        config,
    ):
        check_hook_validation_deadline()
        dependencies.append(TransitionFile.identity_dependency(path))
    receipt = load_hook_authority_receipt(spec.guard_home, config)
    payload = parse_toml_object(receipt.config_bytes, path=config, label="Codex config file")
    check_hook_validation_deadline()
    features = payload.get("features")
    if isinstance(features, Mapping) and features.get("hooks") is False:
        raise TransitionError("authority_repair_hooks_disabled")
    state = _verify_hook_manifest(
        spec,
        hooks=payload.get("hooks"),
        captured_text=receipt.manifest_bytes.decode("utf-8"),
    )
    if state.get("integrity_status") != "valid":
        raise CodexHookIntegrityError(str(state["integrity_reason"]), str(state["integrity_message"]))
    manifest = authenticate_hook_manifest_text(spec.guard_home, receipt.manifest_bytes.decode("utf-8"))
    try:
        generations = [manifest, *retained_launch_generations(manifest)]
        for generation in generations:
            interpreter, packaged = verify_captured_launch_generation(generation)
            for identity in packaged.values():
                check_hook_validation_deadline()
                dependencies.append(TransitionFile.artifact_dependency(identity))
            target = interpreter.get("target")
            if not isinstance(target, dict):
                raise TransitionError("authority_repair_identity_invalid")
            check_hook_validation_deadline()
            dependencies.append(TransitionFile.artifact_dependency(target, invocation=interpreter))
    except ValueError as exc:
        raise CodexHookIntegrityError(
            "codex_hook_repair_retained_identity_invalid", "Guard could not verify a retained Codex launch generation."
        ) from exc
    change = TransitionFile(manifest_path, None, receipt.manifest_bytes, no_follow=True)
    unique: dict[Path, TransitionFile] = {change.path: change}
    for dependency in dependencies:
        previous = unique.get(dependency.path)
        unique[dependency.path] = dependency if previous is None else merge_transition_dependency(previous, dependency)
    files = tuple(unique.values())
    RuntimeTransition._compare({"files": [item.payload() for item in files]}, "before")
    check_hook_validation_deadline()
    prepared = PreparedCodexHookRepair(change, files, spec.guard_home.resolve(strict=False), config, str(uuid.uuid4()))
    prepared.payload()
    return prepared


def manifest_bindings(manifest: object) -> list[dict[str, object]]:
    if not isinstance(manifest, dict):
        return []
    events = manifest.get("events")
    if not isinstance(events, list):
        return []
    return [dict(binding) for binding in events if isinstance(binding, dict)]


def verify_live_hook_manifest(
    spec: CodexHookManifestSpec,
    *,
    hooks: object,
) -> dict[str, object]:
    return _verify_hook_manifest(spec, hooks=hooks)


def _verify_hook_manifest(
    spec: CodexHookManifestSpec,
    *,
    hooks: object,
    captured_text: str | None = None,
) -> dict[str, object]:
    """Authenticate the manifest here and let the resident verify the rest."""

    manifest: dict[str, object] | None = None
    expected: dict[str, object] | None = None
    failure: tuple[str, str] | None = None
    try:
        manifest = (
            load_authenticated_hook_manifest(spec.guard_home, spec.config_path)
            if captured_text is None
            else authenticate_hook_manifest_text(spec.guard_home, captured_text)
        )
        expected = {
            "config_path": str(spec.config_path),
            "config_target": canonical_path(spec.config_path),
            "context": _expected_context(spec),
            "package_version": spec.package_version,
            "interpreter_path": str(spec.interpreter_path),
            "packaged_paths": {role: canonical_path(path) for role, path in spec.packaged_file_paths},
            "fallback_argv": list(spec.fallback_argv),
            "daemon_start_argv": list(spec.daemon_start_argv),
            "event_bindings": [dict(binding) for binding in spec.event_bindings],
        }
    except CodexHookIntegrityError as exc:
        failure = (exc.reason, exc.message)
    except OSError:
        failure = (
            "codex_hook_integrity_io_error",
            "Guard could not verify the Codex hook installation; run repair and inspect file permissions.",
        )
    state = native_codex_hook_manifest_verify(
        guard_home=spec.guard_home,
        hooks=hooks,
        manifest=manifest,
        expected=expected,
        failure=failure,
    )
    state["manifest_path"] = str(hook_manifest_path(spec.guard_home, spec.config_path))
    return state


def _expected_context(spec: CodexHookManifestSpec) -> dict[str, object]:
    return {
        "guard_home": canonical_path(spec.guard_home),
        "home_dir": canonical_path(spec.home_dir),
        "runtime_guard_home": canonical_path(spec.runtime_guard_home),
        "workspace_dir": canonical_path(spec.workspace_dir) if spec.workspace_dir is not None else None,
    }


def _manifest_has_owned_installation_context(
    manifest: Mapping[str, object],
    spec: CodexHookManifestSpec,
) -> bool:
    config = manifest.get("config")
    context = manifest.get("context")
    expected_context = _expected_context(spec)
    return (
        manifest.get("harness") == "codex"
        and isinstance(config, dict)
        and config.get("scope") == "global"
        and config.get("target") == canonical_path(spec.config_path)
        and isinstance(context, dict)
        and (
            context == expected_context
            or (
                spec.workspace_rebinding_allowed
                and context.keys() == expected_context.keys()
                and context["guard_home"] == expected_context["guard_home"]
                and context["home_dir"] == expected_context["home_dir"]
                and context["runtime_guard_home"] == expected_context["runtime_guard_home"]
            )
        )
    )


def _untrusted_baseline_error() -> CodexHookIntegrityError:
    return CodexHookIntegrityError(
        "codex_hook_manifest_baseline_untrusted",
        "Guard refused to authenticate hook package bytes because the existing managed-hook baseline is "
        "missing, invalid, or belongs to another installation. Reinstall hol-guard from a trusted package, "
        "then run `hol-guard install codex` again.",
    )


__all__ = [
    "MANAGED_CODEX_HOOK_EVENTS",
    "CodexHookManifestSpec",
    "PreparedCodexHookPublication",
    "assert_package_reauthentication_is_safe",
    "build_authenticated_hook_manifest",
    "load_hook_manifest_baseline",
    "manifest_bindings",
    "prepare_authenticated_hook_publication",
    "verify_live_hook_manifest",
]
