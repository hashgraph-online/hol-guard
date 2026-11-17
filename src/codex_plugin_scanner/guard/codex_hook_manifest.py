"""Build and verify authenticated identities for Guard-managed Codex hooks.

This module owns the manifest trust model without importing the Codex adapter.
The adapter supplies one complete expected specification, which keeps command
construction at the harness boundary and prevents a circular dependency.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .codex_hook_events import MANAGED_CODEX_HOOK_EVENTS
from .codex_hook_file_integrity import (
    CodexHookIntegrityError,
    canonical_path,
    check_hook_validation_deadline,
)
from .codex_hook_integrity import (
    _MANIFEST_MESSAGES,
    authenticate_hook_manifest_text,
    hook_manifest_path,
    load_authenticated_hook_manifest,
)
from .native_codex_hook_manifest_verify import native_codex_hook_manifest_verify

if TYPE_CHECKING:
    from .native_runtime import NativeRuntimeIdentity
    from .runtime_transition import TransitionFile

CODEX_AUTHORITY_REPAIR_ACTION = "apps.repair.codex-authority"


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


def _spec_payload(spec: CodexHookManifestSpec) -> dict[str, object]:
    def spelled(path: Path) -> str:
        return str(path.expanduser())

    return {
        "guard_home": spelled(spec.guard_home),
        "home_dir": spelled(spec.home_dir),
        "runtime_guard_home": spelled(spec.runtime_guard_home),
        "workspace_dir": spelled(spec.workspace_dir) if spec.workspace_dir is not None else None,
        "config_path": spelled(spec.config_path),
        "interpreter_path": str(spec.interpreter_path.expanduser().absolute()),
        "package_version": spec.package_version,
        "packaged_file_paths": [[role, spelled(path)] for role, path in spec.packaged_file_paths],
        "fallback_argv": list(spec.fallback_argv),
        "daemon_start_argv": list(spec.daemon_start_argv),
        "event_bindings": [dict(binding) for binding in spec.event_bindings],
    }


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


def generation_request(
    spec: CodexHookManifestSpec,
    *,
    previous_manifest: Mapping[str, object] | None,
    create_key: bool,
) -> dict[str, object]:
    """The ``publication_generation`` request for ``spec``, without its rendered config."""
    import os

    def spelled(path: Path) -> str:
        return os.path.abspath(path.expanduser())

    return {
        "config": spelled(spec.config_path),
        "guard_home": spelled(spec.guard_home),
        "home_dir": spelled(spec.home_dir),
        "runtime_guard_home": spelled(spec.runtime_guard_home),
        "workspace_dir": spelled(spec.workspace_dir) if spec.workspace_dir is not None else None,
        "workspace_rebinding_allowed": spec.workspace_rebinding_allowed,
        "spec": _spec_payload(spec),
        "previous_manifest": None if previous_manifest is None else dict(previous_manifest),
        "create_key": create_key,
    }


def load_hook_manifest_baseline(spec: CodexHookManifestSpec) -> dict[str, object] | None:
    """The runtime loads a prior authenticated baseline or proves a clean install."""
    import os

    from .native_transition_files import publication

    def spelled(path: Path) -> str:
        return os.path.abspath(path.expanduser())

    check_hook_validation_deadline()
    answer = publication(
        "baseline",
        spec.guard_home,
        config=spelled(spec.config_path),
        guard_home=spelled(spec.guard_home),
        home_dir=spelled(spec.home_dir),
        runtime_guard_home=spelled(spec.runtime_guard_home),
        workspace_dir=spelled(spec.workspace_dir) if spec.workspace_dir is not None else None,
        workspace_rebinding_allowed=spec.workspace_rebinding_allowed,
    )
    check_hook_validation_deadline()
    if not isinstance(answer, dict) or set(answer) not in ({"manifest"}, {"untrusted"}):
        raise _untrusted_baseline_error()
    if "untrusted" in answer:
        cause = answer["untrusted"]
        if isinstance(cause, str):
            raise _untrusted_baseline_error() from CodexHookIntegrityError(cause, _MANIFEST_MESSAGES.get(cause, cause))
        raise _untrusted_baseline_error()
    manifest = answer["manifest"]
    if manifest is not None and not isinstance(manifest, dict):
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

    def _checked(self) -> dict[str, object]:
        """The runtime checks the plan and answers its payload and subject."""
        from .native_transition_files import publication

        native = self.native_runtime
        answer = publication(
            "repair_plan",
            self.guard_home,
            config=os.path.abspath(self.config_path),
            operation_id=self.operation_id,
            change=self.manifest_change.payload(),
            files=[item.payload() for item in self.files],
            native_runtime=None
            if native is None
            else {"path": str(native.path), "size": native.size, "mtime_ns": native.mtime_ns, "sha256": native.sha256},
            verification_workspace=None if self.verification_workspace is None else str(self.verification_workspace),
        )
        if not isinstance(answer, dict) or not isinstance(answer.get("payload"), dict):
            from .runtime_transition import TransitionError

            raise TransitionError("authority_repair_plan_invalid")
        return answer

    def payload(self) -> dict[str, object]:
        return cast(dict[str, object], self._checked()["payload"])

    def subject(self) -> str:
        return str(self._checked()["subject"])


def transition_file(item: Mapping[str, object]) -> TransitionFile:
    """One planned file as the runtime answered its payload."""
    from .codex_hook_recovery import _decode
    from .runtime_transition import TransitionFile

    return TransitionFile(
        path=Path(str(item["path"])),
        before=_decode(item["before"]),
        after=_decode(item["after"]),
        before_mode=cast(int, item["before_mode"]),
        after_mode=cast(int, item["after_mode"]),
        kind=cast(str, item["kind"]),
        no_follow=cast(bool, item.get("no_follow", False)),
        expected_digest=cast("str | None", item.get("expected_digest")),
        artifact_identity=cast("dict[str, object] | None", item.get("artifact_identity")),
        invocation_identity=cast("dict[str, object] | None", item.get("invocation_identity")),
    )


def prepare_authenticated_hook_manifest_repair(spec: CodexHookManifestSpec) -> PreparedCodexHookRepair:
    """Prepare only restoration of a missing manifest from retained authority.

    The runtime pins the key, receipt, config and every captured launch
    artifact; this keeps the receipt checks and the manifest change.
    """
    from .codex_hook_recovery import _snapshot, load_hook_authority_receipt
    from .codex_hook_sources import parse_toml_object
    from .native_transition_files import publication
    from .runtime_transition import RuntimeTransition, TransitionError, TransitionFile

    check_hook_validation_deadline()
    config = spec.config_path.parent.resolve(strict=False) / spec.config_path.name
    manifest_path = hook_manifest_path(spec.guard_home, config)
    if _snapshot(manifest_path) is not None:
        raise TransitionError("authority_repair_manifest_present")
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
    check_hook_validation_deadline()
    answer = publication(
        "repair_files",
        spec.guard_home,
        config=str(config),
        manifest=manifest,
        receipt_sha256=hashlib.sha256(receipt.receipt_bytes).hexdigest(),
        config_sha256=hashlib.sha256(receipt.config_bytes).hexdigest(),
    )
    pinned = answer.get("files") if isinstance(answer, dict) else None
    if not isinstance(pinned, list) or not all(isinstance(item, dict) for item in pinned):
        raise TransitionError("native_transition_invalid")
    change = TransitionFile(manifest_path, None, receipt.manifest_bytes, no_follow=True)
    files = (change, *(transition_file(item) for item in pinned))
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
    "load_hook_manifest_baseline",
    "manifest_bindings",
    "verify_live_hook_manifest",
]
