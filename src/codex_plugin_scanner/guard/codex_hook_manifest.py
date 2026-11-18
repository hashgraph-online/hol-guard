"""Build and verify authenticated identities for Guard-managed Codex hooks.

This module owns the manifest trust model without importing the Codex adapter.
The adapter supplies one complete expected specification, which keeps command
construction at the harness boundary and prevents a circular dependency.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .codex_hook_events import MANAGED_CODEX_HOOK_EVENTS
from .codex_hook_file_integrity import CodexHookIntegrityError, check_hook_validation_deadline

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

    def payload(self) -> dict[str, object]:
        """The installation as the runtime reads it: spellings only, never resolved here."""
        return {
            "guard_home": str(self.guard_home),
            "home_dir": str(self.home_dir),
            "runtime_guard_home": str(self.runtime_guard_home),
            "workspace_dir": None if self.workspace_dir is None else str(self.workspace_dir),
            "config_path": str(self.config_path),
            "interpreter_path": str(self.interpreter_path),
            "package_version": self.package_version,
            "packaged_file_paths": [[role, str(path)] for role, path in self.packaged_file_paths],
            "fallback_argv": list(self.fallback_argv),
            "daemon_start_argv": list(self.daemon_start_argv),
            "event_bindings": [dict(binding) for binding in self.event_bindings],
            "workspace_rebinding_allowed": self.workspace_rebinding_allowed,
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


def load_hook_manifest_baseline(spec: CodexHookManifestSpec) -> dict[str, object] | None:
    """The runtime loads a prior authenticated baseline or proves a clean install."""
    from .native_transition_files import publication

    answer = publication("baseline", spec.guard_home, spec=spec.payload())
    malformed = CodexHookIntegrityError("native_transition_invalid", "Guard could not read the managed-hook baseline.")
    if not isinstance(answer, dict) or set(answer) not in ({"manifest"}, {"untrusted"}):
        raise malformed
    untrusted = answer.get("untrusted")
    if "untrusted" in answer:
        if not isinstance(untrusted, dict):
            raise malformed
        error = CodexHookIntegrityError(str(untrusted["reason"]), str(untrusted["message"]))
        cause = untrusted.get("cause")
        if isinstance(cause, str):
            raise error from CodexHookIntegrityError(cause, cause)
        raise error
    manifest = answer["manifest"]
    if manifest is not None and not isinstance(manifest, dict):
        raise malformed
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

    The runtime does the whole preparation: it refuses a present manifest,
    loads the receipt under its own key, parses the retained config, verifies
    the retained manifest, pins the key, receipt, config and every captured
    launch artifact, compares them and checks the plan. This sends the facts
    of this process and settles the answer.
    """
    from .harness_context import HarnessContext
    from .native_harness_client import wire_context
    from .native_transition_files import publication
    from .runtime_transition import TransitionError

    context = HarnessContext(home_dir=spec.home_dir, workspace_dir=spec.workspace_dir, guard_home=spec.guard_home)
    operation_id = str(uuid.uuid4())
    answer = publication(
        "repair_prepare",
        spec.guard_home,
        config=os.path.abspath(spec.config_path),
        operation_id=operation_id,
        spec=spec.payload(),
        context=wire_context(context),
    )
    prepared: dict[str, object] = answer if isinstance(answer, dict) else {}
    change, pinned = prepared.get("change"), prepared.get("files")
    guard_home, config = prepared.get("guard_home"), prepared.get("config")
    if (
        not isinstance(change, dict)
        or not isinstance(pinned, list)
        or not all(isinstance(item, dict) for item in pinned)
        or not isinstance(guard_home, str)
        or not isinstance(config, str)
    ):
        raise TransitionError("native_transition_invalid")
    files = tuple(transition_file(item) for item in pinned)
    return PreparedCodexHookRepair(transition_file(change), files, Path(guard_home), Path(config), operation_id)


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
    """The runtime authenticates the manifest with its own key and decides the state."""
    from .codex_harness_client import verify_manifest_state

    check_hook_validation_deadline()
    state = verify_manifest_state(spec, hooks=hooks, captured_text=captured_text)
    check_hook_validation_deadline()
    return state


__all__ = [
    "MANAGED_CODEX_HOOK_EVENTS",
    "CodexHookManifestSpec",
    "PreparedCodexHookPublication",
    "load_hook_manifest_baseline",
    "manifest_bindings",
    "verify_live_hook_manifest",
]
