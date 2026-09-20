"""Carry captured terminal controls across the generic command boundary."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from ..runtime.extension_control_authority import AuthorityHealth
from ..runtime.extension_control_contract import ControlSurface
from ..runtime.extension_control_resolver import resolve_extension_controls
from ..runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot

if TYPE_CHECKING:
    from ..store import GuardStore


@dataclass(frozen=True, slots=True)
class GenericCommandControl:
    reason_code: Literal["control.global-lockdown", "control.resolver-failure"]
    failure_codes: tuple[str, ...]

    @property
    def message(self) -> str:
        if self.reason_code == "control.global-lockdown":
            return (
                "Guard Lockdown is active. "
                "An authorized administrator must turn off Lockdown before this command can run."
            )
        return (
            "Guard could not verify required policy controls. "
            "Restore policy access or contact your administrator before retrying."
        )

    def to_evidence(self) -> dict[str, object]:
        return {
            "source": "extension_control",
            "status": "blocked",
            "reason_code": self.reason_code,
            "failure_codes": list(self.failure_codes),
            "reason": self.message,
        }


def generic_command_control(
    store: GuardStore,
    snapshot: ExtensionControlRuntimeSnapshot | None,
    *,
    event: str | None,
    command: str | None,
) -> GenericCommandControl | None:
    """Generic commands have no catalog observations, while Lockdown still applies."""
    if event != "PreToolUse" or not isinstance(command, str) or not command.strip():
        return None
    if snapshot is None:
        # Direct calls and post-claim revalidation must capture fresh authority;
        # caller-provided payload fields are never a source for this boundary.
        snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
            store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
        )
    if snapshot.health is AuthorityHealth.UNENROLLED:
        # No protected authority exists yet. Preserve the existing generic
        # configuration contract; an enrolled failure is handled below.
        return None
    resolution = resolve_extension_controls(
        snapshot.layers,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=(),
        permission_ids=(),
        surface=ControlSurface.COMMAND_EVALUATION,
        authority_failure=snapshot.authority_failure,
    )
    if not resolution.blocked:
        return None
    if resolution.failures:
        return GenericCommandControl(
            "control.resolver-failure", tuple(sorted({failure.code.value for failure in resolution.failures}))
        )
    return GenericCommandControl("control.global-lockdown", ())
