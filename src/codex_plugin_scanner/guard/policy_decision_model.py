"""Typed persisted generic policy authority."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

from .exact_command import EXACT_COMMAND_CONTRACT, validate_exact_command_selector

if TYPE_CHECKING:
    from .models import DecisionScope, GuardAction


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Persisted policy decision."""

    harness: str
    scope: DecisionScope
    action: GuardAction
    artifact_id: str | None = None
    artifact_hash: str | None = None
    workspace: str | None = None
    publisher: str | None = None
    reason: str | None = None
    owner: str | None = None
    source: str = "local"
    expires_at: str | None = None
    exact_command_sha256: str | None = None

    def __post_init__(self) -> None:
        if self.exact_command_sha256 is None:
            return
        validate_exact_command_selector(
            {"contractVersion": EXACT_COMMAND_CONTRACT, "sha256": self.exact_command_sha256}
        )
        if self.scope not in {"artifact", "workspace"} or not self.artifact_id:
            raise ValueError("exact_command_requires_artifact_or_workspace_target")

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
