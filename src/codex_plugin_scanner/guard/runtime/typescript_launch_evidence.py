"""Typed evidence for reviewable local TypeScript compiler launches."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

TypeScriptLaunchStatus = Literal["complete", "incomplete"]


@dataclass(frozen=True, slots=True)
class TypeScriptLaunchEvidence:
    """Complete launch identity evidence that never grants a silent allow."""

    schema_version: int
    status: TypeScriptLaunchStatus
    reasons: tuple[str, ...]
    binding_digest: str
    manager_name: str
    package_name: str | None
    executable_name: str | None
    declared_version: str | None
    locked_version: str | None
    installed_version: str | None
    config_mode: str
    source_files: tuple[str, ...]
    evidence_scope: Literal["launch_identity"] = "launch_identity"
    review_disposition: Literal["review_required"] = "review_required"
    direct_silent_verification: bool = False

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
