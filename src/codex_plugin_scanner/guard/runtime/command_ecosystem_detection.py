"""Secret-safe command ecosystem detection for setup recommendations."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from .command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    COMMAND_EXTENSION_SCHEMA_VERSION,
    CommandSafetyExtension,
    CommandSafetyExtensionRegistry,
)


@dataclass(frozen=True, slots=True)
class CommandEcosystemDetection:
    """One deterministic extension recommendation without sensitive values."""

    extension: CommandSafetyExtension
    project_markers: tuple[str, ...]
    available_executables: tuple[str, ...]

    @property
    def detected(self) -> bool:
        return bool(self.project_markers or self.available_executables)

    @property
    def recommended(self) -> bool:
        return bool(self.project_markers)

    def to_dict(self) -> dict[str, object]:
        return {
            "extension_id": self.extension.extension_id,
            "name": self.extension.name,
            "version": self.extension.version,
            "source": self.extension.source,
            "delegated_protection": self.extension.delegated_protection,
            "ecosystem_ids": list(self.extension.ecosystem_ids),
            "detected": self.detected,
            "recommended": self.recommended,
            "project_markers": list(self.project_markers),
            "available_executables": list(self.available_executables),
        }


def detect_command_ecosystems(
    workspace: Path,
    *,
    registry: CommandSafetyExtensionRegistry = BUILT_IN_COMMAND_EXTENSION_REGISTRY,
) -> tuple[CommandEcosystemDetection, ...]:
    """Detect package ecosystems from marker names and command availability only."""

    workspace_root = workspace.resolve()
    detections: list[CommandEcosystemDetection] = []
    for extension in registry.extensions:
        if extension.delegated_protection != "package-firewall":
            continue
        markers = tuple(marker for marker in extension.project_markers if (workspace_root / marker).is_file())
        executables = tuple(executable for executable in extension.executables if shutil.which(executable) is not None)
        detections.append(
            CommandEcosystemDetection(
                extension=extension,
                project_markers=markers,
                available_executables=executables,
            )
        )
    return tuple(detections)


def command_setup_detection_payload(workspace: Path) -> dict[str, object]:
    """Build a side-effect-free setup preview for command ecosystem protection."""

    detections = detect_command_ecosystems(workspace)
    detected = tuple(item for item in detections if item.detected)
    recommended = tuple(item for item in detections if item.recommended)
    return {
        "schema_version": COMMAND_EXTENSION_SCHEMA_VERSION,
        "mode": "detect",
        "side_effects": "none",
        "detected_count": len(detected),
        "recommended_count": len(recommended),
        "available_count": len(detections),
        "recommended_extension_ids": [item.extension.extension_id for item in recommended],
        "detections": [item.to_dict() for item in detections],
    }
