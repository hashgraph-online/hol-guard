"""Public secret-sensitivity DTOs presented from native authority."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ..native_content_sensitivity import content_query

SecretSensitivity = Literal["high", "critical"]
SecretContentSensitivity = Literal["medium", "high", "critical"]


@dataclass(frozen=True, slots=True)
class SecretPathMatch:
    family: str
    path: str
    sensitivity: SecretSensitivity
    reason: str
    requested_path: str = ""

    @property
    def normalized_path(self) -> str:
        return self.path

    @property
    def path_class(self) -> str:
        return self.family


@dataclass(frozen=True, slots=True)
class SecretContentMatch:
    classifier: str
    family: str
    sensitivity: SecretContentSensitivity
    reason: str


def classify_secret_path(
    path: str | None, *, cwd: Path | None = None, home_dir: Path | None = None
) -> SecretPathMatch | None:
    result = content_query(
        "path", {"path": path, "cwd": str(cwd) if cwd is not None else None, "home_dir": str(home_dir or Path.home())}
    )
    return None if result is None else SecretPathMatch(**result)


def classify_legacy_secret_path_families(text: str) -> set[str]:
    return set(content_query("legacy", {"text": text}))


def classify_secret_paths_batch(
    paths: list[str], *, cwd: Path | None = None, home_dir: Path | None = None, deadline_monotonic: float | None = None
) -> tuple[SecretPathMatch | None, ...]:
    """Present one bounded native classification batch without recomputing it."""
    result = content_query(
        "path_batch",
        {"paths": paths, "cwd": str(cwd) if cwd is not None else None, "home_dir": str(home_dir or Path.home())},
        deadline_monotonic=deadline_monotonic,
    )
    if len(result) != len(paths):
        from ..native_content_sensitivity import NativeContentSensitivityError

        raise NativeContentSensitivityError("native_content_sensitivity_batch_unbound")
    return tuple(None if item is None else SecretPathMatch(**item) for item in result)


def classify_secret_content(
    text: str | None, *, suppress_samples: bool = True, documentation_sample_context: bool = False
) -> tuple[SecretContentMatch, ...]:
    result = content_query(
        "content",
        {
            "text": text,
            "suppress_samples": suppress_samples,
            "documentation_sample_context": documentation_sample_context,
        },
    )
    return tuple(SecretContentMatch(**item) for item in result)
