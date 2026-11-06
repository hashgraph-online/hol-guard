"""Known skill-doc roots shared by Guard's local skill index.

The false-positive signal classifiers (source search, health endpoint, read-only
HTTP probe, version, manifest and docs/example paths) are owned by the native
resident as part of the runtime detector run; see ``native_runtime_detectors``.
"""

from __future__ import annotations

KNOWN_SKILL_DOC_ROOT_SUFFIXES = (
    ".codex/superpowers/skills",
    ".codex/skills",
    ".agents/skills",
    ".claude/skills",
)
