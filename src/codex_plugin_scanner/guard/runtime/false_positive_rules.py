"""Path and ``fd`` argument helpers shared by Guard secret-file request detectors.

The false-positive signal classifiers (source search, health endpoint, read-only
HTTP probe, version, manifest and docs/example paths) are owned by the native
resident as part of the runtime detector run; see ``native_runtime_detectors``.
"""

from __future__ import annotations

from pathlib import Path

from ..native_cli_runtime_support import cli_runtime_support

SOURCE_INSPECTION_PARTS = frozenset(
    {
        "__tests__",
        "app",
        "constants",
        "dashboard",
        "docs",
        "lib",
        "packages",
        "scripts",
        "src",
        "test",
        "tests",
        "workers",
    }
)
SOURCE_INSPECTION_EXTENSIONS = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".css",
        ".go",
        ".h",
        ".hpp",
        ".html",
        ".java",
        ".js",
        ".jsx",
        ".json",
        ".md",
        ".mjs",
        ".py",
        ".rs",
        ".sh",
        ".toml",
        ".ts",
        ".tsx",
        ".yaml",
        ".yml",
    }
)
SOURCE_INSPECTION_SENSITIVE_PARTS = frozenset(
    {".aws", ".docker", ".env", ".git-credentials", ".kube", ".netrc", ".npmrc", ".pypirc", ".ssh", "credentials"}
)
SOURCE_INSPECTION_BENIGN_DOTFILES = frozenset({".nvmrc"})
KNOWN_SKILL_DOC_ROOT_SUFFIXES = (
    ".codex/superpowers/skills",
    ".codex/skills",
    ".agents/skills",
    ".claude/skills",
)


def _bound_rule(operation: str, params: dict[str, object]) -> bool:
    result = cli_runtime_support(operation, params)
    if not isinstance(result, bool):
        raise ValueError("native_cli_runtime_support_result_invalid")
    return result


def target_is_known_skill_doc_path(target: str, *, home_dir: Path | None = None) -> bool:
    """Return true for known local skill-doc roots without resolving user path text."""
    home = str(home_dir) if home_dir is not None else str(Path.home())
    return _bound_rule("skill_doc_path", {"value": target, "home_dir": home})


def fd_arg_requests_exec(arg: str) -> bool:
    return _bound_rule("fd_exec_request", {"value": arg})
