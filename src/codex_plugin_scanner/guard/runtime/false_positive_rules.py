"""Path and ``fd`` argument helpers shared by Guard secret-file request detectors.

The false-positive signal classifiers (source search, health endpoint, read-only
HTTP probe, version, manifest and docs/example paths) are owned by the native
resident; see ``native_false_positive_rules``.
"""

from __future__ import annotations

import os
from pathlib import Path

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
KNOWN_AGENT_DOC_SUFFIXES = (
    ".codex/docs/harness-engineering.md",
    ".codex/docs/token-discipline.md",
)
FD_OPTION_VALUE_FLAGS = frozenset(
    {
        "-d",
        "--max-depth",
        "-E",
        "--exclude",
        "-e",
        "--extension",
        "-t",
        "--type",
        "-S",
        "--size",
        "-o",
        "--owner",
        "--changed-before",
        "--changed-within",
        "--changed-after",
        "-j",
        "--threads",
        "--path-separator",
    }
)


def target_is_known_skill_doc_path(target: str, *, home_dir: Path | None = None) -> bool:
    """Return true for known local skill-doc roots without resolving user path text."""
    if any(marker in target for marker in ("$", "`", "<", ">", "|", ";", "&")):
        return False
    # Handle skill:// URIs: resolve the skill name against known doc roots.
    if target.startswith("skill://"):
        skill_name = target[len("skill://") :].strip().strip("'\"")
        if skill_name:
            skill_name = os.path.normpath(skill_name).replace("\\", "/")
            if not skill_name or skill_name.startswith("..") or skill_name == "." or skill_name.startswith("/"):
                return False
            home = os.path.normpath(str(home_dir or Path.home())).replace("\\", "/")
            for suffix in KNOWN_SKILL_DOC_ROOT_SUFFIXES:
                root = f"{home}/{suffix}"
                candidate_dir = f"{root}/{skill_name}"
                candidate_file = f"{candidate_dir}/SKILL.md"
                if not os.path.isfile(candidate_file):
                    continue
                # Skill directories are often symlinks managed by the harness
                # (e.g. ~/.claude/skills/foo -> /project/.agents/skills/foo).
                # Require SKILL.md to exist and not be a symlink escaping its dir.
                real_candidate = os.path.realpath(candidate_dir)
                real_file = os.path.realpath(candidate_file)
                if real_file != real_candidate and not real_file.startswith(f"{real_candidate}/"):
                    continue
                return True
        return False
    if target == "~" or target.startswith("~/"):
        expanded = f"{home_dir or Path.home()}{target[1:]}"
    else:
        expanded = os.path.expanduser(target)
    normalized = os.path.normpath(expanded).replace("\\", "/")
    home = os.path.normpath(str(home_dir or Path.home())).replace("\\", "/")
    for suffix in KNOWN_SKILL_DOC_ROOT_SUFFIXES:
        root = f"{home}/{suffix}"
        if normalized != root and not normalized.startswith(f"{root}/"):
            continue
        if os.path.islink(root):
            continue
        if not _path_has_symlink_component(normalized, root=root):
            return True
        relative_parts = Path(normalized).relative_to(root).parts
        if len(relative_parts) != 2 or relative_parts[-1] != "SKILL.md":
            continue
        candidate_dir = Path(root) / relative_parts[0]
        candidate_file = candidate_dir / "SKILL.md"
        try:
            real_candidate = candidate_dir.resolve(strict=True)
            real_file = candidate_file.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if candidate_file.is_file() and real_candidate in real_file.parents:
            return True
    for suffix in KNOWN_AGENT_DOC_SUFFIXES:
        expected = f"{home}/{suffix}"
        if (
            normalized == expected
            and os.path.isfile(expected)
            and not os.path.islink(home)
            and not _path_has_symlink_component(normalized, root=home)
        ):
            return True
    return False


def _path_has_symlink_component(normalized_target: str, *, root: str) -> bool:
    if os.path.islink(root):
        return True
    if normalized_target == root:
        return False
    relative = normalized_target.removeprefix(f"{root}/")
    current = root
    for part in relative.split("/"):
        if not part:
            return True
        current = f"{current}/{part}"
        if os.path.islink(current):
            return True
    return False


def fd_arg_requests_exec(arg: str) -> bool:
    if arg in {"-x", "-X", "--exec", "--exec-batch"} or arg.startswith(("-x", "-X", "--exec=", "--exec-batch=")):
        return True
    if not arg.startswith("-") or arg.startswith("--"):
        return False
    cluster = arg[1:]
    for flag in cluster:
        if flag in {"d", "E", "e", "j", "o", "S", "t"}:
            return False
        if flag in {"x", "X"}:
            return True
    return False


def fd_args_follow_symlinks(args: list[str]) -> bool:
    after_options = False
    for arg in args:
        if after_options:
            continue
        if arg == "--":
            after_options = True
            continue
        if arg == "--follow":
            return True
        if arg.startswith("--"):
            continue
        if not arg.startswith("-") or arg == "-":
            continue
        cluster = arg[1:]
        for flag in cluster:
            if flag in {"c", "d", "E", "e", "j", "o", "S", "t", "x", "X"}:
                break
            if flag == "L":
                return True
    return False


def split_fd_args_and_exec(args: list[str]) -> tuple[list[str], list[str]] | None:
    for index, arg in enumerate(args):
        if arg == "-X" or arg.startswith("-X") or arg == "--exec-batch" or arg.startswith(("--exec=", "--exec-batch=")):
            return None
        if arg in {"-x", "--exec"}:
            return args[:index], args[index + 1 :]
        if arg.startswith("-x"):
            exec_token = arg[2:]
            if not exec_token:
                return None
            return args[:index], [exec_token, *args[index + 1 :]]
        if arg.startswith("-") and not arg.startswith("--"):
            cluster = arg[1:]
            for flag_index, flag in enumerate(cluster):
                if flag in {"d", "E", "e", "j", "o", "S", "t"}:
                    break
                if flag == "X":
                    return None
                if flag == "x":
                    exec_token = cluster[flag_index + 1 :]
                    exec_parts = ([exec_token] if exec_token else []) + args[index + 1 :]
                    return args[:index], exec_parts
    return None


def fd_exec_token_is_plain_sed(token: str) -> bool:
    shell_markers = ("/", "\\", ";", "&", "|", "<", ">", "`", "$")
    return Path(token).name == "sed" and not any(marker in token for marker in shell_markers)


def fd_search_targets(args: list[str]) -> tuple[str, ...] | None:
    parsed = split_fd_args_and_exec(args)
    fd_args = parsed[0] if parsed is not None else args
    positional: list[str] = []
    search_paths: list[str] = []
    skip_next = False
    for index, arg in enumerate(fd_args):
        if skip_next:
            skip_next = False
            continue
        if arg == "--base-directory" or arg.startswith("--base-directory="):
            return None
        if arg == "--search-path":
            if index + 1 >= len(fd_args):
                return None
            search_paths.append(fd_args[index + 1])
            skip_next = True
            continue
        if arg.startswith("--search-path="):
            search_paths.append(arg.split("=", 1)[1])
            continue
        if arg in FD_OPTION_VALUE_FLAGS:
            skip_next = True
            continue
        if any(arg.startswith(f"{flag}=") for flag in FD_OPTION_VALUE_FLAGS if flag.startswith("--")):
            continue
        if arg.startswith("-"):
            continue
        positional.append(arg)
    if search_paths:
        return tuple(search_paths)
    if len(positional) >= 2:
        return tuple(positional[1:])
    return ()
