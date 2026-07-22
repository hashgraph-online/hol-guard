"""Git configuration safety helpers for Guard CLI command inspection."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .commands_support_codex_paths import (
        _git_config_enables_diff_helper,
        _git_config_logical_lines,
        _git_config_value_without_inline_comment,
    )


from ._commands_shared import *
from .commands_parser_helpers import *


def _git_repo_diff_helpers_are_unconfigured(cwd: Path | None) -> bool:
    if cwd is None:
        return False
    if (
        os.environ.get("GIT_EXTERNAL_DIFF")
        or os.environ.get("GIT_CONFIG_COUNT")
        or os.environ.get("GIT_CONFIG_PARAMETERS")
    ):
        return False
    config_paths = _git_repo_config_paths(cwd)
    if not config_paths:
        return True
    repo_dir = _git_repo_root(cwd)
    seen_paths: set[Path] = set()
    for config_path in config_paths:
        if not _git_config_tree_disables_diff_helpers(config_path, seen_paths=seen_paths, repo_dir=repo_dir):
            return False
    return True


def _git_repo_config_paths(cwd: Path) -> tuple[Path, ...]:
    current = cwd.resolve()
    if current.is_file():
        current = current.parent
    for candidate in (current, *current.parents):
        git_path = candidate / ".git"
        if git_path.is_dir():
            return (*_git_global_config_paths(), git_path / "config", git_path / "config.worktree")
        if git_path.is_file():
            git_dir = _git_dir_from_file(git_path)
            if git_dir is None:
                return ()
            common_dir = _git_common_dir(git_dir)
            paths = [*_git_global_config_paths(), git_dir / "config", git_dir / "config.worktree"]
            if common_dir != git_dir:
                paths.extend([common_dir / "config", common_dir / "config.worktree"])
            return tuple(paths)
    return _git_global_config_paths()


def _git_repo_root(cwd: Path) -> Path | None:
    current = cwd.absolute()
    if current.is_file():
        current = current.parent
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def _git_global_config_paths() -> tuple[Path, ...]:
    paths: list[Path] = []
    system_config = os.environ.get("GIT_CONFIG_SYSTEM")
    if system_config:
        if system_config != os.devnull:
            paths.append(Path(system_config).expanduser())
    elif not os.environ.get("GIT_CONFIG_NOSYSTEM"):
        paths.append(Path("/etc/gitconfig"))
    global_config = os.environ.get("GIT_CONFIG_GLOBAL")
    if global_config:
        if global_config != os.devnull:
            paths.append(Path(global_config).expanduser())
    else:
        home = os.environ.get("HOME")
        if home:
            home_path = Path(home).expanduser()
            paths.append(home_path / ".gitconfig")
            xdg_config_home = Path(os.environ.get("XDG_CONFIG_HOME", str(home_path / ".config"))).expanduser()
            paths.append(xdg_config_home / "git" / "config")
    return tuple(paths)


def _git_dir_from_file(git_file: Path) -> Path | None:
    try:
        content = git_file.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return None
    prefix = "gitdir:"
    if not content.lower().startswith(prefix):
        return None
    raw_path = content[len(prefix) :].strip()
    git_dir = Path(raw_path)
    if not git_dir.is_absolute():
        git_dir = (git_file.parent / git_dir).resolve()
    return git_dir


def _git_common_dir(git_dir: Path) -> Path:
    common_dir_file = git_dir / "commondir"
    if not common_dir_file.is_file():
        return git_dir
    try:
        raw_path = common_dir_file.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return git_dir
    common_dir = Path(raw_path)
    if not common_dir.is_absolute():
        common_dir = (git_dir / common_dir).resolve()
    return common_dir


def _git_config_tree_disables_diff_helpers(config_path: Path, *, seen_paths: set[Path], repo_dir: Path | None) -> bool:
    normalized_path = config_path.expanduser().resolve()
    if normalized_path in seen_paths:
        return True
    seen_paths.add(normalized_path)
    if not normalized_path.is_file():
        return True
    try:
        config_text = normalized_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    if _git_config_enables_diff_helper(config_text):
        return False
    for included_path in _git_config_include_paths(
        config_text,
        allow_hasconfig=True,
        base_dir=normalized_path.parent,
        repo_dir=repo_dir,
    ):
        if not _git_config_tree_disables_diff_helpers(included_path, seen_paths=seen_paths, repo_dir=repo_dir):
            return False
    return True


def _git_config_include_paths(
    config_text: str,
    *,
    allow_hasconfig: bool,
    base_dir: Path,
    repo_dir: Path | None,
) -> tuple[Path, ...]:
    paths: list[Path] = []
    section = ""
    section_active = False
    for raw_line in _git_config_logical_lines(config_text):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        section_match = re.fullmatch(r"\[([^\]]+)\](?:\s*[#;].*)?", line)
        if section_match:
            section = section_match.group(1).strip()
            section_active = _git_include_section_is_active(
                section,
                allow_hasconfig=allow_hasconfig,
                base_dir=base_dir,
                repo_dir=repo_dir,
            )
            continue
        if not section_active:
            continue
        key_match = re.match(r"(?i)^path\s*=\s*(.+)$", line)
        if key_match is None:
            continue
        include_path = Path(_git_config_value_without_inline_comment(key_match.group(1))).expanduser()
        if not include_path.is_absolute():
            include_path = (base_dir / include_path).resolve()
        paths.append(include_path)
    return tuple(paths)


def _git_include_section_is_active(
    section: str,
    *,
    allow_hasconfig: bool,
    base_dir: Path,
    repo_dir: Path | None,
) -> bool:
    section_lower = section.lower()
    if section_lower == "include":
        return True
    if not section_lower.startswith("includeif"):
        return False
    if repo_dir is None:
        return False
    condition_match = re.search(r'"([^"]+)"', section)
    condition = condition_match.group(1) if condition_match else section.removeprefix("includeif").strip()
    condition_lower = condition.lower()
    if condition_lower.startswith("gitdir/i:"):
        return _git_gitdir_condition_matches(
            condition[len("gitdir/i:") :],
            base_dir=base_dir,
            repo_dir=repo_dir,
            case_sensitive=False,
        )
    if condition_lower.startswith("gitdir:"):
        return _git_gitdir_condition_matches(
            condition[len("gitdir:") :],
            base_dir=base_dir,
            repo_dir=repo_dir,
            case_sensitive=True,
        )
    if condition_lower.startswith("onbranch:"):
        return _git_onbranch_condition_matches(condition[len("onbranch:") :], repo_dir=repo_dir)
    if allow_hasconfig and condition_lower.startswith("hasconfig:"):
        return _git_hasconfig_condition_matches(condition[len("hasconfig:") :], repo_dir=repo_dir)
    return False


def _git_gitdir_condition_matches(pattern: str, *, base_dir: Path, repo_dir: Path, case_sensitive: bool) -> bool:
    pattern_text = _git_gitdir_condition_pattern(pattern, base_dir=base_dir)
    patterns = _git_gitdir_condition_patterns(pattern_text)
    candidates = [_git_gitdir_condition_candidate(path) for path in _git_path_aliases(repo_dir)]
    git_dir = _git_effective_git_dir(repo_dir)
    if git_dir is not None:
        candidates.extend(_git_gitdir_condition_candidate(path) for path in _git_path_aliases(git_dir))
    if case_sensitive:
        return any(fnmatch.fnmatchcase(candidate, item) for candidate in candidates for item in patterns)
    return any(fnmatch.fnmatchcase(candidate.lower(), item.lower()) for candidate in candidates for item in patterns)


def _git_path_aliases(path: Path) -> tuple[Path, ...]:
    resolved = path.resolve()
    if resolved == path:
        return (path,)
    return (path, resolved)


def _git_gitdir_condition_candidate(path: Path) -> str:
    return path.as_posix().rstrip("/") + "/"


def _git_gitdir_condition_patterns(pattern_text: str) -> tuple[str, ...]:
    if pattern_text.endswith("/**"):
        return (pattern_text,)
    if pattern_text.endswith("/"):
        return (pattern_text, f"{pattern_text}**")
    return (pattern_text, f"{pattern_text}/", f"{pattern_text}/**")


def _git_gitdir_condition_pattern(pattern: str, *, base_dir: Path) -> str:
    expanded_pattern = pattern.strip()
    pattern_path = Path(expanded_pattern).expanduser()
    if pattern_path.is_absolute():
        return pattern_path.as_posix()
    if expanded_pattern.startswith(("./", "../")):
        return (base_dir / pattern_path).resolve().as_posix()
    return f"**/{expanded_pattern}"


def _git_effective_git_dir(repo_dir: Path) -> Path | None:
    git_path = repo_dir / ".git"
    if git_path.is_dir():
        return git_path
    if git_path.is_file():
        return _git_dir_from_file(git_path)
    return None


def _git_onbranch_condition_matches(pattern: str, *, repo_dir: Path) -> bool:
    git_dir = repo_dir / ".git"
    head_path: Path | None = None
    if git_dir.is_dir():
        head_path = git_dir / "HEAD"
    elif git_dir.is_file():
        parsed_git_dir = _git_dir_from_file(git_dir)
        if parsed_git_dir is not None:
            head_path = parsed_git_dir / "HEAD"
    if head_path is None or not head_path.is_file():
        return False
    try:
        head = head_path.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return False
    prefix = "ref: refs/heads/"
    if not head.startswith(prefix):
        return False
    normalized_pattern = f"{pattern}**" if pattern.endswith("/") else pattern
    return fnmatch.fnmatchcase(head.removeprefix(prefix), normalized_pattern)


def _git_hasconfig_condition_matches(condition: str, *, repo_dir: Path) -> bool:
    key_pattern, _, value_pattern = condition.partition(":")
    if not key_pattern or not value_pattern:
        return False
    if key_pattern.lower() != "remote.*.url":
        return False
    seen_paths: set[Path] = set()
    for config_path in _git_repo_config_paths(repo_dir):
        if any(
            fnmatch.fnmatchcase(value, value_pattern)
            for value in _git_remote_urls_from_config_tree(config_path, seen_paths=seen_paths, repo_dir=repo_dir)
        ):
            return True
    return False


def _git_remote_urls_from_config_tree(config_path: Path, *, seen_paths: set[Path], repo_dir: Path) -> tuple[str, ...]:
    normalized_path = config_path.expanduser().resolve()
    if normalized_path in seen_paths:
        return ()
    seen_paths.add(normalized_path)
    if not normalized_path.is_file():
        return ()
    try:
        config_text = normalized_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ()
    urls = list(_git_remote_urls_from_config(config_text))
    for included_path in _git_config_include_paths(
        config_text,
        allow_hasconfig=False,
        base_dir=normalized_path.parent,
        repo_dir=repo_dir,
    ):
        urls.extend(_git_remote_urls_from_config_tree(included_path, seen_paths=seen_paths, repo_dir=repo_dir))
    return tuple(urls)


def _git_remote_urls_from_config(config_text: str) -> tuple[str, ...]:
    urls: list[str] = []
    in_remote_section = False
    for raw_line in _git_config_logical_lines(config_text):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        section_match = re.fullmatch(r"\[([^\]]+)\](?:\s*[#;].*)?", line)
        if section_match:
            in_remote_section = section_match.group(1).strip().lower().startswith("remote ")
            continue
        if not in_remote_section:
            continue
        key_match = re.match(r"(?i)^url\s*=\s*(.+)$", line)
        if key_match is not None:
            urls.append(_git_config_value_without_inline_comment(key_match.group(1)))
    return tuple(urls)


__all__ = [
    "_git_common_dir",
    "_git_config_include_paths",
    "_git_config_tree_disables_diff_helpers",
    "_git_dir_from_file",
    "_git_effective_git_dir",
    "_git_gitdir_condition_candidate",
    "_git_gitdir_condition_matches",
    "_git_gitdir_condition_pattern",
    "_git_gitdir_condition_patterns",
    "_git_global_config_paths",
    "_git_hasconfig_condition_matches",
    "_git_include_section_is_active",
    "_git_onbranch_condition_matches",
    "_git_path_aliases",
    "_git_remote_urls_from_config",
    "_git_remote_urls_from_config_tree",
    "_git_repo_config_paths",
    "_git_repo_diff_helpers_are_unconfigured",
    "_git_repo_root",
]
