"""Normalize transparent shell wrappers before Guard evaluates a command."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path

_MAX_NORMALIZE_BYTES = 8192
_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
_SHELL_CONTROL_TOKENS = frozenset({"&&", "||", ";", "|", "|&", "&"})
_LEAN_CTX_BINARIES = frozenset({"lean-ctx"})
_SHELL_STRING_WRAPPERS = frozenset({"ash", "bash", "dash", "fish", "sh", "zsh"})
_PLAIN_WRAPPERS = frozenset({"command", "nice", "nohup", "stdbuf", "time"})
_ENV_OPTION_FLAGS_WITH_VALUES = frozenset({"-u", "-C", "--unset", "--chdir"})
_NICE_OPTION_FLAGS_WITH_VALUES = frozenset({"-n", "--adjustment"})
_STDBUF_VALUE_FLAGS = frozenset({"-i", "-o", "-e"})
_TIME_OPTION_FLAGS_WITH_VALUES = frozenset({"-f", "-o", "--format", "--output"})
_TRUSTED_INSTALL_DIRS = (Path("/opt/homebrew/bin"), Path("/usr/local/bin"))


@dataclass(frozen=True, slots=True)
class ShellCommandNormalization:
    raw_command: str
    normalized_command: str
    wrapper_chain: tuple[str, ...] = ()


def normalize_transparent_shell_command(
    command_text: str,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> ShellCommandNormalization:
    stripped = command_text.strip()
    if not stripped or len(stripped) > _MAX_NORMALIZE_BYTES:
        return ShellCommandNormalization(
            raw_command=stripped,
            normalized_command=stripped,
            wrapper_chain=(),
        )
    normalized_command, wrapper_chain = _normalize_command_text(stripped, depth=0, cwd=cwd, home_dir=home_dir)
    return ShellCommandNormalization(
        raw_command=stripped,
        normalized_command=normalized_command or stripped,
        wrapper_chain=wrapper_chain,
    )


def _normalize_command_text(
    command_text: str,
    *,
    depth: int,
    cwd: Path | None,
    home_dir: Path | None,
) -> tuple[str, tuple[str, ...]]:
    if depth > 8:
        return command_text, ()
    try:
        parts = shlex.split(command_text, posix=True, comments=False)
    except ValueError:
        return command_text, ()
    if not parts:
        return command_text, ()
    prefix_env, index = _consume_leading_env_assignments(parts, start=0)
    normalized, wrappers = _normalize_parts(
        parts[index:], depth=depth, initial_env=prefix_env, cwd=cwd, home_dir=home_dir
    )
    if not wrappers:
        return command_text, ()
    if normalized is None:
        return command_text, wrappers
    return normalized, wrappers


def _normalize_parts(
    parts: list[str],
    *,
    depth: int,
    cwd: Path | None,
    home_dir: Path | None,
    initial_env: list[str] | None = None,
) -> tuple[str | None, tuple[str, ...]]:
    current = list(parts)
    preserved_env: list[str] = list(initial_env or [])
    wrappers: list[str] = []
    while current:
        current_env, env_index = _consume_leading_env_assignments(current, start=0)
        if current_env:
            preserved_env.extend(current_env)
            current = current[env_index:]
            if not current:
                break
        command_name = _command_name(current[0], env_assignments=preserved_env, cwd=cwd, home_dir=home_dir)
        if command_name in _LEAN_CTX_BINARIES:
            normalized = _unwrap_lean_ctx(current)
            if normalized is None:
                break
            inner_command, suffix = normalized
            wrappers.append(command_name)
            inner_text, inner_wrappers = _normalize_command_text(
                inner_command,
                depth=depth + 1,
                cwd=cwd,
                home_dir=home_dir,
            )
            suffix_text = _join_shell_tokens(suffix) if suffix else ""
            inner_command_text = _join_command_fragments(inner_text, suffix_text)
            if preserved_env:
                inner_command_text = _join_command_fragments(_join_shell_tokens(preserved_env), inner_command_text)
            return inner_command_text, tuple((*wrappers, *inner_wrappers))
        if command_name in _SHELL_STRING_WRAPPERS:
            normalized = _unwrap_shell_string_wrapper(current)
            if normalized is None:
                break
            inner_command, suffix = normalized
            wrappers.append(command_name)
            inner_text, inner_wrappers = _normalize_command_text(
                inner_command,
                depth=depth + 1,
                cwd=cwd,
                home_dir=home_dir,
            )
            suffix_text = _join_shell_tokens(suffix) if suffix else ""
            inner_command_text = _join_command_fragments(inner_text, suffix_text)
            if preserved_env:
                inner_command_text = _join_command_fragments(_join_shell_tokens(preserved_env), inner_command_text)
            return inner_command_text, tuple((*wrappers, *inner_wrappers))
        if command_name == "env":
            next_parts, env_prefix, env_split = _strip_env_wrapper(current)
            if env_split is not None:
                wrappers.append("env")
                inner_text, inner_wrappers = _normalize_command_text(
                    env_split,
                    depth=depth + 1,
                    cwd=cwd,
                    home_dir=home_dir,
                )
                all_env = [*preserved_env, *env_prefix]
                if all_env:
                    inner_text = _join_command_fragments(_join_shell_tokens(all_env), inner_text)
                return inner_text, tuple((*wrappers, *inner_wrappers))
            if next_parts is None:
                break
            wrappers.append("env")
            preserved_env.extend(env_prefix)
            current = next_parts
            continue
        if command_name == "command":
            next_parts = _strip_command_wrapper(current)
            if next_parts is None:
                break
            wrappers.append("command")
            current = next_parts
            continue
        if command_name == "time":
            next_parts = _strip_time_wrapper(current)
            if next_parts is None:
                break
            wrappers.append("time")
            current = next_parts
            continue
        if command_name == "nice":
            next_parts = _strip_nice_wrapper(current)
            if next_parts is None:
                break
            wrappers.append("nice")
            current = next_parts
            continue
        if command_name == "nohup":
            next_parts = _strip_nohup_wrapper(current)
            if next_parts is None:
                break
            wrappers.append("nohup")
            current = next_parts
            continue
        if command_name == "stdbuf":
            next_parts = _strip_stdbuf_wrapper(current)
            if next_parts is None:
                break
            wrappers.append("stdbuf")
            current = next_parts
            continue
        break
    current_text = _join_shell_tokens(current)
    if preserved_env:
        current_text = _join_command_fragments(_join_shell_tokens(preserved_env), current_text)
    return current_text, tuple(wrappers)


def _consume_leading_env_assignments(parts: list[str], *, start: int) -> tuple[list[str], int]:
    prefix: list[str] = []
    index = start
    while index < len(parts) and _ENV_ASSIGNMENT_RE.fullmatch(parts[index]):
        prefix.append(parts[index])
        index += 1
    return prefix, index


def _unwrap_lean_ctx(parts: list[str]) -> tuple[str, list[str]] | None:
    index = 1
    while index < len(parts):
        token = parts[index]
        if token == "--":
            index += 1
            break
        if token in {"-c", "--command"}:
            if index + 1 >= len(parts):
                return None
            return parts[index + 1], parts[index + 2 :]
        index += 1
    return None


def _unwrap_shell_string_wrapper(parts: list[str]) -> tuple[str, list[str]] | None:
    index = 1
    while index < len(parts):
        token = parts[index]
        if token == "--":
            index += 1
            break
        if token.startswith("-") and not token.startswith("--") and "c" in token[1:]:
            if index + 1 >= len(parts):
                return None
            return parts[index + 1], parts[index + 2 :]
        if token.startswith("-"):
            index += 1
            continue
        return None
    return None


def _strip_env_wrapper(parts: list[str]) -> tuple[list[str] | None, list[str], str | None]:
    env_prefix: list[str] = []
    index = 1
    while index < len(parts):
        token = parts[index]
        if _ENV_ASSIGNMENT_RE.fullmatch(token):
            env_prefix.append(token)
            index += 1
            continue
        if token == "--":
            return parts[index + 1 :], env_prefix, None
        if token in {"-S", "--split-string"}:
            if index + 1 >= len(parts):
                return None, env_prefix, None
            return [], env_prefix, parts[index + 1]
        split_string = _env_clustered_split_string_payload(token)
        if split_string is not None:
            if split_string:
                return [], env_prefix, split_string
            if index + 1 >= len(parts):
                return None, env_prefix, None
            return [], env_prefix, parts[index + 1]
        short_option_tokens = _env_short_option_tokens_consumed(token)
        if short_option_tokens is not None:
            if index + short_option_tokens - 1 >= len(parts):
                return None, env_prefix, None
            index += short_option_tokens
            continue
        if token in _ENV_OPTION_FLAGS_WITH_VALUES:
            if index + 1 >= len(parts):
                return None, env_prefix, None
            index += 2
            continue
        if any(token.startswith(f"{flag}=") for flag in {"--unset", "--chdir", "--split-string"}):
            if token.startswith("--split-string="):
                return [], env_prefix, token.partition("=")[2]
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        return parts[index:], env_prefix, None
    return None, env_prefix, None


def _strip_command_wrapper(parts: list[str]) -> list[str] | None:
    index = 1
    while index < len(parts):
        token = parts[index]
        if token == "--":
            return parts[index + 1 :]
        if not token.startswith("-"):
            return parts[index:]
        if "v" in token[1:] or "V" in token[1:]:
            return None
        index += 1
    return None


def _strip_time_wrapper(parts: list[str]) -> list[str] | None:
    index = 1
    while index < len(parts):
        token = parts[index]
        if token == "--":
            return parts[index + 1 :]
        if token in _TIME_OPTION_FLAGS_WITH_VALUES:
            if index + 1 >= len(parts):
                return None
            index += 2
            continue
        if token.startswith("--format=") or token.startswith("--output="):
            index += 1
            continue
        if (token.startswith("-f") and token != "-f") or (token.startswith("-o") and token != "-o"):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        return parts[index:]
    return None


def _strip_nice_wrapper(parts: list[str]) -> list[str] | None:
    index = 1
    while index < len(parts):
        token = parts[index]
        if token == "--":
            return parts[index + 1 :]
        if token in _NICE_OPTION_FLAGS_WITH_VALUES:
            if index + 1 >= len(parts):
                return None
            index += 2
            continue
        if token.startswith("--adjustment=") or (token.startswith("-n") and token != "-n"):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        return parts[index:]
    return None


def _strip_nohup_wrapper(parts: list[str]) -> list[str] | None:
    index = 1
    while index < len(parts) and parts[index].startswith("-"):
        index += 1
    return parts[index:] or None


def _strip_stdbuf_wrapper(parts: list[str]) -> list[str] | None:
    index = 1
    while index < len(parts):
        token = parts[index]
        if token == "--":
            return parts[index + 1 :]
        if token in _STDBUF_VALUE_FLAGS:
            if index + 1 >= len(parts):
                return None
            index += 2
            continue
        if any(token.startswith(flag) for flag in _STDBUF_VALUE_FLAGS):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        return parts[index:]
    return None


def _env_short_option_tokens_consumed(token: str) -> int | None:
    if not token.startswith("-") or token.startswith("--") or len(token) <= 2:
        return None
    for index, flag_character in enumerate(token[1:], start=1):
        if flag_character not in {"C", "S", "u"}:
            continue
        if index < len(token) - 1:
            return 1
        return 2
    return 1


def _env_clustered_split_string_payload(token: str) -> str | None:
    if not token.startswith("-") or token.startswith("--") or len(token) <= 2:
        return None
    split_index = token.find("S", 1)
    if split_index == -1:
        return None
    if split_index + 1 >= len(token):
        return ""
    return token[split_index + 1 :]


def _command_name(
    token: str,
    *,
    env_assignments: list[str] | tuple[str, ...] = (),
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> str:
    if "/" not in token and "\\" not in token:
        if _env_assignments_override_path(env_assignments):
            return ""
        return token.lower()
    command_path = Path(token)
    if not command_path.is_absolute():
        return ""
    if not _trusted_absolute_command_path(command_path, cwd=cwd, home_dir=home_dir):
        return ""
    return command_path.name.lower()


def _trusted_absolute_command_path(command_path: Path, *, cwd: Path | None, home_dir: Path | None) -> bool:
    try:
        if _path_is_under(command_path, cwd) or not _stable_non_writable_path(command_path):
            return False
    except OSError:
        return False
    if _root_owned_path_chain(command_path):
        return True
    return _path_is_under_trusted_install_dir(command_path, home_dir=home_dir)


def _stable_non_writable_path(path: Path) -> bool:
    for candidate in (path, *path.parents):
        if candidate.is_symlink() or not _path_is_non_writable(candidate):
            return False
        if candidate == candidate.parent:
            break
    return True


def _root_owned_path_chain(path: Path) -> bool:
    return all(_path_is_root_owned(candidate) for candidate in (path, *path.parents))


def _path_is_under_trusted_install_dir(path: Path, *, home_dir: Path | None) -> bool:
    trusted_dirs = [*_TRUSTED_INSTALL_DIRS]
    if home_dir is not None:
        trusted_dirs.append(home_dir / ".local" / "bin")
    return any(_path_is_under(path, trusted_dir) for trusted_dir in trusted_dirs)


def _path_is_under(path: Path, base: Path | None) -> bool:
    if base is None:
        return False
    try:
        path.resolve(strict=False).relative_to(base.resolve(strict=False))
    except ValueError:
        return False
    return True


def _path_is_root_owned(path: Path) -> bool:
    return path.stat().st_uid == 0


def _path_is_non_writable(path: Path) -> bool:
    return not path.stat().st_mode & 0o022


def _env_assignments_override_path(env_assignments: list[str] | tuple[str, ...]) -> bool:
    return any(assignment.split("=", 1)[0] == "PATH" for assignment in env_assignments)


def _join_command_fragments(*fragments: str) -> str:
    return " ".join(fragment for fragment in fragments if fragment).strip()


def _join_shell_tokens(tokens: list[str]) -> str:
    rendered: list[str] = []
    for token in tokens:
        if token in _SHELL_CONTROL_TOKENS:
            rendered.append(token)
            continue
        rendered.append(shlex.quote(token))
    return " ".join(rendered).strip()


__all__ = ["ShellCommandNormalization", "normalize_transparent_shell_command"]
