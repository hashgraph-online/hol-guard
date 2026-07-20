"""Semantic, fail-closed parsing for pytest configuration files."""

from __future__ import annotations

import configparser
import hashlib
import importlib
import json
import os
import shlex
import stat
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING or sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised by the Python 3.10 validation job
    tomllib = importlib.import_module("tomli")

MAX_PYTEST_CONFIG_FILE_BYTES = 1_000_000
PYTEST_CONFIG_PATH_INVALID = "pytest_config_path_invalid"
PYTEST_CONFIG_SYMLINK = "pytest_config_symlink"
PYTEST_CONFIG_NOT_REGULAR = "pytest_config_not_regular"
PYTEST_CONFIG_OVERSIZE = "pytest_config_oversize"
PYTEST_CONFIG_DECODE_ERROR = "pytest_config_decode_error"
PYTEST_CONFIG_DUPLICATE_KEY = "pytest_config_duplicate_key"
PYTEST_CONFIG_SYNTAX_ERROR = "pytest_config_syntax_error"
PYTEST_CONFIG_VALUE_TYPE_INVALID = "pytest_config_value_type_invalid"
PYTEST_CONFIG_IO_ERROR = "pytest_config_io_error"
PYTEST_CONFIG_FILE_CHANGED = "pytest_config_file_changed"
PYTEST_CONFIG_MISSING = "pytest_config_missing"

_UNSAFE_ADDOPTS_MARKERS = (
    "--basetemp",
    "--cache-clear",
    "--config-file",
    "--debug",
    "--junit-xml",
    "--junitxml",
    "--log-file",
    "--confcutdir",
    "--override-ini",
    "--rootdir",
    "-c",
    "-o",
)
_UNSAFE_VALUE_KEYS = frozenset({"log_file", "pythonpath", "required_plugins"})


@dataclass(frozen=True, slots=True)
class PytestConfigValue:
    """Execution-affecting values resolved by the containing config grammar."""

    addopts: tuple[str, ...] = ()
    log_file: str | None = None
    execution_options: tuple[tuple[str, str], ...] = ()
    unsafe: bool = False


@dataclass(frozen=True, slots=True)
class PytestConfigParseResult:
    """One config parse with an explicit completeness and evidence identity."""

    source_path: str
    present: bool
    value: PytestConfigValue | None
    complete: bool
    reason_code: str | None
    content_sha256: str | None


@dataclass(frozen=True, slots=True)
class PytestConfigAssessment:
    """Deterministic aggregate used by policy and approval identity."""

    results: tuple[PytestConfigParseResult, ...]
    complete: bool
    unsafe: bool
    reason_codes: tuple[str, ...]
    identity_sha256: str | None


@dataclass(frozen=True, slots=True)
class _ConfigRead:
    present: bool
    content: bytes | None
    reason_code: str | None


def parse_pytest_config(workspace_root: Path, relative_path: str) -> PytestConfigParseResult:
    """Parse one supported config without following a symlink or partial file."""

    normalized_path = Path(relative_path).as_posix()
    read = _read_config_bytes(workspace_root, relative_path)
    if not read.present:
        return PytestConfigParseResult(normalized_path, False, None, read.reason_code is None, read.reason_code, None)
    if read.content is None:
        return PytestConfigParseResult(normalized_path, True, None, False, read.reason_code, None)
    content_hash = hashlib.sha256(read.content).hexdigest()
    try:
        text = read.content.decode("utf-8")
    except UnicodeDecodeError:
        return PytestConfigParseResult(
            normalized_path,
            True,
            None,
            False,
            PYTEST_CONFIG_DECODE_ERROR,
            content_hash,
        )
    try:
        if Path(relative_path).suffix.lower() == ".toml":
            value = _parse_toml(text, filename=Path(relative_path).name)
        else:
            value = _parse_ini(text, filename=Path(relative_path).name)
    except (configparser.DuplicateOptionError, configparser.DuplicateSectionError):
        return _parse_failure(normalized_path, content_hash, PYTEST_CONFIG_DUPLICATE_KEY)
    except tomllib.TOMLDecodeError as error:
        reason = PYTEST_CONFIG_DUPLICATE_KEY if "overwrite" in str(error).lower() else PYTEST_CONFIG_SYNTAX_ERROR
        return _parse_failure(normalized_path, content_hash, reason)
    except (configparser.Error, ValueError):
        return _parse_failure(normalized_path, content_hash, PYTEST_CONFIG_SYNTAX_ERROR)
    except TypeError:
        return _parse_failure(normalized_path, content_hash, PYTEST_CONFIG_VALUE_TYPE_INVALID)
    return PytestConfigParseResult(normalized_path, True, value, True, None, content_hash)


def assess_pytest_configs(
    workspace_root: Path,
    relative_paths: Iterable[str],
    *,
    require_present: bool = False,
) -> PytestConfigAssessment:
    """Parse existing candidates and produce one collision-resistant identity."""

    parsed_results = tuple(parse_pytest_config(workspace_root, path) for path in dict.fromkeys(relative_paths))
    results = tuple(
        PytestConfigParseResult(
            source_path=result.source_path,
            present=False,
            value=None,
            complete=False,
            reason_code=PYTEST_CONFIG_MISSING,
            content_sha256=None,
        )
        if require_present and not result.present and result.complete
        else result
        for result in parsed_results
    )
    relevant = tuple(result for result in results if result.present or not result.complete)
    if not relevant:
        return PytestConfigAssessment((), True, False, (), None)
    reason_codes = tuple(dict.fromkeys(result.reason_code for result in relevant if result.reason_code is not None))
    complete = all(result.complete for result in relevant)
    unsafe = not complete or any(result.value is not None and result.value.unsafe for result in relevant)
    identity_payload = [
        {
            "complete": result.complete,
            "content_sha256": result.content_sha256,
            "reason_code": result.reason_code,
            "source_path": result.source_path,
        }
        for result in relevant
    ]
    identity = hashlib.sha256(
        json.dumps(identity_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return PytestConfigAssessment(relevant, complete, unsafe, reason_codes, identity)


def assess_selected_pytest_config(
    workspace_root: Path,
    relative_paths: Iterable[str],
) -> PytestConfigAssessment:
    """Apply pytest's first-applicable-config precedence to bounded candidates."""

    fallback_pyproject: PytestConfigParseResult | None = None
    for relative_path in dict.fromkeys(relative_paths):
        result = parse_pytest_config(workspace_root, relative_path)
        if not result.present:
            continue
        if not result.complete:
            return _assessment_from_results((result,))
        if result.value is not None:
            return _assessment_from_results((result,))
        if Path(relative_path).name == "pyproject.toml" and fallback_pyproject is None:
            fallback_pyproject = result
    if fallback_pyproject is not None:
        return _assessment_from_results((fallback_pyproject,))
    return PytestConfigAssessment((), True, False, (), None)


def combine_pytest_config_assessments(
    assessments: Iterable[PytestConfigAssessment],
) -> PytestConfigAssessment:
    """Combine per-segment assessments without dropping incomplete evidence."""

    selected = tuple(
        assessment
        for assessment in assessments
        if assessment.results
        or not assessment.complete
        or assessment.unsafe
        or assessment.reason_codes
        or assessment.identity_sha256 is not None
    )
    if not selected:
        return PytestConfigAssessment((), True, False, (), None)
    results = tuple(result for assessment in selected for result in assessment.results)
    reason_codes = tuple(
        dict.fromkeys(reason_code for assessment in selected for reason_code in assessment.reason_codes)
    )
    identity = hashlib.sha256(
        json.dumps(
            [assessment.identity_sha256 for assessment in selected],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return PytestConfigAssessment(
        results=results,
        complete=all(assessment.complete for assessment in selected),
        unsafe=any(assessment.unsafe for assessment in selected),
        reason_codes=reason_codes,
        identity_sha256=identity,
    )


def _parse_failure(source_path: str, content_hash: str, reason_code: str) -> PytestConfigParseResult:
    return PytestConfigParseResult(source_path, True, None, False, reason_code, content_hash)


def _assessment_from_results(results: tuple[PytestConfigParseResult, ...]) -> PytestConfigAssessment:
    reason_codes = tuple(dict.fromkeys(result.reason_code for result in results if result.reason_code is not None))
    complete = all(result.complete for result in results)
    unsafe = not complete or any(result.value is not None and result.value.unsafe for result in results)
    identity_payload = [
        {
            "complete": result.complete,
            "content_sha256": result.content_sha256,
            "reason_code": result.reason_code,
            "source_path": result.source_path,
        }
        for result in results
    ]
    identity = hashlib.sha256(
        json.dumps(identity_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return PytestConfigAssessment(results, complete, unsafe, reason_codes, identity)


def _parse_toml(text: str, *, filename: str) -> PytestConfigValue | None:
    payload = tomllib.loads(text)
    if filename in {"pytest.toml", ".pytest.toml"}:
        pytest_payload = payload.get("pytest")
        if pytest_payload is None:
            return PytestConfigValue()
        if not isinstance(pytest_payload, dict):
            raise TypeError("pytest must be a table")
        return _config_value({str(key): value for key, value in pytest_payload.items()})
    tool = payload.get("tool")
    if tool is None:
        return None
    if not isinstance(tool, dict):
        raise TypeError("tool must be a table")
    pytest_payload = tool.get("pytest")
    if pytest_payload is None:
        return None
    if not isinstance(pytest_payload, dict):
        raise TypeError("tool.pytest must be a table")
    ini_options = pytest_payload.get("ini_options")
    native_options = {str(key): value for key, value in pytest_payload.items() if key != "ini_options"}
    if native_options and ini_options is not None:
        raise ValueError("tool.pytest and tool.pytest.ini_options cannot both define options")
    if native_options:
        return _config_value(native_options)
    if ini_options is None:
        return None
    if not isinstance(ini_options, dict):
        raise TypeError("tool.pytest.ini_options must be a table")
    raw_addopts = ini_options.get("addopts")
    if raw_addopts is not None and not (
        isinstance(raw_addopts, str)
        or (isinstance(raw_addopts, list) and all(isinstance(item, str) for item in raw_addopts))
    ):
        raise TypeError("tool.pytest.ini_options.addopts must be a string or string list")
    ini_compatible: dict[str, object] = {
        str(key): value if isinstance(value, list) else str(value) for key, value in ini_options.items()
    }
    return _config_value(ini_compatible)


def _parse_ini(text: str, *, filename: str) -> PytestConfigValue | None:
    parser = configparser.ConfigParser(interpolation=None, strict=True, empty_lines_in_values=True)
    parser.optionxform = lambda optionstr: optionstr.lower()
    parser.read_string(text)
    section = "tool:pytest" if filename == "setup.cfg" else "pytest"
    if not parser.has_section(section):
        return PytestConfigValue() if filename in {"pytest.ini", ".pytest.ini"} else None
    return _config_value(dict(parser.items(section, raw=True)))


def _config_value(options: dict[str, object]) -> PytestConfigValue:
    addopts = _addopts_tokens(options.get("addopts"))
    log_file = _optional_config_string(options.get("log_file"), key="log_file")
    execution_options: list[tuple[str, str]] = []
    for key, raw_value in sorted(options.items()):
        if key == "addopts":
            execution_options.append((key, " ".join(addopts)))
            continue
        execution_options.append((key, _execution_option_text(raw_value)))
    unsafe = _addopts_are_unsafe(addopts) or any(
        key in _UNSAFE_VALUE_KEYS and bool(value.strip()) for key, value in execution_options
    )
    return PytestConfigValue(
        addopts=addopts,
        log_file=log_file,
        execution_options=tuple(execution_options),
        unsafe=unsafe,
    )


def _execution_option_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(_execution_option_text(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    if isinstance(value, bool | int | float) or value is None:
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def _addopts_tokens(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, list):
        if not all(isinstance(item, str) for item in value):
            raise TypeError("addopts list values must be strings")
        return tuple(value)
    if not isinstance(value, str):
        raise TypeError("addopts must be a string or string list")
    try:
        return tuple(shlex.split(value, comments=True, posix=True))
    except ValueError as error:
        raise ValueError("addopts is not valid shell-style option text") from error


def _optional_config_string(value: object, *, key: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{key} must be a string")
    stripped = value.strip()
    return stripped or None


def _addopts_are_unsafe(tokens: tuple[str, ...]) -> bool:
    for token in tokens:
        if token == "-p" or (token.startswith("-p") and not token.startswith("--")):
            return True
        if token in _UNSAFE_ADDOPTS_MARKERS:
            return True
        if any(token.startswith(f"{marker}=") for marker in _UNSAFE_ADDOPTS_MARKERS if marker != "-c"):
            return True
        if token.startswith("-c") and token != "-c":
            return True
        if token.startswith("-o") and token != "-o":
            return True
    return False


def _read_config_bytes(workspace_root: Path, relative_path: str) -> _ConfigRead:
    relative = Path(relative_path)
    if not relative_path or relative.is_absolute() or ".." in relative.parts:
        return _ConfigRead(False, None, PYTEST_CONFIG_PATH_INVALID)
    try:
        root = workspace_root.expanduser().resolve(strict=True)
    except OSError:
        return _ConfigRead(False, None, PYTEST_CONFIG_IO_ERROR)
    candidate = root / relative
    try:
        current = root
        for part in relative.parts:
            current = current / part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                return _ConfigRead(True, None, PYTEST_CONFIG_SYMLINK)
    except FileNotFoundError:
        return _ConfigRead(False, None, None)
    except OSError:
        return _ConfigRead(True, None, PYTEST_CONFIG_IO_ERROR)
    try:
        resolved = candidate.resolve(strict=True)
        _ = resolved.relative_to(root)
        before = resolved.stat()
    except (OSError, ValueError):
        return _ConfigRead(True, None, PYTEST_CONFIG_PATH_INVALID)
    if not stat.S_ISREG(before.st_mode):
        return _ConfigRead(True, None, PYTEST_CONFIG_NOT_REGULAR)
    if before.st_size > MAX_PYTEST_CONFIG_FILE_BYTES:
        return _ConfigRead(True, None, PYTEST_CONFIG_OVERSIZE)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(resolved, flags)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            return _ConfigRead(True, None, PYTEST_CONFIG_FILE_CHANGED)
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            content = handle.read(MAX_PYTEST_CONFIG_FILE_BYTES + 1)
            opened_after_read = os.fstat(handle.fileno())
            handle.seek(0)
            verified_content = handle.read(MAX_PYTEST_CONFIG_FILE_BYTES + 1)
            opened_after_verify = os.fstat(handle.fileno())
        if len(content) > MAX_PYTEST_CONFIG_FILE_BYTES or len(verified_content) > MAX_PYTEST_CONFIG_FILE_BYTES:
            return _ConfigRead(True, None, PYTEST_CONFIG_OVERSIZE)
        if verified_content != content:
            return _ConfigRead(True, None, PYTEST_CONFIG_FILE_CHANGED)
        opened_identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        if (
            opened_after_read.st_dev,
            opened_after_read.st_ino,
            opened_after_read.st_size,
            opened_after_read.st_mtime_ns,
            opened_after_read.st_ctime_ns,
        ) != opened_identity:
            return _ConfigRead(True, None, PYTEST_CONFIG_FILE_CHANGED)
        if (
            opened_after_verify.st_dev,
            opened_after_verify.st_ino,
            opened_after_verify.st_size,
            opened_after_verify.st_mtime_ns,
            opened_after_verify.st_ctime_ns,
        ) != opened_identity:
            return _ConfigRead(True, None, PYTEST_CONFIG_FILE_CHANGED)
        after = resolved.stat()
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != opened_identity:
            return _ConfigRead(True, None, PYTEST_CONFIG_FILE_CHANGED)
        return _ConfigRead(True, content, None)
    except FileNotFoundError:
        return _ConfigRead(True, None, PYTEST_CONFIG_FILE_CHANGED)
    except OSError:
        return _ConfigRead(True, None, PYTEST_CONFIG_IO_ERROR)
    finally:
        if descriptor is not None:
            os.close(descriptor)


__all__ = [
    "MAX_PYTEST_CONFIG_FILE_BYTES",
    "PYTEST_CONFIG_DECODE_ERROR",
    "PYTEST_CONFIG_DUPLICATE_KEY",
    "PYTEST_CONFIG_FILE_CHANGED",
    "PYTEST_CONFIG_IO_ERROR",
    "PYTEST_CONFIG_MISSING",
    "PYTEST_CONFIG_NOT_REGULAR",
    "PYTEST_CONFIG_OVERSIZE",
    "PYTEST_CONFIG_PATH_INVALID",
    "PYTEST_CONFIG_SYMLINK",
    "PYTEST_CONFIG_SYNTAX_ERROR",
    "PYTEST_CONFIG_VALUE_TYPE_INVALID",
    "PytestConfigAssessment",
    "PytestConfigParseResult",
    "PytestConfigValue",
    "assess_pytest_configs",
    "assess_selected_pytest_config",
    "combine_pytest_config_assessments",
    "parse_pytest_config",
]
