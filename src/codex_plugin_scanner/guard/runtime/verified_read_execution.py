"""Guard-owned execution for a narrow cohort of bounded workspace reads."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Final, cast

from .effect_contract import (
    ContainmentRequirement,
    DecisionBasis,
    EffectAssessment,
    EffectBlastRadius,
    EffectConfidence,
    EffectEvidenceSource,
    EffectKind,
    EffectReversibility,
    EffectTargetScope,
    ProofRequirement,
    ProofRoute,
)
from .effect_decision import (
    DecisionFactor,
    DecisionFactorSource,
    EffectDecision,
    EffectDecisionRequest,
    FinalDisposition,
    PositiveProof,
    evaluate_effect_decision,
)
from .secret_sensitivity import classify_secret_path
from .verified_read_common import verified_read_digest

VERIFIED_READ_EXECUTION_VERSION: Final = "guard.verified-read-execution.v1"
VERIFIED_READ_POLICY_VERSION: Final = "guard.verified-read-policy.v1"
VERIFIED_READ_RULE_VERSION: Final = "guard.verified-read.local.v1"
_MAX_COUNT: Final = 1_000
_MAX_FILE_BYTES: Final = 16 * 1024 * 1024
_MAX_OUTPUT_BYTES: Final = 1_048_576
_SED_RANGE = re.compile(r"([0-9]{1,6})(?:,([0-9]{1,6}))?p")
_REQUIREMENTS: Final = frozenset(
    {
        ProofRequirement.OPERATION_AND_TARGETS,
        ProofRequirement.WORKSPACE_IDENTITY,
        ProofRequirement.REPOSITORY_IDENTITY,
        ProofRequirement.WORKING_DIRECTORY_IDENTITY,
        ProofRequirement.CONFIGURATION_IDENTITY,
        ProofRequirement.SHELL_DATA_FLOW,
        ProofRequirement.PARSER_CONFIDENCE,
        ProofRequirement.EXPECTED_EFFECTS,
    }
)


@dataclass(frozen=True, slots=True)
class VerifiedReadResult:
    exit_code: int
    stdout: str
    stderr: str
    proof: PositiveProof
    decision: EffectDecision
    operation_id: str


@dataclass(frozen=True, slots=True)
class _WorkspaceContext:
    repository: Path
    cwd: Path
    identity: str
    repository_file_identity: tuple[int, int]


@dataclass(frozen=True, slots=True)
class _ReadOutput:
    operation_id: str
    stdout: str
    targets: tuple[dict[str, object], ...]


def try_execute_verified_local_read(argv: tuple[str, ...]) -> VerifiedReadResult | None:
    """Perform one bounded read from the actual process workspace or fail closed."""

    try:
        source_digest = _source_digest()
        context = _current_workspace_context()
        output = _perform_read(argv, context=context)
        if len(output.stdout.encode("utf-8")) > _MAX_OUTPUT_BYTES:
            return None
        if _current_workspace_context() != context or _source_digest() != source_digest:
            return None
        proof = _proof(context, argv=argv, output=output, source_digest=source_digest)
        decision = _decision(proof, operation_id=output.operation_id)
    except (OSError, TypeError, UnicodeError, ValueError):
        return None
    if decision.disposition is not FinalDisposition.SILENT_VERIFIED:
        return None
    return VerifiedReadResult(0, output.stdout, "", proof, decision, output.operation_id)


def _current_workspace_context() -> _WorkspaceContext:
    cwd = Path(os.getcwd())
    if cwd.is_symlink() or not cwd.is_dir() or cwd.resolve(strict=True) != cwd:
        raise ValueError("working directory must be canonical")
    repository: Path | None = None
    git_identity: dict[str, object] | None = None
    for candidate in (cwd, *cwd.parents):
        try:
            git_identity = _repository_git_identity(candidate)
        except (OSError, UnicodeError, ValueError):
            continue
        else:
            repository = candidate
            break
    if repository is None or git_identity is None:
        raise ValueError("verified reads require a regular Git checkout")
    repository_stat = repository.stat(follow_symlinks=False)
    identity = verified_read_digest(
        {
            "repository": _path_identity(repository_stat),
            "git": git_identity,
        }
    )
    return _WorkspaceContext(repository, cwd, identity, (repository_stat.st_dev, repository_stat.st_ino))


def _repository_git_identity(path: Path) -> dict[str, object]:
    marker = path / ".git"
    metadata = marker.stat(follow_symlinks=False)
    if marker.is_symlink():
        raise ValueError("Git identity cannot be a symlink")
    if stat.S_ISDIR(metadata.st_mode):
        return {
            "kind": "directory",
            "identity": _path_identity(metadata),
            "head": _regular_file_digest(marker / "HEAD", max_bytes=4_096),
            "config": _optional_regular_file_digest(marker / "config"),
        }
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > 4_096:
        raise ValueError("Git worktree identity must be a bounded regular file")
    with _OpenRegularFile(marker, max_bytes=4_096) as stream:
        payload = stream.read().decode("utf-8")
    match = re.fullmatch(r"gitdir: ([^\r\n]+)\r?\n?", payload)
    if match is None:
        raise ValueError("Git worktree identity is malformed")
    git_directory = Path(match.group(1))
    if not git_directory.is_absolute():
        git_directory = marker.parent / git_directory
    canonical = git_directory.resolve(strict=True)
    if git_directory.is_symlink() or not canonical.is_dir():
        raise ValueError("Git worktree directory identity is invalid")
    commondir_payload = _regular_file_text(canonical / "commondir", max_bytes=4_096)
    if not commondir_payload or "\x00" in commondir_payload or "\n" in commondir_payload.rstrip("\r\n"):
        raise ValueError("Git common-directory identity is malformed")
    common_directory = (canonical / commondir_payload.strip()).resolve(strict=True)
    if not common_directory.is_dir():
        raise ValueError("Git common-directory identity is invalid")
    return {
        "kind": "worktree",
        "marker": hashlib.sha256(payload.encode()).hexdigest(),
        "directory": _path_identity(canonical.stat(follow_symlinks=False)),
        "head": _regular_file_digest(canonical / "HEAD", max_bytes=4_096),
        "common_directory": _path_identity(common_directory.stat(follow_symlinks=False)),
        "common_config": _optional_regular_file_digest(common_directory / "config"),
    }


def _perform_read(argv: tuple[str, ...], *, context: _WorkspaceContext) -> _ReadOutput:
    raw = cast(object, argv)
    if not isinstance(raw, tuple) or not raw:
        raise ValueError("argv must be a non-empty tuple")
    values = cast(tuple[object, ...], raw)
    if any(not isinstance(value, str) or not value or "\x00" in value for value in values):
        raise ValueError("argv must contain exact non-empty strings")
    typed = cast(tuple[str, ...], raw)
    name = typed[0]
    if Path(name).name != name:
        raise ValueError("verified reads do not launch caller-selected executables")
    if name == "pwd" and len(typed) == 1:
        target = _directory_target(context.cwd, context=context)
        return _ReadOutput("working-directory", f"{context.cwd}\n", (target,))
    if name in {"head", "tail"}:
        return _head_tail(name, typed[1:], context=context)
    if name == "sed":
        return _sed(typed[1:], context=context)
    raise ValueError("operation is outside the verified-read cohort")


def _head_tail(name: str, args: tuple[str, ...], *, context: _WorkspaceContext) -> _ReadOutput:
    if len(args) != 2:
        raise ValueError("head and tail require one bound and one file")
    count = _line_count(args[0])
    with _open_target(args[1], context=context) as (stream, target):
        lines = _read_bounded_text(stream).splitlines(keepends=True)
    selected = lines[:count] if name == "head" else lines[-count:]
    return _ReadOutput(f"bounded-{name}", "".join(selected), (target,))


def _sed(args: tuple[str, ...], *, context: _WorkspaceContext) -> _ReadOutput:
    if len(args) != 3 or args[0] != "-n":
        raise ValueError("sed requires one bounded print expression and one file")
    match = _SED_RANGE.fullmatch(args[1])
    if match is None:
        raise ValueError("sed expression is outside the verified grammar")
    start = int(match.group(1))
    end = int(match.group(2) or match.group(1))
    if not 1 <= start <= end <= _MAX_COUNT:
        raise ValueError("sed range exceeds the bound")
    with _open_target(args[2], context=context) as (stream, target):
        lines = _read_bounded_text(stream).splitlines(keepends=True)
    return _ReadOutput("bounded-source-view", "".join(lines[start - 1 : end]), (target,))


class _OpenTarget:
    def __init__(self, value: str, *, context: _WorkspaceContext) -> None:
        self._path: Path = _resolve_target(value, context=context)
        self._repository: Path = context.repository
        self._repository_file_identity: tuple[int, int] = context.repository_file_identity
        self._stream: BinaryIO | None = None
        self.target: dict[str, object] | None = None
        self._identity: tuple[int, int, int, int] | None = None

    def __enter__(self) -> tuple[BinaryIO, dict[str, object]]:
        descriptor = _open_beneath_repository(
            self._path.relative_to(self._repository),
            repository=self._repository,
            repository_file_identity=self._repository_file_identity,
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > _MAX_FILE_BYTES:
            os.close(descriptor)
            raise ValueError("target must be a bounded, singly linked regular file")
        self._stream = os.fdopen(descriptor, "rb")
        self._identity = _stable_file_identity(metadata)
        self.target = {
            "path": verified_read_digest(self._path.relative_to(self._repository).as_posix()),
            "identity": _path_identity(metadata),
        }
        return self._stream, self.target

    def __exit__(self, *_args: object) -> None:
        if self._stream is not None:
            try:
                if _stable_file_identity(os.fstat(self._stream.fileno())) != self._identity:
                    raise ValueError("target identity changed during read")
            finally:
                self._stream.close()


def _open_target(value: str, *, context: _WorkspaceContext) -> _OpenTarget:
    return _OpenTarget(value, context=context)


def _read_bounded_text(stream: BinaryIO) -> str:
    payload = stream.read(_MAX_FILE_BYTES + 1)
    if len(payload) > _MAX_FILE_BYTES:
        raise ValueError("target grew beyond the verified-read bound")
    return payload.decode("utf-8")


def _open_beneath_repository(
    relative: Path,
    *,
    repository: Path,
    repository_file_identity: tuple[int, int],
) -> int:
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("target must remain beneath the repository")
    raw_nofollow = cast(object, getattr(os, "O_NOFOLLOW", None))
    raw_directory_flag = cast(object, getattr(os, "O_DIRECTORY", None))
    if (
        type(raw_nofollow) is not int
        or type(raw_directory_flag) is not int
        or not os.supports_dir_fd
        or os.open not in os.supports_dir_fd
    ):
        raise ValueError("secure repository-relative opens are unavailable")
    nofollow = raw_nofollow
    directory_flag = raw_directory_flag
    common_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
    descriptors: list[int] = []
    try:
        current = os.open(repository, common_flags | directory_flag)
        descriptors.append(current)
        root_metadata = os.fstat(current)
        if (root_metadata.st_dev, root_metadata.st_ino) != repository_file_identity:
            raise ValueError("repository identity changed before read")
        for part in relative.parts[:-1]:
            current = os.open(part, common_flags | directory_flag, dir_fd=current)
            descriptors.append(current)
        return os.open(relative.parts[-1], common_flags, dir_fd=current)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _resolve_target(value: str, *, context: _WorkspaceContext) -> Path:
    if not value or Path(value).is_absolute() or _dynamic(value):
        raise ValueError("target must be a static relative path")
    lexical = context.cwd / value
    if classify_secret_path(value, cwd=context.cwd) is not None:
        raise ValueError("sensitive targets require review")
    _reject_symlink_components(lexical, root=context.repository)
    target = lexical.resolve(strict=True)
    try:
        relative = target.relative_to(context.repository)
    except ValueError as exc:
        raise ValueError("target escapes the repository") from exc
    if classify_secret_path(relative.as_posix(), cwd=context.repository) is not None:
        raise ValueError("sensitive targets require review")
    return target


def _reject_symlink_components(path: Path, *, root: Path) -> None:
    relative = path.relative_to(root)
    current = root
    for part in relative.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            raise ValueError("target path cannot contain parent traversal")
        current /= part
        if current.is_symlink():
            raise ValueError("target path cannot traverse symlinks")


def _directory_target(path: Path, *, context: _WorkspaceContext) -> dict[str, object]:
    try:
        relative = path.relative_to(context.repository)
    except ValueError as exc:
        raise ValueError("working directory escapes the repository") from exc
    metadata = path.stat(follow_symlinks=False)
    return {"path": verified_read_digest(relative.as_posix()), "identity": _path_identity(metadata)}


def _optional_regular_file_digest(path: Path) -> str:
    try:
        with _OpenRegularFile(path) as stream:
            return hashlib.sha256(stream.read(_MAX_FILE_BYTES + 1)).hexdigest()
    except FileNotFoundError:
        return verified_read_digest("missing")


def _regular_file_digest(path: Path, *, max_bytes: int) -> str:
    with _OpenRegularFile(path, max_bytes=max_bytes) as stream:
        return hashlib.sha256(stream.read(max_bytes + 1)).hexdigest()


def _regular_file_text(path: Path, *, max_bytes: int) -> str:
    with _OpenRegularFile(path, max_bytes=max_bytes) as stream:
        return stream.read(max_bytes + 1).decode("utf-8")


class _OpenRegularFile:
    def __init__(self, path: Path, *, max_bytes: int = _MAX_FILE_BYTES) -> None:
        self._path: Path = path
        self._max_bytes: int = max_bytes
        self._stream: BinaryIO | None = None
        self._identity: tuple[int, int, int, int] | None = None

    def __enter__(self) -> BinaryIO:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self._path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > self._max_bytes:
            os.close(descriptor)
            raise ValueError("configuration identity is not a bounded regular file")
        self._stream = os.fdopen(descriptor, "rb")
        self._identity = _stable_file_identity(metadata)
        return self._stream

    def __exit__(self, *_args: object) -> None:
        if self._stream is not None:
            try:
                if _stable_file_identity(os.fstat(self._stream.fileno())) != self._identity:
                    raise ValueError("configuration identity changed during read")
            finally:
                self._stream.close()


def _line_count(value: str) -> int:
    normalized = value.removeprefix("--lines=").removeprefix("-")
    if not normalized.isdigit() or not 1 <= int(normalized) <= _MAX_COUNT:
        raise ValueError("line count exceeds the bound")
    return int(normalized)


def _proof(
    context: _WorkspaceContext,
    *,
    argv: tuple[str, ...],
    output: _ReadOutput,
    source_digest: str,
) -> PositiveProof:
    material = {
        "schema_version": VERIFIED_READ_EXECUTION_VERSION,
        "policy_version": VERIFIED_READ_POLICY_VERSION,
        "rule_version": VERIFIED_READ_RULE_VERSION,
        "operation": output.operation_id,
        "workspace": context.identity,
        "repository": context.identity,
        "working_directory": _directory_target(context.cwd, context=context),
        "targets": output.targets,
        "request": verified_read_digest(argv),
        "executor_source": source_digest,
        "parser": "guard-internal-direct-argv-v1",
        "io_flow": "guard-file-descriptor-to-bounded-output",
        "expected_effects": ["workspace-or-public-read"],
        "stdout": verified_read_digest(output.stdout),
    }
    return PositiveProof(ProofRoute.VERIFIED, verified_read_digest(material), _REQUIREMENTS)


def _decision(proof: PositiveProof, *, operation_id: str) -> EffectDecision:
    factor = DecisionFactor(
        source=DecisionFactorSource.EFFECT,
        reason_code="verified-workspace-read",
        basis=DecisionBasis("allow", ProofRoute.VERIFIED),
        operation_ref=f"operation:{operation_id}",
        producer_ref="executor:verified-read-v1",
        evidence_digest=proof.binding_digest,
        assessment=EffectAssessment(
            EffectKind.WORKSPACE_OR_PUBLIC_READ,
            EffectTargetScope.WORKSPACE,
            EffectReversibility.TRIVIALLY_RECOVERABLE,
            EffectBlastRadius.WORKSPACE,
            EffectEvidenceSource.RUNTIME,
            EffectConfidence.EXACT,
            ContainmentRequirement.NONE,
            _REQUIREMENTS,
        ),
        proof=proof,
    )
    return evaluate_effect_decision(EffectDecisionRequest(factors=(factor,)))


def _path_identity(metadata: os.stat_result) -> dict[str, int]:
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "size": metadata.st_size,
        "modified_ns": metadata.st_mtime_ns,
    }


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns


def _dynamic(value: str) -> bool:
    return any(marker in value for marker in ("$", "`", "<", ">", "|", ";", "&", "*", "?", "[", "\x00"))


def _source_digest() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


__all__ = (
    "VERIFIED_READ_EXECUTION_VERSION",
    "VERIFIED_READ_POLICY_VERSION",
    "VERIFIED_READ_RULE_VERSION",
    "VerifiedReadResult",
    "try_execute_verified_local_read",
)
