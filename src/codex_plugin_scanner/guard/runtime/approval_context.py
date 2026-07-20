"""Opaque context binding for saved runtime approvals.

Approval evidence is valid only for the context that was reviewed.  These
tokens bind the five context dimensions that can invalidate a saved approval
without persisting their potentially sensitive source values.  The token is
not an authority or a signature; consumers must still resolve and claim saved
approval evidence through the policy store.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import shutil
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal, TypeGuard, cast

from .env_wrapper import parse_env_wrapper

APPROVAL_CONTEXT_TOKEN_PREFIX = "guard-approval-context:v1:"

ApprovalContextValidationFailure = Literal[
    "approval_reuse_identity_changed",
    "approval_reuse_content_changed",
    "approval_reuse_capability_changed",
    "approval_reuse_policy_changed",
    "approval_reuse_sandbox_changed",
]

_TOKEN_VERSION = 1
_TOKEN_DOMAIN = "hol.guard.approval-context"
_CONFIGURED_ENV_HASH_DOMAIN = b"hol.guard.configured-environment:v1\x00"
_CONFIGURED_HEADER_HASH_DOMAIN = b"hol.guard.configured-headers:v1\x00"
_TOKEN_FIELDS = frozenset({"version", "identity", "content", "capabilities", "policy", "sandbox"})
_ENCODED_PAYLOAD_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_SHA256_HEX_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MAX_TOKEN_LENGTH = 2048
_MAX_EXECUTABLE_HASH_BYTES = 256 * 1024 * 1024
_EXECUTABLE_HASH_CHUNK_BYTES = 1024 * 1024
_MAX_SHEBANG_BYTES = 4096


@dataclass(frozen=True, slots=True)
class ApprovalContextToken:
    """Parsed, non-secret approval-context component digests."""

    identity_hash: str
    content_hash: str
    capabilities_hash: str
    policy_hash: str
    sandbox_hash: str

    def _payload(self) -> dict[str, object]:
        return {
            "version": _TOKEN_VERSION,
            "identity": self.identity_hash,
            "content": self.content_hash,
            "capabilities": self.capabilities_hash,
            "policy": self.policy_hash,
            "sandbox": self.sandbox_hash,
        }


def build_approval_context_token(
    *,
    identity: object,
    content: object,
    capabilities: object,
    policy: object,
    sandbox: object,
) -> str:
    """Build a deterministic token from JSON-compatible context components.

    Mapping keys are canonicalized, so their insertion order does not affect
    the result.  Each component is hashed independently with a domain label;
    only those digests are serialized into the returned token.  In particular,
    ``content`` may be any artifact-hash text and is never parsed or embedded.
    """

    parsed = ApprovalContextToken(
        identity_hash=_component_hash("identity", identity),
        content_hash=_component_hash("content", content),
        capabilities_hash=_component_hash("capabilities", capabilities),
        policy_hash=_component_hash("policy", policy),
        sandbox_hash=_component_hash("sandbox", sandbox),
    )
    payload = json.dumps(
        parsed._payload(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    return f"{APPROVAL_CONTEXT_TOKEN_PREFIX}{encoded}"


def parse_approval_context_token(token: object) -> ApprovalContextToken | None:
    """Parse a well-formed v1 token, returning ``None`` for legacy/malformed input."""

    if not isinstance(token, str) or not token.startswith(APPROVAL_CONTEXT_TOKEN_PREFIX):
        return None
    if len(token) > _MAX_TOKEN_LENGTH:
        return None
    encoded = token[len(APPROVAL_CONTEXT_TOKEN_PREFIX) :]
    if not encoded or _ENCODED_PAYLOAD_PATTERN.fullmatch(encoded) is None:
        return None
    padding = "=" * (-len(encoded) % 4)
    try:
        raw_payload = base64.b64decode(
            f"{encoded}{padding}".encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
        payload = json.loads(raw_payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, Mapping) or set(payload) != _TOKEN_FIELDS:
        return None
    if payload.get("version") != _TOKEN_VERSION:
        return None
    identity_hash = payload.get("identity")
    content_hash = payload.get("content")
    capabilities_hash = payload.get("capabilities")
    policy_hash = payload.get("policy")
    sandbox_hash = payload.get("sandbox")
    if not (
        _is_sha256_hex(identity_hash)
        and _is_sha256_hex(content_hash)
        and _is_sha256_hex(capabilities_hash)
        and _is_sha256_hex(policy_hash)
        and _is_sha256_hex(sandbox_hash)
    ):
        return None
    return ApprovalContextToken(
        identity_hash=identity_hash,
        content_hash=content_hash,
        capabilities_hash=capabilities_hash,
        policy_hash=policy_hash,
        sandbox_hash=sandbox_hash,
    )


def approval_context_validation_reason(
    saved_token: object,
    *,
    identity: object,
    content: object,
    capabilities: object,
    policy: object,
    sandbox: object,
) -> ApprovalContextValidationFailure | None:
    """Return the first changed context dimension for saved approval evidence."""

    current_token = build_approval_context_token(
        identity=identity,
        content=content,
        capabilities=capabilities,
        policy=policy,
        sandbox=sandbox,
    )
    return approval_context_tokens_validation_reason(saved_token, current_token)


def approval_context_tokens_validation_reason(
    saved_token: object,
    current_token: object,
) -> ApprovalContextValidationFailure | None:
    """Compare opaque saved/current tokens without requiring their raw context.

    Legacy artifact hashes and malformed tokens cannot prove that all context
    dimensions are unchanged, so they fail closed as changed content.
    """

    saved = parse_approval_context_token(saved_token)
    current = parse_approval_context_token(current_token)
    if saved is None or current is None:
        return "approval_reuse_content_changed"
    comparisons: tuple[tuple[str, str, ApprovalContextValidationFailure], ...] = (
        (saved.identity_hash, current.identity_hash, "approval_reuse_identity_changed"),
        (saved.content_hash, current.content_hash, "approval_reuse_content_changed"),
        (saved.capabilities_hash, current.capabilities_hash, "approval_reuse_capability_changed"),
        (saved.policy_hash, current.policy_hash, "approval_reuse_policy_changed"),
        (saved.sandbox_hash, current.sandbox_hash, "approval_reuse_sandbox_changed"),
    )
    for saved_hash, current_hash, reason in comparisons:
        if not hmac.compare_digest(saved_hash, current_hash):
            return reason
    return None


def build_runtime_executable_identity(
    command: object,
    *,
    search_path: str | None = None,
    cwd: Path | None = None,
) -> dict[str, object]:
    """Resolve and content-bind an executable without launching it.

    Files that cannot be safely and completely hashed receive a per-evaluation
    nonce. That deliberately disables approval reuse instead of treating an
    incomplete executable identity as stable.
    """

    effective_cwd: Path | None = None
    if cwd is not None:
        try:
            effective_cwd = cwd.expanduser().resolve(strict=False)
        except (OSError, RuntimeError):
            effective_cwd = cwd.expanduser().absolute()

    def with_launch_cwd(identity: dict[str, object]) -> dict[str, object]:
        if effective_cwd is not None:
            identity["launch_cwd"] = str(effective_cwd)
        return identity

    if command is None or command == "":
        return with_launch_cwd({"command": None, "path": None, "status": "not_applicable"})
    if not isinstance(command, str) or not command.strip():
        return with_launch_cwd(_unreusable_executable_identity(command, status="invalid_command"))
    candidate = Path(command).expanduser()
    has_explicit_path = os.sep in command or (os.altsep is not None and os.altsep in command)
    if candidate.is_absolute():
        resolved = candidate
    elif has_explicit_path:
        resolved = effective_cwd / candidate if effective_cwd is not None else candidate
    else:
        effective_search_path = search_path
        if effective_cwd is not None:
            inherited_search_path = search_path if search_path is not None else os.environ.get("PATH")
            if inherited_search_path is not None:
                normalized_entries: list[str] = []
                for entry in inherited_search_path.split(os.pathsep):
                    path_entry = Path(entry or ".").expanduser()
                    if not path_entry.is_absolute():
                        path_entry = effective_cwd / path_entry
                    normalized_entries.append(str(path_entry))
                effective_search_path = os.pathsep.join(normalized_entries)
        located = shutil.which(command, path=effective_search_path)
        if located is None:
            return with_launch_cwd(_unreusable_executable_identity(command, status="unresolved"))
        resolved = Path(located)
    try:
        canonical = resolved.resolve(strict=True)
        metadata = canonical.stat()
    except (OSError, RuntimeError):
        return with_launch_cwd(_unreusable_executable_identity(command, status="unreadable", path=resolved))
    if not stat.S_ISREG(metadata.st_mode):
        return with_launch_cwd(_unreusable_executable_identity(command, status="not_regular", path=canonical))
    stat_key = _executable_stat_key(metadata)
    digest, hash_status, shebang, shebang_status = _cached_executable_hash(str(canonical), stat_key)
    if shebang_status == "verified":
        file_format = "script"
    elif shebang_status == "not_script":
        file_format = "native"
    else:
        file_format = "unverified"
    identity: dict[str, object] = {
        "command": command,
        "file_format": file_format,
        "path": str(canonical),
        "shebang_status": shebang_status,
        "size": metadata.st_size,
        "mode": stat.S_IMODE(metadata.st_mode),
        "status": hash_status,
    }
    if digest is None:
        identity["reuse_nonce"] = secrets.token_hex(16)
    else:
        identity["sha256"] = digest
    if shebang is not None:
        identity["shebang_sha256"] = hashlib.sha256(shebang.encode("utf-8")).hexdigest()
    return with_launch_cwd(identity)


_PYTHON_LAUNCHER_PATTERN = re.compile(
    r"(?:python|pypy)(?:\d+(?:\.\d+)*)?(?:\.exe)?",
    re.IGNORECASE,
)
_NODE_LAUNCHER_NAMES = frozenset({"node", "node.exe", "nodejs", "nodejs.exe"})
_SHELL_LAUNCHER_NAMES = frozenset(
    {
        "bash",
        "bash.exe",
        "dash",
        "dash.exe",
        "fish",
        "fish.exe",
        "ksh",
        "ksh.exe",
        "sh",
        "sh.exe",
        "zsh",
        "zsh.exe",
    }
)
_SIMPLE_SCRIPT_LAUNCHER_NAMES = frozenset(
    {
        "lua",
        "lua.exe",
        "perl",
        "perl.exe",
        "php",
        "php.exe",
        "rscript",
        "rscript.exe",
        "ruby",
        "ruby.exe",
        "ts-node",
        "ts-node.cmd",
        "tsx",
        "tsx.cmd",
    }
)
_UNRESOLVED_CODE_LAUNCHER_NAMES = frozenset(
    {
        "bunx",
        "bunx.exe",
        "docker",
        "docker.exe",
        "go",
        "go.exe",
        "npm",
        "npm.cmd",
        "npx",
        "npx.cmd",
        "pipx",
        "pipx.exe",
        "pnpm",
        "pnpm.cmd",
        "podman",
        "podman.exe",
        "uv",
        "uv.exe",
        "uvx",
        "uvx.exe",
        "yarn",
        "yarn.cmd",
    }
)


def build_runtime_launch_identity(
    command: object,
    *,
    args: Sequence[object] = (),
    structured_command: bool = False,
    direct_executable: bool = False,
    search_path: str | None = None,
    cwd: Path | None = None,
    launch_env: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Content-bind an executable and any local code-bearing entrypoint.

    Hashing only an interpreter such as ``python`` or ``node`` does not bind
    the code that will actually run.  This helper parses the launch vector,
    resolves supported script/module entrypoints from the real launch cwd,
    and hashes those bytes with the same race-resistant primitive used for
    executables.  Ambiguous, unsupported, stdin-backed, or unreadable code
    entrypoints receive a fresh nonce so saved approvals fail closed.
    """

    effective_cwd = _normalized_launch_cwd(cwd)
    if command is None or command == "":
        return {
            "argv_sha256": _launch_argv_digest(()),
            "entrypoint": {"kind": "not-applicable", "status": "not_applicable"},
            "executable": build_runtime_executable_identity(command, search_path=search_path, cwd=effective_cwd),
            "launch_cwd": str(effective_cwd),
        }
    if not isinstance(command, str) or not command.strip():
        return {
            "argv_sha256": _launch_argv_digest(()),
            "entrypoint": _unproven_runtime_entrypoint(
                kind="unknown-launch",
                reason="invalid_launch_command",
            ),
            "executable": build_runtime_executable_identity(command, search_path=search_path, cwd=effective_cwd),
            "launch_cwd": str(effective_cwd),
        }
    if structured_command:
        command_tokens = [command]
    else:
        try:
            command_tokens = shlex.split(command, posix=os.name != "nt")
        except ValueError:
            command_tokens = []
    if not command_tokens or any(not isinstance(argument, str) for argument in args):
        return {
            "argv_sha256": _launch_argv_digest(()),
            "entrypoint": _unproven_runtime_entrypoint(
                kind="unknown-launch",
                reason="unparseable_launch_vector",
            ),
            "executable": build_runtime_executable_identity(
                command_tokens[0] if command_tokens else command,
                search_path=search_path,
                cwd=effective_cwd,
            ),
            "launch_cwd": str(effective_cwd),
        }

    executable = command_tokens[0]
    launch_args = tuple(command_tokens[1:]) + tuple(str(argument) for argument in args)
    environment = launch_env if launch_env is not None else os.environ
    effective_search_path = search_path if search_path is not None else environment.get("PATH")
    executable_identity = build_runtime_executable_identity(
        executable,
        search_path=effective_search_path,
        cwd=effective_cwd,
    )
    executable_shebang, executable_shebang_status = _raw_shebang_for_identity(executable_identity)
    return {
        "argv_sha256": _launch_argv_digest((executable, *launch_args)),
        "entrypoint": _runtime_entrypoint_identity(
            executable_identity=executable_identity,
            executable_shebang=executable_shebang,
            executable_shebang_status=executable_shebang_status,
            direct_executable=direct_executable,
            launch_args=launch_args,
            launch_cwd=effective_cwd,
            launch_env=environment,
        ),
        "executable": executable_identity,
        "launch_cwd": str(effective_cwd),
    }


def resolved_runtime_launch_executable(identity: Mapping[str, object]) -> str | None:
    """Return the verified canonical executable path pinned by a launch identity.

    Callers that spawn a process should prefer this absolute path over asking
    the operating system to resolve the original command a second time.  This
    closes the ordinary PATH/symlink resolution gap between identity creation
    and ``exec``.  Unverified identities intentionally return ``None``.
    """

    executable = identity.get("executable")
    if not isinstance(executable, Mapping):
        return None
    typed_executable = cast(Mapping[str, object], executable)
    path = typed_executable.get("path")
    digest = typed_executable.get("sha256")
    if typed_executable.get("status") != "verified" or not isinstance(path, str) or not _is_sha256_hex(digest):
        return None
    candidate = Path(path)
    return path if candidate.is_absolute() else None


def runtime_launch_identity_is_reusable(identity: Mapping[str, object]) -> bool:
    """Return whether every launch-identity dimension was proven stable."""

    return not _runtime_identity_contains_reuse_nonce(identity)


def resolved_runtime_launch_argv(
    identity: Mapping[str, object],
    *,
    args: Sequence[str] = (),
) -> tuple[str, ...] | None:
    """Return a path-pinned argv for a verified direct executable launch.

    Native executables use their canonical path. Script-backed executables
    invoke the already verified shebang interpreter directly, avoiding a
    second PATH lookup by the kernel or ``env``. Raw shebang arguments are
    recovered from the descriptor-verified hash cache and are never persisted
    in the identity.
    """

    if not runtime_launch_identity_is_reusable(identity):
        return None
    executable = identity.get("executable")
    entrypoint = identity.get("entrypoint")
    if not isinstance(executable, Mapping) or not isinstance(entrypoint, Mapping):
        return None
    executable_path = resolved_runtime_launch_executable(identity)
    if executable_path is None:
        return None
    if entrypoint.get("kind") == "direct-executable" and entrypoint.get("status") == "bound-by-executable":
        return (executable_path, *args)
    if entrypoint.get("status") != "verified" or entrypoint.get("kind") not in {
        "direct-script",
        "direct-env-script",
    }:
        return None
    shebang, shebang_status = _raw_shebang_for_identity(cast(Mapping[str, object], executable))
    if shebang_status != "verified" or shebang is None:
        return None
    try:
        shebang_tokens = tuple(shlex.split(shebang, posix=True))
    except ValueError:
        return None
    if not shebang_tokens:
        return None
    launcher_name = Path(shebang_tokens[0]).name.lower()
    shebang_args = shebang_tokens[1:]
    if _launch_argv_digest(shebang_args) != entrypoint.get("shebang_args_sha256"):
        return None
    if launcher_name not in {"env", "env.exe"}:
        # Kernels disagree about multiple non-env shebang arguments. Refuse to
        # rewrite an invocation whose semantics cannot be preserved exactly.
        if len(shebang_args) > 1:
            return None
        launcher_path = _verified_identity_path(entrypoint.get("launcher"))
        if launcher_path is None:
            return None
        return (launcher_path, *shebang_args, executable_path, *args)
    env_command = _env_shebang_command(shebang_args)
    if env_command is None:
        return None
    _interpreter, interpreter_args = env_command
    if _launch_argv_digest(interpreter_args) != entrypoint.get("interpreter_args_sha256"):
        return None
    interpreter_path = _verified_identity_path(entrypoint.get("interpreter"))
    if interpreter_path is None:
        return None
    return (interpreter_path, *interpreter_args, executable_path, *args)


def runtime_launch_identity_matches(
    expected_identity: Mapping[str, object],
    command: object,
    *,
    args: Sequence[object] = (),
    structured_command: bool = False,
    direct_executable: bool = False,
    search_path: str | None = None,
    cwd: Path | None = None,
    launch_env: Mapping[str, str] | None = None,
) -> bool:
    """Rebuild and compare all provable launch identity at a spawn boundary.

    Fresh ``reuse_nonce`` values are excluded from this comparison because
    they describe deliberately unprovable launch portions rather than file
    identity.  Every resolved executable, interpreter, package initializer,
    and entrypoint path/hash remains in the comparison.  Callers must retain
    the original nonce-bearing identity for approval decisions so unprovable
    launches remain non-reusable.

    This is a post-spawn containment check, not an atomic execution primitive:
    platforms do not expose a portable descriptor-based process spawn, and an
    interpreter can open its script after the parent returns from spawn.  A
    caller should therefore also launch the canonical executable returned by
    :func:`resolved_runtime_launch_executable`, validate immediately, and
    terminate the child before forwarding traffic on mismatch.
    """

    current_identity = build_runtime_launch_identity(
        command,
        args=args,
        structured_command=structured_command,
        direct_executable=direct_executable,
        search_path=search_path,
        cwd=cwd,
        launch_env=launch_env,
    )
    expected_digest = _runtime_launch_verification_digest(expected_identity)
    current_digest = _runtime_launch_verification_digest(current_identity)
    return (
        expected_digest is not None
        and current_digest is not None
        and hmac.compare_digest(
            expected_digest,
            current_digest,
        )
    )


def build_configured_environment_hash(
    environment: Mapping[str, str] | None,
    *,
    configured_keys: Sequence[str] | None = None,
) -> str:
    """Hash configured environment values without exposing or binding ambient values."""

    return _build_configured_values_hash(
        environment,
        configured_keys=configured_keys,
        domain=_CONFIGURED_ENV_HASH_DOMAIN,
    )


def build_configured_header_values_hash(
    headers: Mapping[str, str] | None,
    *,
    configured_keys: Sequence[str] | None = None,
) -> str:
    """Hash configured header values without retaining or exposing them."""

    return _build_configured_values_hash(
        headers,
        configured_keys=configured_keys,
        domain=_CONFIGURED_HEADER_HASH_DOMAIN,
    )


def _build_configured_values_hash(
    values: Mapping[str, str] | None,
    *,
    configured_keys: Sequence[str] | None,
    domain: bytes,
) -> str:
    """Hash one configured key/value namespace with stable framing."""

    normalized_values = {str(key).strip(): value for key, value in (values or {}).items() if str(key).strip()}
    keys = normalized_values.keys() if configured_keys is None else (str(key).strip() for key in configured_keys)
    normalized_keys = sorted({key for key in keys if key})
    digest = hashlib.sha256(domain)
    for key in normalized_keys:
        key_bytes = key.encode("utf-8")
        digest.update(len(key_bytes).to_bytes(8, "big"))
        digest.update(key_bytes)
        if key not in normalized_values:
            digest.update(b"\x00")
            continue
        value_bytes = normalized_values[key].encode("utf-8")
        digest.update(b"\x01")
        digest.update(len(value_bytes).to_bytes(8, "big"))
        digest.update(value_bytes)
    return digest.hexdigest()


def _normalized_launch_cwd(cwd: Path | None) -> Path:
    candidate = cwd if cwd is not None else Path.cwd()
    try:
        return candidate.expanduser().resolve(strict=False)
    except (OSError, RuntimeError):
        return candidate.expanduser().absolute()


def _launch_argv_digest(argv: Sequence[str]) -> str:
    material = json.dumps(list(argv), ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _runtime_entrypoint_identity(
    *,
    executable_identity: Mapping[str, object],
    executable_shebang: str | None,
    executable_shebang_status: str,
    direct_executable: bool,
    launch_args: tuple[str, ...],
    launch_cwd: Path,
    launch_env: Mapping[str, str],
) -> dict[str, object]:
    command_name = Path(str(executable_identity.get("command") or "")).name.lower()
    resolved_path = executable_identity.get("path")
    executable_name = Path(str(resolved_path or command_name)).name.lower()
    if direct_executable:
        return _direct_executable_runtime_entrypoint_identity(
            executable_identity=executable_identity,
            executable_shebang=executable_shebang,
            executable_shebang_status=executable_shebang_status,
            launch_args=launch_args,
            launch_cwd=launch_cwd,
            launch_env=launch_env,
        )
    if executable_name.endswith((".bat", ".cmd")):
        return _unproven_runtime_entrypoint(
            kind="command-script-launcher",
            reason="command_interpreter_unresolved",
            selector=launch_args,
        )
    if command_name in _UNRESOLVED_CODE_LAUNCHER_NAMES or executable_name in _UNRESOLVED_CODE_LAUNCHER_NAMES:
        return _unproven_runtime_entrypoint(
            kind="code-launcher",
            reason="launcher_entrypoint_unresolved",
            selector=launch_args,
        )
    if _known_runtime_launcher_name(executable_name) and _identity_shebang_status(executable_identity) != "native":
        return _unproven_runtime_entrypoint(
            kind="code-launcher",
            reason="script_backed_launcher_unresolved",
            selector=launch_args,
        )
    if _PYTHON_LAUNCHER_PATTERN.fullmatch(executable_name):
        return _python_runtime_entrypoint_identity(
            args=launch_args,
            launch_cwd=launch_cwd,
            launch_env=launch_env,
        )
    if executable_name in _NODE_LAUNCHER_NAMES:
        return _node_runtime_entrypoint_identity(
            args=launch_args,
            launch_cwd=launch_cwd,
            launch_env=launch_env,
        )
    if executable_name in _SHELL_LAUNCHER_NAMES:
        return _shell_runtime_entrypoint_identity(
            shell=executable_name,
            args=launch_args,
            launch_cwd=launch_cwd,
            launch_env=launch_env,
        )
    if executable_name in _SIMPLE_SCRIPT_LAUNCHER_NAMES:
        return _simple_runtime_entrypoint_identity(
            launcher=executable_name,
            args=launch_args,
            launch_cwd=launch_cwd,
        )
    if executable_name in {"bun", "bun.exe", "deno", "deno.exe"}:
        return _javascript_runtime_entrypoint_identity(
            launcher=executable_name,
            args=launch_args,
            launch_cwd=launch_cwd,
        )
    if executable_name in {"java", "java.exe"}:
        return _java_runtime_entrypoint_identity(args=launch_args, launch_cwd=launch_cwd)
    if executable_name in {"dotnet", "dotnet.exe"}:
        return _dotnet_runtime_entrypoint_identity(args=launch_args, launch_cwd=launch_cwd)
    if executable_name in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
        return _powershell_runtime_entrypoint_identity(args=launch_args, launch_cwd=launch_cwd)
    return _direct_executable_runtime_entrypoint_identity(
        executable_identity=executable_identity,
        executable_shebang=executable_shebang,
        executable_shebang_status=executable_shebang_status,
        launch_args=launch_args,
        launch_cwd=launch_cwd,
        launch_env=launch_env,
    )


def _known_runtime_launcher_name(executable_name: str) -> bool:
    return bool(
        _PYTHON_LAUNCHER_PATTERN.fullmatch(executable_name)
        or executable_name in _NODE_LAUNCHER_NAMES
        or executable_name in _SHELL_LAUNCHER_NAMES
        or executable_name in _SIMPLE_SCRIPT_LAUNCHER_NAMES
        or executable_name
        in {
            "bun",
            "bun.exe",
            "deno",
            "deno.exe",
            "dotnet",
            "dotnet.exe",
            "java",
            "java.exe",
            "powershell",
            "powershell.exe",
            "pwsh",
            "pwsh.exe",
        }
    )


def _direct_executable_runtime_entrypoint_identity(
    *,
    executable_identity: Mapping[str, object],
    executable_shebang: str | None,
    executable_shebang_status: str,
    launch_args: tuple[str, ...],
    launch_cwd: Path,
    launch_env: Mapping[str, str],
) -> dict[str, object]:
    """Bind the interpreter selected by a direct executable script shebang."""

    if not isinstance(executable_identity.get("sha256"), str):
        return {"kind": "direct-executable", "status": "bound-by-executable"}
    if executable_shebang_status == "not_script":
        return {"kind": "direct-executable", "status": "bound-by-executable"}
    if executable_shebang is None:
        return _unproven_runtime_entrypoint(
            kind="direct-script",
            reason=f"shebang_{executable_shebang_status}",
        )
    try:
        shebang_tokens = shlex.split(executable_shebang, posix=True)
    except ValueError:
        shebang_tokens = []
    if not shebang_tokens:
        return _unproven_runtime_entrypoint(
            kind="direct-script",
            reason="shebang_interpreter_unparseable",
        )

    shebang_launcher = shebang_tokens[0]
    shebang_args = tuple(shebang_tokens[1:])
    launcher_identity = build_runtime_executable_identity(
        shebang_launcher,
        search_path=None,
        cwd=launch_cwd,
    )
    launcher_name = Path(shebang_launcher).name.lower()
    result: dict[str, object] = {
        "kind": "direct-script",
        "launcher": launcher_identity,
        "script_args_sha256": _launch_argv_digest(launch_args),
        "shebang_args_sha256": _launch_argv_digest(shebang_args),
        "shebang_sha256": hashlib.sha256(executable_shebang.encode("utf-8")).hexdigest(),
        "status": "verified",
    }
    if launcher_name not in {"env", "env.exe"}:
        if len(shebang_args) > 1:
            result.update(
                _unproven_runtime_entrypoint(
                    kind="direct-script",
                    reason="nonportable_shebang_arguments",
                    selector=shebang_args,
                )
            )
            result["launcher"] = launcher_identity
            return result
        if launcher_name in _UNRESOLVED_CODE_LAUNCHER_NAMES or launcher_identity.get("status") != "verified":
            result.update(
                _unproven_runtime_entrypoint(
                    kind="direct-script",
                    reason="shebang_interpreter_unresolved",
                )
            )
            result["launcher"] = launcher_identity
            return result
        if _identity_shebang_status(launcher_identity) != "native":
            result.update(
                _unproven_runtime_entrypoint(
                    kind="direct-script",
                    reason="nested_shebang_interpreter_unresolved",
                )
            )
            result["launcher"] = launcher_identity
            return result
        nested_identity = _nested_shebang_interpreter_identity(
            interpreter_name=launcher_name,
            interpreter_args=shebang_args,
            script_path=str(executable_identity.get("path") or ""),
            launch_cwd=launch_cwd,
            launch_env=launch_env,
        )
        result["interpreter_launch"] = nested_identity
        if _runtime_identity_contains_reuse_nonce(nested_identity):
            result.update(
                _unproven_runtime_entrypoint(
                    kind="direct-script",
                    reason="shebang_interpreter_options_unresolved",
                    selector=shebang_args,
                )
            )
            result["launcher"] = launcher_identity
        return result

    env_command = _env_shebang_command(shebang_args)
    search_path = launch_env.get("PATH")
    result["search_path_sha256"] = hashlib.sha256((search_path or "").encode("utf-8")).hexdigest()
    if env_command is None:
        result.update(
            _unproven_runtime_entrypoint(
                kind="direct-env-script",
                reason="env_shebang_command_unresolved",
                selector=shebang_args,
            )
        )
        result["launcher"] = launcher_identity
        return result
    interpreter, interpreter_args = env_command
    interpreter_identity = build_runtime_executable_identity(
        interpreter,
        search_path=search_path,
        cwd=launch_cwd,
    )
    result["interpreter"] = interpreter_identity
    result["interpreter_args_sha256"] = _launch_argv_digest(interpreter_args)
    interpreter_name = Path(interpreter).name.lower()
    if (
        interpreter_name in _UNRESOLVED_CODE_LAUNCHER_NAMES
        or interpreter_identity.get("status") != "verified"
        or _identity_shebang_status(interpreter_identity) != "native"
    ):
        result.update(
            _unproven_runtime_entrypoint(
                kind="direct-env-script",
                reason="env_interpreter_unresolved",
                selector=(interpreter, *interpreter_args),
            )
        )
        result["interpreter"] = interpreter_identity
        result["launcher"] = launcher_identity
        return result
    nested_identity = _nested_shebang_interpreter_identity(
        interpreter_name=interpreter_name,
        interpreter_args=interpreter_args,
        script_path=str(executable_identity.get("path") or ""),
        launch_cwd=launch_cwd,
        launch_env=launch_env,
    )
    result["interpreter_launch"] = nested_identity
    if _runtime_identity_contains_reuse_nonce(nested_identity):
        result.update(
            _unproven_runtime_entrypoint(
                kind="direct-env-script",
                reason="env_interpreter_options_unresolved",
                selector=(interpreter, *interpreter_args),
            )
        )
        result["interpreter"] = interpreter_identity
        result["launcher"] = launcher_identity
    return result


def _nested_shebang_interpreter_identity(
    *,
    interpreter_name: str,
    interpreter_args: tuple[str, ...],
    script_path: str,
    launch_cwd: Path,
    launch_env: Mapping[str, str],
) -> dict[str, object]:
    """Bind code loaded by shebang interpreter options, or disable reuse."""

    launch_args = (*interpreter_args, script_path)
    if _PYTHON_LAUNCHER_PATTERN.fullmatch(interpreter_name):
        return _python_runtime_entrypoint_identity(
            args=launch_args,
            launch_cwd=launch_cwd,
            launch_env=launch_env,
        )
    if interpreter_name in _NODE_LAUNCHER_NAMES:
        return _node_runtime_entrypoint_identity(
            args=launch_args,
            launch_cwd=launch_cwd,
            launch_env=launch_env,
        )
    if interpreter_name in _SHELL_LAUNCHER_NAMES:
        return _shell_runtime_entrypoint_identity(
            shell=interpreter_name,
            args=launch_args,
            launch_cwd=launch_cwd,
            launch_env=launch_env,
        )
    if interpreter_name in _SIMPLE_SCRIPT_LAUNCHER_NAMES:
        return _simple_runtime_entrypoint_identity(
            launcher=interpreter_name,
            args=launch_args,
            launch_cwd=launch_cwd,
        )
    if interpreter_args:
        return _unproven_runtime_entrypoint(
            kind="shebang-interpreter-options",
            reason="unsupported_interpreter_options",
            selector=interpreter_args,
        )
    return {"kind": "shebang-interpreter", "status": "verified"}


def _env_shebang_command(args: tuple[str, ...]) -> tuple[str, tuple[str, ...]] | None:
    parsed = parse_env_wrapper(args)
    if not parsed.complete or not parsed.executable_argv:
        return None
    return parsed.executable_argv[0], parsed.executable_argv[1:]


def _identity_shebang_status(identity: Mapping[str, object]) -> Literal["native", "script", "unverified"]:
    if not isinstance(identity.get("sha256"), str):
        return "unverified"
    status = identity.get("shebang_status")
    if isinstance(identity.get("shebang_sha256"), str) and status == "verified":
        return "script"
    return "native" if status == "not_script" else "unverified"


def _raw_shebang_for_identity(identity: Mapping[str, object]) -> tuple[str | None, str]:
    """Recover a verified shebang from the private hash cache without exposing it."""

    initial_status = identity.get("shebang_status")
    if initial_status != "verified":
        return None, str(initial_status or "unverified")
    path = identity.get("path")
    expected_digest = identity.get("sha256")
    if not isinstance(path, str) or not isinstance(expected_digest, str):
        return None, "unverified"
    try:
        metadata = Path(path).stat()
    except OSError:
        return None, "identity_changed"
    digest, hash_status, shebang, shebang_status = _cached_executable_hash(
        path,
        _executable_stat_key(metadata),
    )
    if (
        hash_status != "verified"
        or digest is None
        or not hmac.compare_digest(digest, expected_digest)
        or shebang_status != "verified"
        or shebang is None
    ):
        return None, "identity_changed"
    return shebang, "verified"


def _python_runtime_entrypoint_identity(
    *,
    args: tuple[str, ...],
    launch_cwd: Path,
    launch_env: Mapping[str, str],
) -> dict[str, object]:
    index = 0
    ignore_environment = False
    isolated = False
    no_value_flags = frozenset({"-b", "-B", "-d", "-O", "-OO", "-q", "-s", "-S", "-u", "-v", "-x"})
    while index < len(args):
        argument = args[index]
        if argument == "--":
            index += 1
            break
        if argument == "-E":
            ignore_environment = True
            index += 1
            continue
        if argument == "-I":
            ignore_environment = True
            isolated = True
            index += 1
            continue
        if argument == "-c":
            interactive = _python_interactive_environment_identity(
                launch_env=launch_env,
                ignore_environment=ignore_environment,
            )
            if interactive is not None:
                return interactive
            if index + 1 >= len(args):
                return _unproven_runtime_entrypoint(kind="python-inline", reason="missing_inline_code")
            return _inline_runtime_entrypoint(kind="python-inline", source=args[index + 1])
        if argument.startswith("-c") and argument != "-c":
            interactive = _python_interactive_environment_identity(
                launch_env=launch_env,
                ignore_environment=ignore_environment,
            )
            if interactive is not None:
                return interactive
            return _inline_runtime_entrypoint(kind="python-inline", source=argument[2:])
        if argument == "-m":
            interactive = _python_interactive_environment_identity(
                launch_env=launch_env,
                ignore_environment=ignore_environment,
            )
            if interactive is not None:
                return interactive
            if index + 1 >= len(args):
                return _unproven_runtime_entrypoint(kind="python-module", reason="missing_module_name")
            return _python_module_runtime_entrypoint_identity(
                module=args[index + 1],
                launch_cwd=launch_cwd,
                launch_env=launch_env,
                include_launch_cwd=not isolated,
                include_python_path=not ignore_environment,
            )
        if argument.startswith("-m") and argument != "-m":
            interactive = _python_interactive_environment_identity(
                launch_env=launch_env,
                ignore_environment=ignore_environment,
            )
            if interactive is not None:
                return interactive
            return _python_module_runtime_entrypoint_identity(
                module=argument[2:],
                launch_cwd=launch_cwd,
                launch_env=launch_env,
                include_launch_cwd=not isolated,
                include_python_path=not ignore_environment,
            )
        if argument in no_value_flags:
            index += 1
            continue
        if argument in {"-W", "-X"} or argument.startswith(("-W", "-X")):
            return _unproven_runtime_entrypoint(
                kind="python-script",
                reason="code_loading_option_unresolved",
                selector=(argument,),
            )
        if argument.startswith("-"):
            return _unproven_runtime_entrypoint(
                kind="python-script",
                reason="unsupported_interpreter_option",
                selector=(argument,),
            )
        break
    interactive = _python_interactive_environment_identity(
        launch_env=launch_env,
        ignore_environment=ignore_environment,
    )
    if interactive is not None:
        return interactive
    if index >= len(args):
        return _unproven_runtime_entrypoint(kind="python-script", reason="entrypoint_missing")
    if args[index] == "-":
        return _unproven_runtime_entrypoint(kind="python-stdin", reason="stdin_code_unprovable")
    return _file_runtime_entrypoint(kind="python-script", argument=args[index], launch_cwd=launch_cwd)


def _python_module_runtime_entrypoint_identity(
    *,
    module: str,
    launch_cwd: Path,
    launch_env: Mapping[str, str],
    include_launch_cwd: bool,
    include_python_path: bool,
) -> dict[str, object]:
    if re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", module) is None:
        return _unproven_runtime_entrypoint(
            kind="python-module",
            reason="invalid_module_name",
            selector=(module,),
        )
    roots = [launch_cwd] if include_launch_cwd else []
    raw_python_path = launch_env.get("PYTHONPATH") if include_python_path else None
    if raw_python_path is not None:
        for raw_root in raw_python_path.split(os.pathsep):
            root = Path(raw_root or ".").expanduser()
            roots.append(root if root.is_absolute() else launch_cwd / root)
    relative_module = Path(*module.split("."))
    for root in _unique_normalized_paths(roots):
        candidates = (
            ("python-module", root / relative_module.with_suffix(".py")),
            ("python-module-bytecode", root / relative_module.with_suffix(".pyc")),
            ("python-package-main", root / relative_module / "__main__.py"),
            ("python-package-main-bytecode", root / relative_module / "__main__.pyc"),
        )
        existing = [(kind, path) for kind, path in candidates if path.is_file()]
        if not existing:
            continue
        if len(existing) != 1:
            return _unproven_runtime_entrypoint(
                kind="python-module",
                reason="module_entrypoint_ambiguous",
                selector=(module,),
            )
        kind, entrypoint_path = existing[0]
        identity = _file_runtime_entrypoint(
            kind=kind,
            argument=str(entrypoint_path),
            launch_cwd=launch_cwd,
        )
        identity["module_sha256"] = hashlib.sha256(module.encode("utf-8")).hexdigest()
        identity["package_initializers"] = _python_package_initializer_identities(
            root=root,
            relative_module=relative_module,
            entrypoint_kind=kind,
        )
        return identity
    return _unproven_runtime_entrypoint(
        kind="python-module",
        reason=("module_entrypoint_unresolved" if roots else "isolated_module_resolution_unproven"),
        selector=(module,),
    )


def _python_interactive_environment_identity(
    *,
    launch_env: Mapping[str, str],
    ignore_environment: bool,
) -> dict[str, object] | None:
    if ignore_environment or not launch_env.get("PYTHONINSPECT"):
        return None
    return _unproven_runtime_entrypoint(
        kind="python-launch",
        reason="interactive_environment_unresolved",
    )


def _unique_normalized_paths(paths: Sequence[Path]) -> tuple[Path, ...]:
    unique: list[Path] = []
    observed: set[str] = set()
    for path in paths:
        normalized = _normalized_launch_cwd(path)
        key = os.path.normcase(str(normalized))
        if key not in observed:
            observed.add(key)
            unique.append(normalized)
    return tuple(unique)


def _python_package_initializer_identities(
    *,
    root: Path,
    relative_module: Path,
    entrypoint_kind: str,
) -> list[dict[str, object]]:
    parts = relative_module.parts if entrypoint_kind.startswith("python-package-main") else relative_module.parts[:-1]
    identities: list[dict[str, object]] = []
    current = root
    for part in parts:
        current /= part
        initializer = current / "__init__.py"
        if initializer.is_file():
            identities.append(
                _file_runtime_entrypoint(
                    kind="python-package-initializer",
                    argument=str(initializer),
                    launch_cwd=root,
                )
            )
    return identities


def _node_runtime_entrypoint_identity(
    *,
    args: tuple[str, ...],
    launch_cwd: Path,
    launch_env: Mapping[str, str],
) -> dict[str, object]:
    if launch_env.get("NODE_OPTIONS"):
        return _unproven_runtime_entrypoint(
            kind="node-launch",
            reason="environment_options_unresolved",
        )
    index = 0
    harmless_flags = frozenset(
        {
            "--abort-on-uncaught-exception",
            "--enable-source-maps",
            "--no-addons",
            "--no-deprecation",
            "--no-warnings",
            "--trace-deprecation",
            "--trace-uncaught",
            "--trace-warnings",
            "--use-bundled-ca",
            "--use-openssl-ca",
        }
    )
    while index < len(args):
        argument = args[index]
        if argument == "--":
            index += 1
            break
        if argument in {"-e", "--eval", "-p", "--print"}:
            if index + 1 >= len(args):
                return _unproven_runtime_entrypoint(kind="node-inline", reason="missing_inline_code")
            return _inline_runtime_entrypoint(kind="node-inline", source=args[index + 1])
        if argument.startswith(("--eval=", "--print=")):
            return _inline_runtime_entrypoint(kind="node-inline", source=argument.split("=", 1)[1])
        if argument in harmless_flags:
            index += 1
            continue
        if argument.startswith("-"):
            return _unproven_runtime_entrypoint(
                kind="node-script",
                reason="unsupported_interpreter_option",
                selector=(argument,),
            )
        break
    if index >= len(args):
        return _unproven_runtime_entrypoint(kind="node-script", reason="entrypoint_missing")
    if args[index] == "-":
        return _unproven_runtime_entrypoint(kind="node-stdin", reason="stdin_code_unprovable")
    return _file_runtime_entrypoint(kind="node-script", argument=args[index], launch_cwd=launch_cwd)


def _shell_runtime_entrypoint_identity(
    *,
    shell: str,
    args: tuple[str, ...],
    launch_cwd: Path,
    launch_env: Mapping[str, str],
) -> dict[str, object]:
    if shell.startswith("fish"):
        return _unproven_runtime_entrypoint(
            kind="fish-launch",
            reason="shell_startup_unresolved",
        )
    if launch_env.get("BASH_ENV") or launch_env.get("ENV") or launch_env.get("ZDOTDIR"):
        return _unproven_runtime_entrypoint(
            kind=f"{shell}-launch",
            reason="shell_startup_environment_unresolved",
        )
    index = 0
    harmless_long_flags = frozenset({"--noprofile", "--norc", "--posix", "--restricted", "--verbose"})
    harmless_short_options = frozenset("abefhkmnptuvxBCEHPT") - {"i"}
    while index < len(args):
        argument = args[index]
        if argument == "--":
            index += 1
            break
        if argument in {"-c", "--command"} or (
            argument.startswith("-") and not argument.startswith("--") and "c" in argument[1:]
        ):
            if index + 1 >= len(args):
                return _unproven_runtime_entrypoint(kind=f"{shell}-inline", reason="missing_inline_code")
            return _inline_runtime_entrypoint(kind=f"{shell}-inline", source=args[index + 1])
        if argument in harmless_long_flags:
            index += 1
            continue
        if argument.startswith("-") and not argument.startswith("--") and set(argument[1:]) <= harmless_short_options:
            index += 1
            continue
        if argument.startswith("-"):
            return _unproven_runtime_entrypoint(
                kind=f"{shell}-script",
                reason="unsupported_interpreter_option",
                selector=(argument,),
            )
        break
    if index >= len(args):
        return _unproven_runtime_entrypoint(kind=f"{shell}-stdin", reason="stdin_code_unprovable")
    return _file_runtime_entrypoint(kind=f"{shell}-script", argument=args[index], launch_cwd=launch_cwd)


def _simple_runtime_entrypoint_identity(
    *,
    launcher: str,
    args: tuple[str, ...],
    launch_cwd: Path,
) -> dict[str, object]:
    if not args or args[0].startswith("-"):
        return _unproven_runtime_entrypoint(
            kind=f"{launcher}-script",
            reason="entrypoint_unresolved",
            selector=args[:1],
        )
    return _file_runtime_entrypoint(kind=f"{launcher}-script", argument=args[0], launch_cwd=launch_cwd)


def _javascript_runtime_entrypoint_identity(
    *,
    launcher: str,
    args: tuple[str, ...],
    launch_cwd: Path,
) -> dict[str, object]:
    if launcher.startswith("deno"):
        if not args or args[0] != "run":
            return _unproven_runtime_entrypoint(
                kind="deno-launch",
                reason="launcher_entrypoint_unresolved",
                selector=args,
            )
        args = args[1:]
    elif args and args[0] == "run":
        return _unproven_runtime_entrypoint(
            kind="bun-package-script",
            reason="package_script_entrypoint_unresolved",
            selector=args,
        )
    if not args or args[0].startswith("-"):
        return _unproven_runtime_entrypoint(
            kind=f"{launcher}-script",
            reason="entrypoint_unresolved",
            selector=args[:1],
        )
    return _file_runtime_entrypoint(kind=f"{launcher}-script", argument=args[0], launch_cwd=launch_cwd)


def _java_runtime_entrypoint_identity(*, args: tuple[str, ...], launch_cwd: Path) -> dict[str, object]:
    try:
        jar_index = args.index("-jar")
    except ValueError:
        return _unproven_runtime_entrypoint(
            kind="java-class",
            reason="class_entrypoint_unresolved",
            selector=args,
        )
    if jar_index + 1 >= len(args):
        return _unproven_runtime_entrypoint(kind="java-jar", reason="jar_entrypoint_missing")
    return _file_runtime_entrypoint(kind="java-jar", argument=args[jar_index + 1], launch_cwd=launch_cwd)


def _dotnet_runtime_entrypoint_identity(*, args: tuple[str, ...], launch_cwd: Path) -> dict[str, object]:
    if not args or args[0].startswith("-") or not args[0].lower().endswith((".dll", ".exe")):
        return _unproven_runtime_entrypoint(
            kind="dotnet-launch",
            reason="managed_entrypoint_unresolved",
            selector=args[:1],
        )
    return _file_runtime_entrypoint(kind="dotnet-assembly", argument=args[0], launch_cwd=launch_cwd)


def _powershell_runtime_entrypoint_identity(*, args: tuple[str, ...], launch_cwd: Path) -> dict[str, object]:
    lowered = tuple(argument.lower() for argument in args)
    for option in ("-command", "-c", "-encodedcommand", "-e"):
        if option in lowered:
            index = lowered.index(option)
            if index + 1 >= len(args):
                return _unproven_runtime_entrypoint(kind="powershell-inline", reason="missing_inline_code")
            return _inline_runtime_entrypoint(kind="powershell-inline", source=args[index + 1])
    for option in ("-file", "-f"):
        if option in lowered:
            index = lowered.index(option)
            if index + 1 >= len(args):
                return _unproven_runtime_entrypoint(kind="powershell-script", reason="entrypoint_missing")
            return _file_runtime_entrypoint(
                kind="powershell-script",
                argument=args[index + 1],
                launch_cwd=launch_cwd,
            )
    return _unproven_runtime_entrypoint(
        kind="powershell-launch",
        reason="entrypoint_unresolved",
        selector=args,
    )


def _file_runtime_entrypoint(*, kind: str, argument: str, launch_cwd: Path) -> dict[str, object]:
    candidate = Path(argument).expanduser()
    if not candidate.is_absolute():
        candidate = launch_cwd / candidate
    identity = build_runtime_executable_identity(str(candidate), search_path=None, cwd=launch_cwd)
    identity["argument_sha256"] = hashlib.sha256(argument.encode("utf-8")).hexdigest()
    identity["kind"] = kind
    return identity


def _inline_runtime_entrypoint(*, kind: str, source: str) -> dict[str, object]:
    return {
        "kind": kind,
        "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "status": "verified",
    }


def _unproven_runtime_entrypoint(
    *,
    kind: str,
    reason: str,
    selector: Sequence[str] = (),
) -> dict[str, object]:
    return {
        "kind": kind,
        "reason": reason,
        "reuse_nonce": secrets.token_hex(16),
        "selector_sha256": _launch_argv_digest(selector),
        "status": "unproven",
    }


def _runtime_launch_verification_digest(identity: object) -> str | None:
    """Hash launch identity while ignoring only deliberate instability nonces."""

    try:
        material = json.dumps(
            _without_runtime_reuse_nonces(identity),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(material).hexdigest()


def _runtime_identity_contains_reuse_nonce(value: object) -> bool:
    if isinstance(value, Mapping):
        typed_value = cast(Mapping[object, object], value)
        return "reuse_nonce" in typed_value or any(
            _runtime_identity_contains_reuse_nonce(item) for item in typed_value.values()
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(_runtime_identity_contains_reuse_nonce(item) for item in value)
    return False


def _verified_identity_path(value: object) -> str | None:
    if not isinstance(value, Mapping):
        return None
    path = value.get("path")
    digest = value.get("sha256")
    if value.get("status") != "verified" or not isinstance(path, str) or not _is_sha256_hex(digest):
        return None
    return path if Path(path).is_absolute() else None


def _without_runtime_reuse_nonces(value: object) -> object:
    if isinstance(value, Mapping):
        typed_value = cast(Mapping[object, object], value)
        return {
            str(key): _without_runtime_reuse_nonces(item) for key, item in typed_value.items() if key != "reuse_nonce"
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_without_runtime_reuse_nonces(item) for item in value]
    return value


@lru_cache(maxsize=128)
def _cached_executable_hash(
    path: str,
    expected_stat: tuple[int, int, int, int, int, int],
) -> tuple[str | None, str, str | None, str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None, "open_failed", None, "unverified"
    try:
        opened_stat = os.fstat(descriptor)
        observed_stat = _executable_stat_key(opened_stat)
        if observed_stat != expected_stat or not stat.S_ISREG(opened_stat.st_mode):
            return None, "identity_raced", None, "unverified"
        if opened_stat.st_size > _MAX_EXECUTABLE_HASH_BYTES:
            return None, "too_large", None, "unverified"
        digest = hashlib.sha256()
        prefix = bytearray()
        total = 0
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            while True:
                chunk = stream.read(_EXECUTABLE_HASH_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_EXECUTABLE_HASH_BYTES:
                    return None, "too_large", None, "unverified"
                digest.update(chunk)
                if len(prefix) <= _MAX_SHEBANG_BYTES:
                    prefix.extend(chunk[: _MAX_SHEBANG_BYTES + 1 - len(prefix)])
        if total != opened_stat.st_size:
            return None, "size_changed", None, "unverified"
        if _executable_stat_key(os.fstat(descriptor)) != observed_stat:
            return None, "identity_raced", None, "unverified"
        shebang, shebang_status = _parse_executable_shebang(bytes(prefix))
        return digest.hexdigest(), "verified", shebang, shebang_status
    except OSError:
        return None, "read_failed", None, "unverified"
    finally:
        os.close(descriptor)


def _parse_executable_shebang(prefix: bytes) -> tuple[str | None, str]:
    if not prefix.startswith(b"#!"):
        return None, "not_script"
    first_line = prefix.splitlines()[0]
    if len(first_line) > _MAX_SHEBANG_BYTES:
        return None, "too_long"
    try:
        decoded = first_line[2:].decode("utf-8").strip()
    except UnicodeDecodeError:
        return None, "invalid_encoding"
    return (decoded, "verified") if decoded else (None, "interpreter_missing")


def _executable_stat_key(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_mode,
    )


def _unreusable_executable_identity(
    command: object,
    *,
    status: str,
    path: Path | None = None,
) -> dict[str, object]:
    return {
        "command": command if isinstance(command, str) else None,
        "path": str(path) if path is not None else None,
        "status": status,
        "reuse_nonce": secrets.token_hex(16),
    }


def _component_hash(component: str, value: object) -> str:
    material = {
        "component": component,
        "domain": _TOKEN_DOMAIN,
        "value": value,
        "version": _TOKEN_VERSION,
    }
    try:
        canonical = json.dumps(
            material,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise TypeError(f"approval context component {component!r} must be JSON-compatible") from exc
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _is_sha256_hex(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and _SHA256_HEX_PATTERN.fullmatch(value) is not None
