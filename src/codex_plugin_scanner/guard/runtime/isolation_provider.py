"""Isolation provider contract (``guard.isolation-provider.v1``).

Defines the provider execution surface and the Guard-owned provider registry.
Every execution-provider adapter implements :class:`IsolationProvider`. The
registry discovers only Guard/admin-configured providers with pinned identity;
workspace-controlled paths, sockets, or binaries can never register a provider.

Plan and execution are separated: ``plan`` is pure and side-effect-free and
receives no workspace action payload beyond digest-bound context; ``execute``
is one fenced attempt returning a :class:`TerminalStatement`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol, runtime_checkable

from codex_plugin_scanner.guard.runtime.execution_assurance_contract import (
    AtomicGuarantee,
    DecisionContext,
    ExecutionLease,
    GuardExecutionAssuranceBoundary,
    ProviderHealthState,
    ProviderIdentity,
    TerminalStatement,
)

ISOLATION_PROVIDER_CONTRACT_VERSION: Final = "guard.isolation-provider.v1"

_PROVIDER_PATH_ROOT: Final = "/usr/libexec/hol-guard/providers"
_PROVIDER_REGISTRY_SCHEMA: Final = "guard.provider-registry.v1"
# Path-name tokens that must never appear as a mounted input or declared output.
_FORBIDDEN_PATH_NAMES: Final = frozenset({".env", ".ssh", ".git", ".gnupg", ".hg", ".svn", ".bzr"})
# Exact host socket paths that must never be mounted.
_FORBIDDEN_SOCKET_PATHS: Final = frozenset(
    {
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/var/run/containerd/containerd.sock",
        "/run/crio/crio.sock",
        "/var/run/crio/crio.sock",
    }
)
# Guard state directory names that must never be mounted.
_GUARD_STATE_NAMES: Final = frozenset({".hol-guard", "guard-state"})


class ProviderPlanError(ValueError):
    """Raised when a provider plan is rejected at the trusted planning boundary."""


def _require_health_state(value: object) -> ProviderHealthState:
    if not isinstance(value, ProviderHealthState):
        raise ValueError("state must be a ProviderHealthState")
    return value


@dataclass(frozen=True)
class ProviderHealth:
    """Health for a provider: derived from guarantees, never self-labeled."""

    state: ProviderHealthState
    guarantees: tuple[AtomicGuarantee, ...] = ()
    reason: str | None = None

    def __post_init__(self) -> None:
        _ = _require_health_state(self.state)


@runtime_checkable
class IsolationProvider(Protocol):
    """Execution-provider adapter contract (``guard.isolation-provider.v1``)."""

    def identity(self) -> ProviderIdentity:
        """Return the pinned provider identity."""
        ...

    def capabilities(self) -> tuple[AtomicGuarantee, ...]:
        """Return the atomic guarantees this provider enforces."""
        ...

    def health_check(self) -> ProviderHealth:
        """Return bounded provider health (never a self-labeled level)."""
        ...

    def plan(self, context: DecisionContext, minimum_boundary: GuardExecutionAssuranceBoundary) -> ExecutionLease:
        """Produce a pure, side-effect-free fenced lease or raise ProviderPlanError."""
        ...

    def execute(self, lease: ExecutionLease) -> TerminalStatement:
        """Run one fenced attempt and return the terminal statement."""
        ...

    def cancel(self, execution_instance: str) -> None:
        """Idempotently terminate the execution instance."""
        ...

    def cleanup(self, execution_instance: str) -> None:
        """Idempotently clean up the execution instance, returning leak evidence."""
        ...


def validate_provider_plan_inputs(
    input_paths: tuple[str, ...],
    declared_outputs: tuple[str, ...],
) -> None:
    """Reject a provider plan that targets the forbidden host set.

    Enforcement point for the forbidden-host-mount ruling: any input manifest
    or declared-output path that touches ``.env``, ``.ssh``, Guard state, VCS
    metadata, or host/container control sockets is refused here, at the trusted
    planning boundary, before the provider is asked to honor it.
    """

    for raw in (*input_paths, *declared_outputs):
        # Resolve symlinks so an indirection to a forbidden path cannot pass the
        # lexical check while mounting the real target.
        try:
            path = Path(raw).expanduser().resolve(strict=False)
        except OSError:
            path = Path(raw).expanduser().absolute()
        name = path.name.lower()
        parts = {part.lower() for part in path.parts}
        if name in _FORBIDDEN_PATH_NAMES or parts & _FORBIDDEN_PATH_NAMES:
            raise ProviderPlanError(f"provider plan targets a forbidden host path: {raw!r}")
        if raw in _FORBIDDEN_SOCKET_PATHS or str(path) in _FORBIDDEN_SOCKET_PATHS:
            raise ProviderPlanError(f"provider plan targets a host control socket: {raw!r}")
        if parts & _GUARD_STATE_NAMES:
            raise ProviderPlanError(f"provider plan targets Guard state: {raw!r}")


class ProviderRegistry:
    """Guard-owned registry of pinned providers.

    Only providers configured under the Guard-owned provider root with a pinned
    binary/image digest can register. A workspace path, arbitrary socket, or
    unverified binary is rejected so a repository cannot point Guard at an
    attacker-controlled provider.
    """

    _provider_root: str
    _providers: dict[str, IsolationProvider]
    _artifact_digest_resolver: Callable[[Path], str]

    def __init__(
        self,
        *,
        provider_root: str = _PROVIDER_PATH_ROOT,
        artifact_digest_resolver: Callable[[Path], str] | None = None,
    ) -> None:
        resolved_root = str(Path(provider_root).expanduser().resolve(strict=False))
        if not _provider_root_is_guard_owned(resolved_root):
            raise ValueError("provider root must be a Guard-owned system path")
        self._provider_root = resolved_root
        self._providers = {}
        self._artifact_digest_resolver = artifact_digest_resolver or _sha256_regular_file

    def register(
        self,
        provider: IsolationProvider,
        *,
        configured_path: str,
        trust_anchor: ProviderIdentity,
    ) -> ProviderIdentity:
        """Register a provider only if its path and digest are pinned and trusted."""

        # Normalize so a `..` or `.` traversal cannot escape the provider root
        # while still lexically starting with it.
        root = str(Path(self._provider_root).expanduser().resolve(strict=False))
        configured = Path(configured_path).expanduser()
        normalized = str(configured.resolve(strict=False))
        if normalized != root and not normalized.startswith(root + "/"):
            raise ValueError("provider path is outside the Guard-owned provider root")
        if _path_has_symlink_below_root(configured, Path(root)):
            raise ValueError("provider artifact path must not contain symlinks")
        identity = provider.identity()
        if identity != trust_anchor:
            raise ValueError("provider identity does not match the configured trust anchor")
        actual_digest = self._artifact_digest_resolver(Path(normalized))
        if not hmac.compare_digest(actual_digest, trust_anchor.binary_or_image_digest):
            raise ValueError("provider artifact digest does not match the configured trust anchor")
        key = identity.thumbprint()
        existing = self._providers.get(key)
        if existing is not None and existing is not provider:
            raise ValueError("provider identity thumbprint collision")
        self._providers[key] = provider
        return identity

    def get(self, thumbprint: str) -> IsolationProvider | None:
        return self._providers.get(thumbprint)

    def providers(self) -> tuple[IsolationProvider, ...]:
        return tuple(self._providers.values())


def load_managed_provider_registry() -> ProviderRegistry:
    """Load and verify admin-owned provider declarations during daemon startup."""

    config_path, provider_root = _managed_provider_locations()
    registry = ProviderRegistry(provider_root=provider_root)
    if not config_path.exists():
        return registry
    payload = _read_managed_provider_config(config_path)
    if payload.get("schema") != _PROVIDER_REGISTRY_SCHEMA:
        raise ValueError("managed provider registry schema is invalid")
    providers = payload.get("providers")
    if not isinstance(providers, list):
        raise ValueError("managed provider registry providers are invalid")
    for declaration in providers:
        if not isinstance(declaration, dict):
            raise ValueError("managed provider declaration is invalid")
        kind = declaration.get("kind")
        configured_path = declaration.get("path")
        anchor = declaration.get("trustAnchor")
        if kind != "oci-isolation" or not isinstance(configured_path, str) or not isinstance(anchor, dict):
            raise ValueError("managed provider declaration is invalid")
        from .oci_isolation_provider import OCIIsolationProvider

        trust_anchor = ProviderIdentity(
            provider_kind=_required_config_text(anchor, "providerKind"),
            implementation_version=_required_config_text(anchor, "implementationVersion"),
            binary_or_image_digest=_required_config_text(anchor, "binaryOrImageDigest"),
            signing_identity=_required_config_text(anchor, "signingIdentity"),
            trust_domain=_required_config_text(anchor, "trustDomain"),
        )
        registry.register(
            OCIIsolationProvider(version=trust_anchor.implementation_version),
            configured_path=configured_path,
            trust_anchor=trust_anchor,
        )
    return registry


def _managed_provider_locations() -> tuple[Path, str]:
    system = platform.system()
    if system == "Darwin":
        base = Path("/Library/Application Support/HOL Guard")
        return base / "providers.json", str(base / "providers")
    if system == "Windows":
        base = Path("C:/ProgramData/HOL Guard")
        return base / "providers.json", str(base / "providers")
    return Path("/etc/hol-guard/providers.json"), _PROVIDER_PATH_ROOT


def _read_managed_provider_config(path: Path) -> dict[str, object]:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise ValueError("managed provider registry is unreadable") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or (os.name != "nt" and metadata.st_mode & 0o022):
            raise ValueError("managed provider registry is not admin-owned")
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("managed provider registry is invalid") from error
    if not isinstance(payload, dict):
        raise ValueError("managed provider registry is invalid")
    return payload


def _required_config_text(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError("managed provider trust anchor is invalid")
    return value


def _sha256_regular_file(path: Path) -> str:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise ValueError("provider artifact is missing or unreadable") from error
    try:
        with os.fdopen(descriptor, "rb") as artifact:
            metadata = os.fstat(artifact.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("provider artifact must be a regular non-symlink file")
            digest = hashlib.sha256()
            for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise ValueError("provider artifact is missing or unreadable") from error
    return digest.hexdigest()


def _provider_root_is_guard_owned(path: str) -> bool:
    normalized = path.replace("\\", "/").casefold()
    return (
        normalized.startswith("/usr/")
        or normalized.startswith("/opt/hol-guard/")
        or normalized.startswith("/library/application support/hol guard/")
        or normalized.startswith("c:/programdata/hol guard/")
    )


def _path_has_symlink_below_root(path: Path, root: Path) -> bool:
    lexical = path.absolute()
    while lexical != root:
        try:
            if lexical.is_symlink():
                return True
        except OSError:
            return True
        parent = lexical.parent
        if parent == lexical:
            break
        lexical = parent
    return False


__all__ = [
    "ISOLATION_PROVIDER_CONTRACT_VERSION",
    "IsolationProvider",
    "ProviderHealth",
    "ProviderPlanError",
    "ProviderRegistry",
    "load_managed_provider_registry",
    "validate_provider_plan_inputs",
]
