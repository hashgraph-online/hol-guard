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

    def __init__(self, *, provider_root: str = _PROVIDER_PATH_ROOT) -> None:
        if not provider_root.startswith("/usr/") and not provider_root.startswith("/opt/hol-guard/"):
            raise ValueError("provider root must be a Guard-owned system path")
        self._provider_root = provider_root
        self._providers = {}

    def register(self, provider: IsolationProvider, *, configured_path: str) -> ProviderIdentity:
        """Register a provider only if its path and digest are pinned and trusted."""

        # Normalize so a `..` or `.` traversal cannot escape the provider root
        # while still lexically starting with it.
        root = str(Path(self._provider_root).expanduser().resolve(strict=False))
        normalized = str(Path(configured_path).expanduser().resolve(strict=False))
        if normalized != root and not normalized.startswith(root + "/"):
            raise ValueError("provider path is outside the Guard-owned provider root")
        identity = provider.identity()
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


__all__ = [
    "ISOLATION_PROVIDER_CONTRACT_VERSION",
    "IsolationProvider",
    "ProviderHealth",
    "ProviderPlanError",
    "ProviderRegistry",
    "validate_provider_plan_inputs",
]
