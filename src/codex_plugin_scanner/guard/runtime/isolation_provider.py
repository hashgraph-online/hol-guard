"""Isolation provider contract (``guard.isolation-provider.v1``).

Defines the provider execution surface and the Guard-owned provider registry.
Every execution-provider adapter implements :class:`IsolationProvider`. The
registry discovers only Guard/admin-configured providers with pinned identity;
workspace-controlled paths, sockets, or binaries can never register a provider.

Plan and execution are separated: ``plan`` is pure and side-effect-free and
receives no workspace action payload beyond digest-bound context; ``execute``
is one fenced attempt returning a :class:`TerminalStatement`.

The native runtime (``isolation_provider``) owns the trusted checks: the
forbidden host set, the Guard-owned roots, artifact containment and digests,
and the managed registry file. Python keeps the provider objects and spells
each path with the host's own ``Path`` rules.
"""

from __future__ import annotations

import hmac
import os
import platform
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, runtime_checkable

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
_GUARD_OWNED_ROOTS: Final = (
    "/usr/",
    "/opt/hol-guard/",
    "/library/application support/hol guard/",
    "c:/programdata/hol guard/",
)
_PLAN_REFUSALS: Final = {
    "forbidden_path": "provider plan targets a forbidden host path",
    "control_socket": "provider plan targets a host control socket",
    "guard_state": "provider plan targets Guard state",
}


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

    raws = (*input_paths, *declared_outputs)
    paths = [_spelled(raw) for raw in raws]
    try:
        answer = _ask("plan_inputs", {"paths": paths})
    except ValueError as error:
        raise ProviderPlanError("provider plan inputs could not be verified") from error
    refusal = answer.get("refusal", "unanswered")
    if refusal is None:
        return
    message = _PLAN_REFUSALS.get(str(refusal))
    index = answer.get("index")
    if message is None or not isinstance(index, int) or not 0 <= index < len(raws):
        raise ProviderPlanError("provider plan inputs could not be verified")
    raise ProviderPlanError(f"{message}: {raws[index]!r}")


def _spelled(raw: str) -> dict[str, object]:
    # Resolve symlinks so an indirection to a forbidden path cannot pass the
    # lexical check while mounting the real target.
    try:
        path = Path(raw).expanduser().resolve(strict=False)
    except OSError:
        path = Path(raw).expanduser().absolute()
    return {"raw": raw, "resolved": str(path), "name": path.name, "parts": list(path.parts)}


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
        root_path = Path(self._provider_root).expanduser().resolve(strict=False)
        configured = Path(configured_path).expanduser()
        normalized_path = configured.resolve(strict=False)
        refusal = _ask(
            "locate",
            {
                "root": str(root_path),
                "root_parts": [os.path.normcase(part) for part in root_path.parts],
                "path_parts": [os.path.normcase(part) for part in normalized_path.parts],
                "lexical": str(configured.absolute()),
            },
        ).get("refusal", "unanswered")
        if refusal == "outside":
            raise ValueError("provider path is outside the Guard-owned provider root")
        if refusal == "symlink":
            raise ValueError("provider artifact path must not contain symlinks")
        if refusal is not None:
            raise ValueError("provider artifact path could not be verified")
        identity = provider.identity()
        if identity != trust_anchor:
            raise ValueError("provider identity does not match the configured trust anchor")
        actual_digest = self._artifact_digest_resolver(normalized_path)
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
    answer = _ask("registry", {"config": str(config_path)})
    declarations = answer.get("declarations")
    if not isinstance(declarations, list):
        raise ValueError(str(answer.get("refusal") or "managed provider registry is invalid"))
    from .oci_isolation_provider import OCIIsolationProvider

    for declaration in declarations:
        anchor = declaration["trustAnchor"]
        trust_anchor = ProviderIdentity(
            provider_kind=anchor["providerKind"],
            implementation_version=anchor["implementationVersion"],
            binary_or_image_digest=anchor["binaryOrImageDigest"],
            signing_identity=anchor["signingIdentity"],
            trust_domain=anchor["trustDomain"],
        )
        registry.register(
            OCIIsolationProvider(version=trust_anchor.implementation_version),
            configured_path=declaration["path"],
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


def _sha256_regular_file(path: Path) -> str:
    answer = _ask("digest", {"path": str(path)})
    digest = answer.get("digest")
    if isinstance(digest, str):
        return digest
    if answer.get("refusal") == "not_regular":
        raise ValueError("provider artifact must be a regular non-symlink file")
    raise ValueError("provider artifact is missing or unreadable")


def _provider_root_is_guard_owned(path: str) -> bool:
    # Checked in-process: a daemon without a provider registry builds its empty
    # registry at startup and must not wait on the resident for it.
    normalized = path.replace("\\", "/").casefold()
    return normalized.startswith(_GUARD_OWNED_ROOTS)


def _ask(op: str, fields: Mapping[str, object]) -> dict[str, Any]:
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        return native_runner_authority("isolation_provider", {**fields, "op": op})
    except NativeRunnerAuthorityError as error:
        raise ValueError("isolation provider checks are unavailable") from error


__all__ = [
    "ISOLATION_PROVIDER_CONTRACT_VERSION",
    "IsolationProvider",
    "ProviderHealth",
    "ProviderPlanError",
    "ProviderRegistry",
    "load_managed_provider_registry",
    "validate_provider_plan_inputs",
]
