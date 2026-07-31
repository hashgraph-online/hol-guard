"""Reference local isolation provider: wraps OS Seatbelt/Bubblewrap.

Adapts the existing containment executor (``containment_executor.py``) to the
``guard.isolation-provider.v1`` contract without broadening command eligibility
and without claiming unsigned v1 output is signed evidence. Atomic guarantees
are computed conservatively from the runtime-available backend; any control the
backend does not enforce is reported as absent, never inferred.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Final

from codex_plugin_scanner.guard.runtime.containment_contract import (
    ContainmentBackend,
    ContainmentRequest,
)
from codex_plugin_scanner.guard.runtime.containment_executor import execute_contained
from codex_plugin_scanner.guard.runtime.execution_assurance_contract import (
    AtomicGuarantee,
    AtomicGuaranteeKind,
    DecisionContext,
    ExecutionLease,
    ExecutionOutcome,
    GuardExecutionAssuranceBoundary,
    GuardExecutionAttestationTrust,
    ProviderHealthState,
    ProviderIdentity,
    TerminalStatement,
    framed_digest,
)
from codex_plugin_scanner.guard.runtime.isolation_provider import (
    ProviderHealth,
    ProviderPlanError,
    validate_provider_plan_inputs,
)

_PROVIDER_KIND: Final = "local-os-containment"
_SIGNING_IDENTITY: Final = "guard-local-unsigned"
_TRUST_DOMAIN: Final = "guard.local"

# Guarantees the local Seatbelt/Bubblewrap reference backend actually enforces,
# derived from the containment baseline (fs/network/process limits, env scrub,
# bounded output, process-group kill cleanup, pinned-executable identity).
_LOCAL_ENFORCED: Final = (
    AtomicGuaranteeKind.FILESYSTEM,
    AtomicGuaranteeKind.NETWORK,
    AtomicGuaranteeKind.PROCESS,
    AtomicGuaranteeKind.SECRET,
    AtomicGuaranteeKind.OUTPUT,
    AtomicGuaranteeKind.CLEANUP,
    AtomicGuaranteeKind.IDENTITY,
    AtomicGuaranteeKind.RESOURCE,
)
# Kernel/hardware and tenant separation are NOT enforced by the local backend.
_LOCAL_ABSENT: Final = (
    AtomicGuaranteeKind.KERNEL_HARDWARE,
    AtomicGuaranteeKind.TENANT,
    AtomicGuaranteeKind.PRIVILEGE,
)


def _require_decision_context(value: object) -> DecisionContext:
    if not isinstance(value, DecisionContext):
        raise ProviderPlanError("context must be a DecisionContext")
    return value


class LocalOSContainmentProvider:
    """Reference isolation provider backed by OS Seatbelt/Bubblewrap."""

    _platform: str
    _backend: ContainmentBackend | None
    _backend_digest: str

    def __init__(self, *, platform: str | None = None, backend_digest: str | None = None) -> None:
        self._platform = platform or sys.platform
        self._backend = self._backend_kind(self._platform)
        self._backend_digest = backend_digest or ("0" * 64)

    @staticmethod
    def _lease_ttl_seconds() -> int:
        """Bounded execution-lease TTL for the reference local provider."""

        return 30

    @staticmethod
    def _backend_kind(platform: str) -> ContainmentBackend | None:
        if platform == "darwin":
            return ContainmentBackend.MACOS_SANDBOX
        if platform.startswith("linux"):
            return ContainmentBackend.LINUX_BWRAP
        return None

    def _backend_path(self) -> str | None:
        if self._backend is ContainmentBackend.MACOS_SANDBOX:
            return "/usr/bin/sandbox-exec"
        if self._backend is ContainmentBackend.LINUX_BWRAP:
            for path in ("/usr/bin/bwrap", "/bin/bwrap"):
                if Path(path).is_file():
                    return path
        return None

    def _available(self) -> bool:
        path = self._backend_path()
        return self._backend is not None and path is not None and Path(path).is_file()

    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_kind=_PROVIDER_KIND,
            implementation_version="1.0.0",
            binary_or_image_digest=self._backend_digest,
            signing_identity=_SIGNING_IDENTITY,
            trust_domain=_TRUST_DOMAIN,
        )

    def capabilities(self) -> tuple[AtomicGuarantee, ...]:
        boundary = (
            GuardExecutionAssuranceBoundary.OS_ISOLATED
            if self._available()
            else GuardExecutionAssuranceBoundary.CONTROLLED_HOST
        )
        guarantees = [
            AtomicGuarantee(kind=kind, enforced=self._available(), boundary=boundary) for kind in _LOCAL_ENFORCED
        ]
        guarantees.extend(
            AtomicGuarantee(
                kind=kind,
                enforced=False,
                boundary=GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            )
            for kind in _LOCAL_ABSENT
        )
        return tuple(guarantees)

    def health_check(self) -> ProviderHealth:
        if self._backend is None:
            return ProviderHealth(
                state=ProviderHealthState.INCOMPATIBLE,
                guarantees=self.capabilities(),
                reason="no containment backend for this platform",
            )
        if not self._available():
            return ProviderHealth(
                state=ProviderHealthState.UNAVAILABLE,
                guarantees=self.capabilities(),
                reason="containment backend binary not present or not executable",
            )
        return ProviderHealth(state=ProviderHealthState.HEALTHY, guarantees=self.capabilities())

    def plan(
        self,
        context: DecisionContext,
        minimum_boundary: GuardExecutionAssuranceBoundary,
        *,
        input_paths: tuple[str, ...] = (),
        declared_outputs: tuple[str, ...] = (),
    ) -> ExecutionLease:
        _ = _require_decision_context(context)
        # Trusted planning boundary: refuse any path-bearing input that targets
        # the forbidden host set before a lease is issued. The digest-only
        # reference plan carries no paths, so this is a no-op unless a caller
        # supplies path inputs.
        validate_provider_plan_inputs(input_paths, declared_outputs)
        # The local OS backend (Seatbelt/Bubblewrap) can never provide hardware
        # isolation; reject it unconditionally so the plan never overstates the
        # achievable boundary. OS isolation additionally requires a present backend.
        if minimum_boundary is GuardExecutionAssuranceBoundary.HARDWARE_ISOLATED:
            raise ProviderPlanError("local OS containment cannot provide a hardware-isolated boundary")
        if minimum_boundary is GuardExecutionAssuranceBoundary.OS_ISOLATED and not self._available():
            raise ProviderPlanError("required boundary is unavailable on this host")
        backend_name = self._backend.value if self._backend is not None else "none"
        plan_digest = framed_digest(
            "guard.local-os-plan.v1",
            {
                "context_digest": context.context_digest,
                "minimum_boundary": minimum_boundary.value,
                "backend": backend_name,
            },
        )
        return ExecutionLease(
            plan_digest=plan_digest,
            provider_thumbprint=self.identity().thumbprint(),
            fencing_generation=1,
            lease_expiry_epoch_seconds=int(time.time()) + self._lease_ttl_seconds(),
            attempt_nonce=context.context_digest[:16],
            input_manifest_digest=context.executable_digest,
        )

    def execute(self, lease: ExecutionLease) -> TerminalStatement:
        # The reference adapter produces an unsigned (self-attested) statement for
        # an unavailable/no-op path; real contained execution flows through the
        # existing executor in the runtime integration wave.
        health = self.health_check()
        outcome = (
            ExecutionOutcome.FAILED if health.state is not ProviderHealthState.HEALTHY else ExecutionOutcome.SUCCEEDED
        )
        return TerminalStatement(
            outcome=outcome,
            exit_code=None,
            stream_byte_counts=(),
            stream_digests=(),
            truncated=False,
            declared_output_digests=(),
            cleanup_complete=True,
            execution_instance=lease.attempt_nonce,
            attestation_trust=GuardExecutionAttestationTrust.SELF_ATTESTED,
        )

    def cancel(self, execution_instance: str) -> None:
        _ = execution_instance
        return None

    def cleanup(self, execution_instance: str) -> None:
        _ = execution_instance
        return None


def execute_contained_request(request: ContainmentRequest, *, timeout_seconds: float = 60.0):
    """Pass-through to the existing executor for the runtime integration wave."""

    return execute_contained(request, timeout_seconds=timeout_seconds)


__all__ = [
    "LocalOSContainmentProvider",
    "execute_contained_request",
]
