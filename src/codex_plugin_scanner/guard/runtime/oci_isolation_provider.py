"""OCI (Open Container Initiative) adapter for execution assurance.

Maps OCI bundle/runtime identity, mounts, namespaces, capabilities,
seccomp/LSM, cgroups, network, secrets, outputs, and cleanup to the
atomic guarantee contract.

Deny-by-default: unknown or unsupported OCI features LOWER assurance,
never grant. Hostile specs (SYS_ADMIN, host mounts, host network) are
refused at plan time.

The native resident owns the bundle evidence reader, the violation and
guarantee verdict, the bundle digest and the plan digest. This module ships
typed inputs, rebuilds the typed evidence from the owner's answer and turns
a refusal into ``ProviderPlanError``; it never computes a verdict itself.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Final

from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError, native_runner_authority
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
)
from codex_plugin_scanner.guard.runtime.isolation_provider import (
    ProviderHealth,
    ProviderPlanError,
    validate_provider_plan_inputs,
)
from codex_plugin_scanner.guard.runtime.oci_mount_security import resolve_oci_bundle_root

from .payload_coercion import object_map

_PROVIDE_KIND: Final = "oci-isolation"
_SIGNING_IDENTITY: Final = "guard-oci-builtin"
_TRUST_DOMAIN: Final = "guard.oci"
_MALFORMED_INPUT_CODES: Final = frozenset(
    {"native_runner_authority_component_unencodable", "native_runner_authority_invalid"}
)

# OCI features mapped to atomic guarantees.
# When an OCI spec declares these capabilities, they map to specific
# guarantees. Each entry is (kind, boundary_when_enforced).
# These are the ONLY features that contribute positive guarantees.
_OCI_ENFORCED: Final[tuple[tuple[AtomicGuaranteeKind, GuardExecutionAssuranceBoundary], ...]] = (
    (AtomicGuaranteeKind.FILESYSTEM, GuardExecutionAssuranceBoundary.OS_ISOLATED),
    (AtomicGuaranteeKind.NETWORK, GuardExecutionAssuranceBoundary.OS_ISOLATED),
    (AtomicGuaranteeKind.PROCESS, GuardExecutionAssuranceBoundary.OS_ISOLATED),
    (AtomicGuaranteeKind.SECRET, GuardExecutionAssuranceBoundary.OS_ISOLATED),
    (AtomicGuaranteeKind.OUTPUT, GuardExecutionAssuranceBoundary.OS_ISOLATED),
    (AtomicGuaranteeKind.CLEANUP, GuardExecutionAssuranceBoundary.OS_ISOLATED),
    (AtomicGuaranteeKind.IDENTITY, GuardExecutionAssuranceBoundary.OS_ISOLATED),
    (AtomicGuaranteeKind.RESOURCE, GuardExecutionAssuranceBoundary.OS_ISOLATED),
    (AtomicGuaranteeKind.PRIVILEGE, GuardExecutionAssuranceBoundary.OS_ISOLATED),
)

# Features the OCI runtime can NEVER enforce alone.
_OCI_ABSENT: Final[tuple[AtomicGuaranteeKind, ...]] = (
    AtomicGuaranteeKind.KERNEL_HARDWARE,
    AtomicGuaranteeKind.TENANT,
)


# ---------------------------------------------------------------------------
# Evidence types
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Provider implementation
# ---------------------------------------------------------------------------


class OCIIsolationProvider:
    """OCI (Open Container Initiative) bundle isolation provider.

    Validates an OCI bundle spec and maps its features to atomic
    guarantees. Deny-by-default: every feature must be explicitly
    verified to contribute a guarantee.
    """

    _version: str

    def __init__(self, *, version: str = "1.0.0") -> None:
        self._version = version

    @staticmethod
    def _lease_ttl_seconds() -> int:
        return 60

    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_kind=_PROVIDE_KIND,
            implementation_version=self._version,
            binary_or_image_digest=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            signing_identity=_SIGNING_IDENTITY,
            trust_domain=_TRUST_DOMAIN,
        )

    def capabilities(self) -> tuple[AtomicGuarantee, ...]:
        """Return the atomic guarantees this provider enforces.

        These are the maximum guarantees available when a valid OCI
        bundle with full isolation is provided to :meth:`plan`.
        """
        boundary = GuardExecutionAssuranceBoundary.OS_ISOLATED
        guarantees = [AtomicGuarantee(kind=kind, enforced=True, boundary=boundary) for kind, _ in _OCI_ENFORCED]
        for kind in _OCI_ABSENT:
            guarantees.append(
                AtomicGuarantee(
                    kind=kind,
                    enforced=False,
                    boundary=GuardExecutionAssuranceBoundary.OBSERVED_HOST,
                )
            )
        return tuple(guarantees)

    def health_check(self) -> ProviderHealth:
        """Return bounded provider health.

        The OCI adapter is always available because it operates on
        bundle specs without executing code.
        """
        return ProviderHealth(
            state=ProviderHealthState.HEALTHY,
            guarantees=self.capabilities(),
        )

    def plan(
        self,
        context: object,
        minimum_boundary: GuardExecutionAssuranceBoundary,
        *,
        input_paths: tuple[str, ...] = (),
        declared_outputs: tuple[str, ...] = (),
        bundle_spec: dict[str, object] | None = None,
        rootfs_spec: dict[str, object] | None = None,
        process_spec: dict[str, object] | None = None,
        linux_spec: dict[str, object] | None = None,
        bundle_root: str | Path | None = None,
    ) -> ExecutionLease:
        """Produce a side-effect-free fenced lease.

            context: Decision context from the effect decision engine.
            minimum_boundary: Desired minimum isolation boundary.
            input_paths: Input file paths (validated against forbidden set).
            declared_outputs: Declared output paths.
            bundle_spec: OCI bundle spec dict (``bundle.json``).
            rootfs_spec: Optional rootfs override dict.
            process_spec: Optional process override dict.
            linux_spec: Optional linux spec override dict.
            bundle_root: Authoritative OCI bundle directory used to prove
                rootfs and relative bind-source containment.

        Returns:
            A bounded :class:`ExecutionLease` with a deterministic digest.

        Raises:
            ProviderPlanError: On malformed input, hostile spec, or
                unachievable boundary.
        """
        if not isinstance(context, DecisionContext):
            raise ProviderPlanError("context must be a DecisionContext")
        try:
            bundle_root = resolve_oci_bundle_root(bundle_root)
        except ValueError as error:
            raise ProviderPlanError(str(error)) from error
        validate_provider_plan_inputs(input_paths, declared_outputs)

        # Boundary enforcement
        if minimum_boundary is GuardExecutionAssuranceBoundary.HARDWARE_ISOLATED:
            raise ProviderPlanError("OCI bundle isolation cannot provide a hardware-isolated boundary")

        bundle = bundle_spec or {}
        args: dict[str, object] = {
            "bundle": bundle,
            "minimum_boundary": minimum_boundary.value,
            "context_digest": context.context_digest,
        }
        for key, value in (
            ("rootfs", rootfs_spec),
            ("process", process_spec),
            ("linux", linux_spec),
            ("bundle_root", None if bundle_root is None else str(Path(bundle_root).absolute())),
        ):
            if value is not None:
                args[key] = value
        try:
            answer = native_runner_authority("oci_bundle_plan", args)
        except NativeRunnerAuthorityError as error:
            if str(error) in _MALFORMED_INPUT_CODES:
                raise ProviderPlanError("malformed OCI bundle digest input") from error
            raise ProviderPlanError("OCI plan authority is unavailable") from error
        refusal = answer.get("refusal")
        if refusal is not None:
            raise ProviderPlanError(str(refusal))
        plan_digest = answer.get("plan_digest")
        if not isinstance(plan_digest, str) or not plan_digest:
            raise ProviderPlanError("OCI plan authority returned no digest")

        return ExecutionLease(
            plan_digest=plan_digest,
            provider_thumbprint=self.identity().thumbprint(),
            fencing_generation=1,
            lease_expiry_epoch_seconds=int(time.time()) + self._lease_ttl_seconds(),
            attempt_nonce=context.context_digest[:16],
            input_manifest_digest=context.executable_digest,
        )

    def execute(self, lease: ExecutionLease) -> TerminalStatement:
        """Return a self-attested statement.

        The OCI adapter is a spec-validated provider; actual execution
        is delegated to the underlying runtime (containerd, crun, etc.).
        This method returns the terminal statement for planning purposes.
        """
        return TerminalStatement(
            outcome=ExecutionOutcome.SUCCEEDED,
            exit_code=0,
            stream_byte_counts=(),
            stream_digests=(),
            truncated=False,
            declared_output_digests=(),
            cleanup_complete=True,
            execution_instance=lease.attempt_nonce,
            attestation_trust=GuardExecutionAttestationTrust.SELF_ATTESTED,
        )

    def cancel(self, execution_instance: str) -> None:
        """Cancel is a no-op for the spec-validated OCI adapter."""
        _ = execution_instance

    def cleanup(self, execution_instance: str) -> None:
        """Cleanup is a no-op for the spec-validated OCI adapter."""
        _ = execution_instance


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _mapping(value: object) -> dict[str, object]:
    return object_map(value) or {}


__all__ = [
    "OCIIsolationProvider",
]
