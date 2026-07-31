"""Tests for the isolation provider contract and Guard-owned registry (wave two)."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.execution_assurance_contract import (
    AtomicGuarantee,
    AtomicGuaranteeKind,
    DecisionContext,
    ExecutionLease,
    GuardExecutionAssuranceBoundary,
    ProviderHealthState,
    ProviderIdentity,
    TerminalStatement,
)
from codex_plugin_scanner.guard.runtime.isolation_provider import (
    IsolationProvider,
    ProviderHealth,
    ProviderPlanError,
    ProviderRegistry,
    validate_provider_plan_inputs,
)

_SHA = "a" * 64
_OTHER = "b" * 64


class _FakeProvider:
    def __init__(self, kind: str = "local-seatbelt") -> None:
        self._identity = ProviderIdentity(
            provider_kind=kind,
            implementation_version="1.0.0",
            binary_or_image_digest=_SHA,
            signing_identity="guard-local",
            trust_domain="guard.local",
        )

    def identity(self) -> ProviderIdentity:
        return self._identity

    def capabilities(self) -> tuple[AtomicGuarantee, ...]:
        return (
            AtomicGuarantee(
                kind=AtomicGuaranteeKind.FILESYSTEM,
                enforced=True,
                boundary=GuardExecutionAssuranceBoundary.OS_ISOLATED,
            ),
        )

    def health_check(self) -> ProviderHealth:
        return ProviderHealth(state=ProviderHealthState.HEALTHY, guarantees=self.capabilities())

    def plan(self, context: DecisionContext, minimum_boundary: GuardExecutionAssuranceBoundary) -> ExecutionLease:
        return ExecutionLease(
            plan_digest=_SHA,
            provider_thumbprint=self._identity.thumbprint(),
            fencing_generation=1,
            lease_expiry_epoch_seconds=1000,
            attempt_nonce="n1",
            input_manifest_digest=_OTHER,
        )

    def execute(self, lease: ExecutionLease) -> TerminalStatement:
        raise NotImplementedError

    def cancel(self, execution_instance: str) -> None:
        return None

    def cleanup(self, execution_instance: str) -> None:
        return None


class TestProtocolConformance:
    def test_fake_provider_satisfies_protocol(self) -> None:
        assert isinstance(_FakeProvider(), IsolationProvider)

    def test_incomplete_provider_fails_protocol(self) -> None:
        class _NotAProvider:
            pass

        assert not isinstance(_NotAProvider(), IsolationProvider)


class TestPlanInputValidation:
    @pytest.mark.parametrize(
        "path",
        [
            "/home/user/project/.env",
            "secrets/.env",
            "/root/.ssh/id_rsa",
            "/repo/.git/config",
            "/var/run/docker.sock",
            "/run/containerd/containerd.sock",
            "/home/user/.hol-guard/state.db",
        ],
    )
    def test_rejects_forbidden_input(self, path: str) -> None:
        with pytest.raises(ProviderPlanError):
            validate_provider_plan_inputs((path,), ())

    @pytest.mark.parametrize(
        "path",
        [
            "/home/user/project/src/main.py",
            "/tmp/workspace/output.txt",
            "build/artifact.bin",
        ],
    )
    def test_allows_benign_input(self, path: str) -> None:
        validate_provider_plan_inputs((path,), ())

    def test_rejects_forbidden_declared_output(self) -> None:
        with pytest.raises(ProviderPlanError):
            validate_provider_plan_inputs((), ("/app/.env",))


class TestProviderRegistry:
    def test_registers_guard_owned_path(self) -> None:
        registry = ProviderRegistry()
        identity = registry.register(_FakeProvider(), configured_path="/usr/libexec/hol-guard/providers/seatbelt")
        assert identity.provider_kind == "local-seatbelt"

    def test_rejects_workspace_path(self) -> None:
        registry = ProviderRegistry()
        with pytest.raises(ValueError, match="outside the Guard-owned provider root"):
            registry.register(_FakeProvider(), configured_path="/home/user/project/.guard/provider")

    def test_rejects_relative_path(self) -> None:
        registry = ProviderRegistry()
        with pytest.raises(ValueError, match="outside the Guard-owned provider root"):
            registry.register(_FakeProvider(), configured_path="providers/seatbelt")

    def test_rejects_non_guard_root(self) -> None:
        with pytest.raises(ValueError, match="Guard-owned system path"):
            ProviderRegistry(provider_root="/home/user/providers")

    def test_identity_thumbprint_lookup(self) -> None:
        registry = ProviderRegistry()
        provider = _FakeProvider()
        identity = registry.register(provider, configured_path="/usr/libexec/hol-guard/providers/seatbelt")
        assert registry.get(identity.thumbprint()) is provider

    def test_rejects_thumbprint_collision_with_distinct_provider(self) -> None:
        registry = ProviderRegistry()
        first = _FakeProvider()
        identity = registry.register(first, configured_path="/usr/libexec/hol-guard/providers/seatbelt")
        other = _FakeProvider()
        with pytest.raises(ValueError, match="thumbprint collision"):
            registry.register(other, configured_path="/usr/libexec/hol-guard/providers/seatbelt")
        assert registry.get(identity.thumbprint()) is first


class TestProviderHealth:
    def test_rejects_non_state(self) -> None:
        with pytest.raises(ValueError, match="ProviderHealthState"):
            ProviderHealth(state="healthy", guarantees=())  # type: ignore[arg-type]


def test_registry_rejects_traversal_escape() -> None:
    registry = ProviderRegistry()
    with __import__("pytest").raises(ValueError, match="outside the Guard-owned provider root"):
        registry.register(_FakeProvider(), configured_path="/usr/libexec/hol-guard/providers/../evil/bin")


def test_plan_rejects_additional_vcs_names() -> None:
    for vcs in (".hg", ".svn", ".bzr"):
        with __import__("pytest").raises(ProviderPlanError):
            validate_provider_plan_inputs((f"/repo/{vcs}/config",), ())


def test_plan_rejects_symlink_to_forbidden_path(tmp_path) -> None:
    from codex_plugin_scanner.guard.runtime.isolation_provider import validate_provider_plan_inputs

    secret = tmp_path / ".ssh"
    secret.mkdir()
    link = tmp_path / "link"
    link.symlink_to(secret)
    with __import__("pytest").raises(ProviderPlanError):
        validate_provider_plan_inputs((str(link / "id_rsa"),), (str(tmp_path / "out"),))
