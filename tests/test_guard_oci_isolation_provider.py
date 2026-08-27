"""Tests for OCI isolation provider.

Validates:
- Unknown/unsupported features lower assurance (deny-by-default)
- Hostile path/mount/capability inputs are refused
- Deterministic plan digest (same spec -> same digest)
- No execution of workspace code
- Fail-closed on malformed spec
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard.runtime.execution_assurance_contract import (
    AtomicGuarantee,
    AtomicGuaranteeKind,
    DecisionContext,
    ExecutionOutcome,
    GuardExecutionAssuranceBoundary,
    GuardExecutionAttestationTrust,
    ProviderHealthState,
)
from codex_plugin_scanner.guard.runtime.isolation_provider import (
    ProviderPlanError,
)
from codex_plugin_scanner.guard.runtime.oci_isolation_provider import (
    OCIIsolationProvider,
    OCISeccompProfile,
    _compute_bundle_digest,
    _map_guarantees,
    _validate_bundle,
    build_oci_evidence,
)


@pytest.fixture
def provider():
    return OCIIsolationProvider()


@pytest.fixture
def decision_context():
    mock = MagicMock(spec=DecisionContext)
    mock.context_digest = "abc123def456"
    mock.executable_digest = "00" * 32
    mock.source_label = "test"
    return mock


@pytest.fixture
def minimal_bundle():
    return {
        "ociVersion": "1.0.2",
        "root": {"path": "rootfs", "readonly": True},
        "process": {"user": {"uid": 1000, "gid": 1000}, "cwd": "/"},
        "linux": {
            "namespaces": [
                {"type": "pid"},
                {"type": "net"},
                {"type": "ipc"},
                {"type": "uts"},
                {"type": "user"},
            ],
            "seccomp": {"defaultAction": "SCMP_ACT_ERRNO"},
            "cgroupsPath": "/sys/fs/cgroup/unified/guard/test",
        },
        "mounts": [
            {"destination": "/", "type": "none", "options": ["readonly"]},
        ],
    }


# === Provider identity and capabilities ===


class TestProviderIdentity:
    def test_identity_kind(self, provider):
        assert provider.identity().provider_kind == "oci-isolation"

    def test_identity_trust_domain(self, provider):
        assert provider.identity().trust_domain == "guard.oci"

    def test_identity_version(self):
        p = OCIIsolationProvider(version="1.2.3")
        assert p.identity().implementation_version == "1.2.3"


class TestProviderCapabilities:
    def test_all_guarantees(self, provider):
        caps = provider.capabilities()
        assert len(caps) == 11
        for c in caps:
            assert isinstance(c, AtomicGuarantee)

    def test_enforced_count(self, provider):
        assert len([c for c in provider.capabilities() if c.enforced]) == 9

    def test_absent_kinds(self, provider):
        absent = [c for c in provider.capabilities() if not c.enforced]
        kinds = {c.kind for c in absent}
        assert kinds == {AtomicGuaranteeKind.KERNEL_HARDWARE, AtomicGuaranteeKind.TENANT}

    def test_enforced_boundary(self, provider):
        for c in provider.capabilities():
            if c.enforced:
                assert c.boundary is GuardExecutionAssuranceBoundary.OS_ISOLATED


# === Health check ===


class TestProviderHealth:
    def test_healthy(self, provider):
        health = provider.health_check()
        assert health.state is ProviderHealthState.HEALTHY
        assert len(health.guarantees) == 11

    def test_guarantees_match_capabilities(self, provider):
        assert set(provider.health_check().guarantees) == set(provider.capabilities())


# === Evidence building ===


class TestEvidenceBuilding:
    def test_minimal_bundle(self, minimal_bundle):
        ev = build_oci_evidence(minimal_bundle)
        assert ev.bundle_valid is True
        assert ev.bundle_version == "1.0.2"
        assert ev.namespaces.pid_isolated is True
        assert ev.namespaces.net_isolated is True
        assert ev.rootfs.readonly is True
        assert ev.user.non_root is True
        assert ev.capabilities.dangerous_capabilities == ()

    def test_forbidden_mount_evidence(self):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "mounts": [
                    {"destination": "/", "type": "none"},
                    {"destination": "/etc", "type": "bind", "source": "/etc"},
                ],
            }
        )
        assert ev.mounts.forbidden_bind_sources == ("/etc",)

    @pytest.mark.parametrize(
        "source",
        ["../etc", "foo/../../etc", "/tmp/../etc", "//etc"],
    )
    def test_normalized_forbidden_mount_evidence(self, source):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "mounts": [
                    {"destination": "/mnt/input", "type": "bind", "source": source},
                ],
            }
        )

        assert ev.mounts.forbidden_bind_sources == (source,)

    @pytest.mark.parametrize("bind_option", ["bind", "rbind"])
    def test_option_defined_bind_mount_evidence(self, bind_option):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "mounts": [
                    {
                        "destination": "/mnt/input",
                        "type": "none",
                        "source": "data",
                        "options": [bind_option, "ro"],
                    },
                ],
            }
        )

        assert ev.mounts.host_bind_mounts == ("/mnt/input",)

    def test_dangerous_caps_evidence(self):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "linux": {"capabilities": {"effective": ["CAP_SYS_ADMIN"]}},
            }
        )
        assert ev.capabilities.dangerous_capabilities == ("CAP_SYS_ADMIN",)

    def test_seccomp_strict(self):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "linux": {"seccomp": {"defaultAction": "SCMP_ACT_ERRNO"}},
            }
        )
        assert ev.seccomp.profile_kind is OCISeccompProfile.STRICT

    def test_seccomp_default_action_allow(self):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "linux": {"seccomp": {"defaultAction": "SCMP_ACT_ALLOW"}},
            }
        )
        assert ev.seccomp.profile_kind is OCISeccompProfile.DEFAULT

    def test_seccomp_unset_when_absent(self):
        ev = build_oci_evidence({"ociVersion": "1.0.2", "root": {"path": "rootfs"}})
        assert ev.seccomp.profile_kind is OCISeccompProfile.UNSET

    def test_seccomp_none_when_empty_action(self):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "linux": {"seccomp": {"defaultAction": ""}},
            }
        )
        assert ev.seccomp.profile_kind is OCISeccompProfile.NONE

    def test_host_namespace(self):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "linux": {"namespaces": [{"type": "pid", "host": True}]},
            }
        )
        assert ev.namespaces.pid_isolated is False

    def test_host_network(self):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "linux": {"network": {"mode": "host"}},
            }
        )
        assert ev.network.mode == "host"

    def test_world_writable_bind(self):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "mounts": [
                    {"destination": "/var/data", "type": "bind", "source": "/var/data", "options": ["world-writable"]},
                ],
            }
        )
        assert ev.mounts.world_writable_binds == ("/var/data",)

    def test_non_root_user(self):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "process": {"user": {"uid": 1000, "gid": 1000}},
            }
        )
        assert ev.user.non_root is True
        assert ev.user.uid == 1000

    def test_root_user(self):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "process": {"user": {"uid": 0, "gid": 0}},
            }
        )
        assert ev.user.non_root is False
        assert ev.user.uid == 0

    def test_cgroup_v2(self):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "linux": {"cgroupsPath": "/sys/fs/cgroup/unified/guard/test"},
            }
        )
        assert ev.cgroup.v2 is True

    def test_no_cgroup(self):
        ev = build_oci_evidence({"ociVersion": "1.0.2", "root": {"path": "rootfs"}})
        assert ev.cgroup.v2 is False
        assert ev.cgroup.controller_bound is False

    def test_lsm_apparmor(self):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "linux": {"apparmor": "guard-profile"},
            }
        )
        assert ev.lsm.enabled is True
        assert ev.lsm.profile_name == "guard-profile"


# === Validation ===


class TestBundleValidation:
    def test_valid_bundle(self, minimal_bundle, tmp_path):
        (tmp_path / "rootfs").mkdir()
        assert _validate_bundle(build_oci_evidence(minimal_bundle, bundle_root=tmp_path)) == ()

    def test_root_user_violation(self):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "process": {"user": {"uid": 0, "gid": 0}},
            }
        )
        violations = _validate_bundle(ev)
        assert "running as root (uid=0)" in violations

    def test_host_mount_violation(self):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "mounts": [
                    {"destination": "/", "type": "none"},
                    {"destination": "/etc", "type": "bind", "source": "/etc"},
                ],
            }
        )
        violations = _validate_bundle(ev)
        assert "/etc" in violations

    def test_host_network_violation(self):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "linux": {"network": {"mode": "host"}},
            }
        )
        violations = _validate_bundle(ev)
        assert "host network mode" in violations

    def test_host_namespace_violation(self):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "linux": {"namespaces": [{"type": "pid", "host": True}]},
            }
        )
        violations = _validate_bundle(ev)
        assert "pid namespace not isolated" in violations


# === Guarantee mapping ===


class TestGuaranteeMapping:
    def test_all_enforced_when_valid(self):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs", "readonly": True},
                "process": {"user": {"uid": 1000, "gid": 1000}},
                "linux": {
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "net"},
                        {"type": "ipc"},
                        {"type": "uts"},
                        {"type": "user"},
                    ],
                },
                "mounts": [{"destination": "/", "type": "none", "options": ["readonly"]}],
            }
        )
        guarantees = _map_guarantees(ev, ())
        for g in guarantees[:9]:
            assert g.enforced is True
            assert g.boundary is GuardExecutionAssuranceBoundary.OS_ISOLATED

    def test_dangerous_caps_lower_all(self):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "linux": {"capabilities": {"effective": ["CAP_SYS_ADMIN"]}},
            }
        )
        guarantees = _map_guarantees(ev, ("dangerous capabilities",))
        for g in guarantees:
            assert g.enforced is False
            assert g.boundary is GuardExecutionAssuranceBoundary.OBSERVED_HOST

    def test_absent_guarantees_denied(self):
        ev = build_oci_evidence({"ociVersion": "1.0.2", "root": {"path": "rootfs"}})
        guarantees = _map_guarantees(ev, ())
        absent_kinds = {AtomicGuaranteeKind.KERNEL_HARDWARE, AtomicGuaranteeKind.TENANT}
        for g in guarantees:
            if g.kind in absent_kinds:
                assert g.enforced is False
                assert g.boundary is GuardExecutionAssuranceBoundary.OBSERVED_HOST


# === Plan: refusal ===


class TestPlanRefusal:
    def test_refuse_dangerous_capabilities(self, provider, decision_context):
        with pytest.raises(ProviderPlanError, match="dangerous capabilities"):
            provider.plan(
                decision_context,
                GuardExecutionAssuranceBoundary.OBSERVED_HOST,
                bundle_spec={"ociVersion": "1.0.2"},
                linux_spec={"capabilities": {"effective": ["CAP_SYS_ADMIN"]}},
            )

    def test_refuse_forbidden_host_mounts(self, provider, decision_context):
        with pytest.raises(ProviderPlanError, match="forbidden"):
            provider.plan(
                decision_context,
                GuardExecutionAssuranceBoundary.OBSERVED_HOST,
                bundle_spec={
                    "ociVersion": "1.0.2",
                    "mounts": [
                        {"destination": "/", "type": "none"},
                        {"destination": "/etc", "type": "bind", "source": "/etc"},
                    ],
                },
            )

    def test_refuse_parent_relative_host_mount(self, provider, decision_context):
        with pytest.raises(ProviderPlanError, match="forbidden"):
            provider.plan(
                decision_context,
                GuardExecutionAssuranceBoundary.OBSERVED_HOST,
                bundle_spec={
                    "ociVersion": "1.0.2",
                    "mounts": [
                        {
                            "destination": "/mnt/input",
                            "type": "none",
                            "source": "../secret.txt",
                            "options": ["rbind", "ro"],
                        },
                    ],
                },
            )

    def test_refuse_host_network(self, provider, decision_context):
        with pytest.raises(ProviderPlanError, match="host network"):
            provider.plan(
                decision_context,
                GuardExecutionAssuranceBoundary.OBSERVED_HOST,
                bundle_spec={"ociVersion": "1.0.2"},
                linux_spec={"network": {"mode": "host"}},
            )

    def test_refuse_hardware_boundary(self, provider, decision_context):
        with pytest.raises(ProviderPlanError, match="hardware-isolated"):
            provider.plan(
                decision_context,
                GuardExecutionAssuranceBoundary.HARDWARE_ISOLATED,
            )

    def test_refuse_malformed_spec(self, provider, decision_context):
        with pytest.raises(ProviderPlanError, match="malformed"):
            provider.plan(
                decision_context,
                GuardExecutionAssuranceBoundary.OBSERVED_HOST,
                bundle_spec={},
            )

    def test_refuse_wrong_context_type(self, provider):
        with pytest.raises(ProviderPlanError, match="context must be"):
            provider.plan(
                "not-a-context",
                GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            )


# === Plan: success ===


class TestPlanSuccess:
    def test_minimal_plan(self, provider, decision_context, minimal_bundle):
        lease = provider.plan(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle_spec=minimal_bundle,
        )
        assert lease is not None
        assert len(lease.plan_digest) == 64

    def test_os_isolated_plan(self, provider, decision_context, minimal_bundle, tmp_path):
        (tmp_path / "rootfs").mkdir()
        lease = provider.plan(
            decision_context,
            GuardExecutionAssuranceBoundary.OS_ISOLATED,
            bundle_spec=minimal_bundle,
            bundle_root=tmp_path,
        )
        assert lease is not None

    @pytest.mark.parametrize("rootfs_path", ["/", "../rootfs", "rootfs/../../etc"])
    def test_refuse_rootfs_escape(self, provider, decision_context, rootfs_path):
        with pytest.raises(ProviderPlanError, match="bundle-relative"):
            provider.plan(
                decision_context,
                GuardExecutionAssuranceBoundary.OS_ISOLATED,
                bundle_spec={
                    "ociVersion": "1.0.2",
                    "root": {"path": rootfs_path, "readonly": True},
                },
            )

    def test_refuse_lifecycle_hooks(self, provider, decision_context, minimal_bundle):
        bundle = dict(minimal_bundle)
        bundle["hooks"] = {"prestart": [{"path": "/bin/true"}]}

        with pytest.raises(ProviderPlanError, match="hooks"):
            provider.plan(
                decision_context,
                GuardExecutionAssuranceBoundary.OBSERVED_HOST,
                bundle_spec=bundle,
            )

    def test_symlinked_rootfs_cannot_claim_os_isolation(
        self,
        provider,
        decision_context,
        minimal_bundle,
        tmp_path,
    ):
        (tmp_path / "rootfs").symlink_to("/etc", target_is_directory=True)

        with pytest.raises(ProviderPlanError, match="required boundary"):
            provider.plan(
                decision_context,
                GuardExecutionAssuranceBoundary.OS_ISOLATED,
                bundle_spec=minimal_bundle,
                bundle_root=tmp_path,
            )

    def test_symlinked_bind_source_cannot_claim_os_isolation(
        self,
        provider,
        decision_context,
        minimal_bundle,
        tmp_path,
    ):
        (tmp_path / "rootfs").mkdir()
        (tmp_path / "link-to-etc").symlink_to("/etc", target_is_directory=True)
        bundle = dict(minimal_bundle)
        bundle["mounts"] = [
            {
                "destination": "/mnt/input",
                "type": "bind",
                "source": "link-to-etc",
                "options": ["ro"],
            }
        ]

        with pytest.raises(ProviderPlanError, match="required boundary"):
            provider.plan(
                decision_context,
                GuardExecutionAssuranceBoundary.OS_ISOLATED,
                bundle_spec=bundle,
                bundle_root=tmp_path,
            )

    def test_deterministic_digest(self, provider, decision_context, minimal_bundle):
        l1 = provider.plan(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle_spec=minimal_bundle,
        )
        l2 = provider.plan(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle_spec=minimal_bundle,
        )
        assert l1.plan_digest == l2.plan_digest

    def test_different_context_different_digest(self, provider, decision_context, minimal_bundle):
        ctx2 = MagicMock(spec=DecisionContext)
        ctx2.context_digest = "xyz789"
        ctx2.executable_digest = "00" * 32
        ctx2.source_label = "test"
        l1 = provider.plan(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle_spec=minimal_bundle,
        )
        l2 = provider.plan(
            ctx2,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle_spec=minimal_bundle,
        )
        assert l1.plan_digest != l2.plan_digest


# === Execute ===


class TestExecute:
    def test_returns_terminal_statement(self, provider, decision_context, minimal_bundle):
        lease = provider.plan(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle_spec=minimal_bundle,
        )
        result = provider.execute(lease)
        assert result.outcome is ExecutionOutcome.SUCCEEDED
        assert result.exit_code == 0
        assert result.execution_instance is not None
        assert result.attestation_trust is GuardExecutionAttestationTrust.SELF_ATTESTED


# === Cancel and cleanup ===


class TestCancelCleanup:
    def test_cancel_noop(self, provider):
        provider.cancel("some-instance")

    def test_cleanup_noop(self, provider):
        provider.cleanup("some-instance")


# === Digest computation ===


class TestDigestComputation:
    def test_deterministic(self):
        d1 = _compute_bundle_digest({"ociVersion": "1.0.2", "root": {"path": "rootfs"}})
        d2 = _compute_bundle_digest({"ociVersion": "1.0.2", "root": {"path": "rootfs"}})
        assert d1 == d2

    def test_differs_on_change(self):
        d1 = _compute_bundle_digest({"ociVersion": "1.0.2", "root": {"path": "a"}})
        d2 = _compute_bundle_digest({"ociVersion": "1.0.2", "root": {"path": "b"}})
        assert d1 != d2

    def test_ignores_unrecognized_keys(self):
        d1 = _compute_bundle_digest({"ociVersion": "1.0.2", "root": {"path": "rootfs"}, "x": 1})
        d2 = _compute_bundle_digest({"ociVersion": "1.0.2", "root": {"path": "rootfs"}})
        assert d1 == d2

    def test_nested_mapping_order_is_deterministic(self):
        first = _compute_bundle_digest({"ociVersion": "1.0.2", "root": {"path": "rootfs", "readonly": True}})
        second = _compute_bundle_digest({"root": {"readonly": True, "path": "rootfs"}, "ociVersion": "1.0.2"})

        assert first == second

    def test_rejects_unsupported_values(self):
        with pytest.raises(ValueError, match="unsupported OCI spec field type: set"):
            _compute_bundle_digest({"ociVersion": "1.0.2", "root": {"path": {"unsupported"}}})


# === Unknown features lower assurance ===


class TestUnknownFeaturesLowerAssurance:
    def test_unknown_capability_not_mapped(self, provider, decision_context):
        lease = provider.plan(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle_spec={"ociVersion": "1.0.2", "linux": {"capabilities": {"effective": ["CAP_UNKNOWN"]}}},
        )
        assert lease is not None

    def test_unsupported_feature_not_enforced(self):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "linux": {"someUnsupportedFeature": "x"},
            }
        )
        guarantees = _map_guarantees(ev, ())
        for g in guarantees:
            if g.enforced:
                assert g.boundary is GuardExecutionAssuranceBoundary.OS_ISOLATED

    def test_no_namespace_isolation(self):
        ev = build_oci_evidence({"ociVersion": "1.0.2", "root": {"path": "rootfs"}})
        assert ev.namespaces.pid_isolated is False
        assert ev.namespaces.net_isolated is False

    def test_missing_linux_no_isolation(self):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "process": {"user": {"uid": 1000}},
            }
        )
        violations = _validate_bundle(ev)
        assert len(violations) > 0

    def test_missing_seccomp(self):
        ev = build_oci_evidence({"ociVersion": "1.0.2", "root": {"path": "rootfs"}})
        assert ev.seccomp.profile_kind is OCISeccompProfile.UNSET

    def test_missing_cgroup(self):
        ev = build_oci_evidence({"ociVersion": "1.0.2", "root": {"path": "rootfs"}})
        assert ev.cgroup.controller_bound is False

    def test_lsm_does_not_boost(self):
        ev = build_oci_evidence(
            {
                "ociVersion": "1.0.2",
                "root": {"path": "rootfs"},
                "linux": {"apparmor": "guard-default"},
            }
        )
        assert ev.lsm.enabled is True
        assert ev.lsm.profile_name == "guard-default"
        guarantees = _map_guarantees(ev, ())
        assert len(guarantees) == 11
