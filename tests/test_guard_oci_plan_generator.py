"""Tests for OCI plan generator.

Validates:
- Deterministic plan digest (same spec -> same digest)
- Unknown/unsupported features lower assurance
- Hostile path/mount/capability inputs are refused
- No execution of workspace code
- Fail-closed on malformed spec
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard.runtime.execution_assurance_contract import (
    AtomicGuaranteeKind,
    DecisionContext,
    GuardExecutionAssuranceBoundary,
)
from codex_plugin_scanner.guard.runtime.isolation_provider import ProviderPlanError
from codex_plugin_scanner.guard.runtime.oci_plan_generator import (
    OCIExecutionPlan,
    OCIPlanGenerator,
    _analyze_capabilities,
    _analyze_cgroup,
    _analyze_lsm,
    _analyze_mounts,
    _analyze_network,
    _analyze_rootfs,
    _analyze_seccomp,
    _analyze_user,
    _build_digest_fields,
    _extract_all_capabilities,
    _is_dangerous_cap,
    _is_forbidden_path,
    _is_forbidden_socket,
    _is_guard_state_path,
    _map_guarantees,
    _parse_namespaces,
    _plan_digest,
)


@pytest.fixture
def decision_context():
    mock = MagicMock(spec=DecisionContext)
    mock.context_digest = "abc123def456"
    mock.executable_digest = "00" * 32
    mock.source_label = "test"
    return mock


@pytest.fixture
def good_bundle():
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


@pytest.fixture
def minimal_bundle():
    return {
        "ociVersion": "1.0.2",
        "root": {"path": "rootfs"},
    }


# === Path validation ===


class TestPathValidation:
    def test_forbidden_path_root(self):
        assert _is_forbidden_path("/") == "/"

    def test_forbidden_path_etc(self):
        # Prefix match: /etc/shadow -> /etc
        assert _is_forbidden_path("/etc") == "/etc"
        assert _is_forbidden_path("/etc/shadow") == "/etc"

    def test_forbidden_path_proc(self):
        assert _is_forbidden_path("/proc") == "/proc"

    def test_non_forbidden_path(self):
        assert _is_forbidden_path("/var/data") is None

    def test_empty_path_not_forbidden(self):
        assert _is_forbidden_path("") is None

    def test_forbidden_socket_docker(self):
        assert _is_forbidden_socket("/var/run/docker.sock") == "/var/run/docker.sock"

    def test_forbidden_socket_containerd(self):
        assert _is_forbidden_socket("/var/run/containerd/containerd.sock") == "/var/run/containerd/containerd.sock"

    def test_non_forbidden_socket(self):
        assert _is_forbidden_socket("/tmp/my.sock") is None

    def test_guard_state_hol_guard(self):
        assert _is_guard_state_path("/mnt/.hol-guard/state") is True

    def test_guard_state_guard_state_dir(self):
        assert _is_guard_state_path("/run/guard-state/config") is True

    def test_non_guard_state_path(self):
        assert _is_guard_state_path("/var/data/output") is False


# === Capability validation ===


class TestCapabilityValidation:
    def test_dangerous_cap_sys_admin(self):
        assert _is_dangerous_cap("CAP_SYS_ADMIN") is True

    def test_dangerous_cap_sys_ptrace(self):
        assert _is_dangerous_cap("SYS_PTRACE") is True

    def test_dangerous_cap_net_admin(self):
        assert _is_dangerous_cap("CAP_NET_ADMIN") is True

    def test_normal_cap(self):
        assert _is_dangerous_cap("CAP_NET_BIND_SERVICE") is False

    def test_dangerous_cap_case_insensitive(self):
        assert _is_dangerous_cap("sys_admin") is True
        assert _is_dangerous_cap("SYS_ADMIN") is True

    def test_extract_capabilities(self):
        caps = {
            "effective": ["CAP_NET_BIND_SERVICE", "CAP_SYS_ADMIN"],
            "permitted": ["CAP_NET_BIND_SERVICE"],
            "bounding": ["CAP_SYS_ADMIN", "CAP_NET_ADMIN"],
        }
        all_caps, dangerous = _extract_all_capabilities(caps)
        assert set(all_caps) == {"CAP_NET_BIND_SERVICE", "CAP_SYS_ADMIN", "CAP_NET_ADMIN"}
        assert "CAP_SYS_ADMIN" in dangerous
        assert "CAP_NET_ADMIN" in dangerous
        assert "CAP_NET_BIND_SERVICE" not in dangerous

    def test_extract_no_capabilities(self):
        all_caps, dangerous = _extract_all_capabilities({})
        assert all_caps == []
        assert dangerous == []

    def test_extract_all_capabilities_none(self):
        all_caps, dangerous, has_dangerous = _analyze_capabilities(None)
        assert all_caps == []
        assert dangerous == []
        assert has_dangerous is False

    def test_extract_capabilities_dangerous(self):
        _all_caps, dangerous, has_dangerous = _analyze_capabilities(
            {
                "effective": ["CAP_SYS_ADMIN"],
            }
        )
        assert has_dangerous is True
        assert "CAP_SYS_ADMIN" in dangerous


# === Namespace parsing ===


class TestNamespaceParsing:
    def test_pid_isolated(self):
        ns = _parse_namespaces([{"type": "pid"}])
        assert ns.pid_isolated is True

    def test_pid_host(self):
        ns = _parse_namespaces([{"type": "pid", "host": True}])
        assert ns.pid_isolated is False

    def test_all_host_namespaces(self):
        ns = _parse_namespaces(
            [
                {"type": "pid", "host": True},
                {"type": "net", "host": True},
            ]
        )
        assert ns.pid_isolated is False
        assert ns.net_isolated is False

    def test_isolated_pids(self):
        ns = _parse_namespaces([{"type": "pid"}, {"type": "net"}])
        assert ns.pid_isolated is True
        assert ns.net_isolated is True

    def test_mixed_host_and_isolated(self):
        ns = _parse_namespaces(
            [
                {"type": "pid", "host": True},
                {"type": "net"},
            ]
        )
        # Host namespace -> all isolation denied
        assert ns.pid_isolated is False
        assert ns.net_isolated is False


# === Mount analysis ===


class TestMountAnalysis:
    def test_host_bind_mount(self):
        mounts, _violations, has_forbidden, has_hostile = _analyze_mounts(
            [
                {"destination": "/data", "type": "bind", "source": "/data"},
            ]
        )
        assert len(mounts) == 1
        assert mounts[0].classification == "host"
        assert not has_forbidden
        assert not has_hostile

    def test_forbidden_bind_source(self):
        _mounts, violations, has_forbidden, has_hostile = _analyze_mounts(
            [
                {"destination": "/etc", "type": "bind", "source": "/etc"},
            ]
        )
        assert has_forbidden is True
        assert has_hostile is True
        assert any("forbidden-mount-source" in v for v in violations)

    def test_forbidden_socket(self):
        _mounts, violations, _, has_hostile = _analyze_mounts(
            [
                {"destination": "/var/run/docker.sock", "type": "bind", "source": "/var/run/docker.sock"},
            ]
        )
        assert has_hostile is True
        # source=/var/run/docker.sock matches forbidden source /var/run
        assert any("forbidden-mount-source" in v for v in violations)

    def test_world_writable_mount(self):
        _mounts, violations, _, _ = _analyze_mounts(
            [
                {"destination": "/data", "type": "bind", "source": "/data", "options": ["world-writable"]},
            ]
        )
        assert any("world-writable-mount" in v for v in violations)

    def test_hardening_options_are_not_world_writable(self):
        _mounts, violations, _, _ = _analyze_mounts(
            [
                {
                    "destination": "/data",
                    "type": "bind",
                    "source": "/data",
                    "options": ["ro", "noexec", "nosuid", "nodev"],
                },
            ]
        )
        assert not any("world-writable-mount" in violation for violation in violations)

    def test_guard_state_mount(self):
        _mounts, violations, _, has_hostile = _analyze_mounts(
            [
                {"destination": "/mnt/.hol-guard", "type": "bind", "source": "/mnt/.hol-guard"},
            ]
        )
        assert has_hostile is True
        assert any(v == "guard-state-mount" for v in violations)

    def test_tmpfs_volume(self):
        mounts, _violations, has_forbidden, _ = _analyze_mounts(
            [
                {"destination": "/tmp", "type": "tmpfs"},
            ]
        )
        assert len(mounts) == 1
        assert mounts[0].classification == "system"
        assert not has_forbidden

    def test_rootfs_mount(self):
        mounts, _violations, _, _ = _analyze_mounts(
            [
                {"destination": "/", "type": "none", "options": ["readonly"]},
            ]
        )
        assert len(mounts) == 1
        assert mounts[0].readonly is True
        assert mounts[0].classification == "system"

    def test_socket_mount_classification(self):
        # Docker.sock bind mount: source="/var/run/docker.sock" matches
        # forbidden source "/var/run" first, classification is "forbidden"
        mounts, _, _, _ = _analyze_mounts(
            [
                {"destination": "/var/run/docker.sock", "type": "bind", "source": "/var/run/docker.sock"},
            ]
        )
        assert len(mounts) == 1
        assert mounts[0].classification == "forbidden"

    def test_secret_mount_forbidden(self):
        # /var/run/secrets starts with /var/run (in FORBIDDEN_MOUNT_SOURCES)
        # so it is classified as "forbidden" not "secret"
        mounts, _, _, _ = _analyze_mounts(
            [
                {"destination": "/var/run/secrets", "type": "bind", "source": "/var/run/secrets"},
            ]
        )
        assert len(mounts) == 1
        assert mounts[0].classification == "forbidden"

    def test_output_mount_guard_state(self):
        # Guard-state paths are forbidden regardless of their outer mount root.
        mounts, _, _, _ = _analyze_mounts(
            [
                {"destination": "/mnt/.hol-guard/output", "type": "bind", "source": "/mnt/.hol-guard/output"},
            ]
        )
        assert len(mounts) == 1
        assert mounts[0].classification == "forbidden"

    def test_system_mount(self):
        # non-bind mount type -> unclassified
        mounts, _, _, _ = _analyze_mounts(
            [
                {"destination": "/proc/sys", "type": "proc"},
            ]
        )
        assert len(mounts) == 1
        assert mounts[0].classification == "unclassified"


# === Seccomp analysis ===


class TestSeccompAnalysis:
    def test_strict_seccomp(self):
        kind, enforced = _analyze_seccomp({"seccomp": {"defaultAction": "SCMP_ACT_ERRNO"}})
        assert kind == "strict"
        assert enforced is True

    def test_default_seccomp(self):
        # SCMP_ACT_ALLOW -> "none" (no restrictions)
        kind, enforced = _analyze_seccomp({"seccomp": {"defaultAction": "SCMP_ACT_ALLOW"}})
        assert kind == "none"
        assert enforced is False

    def test_custom_seccomp(self):
        # "path" with specific defaultAction is custom
        kind, enforced = _analyze_seccomp({"seccomp": {"path": "/etc/seccomp.json", "defaultAction": "SCMP_ACT_KILL"}})
        assert kind == "custom"
        assert enforced is True

    def test_none_seccomp(self):
        kind, enforced = _analyze_seccomp({"seccomp": {}})
        assert kind == "none"
        assert enforced is False

    def test_unset_seccomp(self):
        # No seccomp key at all -> unset
        kind, enforced = _analyze_seccomp({})
        assert kind == "unset"
        assert enforced is False

    def test_strict_seccomp_flag(self):
        kind, enforced = _analyze_seccomp({"seccomp": {"strict": True}})
        assert kind == "strict"
        assert enforced is True


# === LSM analysis ===


class TestLSMAnalysis:
    def test_apparmor_enabled(self):
        enabled, profile = _analyze_lsm({"apparmor": "guard-profile"})
        assert enabled is True
        assert profile == "guard-profile"

    def test_selinux_enabled(self):
        enabled, profile = _analyze_lsm({"selinux": {"label": "system_u:system_r:container_t"}})
        assert enabled is True
        assert profile == "system_u:system_r:container_t"

    def test_no_lsm(self):
        enabled, profile = _analyze_lsm({})
        assert enabled is False
        assert profile == ""


# === Cgroup analysis ===


class TestCgroupAnalysis:
    def test_cgroup_v2(self):
        v2, path = _analyze_cgroup({"cgroupsPath": "/sys/fs/cgroup/unified/guard/test"})
        assert v2 is True
        assert path == "/sys/fs/cgroup/unified/guard/test"

    def test_cgroup_v1(self):
        v2, path = _analyze_cgroup({"cgroupsPath": "/sys/fs/cgroup"})
        assert v2 is False
        assert path == "/sys/fs/cgroup"

    def test_no_cgroup(self):
        v2, path = _analyze_cgroup({})
        assert v2 is False
        assert path == ""


# === User analysis ===


class TestUserAnalysis:
    def test_non_root_user(self):
        uid, gid, non_root = _analyze_user({"user": {"uid": 1000, "gid": 1000}})
        assert uid == 1000
        assert gid == 1000
        assert non_root is True

    def test_root_user(self):
        uid, gid, non_root = _analyze_user({"user": {"uid": 0, "gid": 0}})
        assert uid == 0
        assert gid == 0
        assert non_root is False

    def test_no_user_spec(self):
        uid, _gid, non_root = _analyze_user({})
        assert uid == 0
        assert non_root is False

    def test_invalid_uid_type(self):
        uid, _gid, _non_root = _analyze_user({"user": {"uid": "not-a-number"}})
        assert uid == 0


# === Network analysis ===


class TestNetworkAnalysis:
    def test_isolated_network(self):
        ns = _parse_namespaces([{"type": "net"}])
        network = _analyze_network({}, ns)
        assert network.mode == "default"
        assert network.loopback_only is True

    def test_host_network_mode(self):
        ns = _parse_namespaces([{"type": "net"}])
        network = _analyze_network({"network": {"mode": "host"}}, ns)
        assert network.mode == "host"
        assert network.loopback_only is False

    def test_port_mappings(self):
        ns = _parse_namespaces([{"type": "net"}])
        network = _analyze_network(
            {"network": {"mode": "bridge", "ports": ["8080:80", "443:443"]}},
            ns,
        )
        assert network.port_mappings == ("8080:80", "443:443")


# === Rootfs analysis ===


class TestRootfsAnalysis:
    def test_readonly_rootfs(self):
        path, readonly = _analyze_rootfs({"path": "rootfs", "readonly": True})
        assert path == "rootfs"
        assert readonly is True

    def test_writable_rootfs(self):
        _path, readonly = _analyze_rootfs({"path": "rootfs", "readonly": False})
        assert readonly is False

    def test_no_rootfs(self):
        path, readonly = _analyze_rootfs({})
        assert path == ""
        assert readonly is False

    # === Guarantee mapping ===

    def test_namespace_path_is_shared_not_isolated(self):
        namespace = _parse_namespaces(
            [
                {"type": "pid", "path": "/proc/1/ns/pid"},
                {"type": "net", "path": "/proc/1/ns/net"},
            ]
        )
        assert namespace.pid_isolated is False
        assert namespace.net_isolated is False
        assert set(namespace.host_namespaces) == {"pid", "net"}


class TestGuaranteeMapping:
    def test_full_isolation_enforces_all(self):
        ns = _parse_namespaces(
            [
                {"type": "pid"},
                {"type": "net"},
                {"type": "ipc"},
                {"type": "uts"},
                {"type": "user"},
            ]
        )
        enforced, denied = _map_guarantees(
            violations_codes=[],
            namespaces=ns,
            rootfs_readonly=True,
            non_root=True,
            network_loopback=True,
            hostile_mounts=False,
        )
        assert len(enforced) == 9
        assert len(denied) == 2  # KERNEL_HARDWARE, TENANT
        for g in enforced:
            assert g.enforced is True

    def test_violations_lower_all(self):
        ns = _parse_namespaces(
            [
                {"type": "pid"},
                {"type": "net"},
                {"type": "ipc"},
                {"type": "uts"},
                {"type": "user"},
            ]
        )
        enforced, denied = _map_guarantees(
            violations_codes=["rootfs-not-readonly"],
            namespaces=ns,
            rootfs_readonly=False,
            non_root=True,
            network_loopback=True,
            hostile_mounts=False,
        )
        assert len(enforced) == 0
        assert len(denied) == 11

    def test_hostile_mounts_denied(self):
        ns = _parse_namespaces(
            [
                {"type": "pid"},
                {"type": "net"},
                {"type": "ipc"},
                {"type": "uts"},
                {"type": "user"},
            ]
        )
        enforced, denied = _map_guarantees(
            violations_codes=[],
            namespaces=ns,
            rootfs_readonly=True,
            non_root=True,
            network_loopback=True,
            hostile_mounts=True,
        )
        assert len(enforced) == 0
        assert len(denied) == 11

    def test_pid_not_isolated_denies_process(self):
        ns = _parse_namespaces([{"type": "net"}])  # No PID
        enforced, _denied = _map_guarantees(
            violations_codes=[],
            namespaces=ns,
            rootfs_readonly=True,
            non_root=True,
            network_loopback=True,
            hostile_mounts=False,
        )
        assert len(enforced) < 9

    def test_non_root_denies_privilege(self):
        ns = _parse_namespaces(
            [
                {"type": "pid"},
                {"type": "net"},
                {"type": "ipc"},
                {"type": "uts"},
                {"type": "user"},
            ]
        )
        _enforced, denied = _map_guarantees(
            violations_codes=[],
            namespaces=ns,
            rootfs_readonly=True,
            non_root=False,  # running as root
            network_loopback=True,
            hostile_mounts=False,
        )
        priv_denied = any(g.kind == AtomicGuaranteeKind.PRIVILEGE for g in denied)
        assert priv_denied is True

    def test_kernel_hardware_always_absent(self):
        ns = _parse_namespaces(
            [
                {"type": "pid"},
                {"type": "net"},
                {"type": "ipc"},
                {"type": "uts"},
                {"type": "user"},
            ]
        )
        _enforced, denied = _map_guarantees(
            violations_codes=[],
            namespaces=ns,
            rootfs_readonly=True,
            non_root=True,
            network_loopback=True,
            hostile_mounts=False,
        )
        kernel_hw_denied = any(g.kind == AtomicGuaranteeKind.KERNEL_HARDWARE for g in denied)
        assert kernel_hw_denied is True


# === Plan digest ===


class TestPlanDigest:
    def test_digest_deterministic(self):
        ns = _parse_namespaces([{"type": "pid"}])
        net = MagicMock()
        net.mode = "default"
        fields = _build_digest_fields(
            bundle_version="1.0.2",
            minimum_boundary=GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            available_boundary=GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            namespace=ns,
            network=net,
            seccomp_profile="strict",
            seccomp_enforced=True,
            lsm_enabled=False,
            cgroup_v2=False,
            rootfs_readonly=True,
            non_root=True,
            violations_count=0,
            forbidden_capabilities_count=0,
        )
        d1 = _plan_digest(fields)
        d2 = _plan_digest(fields)
        assert d1 == d2
        assert len(d1) > 0

    def test_digest_differs_on_boundary(self):
        ns = _parse_namespaces([{"type": "pid"}])
        net = MagicMock()
        net.mode = "default"
        fields1 = _build_digest_fields(
            bundle_version="1.0.2",
            minimum_boundary=GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            available_boundary=GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            namespace=ns,
            network=net,
            seccomp_profile="strict",
            seccomp_enforced=True,
            lsm_enabled=False,
            cgroup_v2=False,
            rootfs_readonly=True,
            non_root=True,
            violations_count=0,
            forbidden_capabilities_count=0,
        )
        fields2 = _build_digest_fields(
            bundle_version="1.0.2",
            minimum_boundary=GuardExecutionAssuranceBoundary.OS_ISOLATED,
            available_boundary=GuardExecutionAssuranceBoundary.OS_ISOLATED,
            namespace=ns,
            network=net,
            seccomp_profile="strict",
            seccomp_enforced=True,
            lsm_enabled=False,
            cgroup_v2=False,
            rootfs_readonly=True,
            non_root=True,
            violations_count=0,
            forbidden_capabilities_count=0,
        )
        assert _plan_digest(fields1) != _plan_digest(fields2)

    def test_digest_differs_on_violations(self):
        ns = _parse_namespaces([{"type": "pid"}])
        net = MagicMock()
        net.mode = "default"
        fields1 = _build_digest_fields(
            bundle_version="1.0.2",
            minimum_boundary=GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            available_boundary=GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            namespace=ns,
            network=net,
            seccomp_profile="strict",
            seccomp_enforced=True,
            lsm_enabled=False,
            cgroup_v2=False,
            rootfs_readonly=True,
            non_root=True,
            violations_count=0,
            forbidden_capabilities_count=0,
        )
        fields2 = _build_digest_fields(
            bundle_version="1.0.2",
            minimum_boundary=GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            available_boundary=GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            namespace=ns,
            network=net,
            seccomp_profile="strict",
            seccomp_enforced=True,
            lsm_enabled=False,
            cgroup_v2=False,
            rootfs_readonly=True,
            non_root=True,
            violations_count=1,
            forbidden_capabilities_count=0,
        )
        assert _plan_digest(fields1) != _plan_digest(fields2)

    def test_digest_includes_mount_and_capability_detail(self):
        ns = _parse_namespaces([{"type": "pid"}])
        net = MagicMock()
        net.mode = "default"
        common = {
            "bundle_version": "1.0.2",
            "minimum_boundary": GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            "available_boundary": GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            "namespace": ns,
            "network": net,
            "seccomp_profile": "strict",
            "seccomp_enforced": True,
            "lsm_enabled": False,
            "cgroup_v2": False,
            "rootfs_readonly": True,
            "non_root": True,
            "violations_count": 0,
            "forbidden_capabilities_count": 0,
        }
        mount_a, _, _, _ = _analyze_mounts([{"destination": "/a", "type": "tmpfs"}])
        mount_b, _, _, _ = _analyze_mounts([{"destination": "/b", "type": "tmpfs"}])
        digest_a = _plan_digest(
            _build_digest_fields(
                **common,
                mounts=tuple(mount_a),
                capabilities=("CAP_CHOWN",),
                rootfs_path="rootfs-a",
            )
        )
        digest_b = _plan_digest(
            _build_digest_fields(
                **common,
                mounts=tuple(mount_b),
                capabilities=("CAP_NET_BIND_SERVICE",),
                rootfs_path="rootfs-b",
            )
        )
        assert digest_a != digest_b


# === Full plan generation ===


class TestPlanGeneration:
    def test_successful_plan(self, decision_context, good_bundle):
        plan = OCIPlanGenerator.generate(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle=good_bundle,
        )
        assert isinstance(plan, OCIExecutionPlan)
        assert plan.bundle_version == "1.0.2"
        assert plan.available_boundary is GuardExecutionAssuranceBoundary.OS_ISOLATED
        assert plan.boundary_lowered is False
        assert len(plan.enforced_guarantees) > 0
        assert len(plan.denied_guarantees) == 2  # KERNEL_HARDWARE, TENANT

    def test_plan_digest_deterministic(self, decision_context, good_bundle):
        plan1 = OCIPlanGenerator.generate(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle=good_bundle,
        )
        plan2 = OCIPlanGenerator.generate(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle=good_bundle,
        )
        assert plan1.plan_digest == plan2.plan_digest

    def test_different_spec_different_digest(self, decision_context, good_bundle):
        bad_bundle = dict(good_bundle)
        bad_bundle["ociVersion"] = "1.0.0"
        plan1 = OCIPlanGenerator.generate(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle=good_bundle,
        )
        plan2 = OCIPlanGenerator.generate(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle=bad_bundle,
        )
        assert plan1.plan_digest != plan2.plan_digest

    def test_hostile_caps_refused(self, decision_context):
        bundle = {
            "ociVersion": "1.0.2",
            "root": {"path": "rootfs", "readonly": True},
            "process": {"user": {"uid": 1000, "gid": 1000}},
            "linux": {
                "namespaces": [{"type": "pid"}, {"type": "net"}],
                "capabilities": {"effective": ["CAP_SYS_ADMIN"]},
            },
        }
        with pytest.raises(ProviderPlanError, match="dangerous"):
            OCIPlanGenerator.generate(
                decision_context,
                GuardExecutionAssuranceBoundary.OBSERVED_HOST,
                bundle=bundle,
            )

    def test_hostile_mounts_refused(self, decision_context):
        bundle = {
            "ociVersion": "1.0.2",
            "root": {"path": "rootfs"},
            "mounts": [
                {"destination": "/", "type": "none"},
                {"destination": "/etc", "type": "bind", "source": "/etc"},
            ],
        }
        with pytest.raises(ProviderPlanError, match="forbidden"):
            OCIPlanGenerator.generate(
                decision_context,
                GuardExecutionAssuranceBoundary.OBSERVED_HOST,
                bundle=bundle,
            )

    def test_forbidden_socket_refused(self, decision_context):
        # Docker.sock bind mount has source=/var/run/docker.sock
        # which matches forbidden source /var/run -> refused on "forbidden"
        bundle = {
            "ociVersion": "1.0.2",
            "root": {"path": "rootfs"},
            "mounts": [
                {"destination": "/var/run/docker.sock", "type": "bind", "source": "/var/run/docker.sock"},
            ],
        }
        with pytest.raises(ProviderPlanError, match="forbidden"):
            OCIPlanGenerator.generate(
                decision_context,
                GuardExecutionAssuranceBoundary.OBSERVED_HOST,
                bundle=bundle,
            )

    def test_guard_state_mount_refused(self, decision_context):
        bundle = {
            "ociVersion": "1.0.2",
            "root": {"path": "rootfs"},
            "mounts": [
                {"destination": "/mnt/.hol-guard", "type": "bind", "source": "/mnt/.hol-guard"},
            ],
        }
        with pytest.raises(ProviderPlanError, match="hostile"):
            OCIPlanGenerator.generate(
                decision_context,
                GuardExecutionAssuranceBoundary.OBSERVED_HOST,
                bundle=bundle,
            )

    def test_malformed_spec_refused(self, decision_context):
        with pytest.raises(ProviderPlanError, match="malformed"):
            OCIPlanGenerator.generate(
                decision_context,
                GuardExecutionAssuranceBoundary.OBSERVED_HOST,
                bundle={},
            )

    def test_missing_oci_version_refused(self, decision_context):
        with pytest.raises(ProviderPlanError, match="ociVersion"):
            OCIPlanGenerator.generate(
                decision_context,
                GuardExecutionAssuranceBoundary.OBSERVED_HOST,
                bundle={"root": {"path": "rootfs"}},
            )

    def test_wrong_context_type_refused(self, decision_context):
        with pytest.raises(ProviderPlanError, match="context must be"):
            OCIPlanGenerator.generate(
                "not-a-context",
                GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            )


# === Plan structure ===


class TestPlanStructure:
    def test_plan_has_all_guarantees(self, decision_context, good_bundle):
        plan = OCIPlanGenerator.generate(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle=good_bundle,
        )
        all_kinds = {g.kind for g in plan.enforced_guarantees + plan.denied_guarantees}
        assert len(all_kinds) == 11

    def test_plan_has_violations_field(self, decision_context, good_bundle):
        plan = OCIPlanGenerator.generate(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle=good_bundle,
        )
        assert isinstance(plan.violations, tuple)

    def test_plan_digest_is_64_hex_chars(self, decision_context, good_bundle):
        plan = OCIPlanGenerator.generate(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle=good_bundle,
        )
        assert len(plan.plan_digest) == 64
        int(plan.plan_digest, 16)


# === Unknown features lower assurance ===


class TestUnknownFeaturesLowerAssurance:
    def test_unsupported_capability(self, decision_context):
        bundle = {
            "ociVersion": "1.0.2",
            "root": {"path": "rootfs", "readonly": True},
            "process": {"user": {"uid": 1000}},
            "linux": {
                "namespaces": [{"type": "pid"}, {"type": "net"}],
                "capabilities": {"effective": ["CAP_UNKNOWN_FEATURE"]},
            },
        }
        plan = OCIPlanGenerator.generate(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle=bundle,
        )
        assert plan.available_boundary is not GuardExecutionAssuranceBoundary.HARDWARE_ISOLATED

    def test_missing_namespace_isolation_lowers(self, decision_context):
        bundle = {
            "ociVersion": "1.0.2",
            "root": {"path": "rootfs"},
            "process": {"user": {"uid": 1000}},
        }
        plan = OCIPlanGenerator.generate(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle=bundle,
        )
        # Missing namespace evidence fails closed.
        assert plan.available_boundary is GuardExecutionAssuranceBoundary.OBSERVED_HOST

    def test_unmapped_linux_feature(self, decision_context):
        bundle = {
            "ociVersion": "1.0.2",
            "root": {"path": "rootfs", "readonly": True},
            "process": {"user": {"uid": 1000}},
            "linux": {
                "someUnsupportedFeature": "x",
                "namespaces": [{"type": "pid"}],
            },
        }
        plan = OCIPlanGenerator.generate(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle=bundle,
        )
        # Unknown fields and missing net isolation lower assurance.
        assert plan.available_boundary is GuardExecutionAssuranceBoundary.OBSERVED_HOST

    def test_missing_seccomp_lowers(self, decision_context):
        bundle = {
            "ociVersion": "1.0.2",
            "root": {"path": "rootfs", "readonly": True},
            "process": {"user": {"uid": 1000}},
            "linux": {
                "namespaces": [{"type": "pid"}, {"type": "net"}],
            },
        }
        plan = OCIPlanGenerator.generate(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle=bundle,
        )
        # Missing policy is distinct from an explicit allow-all policy.
        assert plan.available_boundary is GuardExecutionAssuranceBoundary.OBSERVED_HOST

    def test_no_lsm_does_not_boost(self, decision_context):
        bundle = {
            "ociVersion": "1.0.2",
            "root": {"path": "rootfs", "readonly": True},
            "process": {"user": {"uid": 1000}},
            "linux": {
                "namespaces": [{"type": "pid"}, {"type": "net"}],
            },
        }
        plan = OCIPlanGenerator.generate(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle=bundle,
        )
        assert plan.lsm_enabled is False


# === Fail-closed on malformed spec ===


class TestFailClosed:
    def test_null_bundle(self, decision_context):
        with pytest.raises(ProviderPlanError, match="bundle must be a dict"):
            OCIPlanGenerator.generate(
                decision_context,
                GuardExecutionAssuranceBoundary.OBSERVED_HOST,
                bundle=None,
            )

    def test_string_bundle(self, decision_context):
        with pytest.raises(ProviderPlanError, match="bundle must be a dict"):
            OCIPlanGenerator.generate(
                decision_context,
                GuardExecutionAssuranceBoundary.OBSERVED_HOST,
                bundle="not-a-dict",
            )

    def test_empty_bundle(self, decision_context):
        with pytest.raises(ProviderPlanError, match="ociVersion"):
            OCIPlanGenerator.generate(
                decision_context,
                GuardExecutionAssuranceBoundary.OBSERVED_HOST,
                bundle={},
            )

    def test_no_namespaces(self, decision_context):
        bundle = {
            "ociVersion": "1.0.2",
            "root": {"path": "rootfs", "readonly": True},
            "process": {"user": {"uid": 1000}},
            "linux": {},
        }
        plan = OCIPlanGenerator.generate(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle=bundle,
        )
        assert plan.available_boundary is GuardExecutionAssuranceBoundary.OBSERVED_HOST

    def test_os_isolated_boundary_unachievable(self, decision_context):
        bundle = {
            "ociVersion": "1.0.2",
            "root": {"path": "rootfs", "readonly": True},
            "process": {"user": {"uid": 1000}},
            "linux": {},
        }
        with pytest.raises(ProviderPlanError, match="not achievable"):
            OCIPlanGenerator.generate(
                decision_context,
                GuardExecutionAssuranceBoundary.OS_ISOLATED,
                bundle=bundle,
            )

    def test_hardware_isolated_always_refused(self, decision_context):
        with pytest.raises(ProviderPlanError, match="hardware"):
            OCIPlanGenerator.generate(
                decision_context,
                GuardExecutionAssuranceBoundary.HARDWARE_ISOLATED,
                bundle={"ociVersion": "1.0.2"},
            )


# === No execution of workspace code ===


class TestNoExecution:
    def test_plan_does_not_execute(self, decision_context, good_bundle):
        bundle = {
            "ociVersion": "1.0.2",
            "root": {"path": "/nonexistent/rootfs"},
            "process": {"user": {"uid": 1000}},
            "linux": {
                "namespaces": [{"type": "pid"}, {"type": "net"}],
            },
            "mounts": [{"destination": "/", "type": "none"}],
        }
        plan = OCIPlanGenerator.generate(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle=bundle,
        )
        assert plan is not None
        assert plan.rootfs_path == "/nonexistent/rootfs"

    def test_plan_does_not_read_filesystem(self, decision_context):
        bundle = {
            "ociVersion": "1.0.2",
            "root": {"path": "/dev/null"},
            "process": {"user": {"uid": 1000}},
            "linux": {
                "namespaces": [{"type": "pid"}, {"type": "net"}],
            },
            "mounts": [{"destination": "/", "type": "none"}],
        }
        plan = OCIPlanGenerator.generate(
            decision_context,
            GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            bundle=bundle,
        )
        assert plan is not None
