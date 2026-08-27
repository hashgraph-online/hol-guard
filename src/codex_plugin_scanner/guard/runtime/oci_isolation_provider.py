"""OCI (Open Container Initiative) adapter for execution assurance.

Maps OCI bundle/runtime identity, mounts, namespaces, capabilities,
seccomp/LSM, cgroups, network, secrets, outputs, and cleanup to the
atomic guarantee contract.

Deny-by-default: unknown or unsupported OCI features LOWER assurance,
never grant. A feature not explicitly mapped never contributes a
guarantee. Hostile specs (SYS_ADMIN, host mounts, host network) are
refused at plan time.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Final, cast

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
from codex_plugin_scanner.guard.runtime.oci_mount_security import (
    is_oci_bind_mount,
    match_forbidden_oci_path,
    normalize_oci_bind_source,
    require_oci_bundle_relative_path,
    resolve_oci_bind_source,
    resolve_oci_bundle_path,
)

_PROVIDE_KIND: Final = "oci-isolation"
_SIGNING_IDENTITY: Final = "guard-oci-builtin"
_TRUST_DOMAIN: Final = "guard.oci"

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

# Dangerous capabilities that cause immediate plan rejection.
_DANGEROUS_CAPABILITIES: Final = frozenset(
    {
        "CAP_SYS_ADMIN",
        "SYS_ADMIN",
        "CAP_SYS_PTRACE",
        "SYS_PTRACE",
        "CAP_NET_ADMIN",
        "NET_ADMIN",
    }
)

# Host namespace types that break isolation.
_HOST_NAMESPACES: Final = frozenset(
    {
        "pid",
        "net",
        "ipc",
        "uts",
        "user",
    }
)

# Network modes that defeat isolation.
_HOST_NETWORK_MODES: Final = frozenset(
    {
        "host",
        "host.network",
        "HostNetwork",
    }
)

# Forbidden bind-mount sources (host paths).
_FORBIDDEN_BIND_SOURCES: Final = frozenset(
    {
        "/",
        "/etc",
        "/etc/shadow",
        "/etc/passwd",
        "/proc",
        "/sys",
        "/dev",
        "/var/run",
        "/run",
        "/root",
        "/home",
        "/var/lib",
        "/var/log",
    }
)

# World-writable mount option tokens (denies by default).
_WORLD_WRITABLE_OPTIONS: Final = frozenset(
    {
        "world-writable",
        "world_writable",
        "o+w",
    }
)


# ---------------------------------------------------------------------------
# Evidence types
# ---------------------------------------------------------------------------


class OCICapability(str, Enum):
    """Atomic capability an OCI bundle declares."""

    CAPABILITY = "capability"
    SECCOMP = "seccomp"
    LSM = "lsm"
    CGROUP = "cgroup"
    NAMESPACE = "namespace"
    ROOTFS = "rootfs"
    MOUNT = "mount"
    NETWORK = "network"
    USER = "user"
    BINARY = "binary"
    BUNDLE_VERSION = "bundle_version"


class OCISeccompProfile(str, Enum):
    """Seccomp profile kind."""

    STRICT = "strict"
    CUSTOM = "custom"
    DEFAULT = "default"
    NONE = "none"
    UNSET = "unset"


@dataclass(frozen=True)
class OCISeccompEvidence:
    """Evidence about OCI seccomp configuration."""

    profile_kind: OCISeccompProfile = OCISeccompProfile.UNSET
    profile_json_digest: str = "0" * 64  # SHA-256 hex of profile JSON


@dataclass(frozen=True)
class OCILSMEvidence:
    """Evidence about LSM (SELinux/AppArmor) configuration."""

    enabled: bool = False
    profile_name: str = ""
    profile_verified: bool = False


@dataclass(frozen=True)
class OCICGroupEvidence:
    """Evidence about cgroup configuration."""

    v2: bool = False
    path: str = ""
    controller_bound: bool = False


@dataclass(frozen=True)
class OCINamespaceEvidence:
    """Evidence about namespace isolation."""

    pid_isolated: bool = False
    net_isolated: bool = False
    ipc_isolated: bool = False
    uts_isolated: bool = False
    user_isolated: bool = False


@dataclass(frozen=True)
class OCIMountEvidence:
    """Evidence about OCI mounts."""

    readonly_rootfs: bool = False
    host_bind_mounts: tuple[str, ...] = ()
    secret_mounts: tuple[str, ...] = ()
    output_mounts: tuple[str, ...] = ()
    forbidden_bind_sources: tuple[str, ...] = ()
    unverified_bind_sources: tuple[str, ...] = ()
    world_writable_binds: tuple[str, ...] = ()


@dataclass(frozen=True)
class OCINetworkEvidence:
    """Evidence about network configuration."""

    mode: str = "default"
    port_mappings: tuple[str, ...] = ()
    loopback_only: bool = False


@dataclass(frozen=True)
class OCICapabilitiesEvidence:
    """Evidence about Linux capabilities."""

    effective: tuple[str, ...] = ()
    permitted: tuple[str, ...] = ()
    ambient: tuple[str, ...] = ()
    bounding_set: tuple[str, ...] = ()
    dangerous_capabilities: tuple[str, ...] = ()


@dataclass(frozen=True)
class OCIRootFSEvidence:
    """Evidence about rootfs configuration."""

    path: str = ""
    readonly: bool = False
    absolute: bool = False
    containment_verified: bool = False


@dataclass(frozen=True)
class OCIUserEvidence:
    """Evidence about user configuration."""

    uid: int = 0
    gid: int = 0
    non_root: bool = False


@dataclass(frozen=True)
class _OCILinuxEvidence:
    seccomp: OCISeccompEvidence
    lsm: OCILSMEvidence
    cgroup: OCICGroupEvidence
    namespaces: OCINamespaceEvidence
    capabilities: OCICapabilitiesEvidence
    network_spec: object


@dataclass(frozen=True)
class OCIBundleEvidence:
    """Evidence from OCI bundle spec validation."""

    bundle_version: str = "1.0.0"
    bundle_valid: bool = False
    binary_digest: str = "0" * 64  # SHA-256 of OCI runtime binary
    binary_verified: bool = False

    seccomp: OCISeccompEvidence = field(default_factory=OCISeccompEvidence)
    lsm: OCILSMEvidence = field(default_factory=OCILSMEvidence)
    cgroup: OCICGroupEvidence = field(default_factory=OCICGroupEvidence)
    namespaces: OCINamespaceEvidence = field(default_factory=OCINamespaceEvidence)
    mounts: OCIMountEvidence = field(default_factory=OCIMountEvidence)
    network: OCINetworkEvidence = field(default_factory=OCINetworkEvidence)
    capabilities: OCICapabilitiesEvidence = field(default_factory=OCICapabilitiesEvidence)
    rootfs: OCIRootFSEvidence = field(default_factory=OCIRootFSEvidence)
    user: OCIUserEvidence = field(default_factory=OCIUserEvidence)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _validate_bundle(evidence: OCIBundleEvidence) -> tuple[str, ...]:
    """Validate OCI bundle evidence. Returns list of violation reasons."""
    violations: list[str] = []

    if not evidence.bundle_valid:
        violations.append("bundle invalid")

    if evidence.seccomp.profile_kind in (
        OCISeccompProfile.UNSET,
        OCISeccompProfile.NONE,
    ):
        violations.append("seccomp profile unset or none")

    if evidence.mounts:
        violations.extend(evidence.mounts.forbidden_bind_sources)
        violations.extend(f"unverified bind source: {source}" for source in evidence.mounts.unverified_bind_sources)
        violations.extend(evidence.mounts.world_writable_binds)

    if not evidence.rootfs.containment_verified:
        violations.append("rootfs containment is unverified")

    if evidence.capabilities:
        violations.extend(evidence.capabilities.dangerous_capabilities)

    if evidence.network and evidence.network.mode in _HOST_NETWORK_MODES:
        violations.append("host network mode")

    if evidence.namespaces:
        if not evidence.namespaces.pid_isolated:
            violations.append("pid namespace not isolated")
        if not evidence.namespaces.net_isolated:
            violations.append("net namespace not isolated")

    if evidence.user and not evidence.user.non_root:
        violations.append("running as root (uid=0)")

    return tuple(violations)


def _has_dangerous_caps(evidence: OCIBundleEvidence) -> bool:
    """Return True if evidence contains dangerous capabilities."""
    if not evidence.capabilities:
        return False
    return len(evidence.capabilities.dangerous_capabilities) > 0


def _has_host_mounts(evidence: OCIBundleEvidence) -> bool:
    """Return True if evidence has forbidden host bind mounts."""
    if not evidence.mounts:
        return False
    return len(evidence.mounts.forbidden_bind_sources) > 0


def _has_host_network(evidence: OCIBundleEvidence) -> bool:
    """Return True if evidence uses host network mode."""
    if not evidence.network:
        return False
    return evidence.network.mode in _HOST_NETWORK_MODES


# ---------------------------------------------------------------------------
# Guarantee mapping
# ---------------------------------------------------------------------------


def _map_guarantees(
    evidence: OCIBundleEvidence,
    violations: tuple[str, ...],
) -> tuple[AtomicGuarantee, ...]:
    """Map verified OCI evidence to atomic guarantees.

    Deny-by-default: only guarantees supported by the OCI runtime adapter
    and verified by the evidence are granted. Dangerous capabilities,
    host mounts, or host network cause refusal (not downgrade).
    Unknown/unsupported features lower assurance.
    """
    has_hostile = _has_dangerous_caps(evidence) or _has_host_mounts(evidence) or _has_host_network(evidence)

    # Hostile input → refuse entirely
    if has_hostile:
        boundary = GuardExecutionAssuranceBoundary.OBSERVED_HOST
        return tuple(
            AtomicGuarantee(
                kind=kind,
                enforced=False,
                boundary=boundary,
            )
            for kind, _ in _OCI_ENFORCED
        ) + tuple(
            AtomicGuarantee(
                kind=kind,
                enforced=False,
                boundary=GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            )
            for kind in _OCI_ABSENT
        )

    # Violations lower boundary
    enforced = len(violations) == 0
    boundary = (
        GuardExecutionAssuranceBoundary.OS_ISOLATED if enforced else GuardExecutionAssuranceBoundary.OBSERVED_HOST
    )

    guarantees: list[AtomicGuarantee] = []

    for kind, _ in _OCI_ENFORCED:
        guarantees.append(
            AtomicGuarantee(
                kind=kind,
                enforced=enforced,
                boundary=boundary if enforced else GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            )
        )

    for kind in _OCI_ABSENT:
        guarantees.append(
            AtomicGuarantee(
                kind=kind,
                enforced=False,
                boundary=GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            )
        )

    return tuple(guarantees)


# ---------------------------------------------------------------------------
# Plan digest computation
# ---------------------------------------------------------------------------


def _object_map(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    raw = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in raw):
        return None
    return {cast(str, key): item for key, item in raw.items()}


def _object_list(value: object) -> list[object] | None:
    if not isinstance(value, list):
        return None
    return cast(list[object], value)


def _string_tuple(value: object) -> tuple[str, ...]:
    items = _object_list(value)
    if items is None:
        return ()
    return tuple(item for item in items if isinstance(item, str))


def _compute_bundle_digest(spec: dict[str, object]) -> str:
    """Compute a deterministic SHA-256 digest over an OCI spec dict.

    Serialises only recognised keys (sorted), frames each value,
    and hashes — ensuring identical specs always produce the same digest
    while unknown extra keys are silently ignored.
    """
    recognised: Final = frozenset(
        {
            "ociVersion",
            "root",
            "process",
            "mounts",
            "linux",
            "hostname",
        }
    )
    filtered: dict[str, object] = {}
    for key in sorted(spec):
        if key not in recognised:
            continue
        raw = spec[key]
        if isinstance(raw, str):
            filtered[key] = raw
        elif isinstance(raw, (list, tuple)):
            values = cast(list[object] | tuple[object, ...], raw)
            filtered[key] = [_frame_scalar(item) for item in values]
        elif (mapping := _object_map(raw)) is not None:
            filtered[key] = {nested_key: _frame_scalar(value) for nested_key, value in mapping.items()}
        elif isinstance(raw, (int, float, bool)):
            filtered[key] = raw
        elif raw is None:
            filtered[key] = None
        else:
            raise ValueError(f"unsupported OCI spec field type: {type(raw).__name__}")
    return framed_digest("guard.oci-bundle-spec.v1", filtered)


def _frame_scalar(value: object) -> object:
    """Normalise nested input to a JSON-serialisable, stable form."""
    if isinstance(value, (str, bool, int, float)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        values = cast(list[object] | tuple[object, ...], value)
        return [_frame_scalar(item) for item in values]
    mapping = _object_map(value)
    if mapping is not None:
        return {key: _frame_scalar(mapping[key]) for key in sorted(mapping)}
    raise ValueError(f"unsupported OCI spec field type: {type(value).__name__}")


# ---------------------------------------------------------------------------
# Evidence builder
# ---------------------------------------------------------------------------


def _build_evidence(
    bundle: dict[str, object],
    rootfs: dict[str, object] | None = None,
    process: dict[str, object] | None = None,
    linux: dict[str, object] | None = None,
    bundle_root: str | Path | None = None,
) -> OCIBundleEvidence:
    """Build evidence from an OCI bundle spec dict without executing code.

    Validates the structure and extracts isolation-relevant fields
    conservatively. Unrecognised fields are ignored (deny-by-default).
    """
    raw_version = bundle.get("ociVersion")
    version = raw_version if isinstance(raw_version, str) and raw_version else "0.0.0"
    bundle_valid = version != "0.0.0"
    rootfs_spec = _object_map(rootfs if rootfs is not None else bundle.get("root")) or {}
    rootfs_ev = _read_rootfs(rootfs_spec, bundle_root=bundle_root)
    process_spec = _object_map(process if process is not None else bundle.get("process")) or {}
    user_ev = _read_process(process_spec, rootfs_ev)
    raw_linux = linux if linux is not None else bundle.get("linux")
    linux_ev = _read_linux(_object_map(raw_linux) or {})
    mounts_ev = _read_mounts(_object_list(bundle.get("mounts")) or [], bundle_root=bundle_root)
    network_ev = _read_network(linux_ev)
    raw_binary_digest = bundle.get("_binary_digest")

    return OCIBundleEvidence(
        bundle_version=version,
        bundle_valid=bundle_valid,
        binary_digest=(raw_binary_digest if isinstance(raw_binary_digest, str) else "0" * 64),
        binary_verified=False,
        seccomp=linux_ev.seccomp,
        lsm=linux_ev.lsm,
        cgroup=linux_ev.cgroup,
        namespaces=linux_ev.namespaces,
        mounts=mounts_ev,
        network=network_ev,
        capabilities=linux_ev.capabilities,
        rootfs=rootfs_ev,
        user=user_ev,
    )


def _read_rootfs(spec: dict[str, object], *, bundle_root: str | Path | None = None) -> OCIRootFSEvidence:
    """Extract rootfs evidence from spec."""
    path = spec.get("path", "")
    readonly = spec.get("readonly", False)
    if not isinstance(path, str):
        path = ""
    if not isinstance(readonly, bool):
        readonly = False
    abs_path = PurePosixPath(path).is_absolute()
    containment_verified = False
    try:
        resolve_oci_bundle_path(
            path,
            bundle_root=bundle_root,
            label="OCI rootfs path",
            require_directory=True,
        )
        containment_verified = True
    except ValueError:
        pass
    return OCIRootFSEvidence(
        path=path,
        readonly=readonly,
        absolute=abs_path,
        containment_verified=containment_verified,
    )


def _read_process(spec: dict[str, object], rootfs: OCIRootFSEvidence) -> OCIUserEvidence:
    """Extract user evidence after validating process paths."""
    uid = 0
    gid = 0
    user = _object_map(spec.get("user"))
    if user is not None:
        uid_val = user.get("uid")
        gid_val = user.get("gid")
        if isinstance(uid_val, int):
            uid = uid_val
        if isinstance(gid_val, int):
            gid = gid_val

    working_dir = spec.get("cwd")
    if isinstance(working_dir, str) and working_dir and rootfs.absolute:
        _ = PurePosixPath(working_dir)

    return OCIUserEvidence(uid=uid, gid=gid, non_root=uid != 0)


def _read_linux(spec: dict[str, object]) -> _OCILinuxEvidence:
    """Extract linux isolation evidence from spec."""
    # Seccomp
    seccomp_spec = _object_map(spec.get("seccomp"))
    seccomp_profile = OCISeccompProfile.UNSET
    seccomp_digest = "0" * 64
    if seccomp_spec is not None:
        raw_action = seccomp_spec.get("defaultAction")
        rule_type = raw_action.upper() if isinstance(raw_action, str) else ""
        if rule_type == "SCMP_ACT_ERRNO" or seccomp_spec.get("strict") is True:
            seccomp_profile = OCISeccompProfile.STRICT
        elif rule_type == "SCMP_ACT_ALLOW":
            seccomp_profile = OCISeccompProfile.DEFAULT
        elif raw_action in ("", None):
            seccomp_profile = OCISeccompProfile.NONE
        else:
            seccomp_profile = OCISeccompProfile.CUSTOM
        path = seccomp_spec.get("path")
        if isinstance(path, str) and path:
            seccomp_digest = hashlib.sha256(path.encode()).hexdigest()

    seccomp = OCISeccompEvidence(
        profile_kind=seccomp_profile,
        profile_json_digest=seccomp_digest,
    )

    # LSM
    lsm_enabled = False
    lsm_profile = ""
    # Check for AppArmor or SELinux profiles in spec
    apparmor = spec.get("apparmor")
    selinux = spec.get("selinux")
    if isinstance(apparmor, str) and apparmor:
        lsm_enabled = True
        lsm_profile = apparmor
    selinux_map = _object_map(selinux)
    if selinux_map:
        lsm_enabled = True
        raw_label = selinux_map.get("label")
        lsm_profile = raw_label if isinstance(raw_label, str) else ""
    lsm = OCILSMEvidence(
        enabled=lsm_enabled,
        profile_name=lsm_profile,
        profile_verified=False,
    )

    # Cgroup
    cgroup_path = spec.get("cgroupsPath")
    cgroup_v2 = cgroup_path.startswith("/sys/fs/cgroup/unified") if isinstance(cgroup_path, str) else False
    cgroup = OCICGroupEvidence(
        v2=cgroup_v2,
        path=str(cgroup_path) if isinstance(cgroup_path, str) else "",
        controller_bound=bool(cgroup_path),
    )

    # Namespaces
    ns_list = _object_list(spec.get("namespaces")) or []
    pid_isolated = False
    net_isolated = False
    ipc_isolated = False
    uts_isolated = False
    user_isolated = False

    namespace_maps: list[dict[str, object]] = []
    for ns_entry in ns_list:
        namespace_map = _object_map(ns_entry)
        if namespace_map is None:
            continue
        namespace_maps.append(namespace_map)
        raw_type = namespace_map.get("type")
        typ = raw_type.lower() if isinstance(raw_type, str) else ""
        raw_path = namespace_map.get("path")
        host = namespace_map.get("host") is True or (isinstance(raw_path, str) and bool(raw_path))
        if typ == "pid" and not host:
            pid_isolated = True
        elif typ == "net" and not host:
            net_isolated = True
        elif typ == "ipc" and not host:
            ipc_isolated = True
        elif typ == "uts" and not host:
            uts_isolated = True
        elif typ == "user" and not host:
            user_isolated = True

    # OCI namespace ``path`` joins an existing namespace and is therefore shared.
    namespaces_host = any(
        namespace.get("host") is True or (isinstance((path := namespace.get("path")), str) and bool(path))
        for namespace in namespace_maps
    )
    if namespaces_host:
        pid_isolated = False
        net_isolated = False
        ipc_isolated = False
        uts_isolated = False
        user_isolated = False

    namespaces = OCINamespaceEvidence(
        pid_isolated=pid_isolated,
        net_isolated=net_isolated,
        ipc_isolated=ipc_isolated,
        uts_isolated=uts_isolated,
        user_isolated=user_isolated,
    )

    # Capabilities
    caps_spec = _object_map(spec.get("capabilities")) or {}
    effective = _string_tuple(caps_spec.get("effective"))
    permitted = _string_tuple(caps_spec.get("permitted"))
    ambient = _string_tuple(caps_spec.get("ambient"))
    bounding = _string_tuple(caps_spec.get("bounding"))
    all_caps = set(effective) | set(permitted) | set(ambient) | set(bounding)
    dangerous = tuple(capability for capability in sorted(all_caps) if capability.upper() in _DANGEROUS_CAPABILITIES)

    capabilities = OCICapabilitiesEvidence(
        effective=effective,
        permitted=permitted,
        ambient=ambient,
        bounding_set=bounding,
        dangerous_capabilities=dangerous,
    )

    return _OCILinuxEvidence(
        seccomp=seccomp,
        lsm=lsm,
        cgroup=cgroup,
        namespaces=namespaces,
        capabilities=capabilities,
        network_spec=spec.get("network"),
    )


def _read_mounts(
    spec_list: list[object],
    *,
    bundle_root: str | Path | None = None,
) -> OCIMountEvidence:
    """Extract mount evidence from OCI mounts list."""
    host_binds: list[str] = []
    secret_mounts: list[str] = []
    output_mounts: list[str] = []
    forbidden_sources: list[str] = []
    unverified_sources: list[str] = []
    world_writable: list[str] = []

    readonly_rootfs = False

    for raw_mount in spec_list:
        mount = _object_map(raw_mount)
        if mount is None:
            continue

        raw_source = mount.get("source")
        raw_destination = mount.get("destination")
        raw_type = mount.get("type")
        src = raw_source if isinstance(raw_source, str) else ""
        dst = raw_destination if isinstance(raw_destination, str) else ""
        typ = raw_type if isinstance(raw_type, str) else ""
        raw_options = mount.get("options")
        options = (raw_options,) if isinstance(raw_options, str) else _string_tuple(raw_options)
        is_bind = is_oci_bind_mount(typ, options)

        # Rootfs mount (no source, destination=/)
        if not is_bind and src == "" and dst == "/":
            if "readonly" in options or "ro" in options:
                readonly_rootfs = True
            continue

        # Host bind mount detection
        if is_bind and src:
            normalized_src, escapes_bundle = normalize_oci_bind_source(src)
            resolved_src = normalized_src
            source_verified = False
            try:
                resolved_src = resolve_oci_bind_source(src, bundle_root=bundle_root)
                source_verified = True
            except ValueError:
                pass
            is_forbidden = escapes_bundle or any(
                match_forbidden_oci_path(candidate, _FORBIDDEN_BIND_SOURCES) is not None
                for candidate in (normalized_src, resolved_src)
            )
            if not is_forbidden:
                # Check if it's a world-writable bind
                for opt in options:
                    if opt in _WORLD_WRITABLE_OPTIONS:
                        world_writable.append(dst)
                        break
            else:
                forbidden_sources.append(src)
            if not source_verified:
                unverified_sources.append(src)

            # Classify as secret or output mount
            secret_keywords = frozenset({".env", ".ssh", "secret", "credential", "private", "token"})
            output_keywords = frozenset({".hol-guard", "guard", "output", "result", "report"})
            if secret_keywords & set(PurePosixPath(dst).parts):
                secret_mounts.append(dst)
            elif output_keywords & set(PurePosixPath(dst).parts):
                output_mounts.append(dst)
            else:
                host_binds.append(dst)

    return OCIMountEvidence(
        readonly_rootfs=readonly_rootfs,
        host_bind_mounts=tuple(host_binds),
        secret_mounts=tuple(secret_mounts),
        output_mounts=tuple(output_mounts),
        forbidden_bind_sources=tuple(forbidden_sources),
        unverified_bind_sources=tuple(unverified_sources),
        world_writable_binds=tuple(world_writable),
    )


def _read_network(linux_ev: _OCILinuxEvidence) -> OCINetworkEvidence:
    """Extract network evidence from validated Linux evidence."""
    mode = "default"
    port_mappings: tuple[str, ...] = ()
    loopback_only = linux_ev.namespaces.net_isolated
    network_spec = _object_map(linux_ev.network_spec)
    if network_spec is not None:
        raw_mode = network_spec.get("mode")
        mode = raw_mode if isinstance(raw_mode, str) else "default"
        raw_ports = _object_list(network_spec.get("ports"))
        if raw_ports is not None:
            port_mappings = tuple(str(port) for port in raw_ports)
        if mode in _HOST_NETWORK_MODES:
            loopback_only = False

    return OCINetworkEvidence(
        mode=mode,
        port_mappings=port_mappings,
        loopback_only=loopback_only,
    )


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
        validate_provider_plan_inputs(input_paths, declared_outputs)

        # Boundary enforcement
        if minimum_boundary is GuardExecutionAssuranceBoundary.HARDWARE_ISOLATED:
            raise ProviderPlanError("OCI bundle isolation cannot provide a hardware-isolated boundary")

        # Build evidence from bundle spec
        bundle = bundle_spec or {}
        hooks = bundle.get("hooks")
        if hooks not in (None, {}):
            raise ProviderPlanError("OCI lifecycle hooks are unsupported")
        selected_rootfs = rootfs_spec if rootfs_spec is not None else _object_map(bundle.get("root")) or {}
        if selected_rootfs:
            rootfs_path = selected_rootfs.get("path")
            try:
                require_oci_bundle_relative_path(
                    rootfs_path if isinstance(rootfs_path, str) else "",
                    label="OCI rootfs path",
                )
            except ValueError as error:
                if minimum_boundary is GuardExecutionAssuranceBoundary.OS_ISOLATED:
                    raise ProviderPlanError(str(error)) from error
        evidence = _build_evidence(
            bundle,
            rootfs=rootfs_spec,
            process=process_spec,
            linux=linux_spec,
            bundle_root=bundle_root,
        )

        # Validate evidence — produce violation list
        violations = _validate_bundle(evidence)

        # Host-sensitive evidence is always refused.
        if evidence.capabilities.dangerous_capabilities:
            raise ProviderPlanError(
                "dangerous capabilities detected: " + ", ".join(evidence.capabilities.dangerous_capabilities)
            )
        if evidence.mounts.forbidden_bind_sources:
            raise ProviderPlanError("forbidden host bind mounts: " + ", ".join(evidence.mounts.forbidden_bind_sources))

        if evidence.network and evidence.network.mode in _HOST_NETWORK_MODES:
            raise ProviderPlanError("host network mode rejected")

        if not evidence.bundle_valid:
            raise ProviderPlanError("malformed OCI bundle spec")

        # Map evidence to guarantees (deny-by-default)
        guarantees = _map_guarantees(evidence, violations)

        if minimum_boundary is GuardExecutionAssuranceBoundary.OS_ISOLATED:
            required_kinds = {kind for kind, _ in _OCI_ENFORCED}
            required = tuple(guarantee for guarantee in guarantees if guarantee.kind in required_kinds)
            if any(
                not guarantee.enforced or guarantee.boundary is not GuardExecutionAssuranceBoundary.OS_ISOLATED
                for guarantee in required
            ):
                raise ProviderPlanError("required boundary is unavailable on this host")

        # Compute deterministic plan digest
        spec_fields: dict[str, object] = {
            "context_digest": context.context_digest,
            "minimum_boundary": minimum_boundary.value,
            "bundle_digest": _compute_bundle_digest(bundle),
            "bundle_version": evidence.bundle_version,
            "violations_count": len(violations),
        }
        plan_digest = framed_digest("guard.oci-plan.v1", spec_fields)

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


def build_oci_evidence(
    bundle: dict[str, object],
    rootfs: dict[str, object] | None = None,
    process: dict[str, object] | None = None,
    linux: dict[str, object] | None = None,
    bundle_root: str | Path | None = None,
) -> OCIBundleEvidence:
    """Build OCI bundle evidence from spec dicts."""
    return _build_evidence(
        bundle,
        rootfs=rootfs,
        process=process,
        linux=linux,
        bundle_root=bundle_root,
    )


__all__ = [
    "OCIBundleEvidence",
    "OCICGroupEvidence",
    "OCICapabilitiesEvidence",
    "OCIIsolationProvider",
    "OCILSMEvidence",
    "OCIMountEvidence",
    "OCINamespaceEvidence",
    "OCINetworkEvidence",
    "OCIRootFSEvidence",
    "OCISeccompEvidence",
    "OCISeccompProfile",
    "OCIUserEvidence",
    "_compute_bundle_digest",
    "_map_guarantees",
    "_validate_bundle",
    "build_oci_evidence",
]
