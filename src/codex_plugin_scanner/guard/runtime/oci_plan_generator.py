"""OCI plan generator: deterministic execution plans from OCI bundle specs.

Produces deny-by-default execution plans from an OCI runtime/bundle spec
WITHOUT executing workspace code. Validates the spec and rejects hostile
path/mount/capability inputs by lowering or refusing assurance.

Deterministic output: identical specs always produce identical plan digests.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final, cast

from codex_plugin_scanner.guard.runtime.execution_assurance_contract import (
    AtomicGuarantee,
    AtomicGuaranteeKind,
    DecisionContext,
    GuardExecutionAssuranceBoundary,
    framed_digest,
)
from codex_plugin_scanner.guard.runtime.isolation_provider import ProviderPlanError

# --- Forbidden / hostile input constants ---

# Capabilities that are always refused.
_FORBIDDEN_CAPABILITIES: Final = frozenset(
    {
        "CAP_SYS_ADMIN",
        "SYS_ADMIN",
        "CAP_SYS_PTRACE",
        "SYS_PTRACE",
        "CAP_NET_ADMIN",
        "NET_ADMIN",
        "CAP_SYS_MODULE",
        "CAP_SYS_RAWIO",
        "CAP_MKNOD",
        "CAP_AUDIT_WRITE",
    }
)

# Forbidden host mount sources (absolute paths).
_FORBIDDEN_MOUNT_SOURCES: Final = frozenset(
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

# Forbidden socket paths.
_FORBIDDEN_SOCKETS: Final = frozenset(
    {
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/var/run/containerd/containerd.sock",
        "/run/containerd/containerd.sock",
        "/run/crio/crio.sock",
        "/var/run/crio/crio.sock",
        "/var/run/kubernetes",
    }
)

# Guard state directory names that must never be mounted.
_GUARD_STATE_NAMES: Final = frozenset({".hol-guard", "guard-state"})

# World-writable mount option tokens.
_WORLD_WRITABLE_OPTIONS: Final = frozenset({"world-writable", "world_writable", "o+w", "rw-all"})

# Network modes that defeat isolation.
_HOST_NETWORK_MODES: Final = frozenset({"host", "host.network", "HostNetwork"})
_KNOWN_LINUX_FIELDS: Final = frozenset(
    {
        "apparmor",
        "capabilities",
        "cgroupsPath",
        "devices",
        "gidMappings",
        "maskedPaths",
        "mountLabel",
        "namespaces",
        "network",
        "readonlyPaths",
        "resources",
        "rootfsPropagation",
        "seccomp",
        "selinux",
        "sysctl",
        "uidMappings",
    }
)

# Namespace types.
_NAMESPACE_TYPES: Final = frozenset({"pid", "net", "ipc", "uts", "user", "mount", "cgroup", "time"})

# --- Plan structure ---


@dataclass(frozen=True)
class OCIPlanInput:
    """An input source for the execution plan."""

    path: str  # Container path
    source: str  # Host source or "none"
    readonly: bool
    mount_type: str  # "bind", "volume", "tmpfs", "none"


@dataclass(frozen=True)
class OCIPlanOutput:
    """An output source for the execution plan."""

    path: str  # Container path
    source: str  # Host source or "none"
    max_bytes: int | None = None


@dataclass(frozen=True)
class OCIPlanSecret:
    """A secret mount or env reference."""

    container_path: str
    secret_handle: str
    readonly: bool = True


@dataclass(frozen=True)
class OCIPlanMount:
    """A mount entry in the plan."""

    container_path: str
    mount_type: str
    readonly: bool
    source: str = ""
    options: tuple[str, ...] = ()
    classification: str = "unclassified"  # "host", "secret", "output", "system"


@dataclass(frozen=True)
class OCIPlanNetwork:
    """Network configuration in the plan."""

    mode: str  # "default", "host", "bridge", "none"
    port_mappings: tuple[str, ...] = ()
    loopback_only: bool = True


@dataclass(frozen=True)
class OCIPlanNamespace:
    """Namespace isolation in the plan."""

    pid_isolated: bool
    net_isolated: bool
    ipc_isolated: bool
    uts_isolated: bool
    user_isolated: bool
    host_namespaces: tuple[str, ...] = ()


@dataclass(frozen=True)
class OCIGuaranteeEntry:
    """A guarantee entry in the plan."""

    kind: AtomicGuaranteeKind
    enforced: bool
    boundary: GuardExecutionAssuranceBoundary
    reason: str = ""


@dataclass(frozen=True)
class OCIPlanViolation:
    """A violation found during plan generation."""

    code: str  # Machine-readable code
    description: str  # Human-readable
    severity: str  # "refuse", "lower", "warn"


@dataclass(frozen=True)
class OCIExecutionPlan:
    """The complete, deterministic execution plan derived from an OCI spec.

    Pure data — no provider, no execution, no side effects.
    """

    plan_digest: str  # SHA-256 hex
    bundle_version: str
    minimum_boundary: GuardExecutionAssuranceBoundary
    available_boundary: GuardExecutionAssuranceBoundary
    boundary_lowered: bool
    inputs: tuple[OCIPlanInput, ...] = ()
    outputs: tuple[OCIPlanOutput, ...] = ()
    secrets: tuple[OCIPlanSecret, ...] = ()
    mounts: tuple[OCIPlanMount, ...] = ()
    network: OCIPlanNetwork | None = None
    namespaces: OCIPlanNamespace | None = None
    capabilities: tuple[str, ...] = ()
    forbidden_capabilities: tuple[str, ...] = ()
    seccomp_profile: str = "unset"
    seccomp_enforced: bool = False
    lsm_enabled: bool = False
    lsm_profile: str = ""
    cgroup_v2: bool = False
    cgroup_path: str = ""
    rootfs_path: str = ""
    rootfs_readonly: bool = False
    non_root: bool = False
    violations: tuple[OCIPlanViolation, ...] = ()
    enforced_guarantees: tuple[AtomicGuarantee, ...] = ()
    denied_guarantees: tuple[AtomicGuarantee, ...] = ()
    reason_code: str = "oci.plan"

    def __post_init__(self) -> None:
        if len(self.plan_digest) != 64:
            raise ValueError("plan_digest must be 64 hex chars")
        _ = _require_str(self.bundle_version, "bundle_version")
        _ = _require_str(self.seccomp_profile, "seccomp_profile")
        _ = _require_str(self.lsm_profile, "lsm_profile")
        _ = _require_str(self.cgroup_path, "cgroup_path")
        _ = _require_str(self.rootfs_path, "rootfs_path")


# --- Validators ---


def _require_str(value: object, label: str, *, max_length: int = 512) -> str:
    if not isinstance(value, str) or len(value) > max_length:
        raise ValueError(f"{label} must be a string of at most {max_length} characters")
    return value


# --- Path validation ---


def _is_forbidden_path(path: str) -> str | None:
    """Return the matching forbidden source, or None."""
    if not path:
        return None
    for forbidden in sorted(_FORBIDDEN_MOUNT_SOURCES):
        if path == forbidden or path.startswith(forbidden + "/"):
            return forbidden
    return None


def _is_forbidden_socket(path: str) -> str | None:
    """Return the matching forbidden socket, or None."""
    if path in _FORBIDDEN_SOCKETS:
        return path
    return None


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


def _is_guard_state_path(path: str) -> bool:
    """Return True if path targets guard state directories."""
    if not path:
        return False
    return any(guard_name in PurePosixPath(path).parts for guard_name in _GUARD_STATE_NAMES)


# --- Capability validation ---


def _is_dangerous_cap(cap: str) -> bool:
    """Return True if a capability is forbidden."""
    return cap.upper() in _FORBIDDEN_CAPABILITIES


def _extract_all_capabilities(
    caps_spec: dict[str, object],
) -> tuple[list[str], list[str]]:
    """Extract all capabilities and their dangerous subset."""
    all_caps: set[str] = set()
    for key in ("effective", "permitted", "ambient", "bounding"):
        all_caps.update(_string_tuple(caps_spec.get(key)))
    all_list = sorted(all_caps)
    dangerous = [capability for capability in all_list if _is_dangerous_cap(capability)]
    return all_list, dangerous


# --- Namespace validation ---


def _parse_namespaces(ns_list: list[object]) -> OCIPlanNamespace:
    """Parse namespace list into plan namespace structure."""
    pid_isolated = False
    net_isolated = False
    ipc_isolated = False
    uts_isolated = False
    user_isolated = False
    host_namespaces: list[str] = []

    for ns_entry in ns_list:
        namespace = _object_map(ns_entry)
        if namespace is None:
            continue
        raw_type = namespace.get("type")
        typ = raw_type.lower() if isinstance(raw_type, str) else ""
        raw_host = namespace.get("host")
        namespace_path = namespace.get("path")
        host = (raw_host if isinstance(raw_host, bool) else False) or (
            isinstance(namespace_path, str) and bool(namespace_path)
        )
        if typ == "pid":
            if not host:
                pid_isolated = True
            else:
                host_namespaces.append("pid")
        elif typ == "net":
            if not host:
                net_isolated = True
            else:
                host_namespaces.append("net")
        elif typ == "ipc":
            if not host:
                ipc_isolated = True
            else:
                host_namespaces.append("ipc")
        elif typ == "uts":
            if not host:
                uts_isolated = True
            else:
                host_namespaces.append("uts")
        elif typ == "user":
            if not host:
                user_isolated = True
            else:
                host_namespaces.append("user")

    # If any namespace is host, deny all isolation (deny-by-default)
    if host_namespaces:
        pid_isolated = False
        net_isolated = False
        ipc_isolated = False
        uts_isolated = False
        user_isolated = False

    return OCIPlanNamespace(
        pid_isolated=pid_isolated,
        net_isolated=net_isolated,
        ipc_isolated=ipc_isolated,
        uts_isolated=uts_isolated,
        user_isolated=user_isolated,
        host_namespaces=tuple(host_namespaces),
    )


# --- Mount analysis ---


def _classify_mount(
    mount: dict[str, object],
) -> tuple[str, str, bool, str, tuple[str, ...]]:
    """Classify a mount entry into path, type, readonly, source, and options."""
    raw_destination = mount.get("destination")
    raw_source = mount.get("source")
    raw_type = mount.get("type")
    destination = raw_destination if isinstance(raw_destination, str) else ""
    source = raw_source if isinstance(raw_source, str) else ""
    mount_type = raw_type if isinstance(raw_type, str) else ""
    raw_options = mount.get("options")
    options = (raw_options,) if isinstance(raw_options, str) else _string_tuple(raw_options)
    readonly = "readonly" in options or "ro" in options
    return destination, mount_type, readonly, source, options


def _analyze_mounts(
    mounts_list: list[object],
) -> tuple[
    list[OCIPlanMount],
    list[str],  # violations codes
    bool,  # has_forbidden
    bool,  # has_hostile
]:
    """Analyze mount entries, return plan mounts and violations."""
    plan_mounts: list[OCIPlanMount] = []
    violations: list[str] = []
    has_forbidden = False
    has_hostile = False

    for raw_mount in mounts_list:
        mount = _object_map(raw_mount)
        if mount is None:
            violations.append("mount:not-object")
            continue
        dst, typ, readonly, src, options = _classify_mount(mount)

        # Skip rootfs mount (destination=/, no source)
        if dst == "/" and (typ == "" or typ == "none"):
            classification = "system"
            plan_mounts.append(
                OCIPlanMount(
                    container_path=dst,
                    mount_type=typ or "none",
                    readonly=readonly,
                    source="",
                    options=tuple(options),
                    classification=classification,
                )
            )
            continue

        # Host bind mount detection
        if typ == "bind" or (not typ and src and (src.startswith("/") or src.startswith("./"))):
            forbidden_match = _is_forbidden_path(src)
            socket_match = _is_forbidden_socket(src)
            guard_match = _is_guard_state_path(dst)

            if forbidden_match:
                violations.append(f"forbidden-mount-source:{forbidden_match}")
                has_forbidden = True
                has_hostile = True
                classification = "forbidden"
            elif socket_match:
                violations.append(f"forbidden-socket:{socket_match}")
                has_hostile = True
                classification = "forbidden"
            elif guard_match:
                violations.append("guard-state-mount")
                has_hostile = True
                classification = "forbidden"
            else:
                # Classify as secret or output or host
                secret_keywords = frozenset({".env", ".ssh", "secret", "credential", "private", "token"})
                output_keywords = frozenset({".hol-guard", "guard", "output", "result", "report"})
                if secret_keywords & set(PurePosixPath(dst).parts):
                    classification = "secret"
                elif output_keywords & set(PurePosixPath(dst).parts):
                    classification = "output"
                else:
                    classification = "host"

                # Check for world-writable
                for opt in options:
                    if opt in _WORLD_WRITABLE_OPTIONS:
                        violations.append(f"world-writable-mount:{dst}")
                        break

        else:
            # Volume or tmpfs mount
            classification = "system" if typ in ("volume", "tmpfs", "none") else "unclassified"

        plan_mounts.append(
            OCIPlanMount(
                container_path=dst,
                mount_type=typ or "unknown",
                readonly=readonly,
                source=src,
                options=tuple(options),
                classification=classification,
            )
        )

    return plan_mounts, violations, has_forbidden, has_hostile


# --- Capability analysis ---


def _analyze_capabilities(
    caps_spec: dict[str, object] | None,
) -> tuple[
    list[str],  # all capabilities
    list[str],  # dangerous
    bool,  # has_dangerous
]:
    """Analyze capabilities from spec."""
    if not caps_spec:
        return [], [], False

    all_caps, dangerous = _extract_all_capabilities(caps_spec)
    return all_caps, dangerous, len(dangerous) > 0


# --- LSM analysis ---


def _analyze_lsm(spec: dict[str, object]) -> tuple[bool, str]:
    """Analyze LSM configuration. Returns (enabled, profile_name)."""
    apparmor = spec.get("apparmor")
    selinux = _object_map(spec.get("selinux"))
    if isinstance(apparmor, str) and apparmor:
        return True, apparmor
    if selinux:
        raw_label = selinux.get("label")
        return True, raw_label if isinstance(raw_label, str) else ""
    return False, ""


# --- Cgroup analysis ---


def _analyze_cgroup(spec: dict[str, object]) -> tuple[bool, str]:
    """Analyze cgroup configuration. Returns (v2, path)."""
    cgroups_path = spec.get("cgroupsPath")
    path = cgroups_path if isinstance(cgroups_path, str) else ""
    v2 = path.startswith("/sys/fs/cgroup/unified")
    return v2, path


def _analyze_seccomp(linux_spec: dict[str, object]) -> tuple[str, bool]:
    """Analyze seccomp profile. Returns (kind, enforced)."""
    seccomp = _object_map(linux_spec.get("seccomp"))
    if seccomp is None:
        return "unset", False
    raw_action = seccomp.get("defaultAction")
    default_action = raw_action.upper() if isinstance(raw_action, str) else ""
    strict = seccomp.get("strict") is True
    if strict or default_action == "SCMP_ACT_ERRNO":
        return "strict", True
    if default_action == "SCMP_ACT_ALLOW":
        return "none", False
    if isinstance(seccomp.get("path"), str) and seccomp.get("path"):
        return "custom", True
    return "none", False


# --- User analysis ---


def _analyze_user(process_spec: dict[str, object]) -> tuple[int, int, bool]:
    """Analyze user configuration. Returns (uid, gid, non_root)."""
    user = _object_map(process_spec.get("user"))
    if user is None:
        return 0, 0, False
    raw_uid = user.get("uid")
    raw_gid = user.get("gid")
    uid = raw_uid if isinstance(raw_uid, int) else 0
    gid = raw_gid if isinstance(raw_gid, int) else 0
    return uid, gid, uid != 0


# --- Network analysis ---


def _analyze_network(
    linux_spec: dict[str, object],
    namespaces: OCIPlanNamespace,
) -> OCIPlanNetwork:
    """Analyze network configuration."""
    network_spec = _object_map(linux_spec.get("network"))
    if network_spec is None:
        return OCIPlanNetwork(
            mode="default",
            loopback_only=namespaces.net_isolated,
        )

    raw_mode = network_spec.get("mode")
    mode = raw_mode if isinstance(raw_mode, str) else "default"
    ports = _object_list(network_spec.get("ports")) or []
    port_mappings = tuple(str(port) for port in ports)

    loopback_only = mode not in _HOST_NETWORK_MODES and namespaces.net_isolated

    if mode in _HOST_NETWORK_MODES:
        loopback_only = False

    return OCIPlanNetwork(
        mode=mode,
        port_mappings=port_mappings,
        loopback_only=loopback_only,
    )


# --- Rootfs analysis ---


def _analyze_rootfs(rootfs_spec: dict[str, object]) -> tuple[str, bool]:
    """Analyze rootfs. Returns (path, readonly)."""
    raw_path = rootfs_spec.get("path")
    raw_readonly = rootfs_spec.get("readonly")
    path = raw_path if isinstance(raw_path, str) else ""
    readonly = raw_readonly if isinstance(raw_readonly, bool) else False
    return path, readonly


# --- Evidence → guarantees mapping ---


def _map_guarantees(
    violations_codes: list[str],
    namespaces: OCIPlanNamespace,
    rootfs_readonly: bool,
    non_root: bool,
    network_loopback: bool,
    hostile_mounts: bool,
) -> tuple[tuple[AtomicGuarantee, ...], tuple[AtomicGuarantee, ...]]:
    """Map validated evidence to enforced and denied guarantees.

    Deny-by-default: a guarantee is enforced only when ALL relevant
    conditions are satisfied. Any violation lowers or denies it.
    """
    enforced_guarantees: list[AtomicGuarantee] = []
    denied_guarantees: list[AtomicGuarantee] = []

    # Overall: hostile inputs always deny
    is_hostile = hostile_mounts

    for kind in [
        AtomicGuaranteeKind.FILESYSTEM,
        AtomicGuaranteeKind.NETWORK,
        AtomicGuaranteeKind.PROCESS,
        AtomicGuaranteeKind.SECRET,
        AtomicGuaranteeKind.OUTPUT,
        AtomicGuaranteeKind.CLEANUP,
        AtomicGuaranteeKind.IDENTITY,
        AtomicGuaranteeKind.RESOURCE,
        AtomicGuaranteeKind.PRIVILEGE,
    ]:
        if is_hostile:
            denied_guarantees.append(
                AtomicGuarantee(
                    kind=kind,
                    enforced=False,
                    boundary=GuardExecutionAssuranceBoundary.OBSERVED_HOST,
                )
            )
            continue

        # Condition-based enforcement
        enforced = True
        reason_parts: list[str] = []

        if kind is AtomicGuaranteeKind.FILESYSTEM and not rootfs_readonly:
            enforced = False
            reason_parts.append("rootfs-not-readonly")
        if kind is AtomicGuaranteeKind.NETWORK and not network_loopback:
            enforced = False
            reason_parts.append("network-not-loopback-only")
        if kind is AtomicGuaranteeKind.PROCESS and not namespaces.pid_isolated:
            enforced = False
            reason_parts.append("pid-not-isolated")
        if kind is AtomicGuaranteeKind.SECRET and not namespaces.net_isolated:
            enforced = False
            reason_parts.append("net-not-isolated")
        if kind is AtomicGuaranteeKind.OUTPUT and not namespaces.pid_isolated:
            enforced = False
            reason_parts.append("pid-not-isolated")
        if kind is AtomicGuaranteeKind.CLEANUP and not namespaces.pid_isolated:
            enforced = False
            reason_parts.append("pid-not-isolated")
        if kind is AtomicGuaranteeKind.IDENTITY and not namespaces.net_isolated:
            enforced = False
            reason_parts.append("net-not-isolated")
        if kind is AtomicGuaranteeKind.RESOURCE and not namespaces.pid_isolated:
            enforced = False
            reason_parts.append("pid-not-isolated")
        if kind is AtomicGuaranteeKind.PRIVILEGE and (not namespaces.user_isolated or not non_root):
            enforced = False
            reason_parts.append("user-not-isolated-or-root")

        # Violations always lower
        if violations_codes:
            enforced = False
            reason_parts.append("violations-present")

        boundary = (
            GuardExecutionAssuranceBoundary.OS_ISOLATED if enforced else GuardExecutionAssuranceBoundary.OBSERVED_HOST
        )

        if enforced:
            enforced_guarantees.append(AtomicGuarantee(kind=kind, enforced=True, boundary=boundary))
        else:
            denied_guarantees.append(
                AtomicGuarantee(
                    kind=kind,
                    enforced=False,
                    boundary=GuardExecutionAssuranceBoundary.OBSERVED_HOST,
                )
            )

    # Always absent
    for kind in (
        AtomicGuaranteeKind.KERNEL_HARDWARE,
        AtomicGuaranteeKind.TENANT,
    ):
        denied_guarantees.append(
            AtomicGuarantee(
                kind=kind,
                enforced=False,
                boundary=GuardExecutionAssuranceBoundary.OBSERVED_HOST,
            )
        )

    return tuple(enforced_guarantees), tuple(denied_guarantees)


# --- Plan digest computation ---


def _plan_digest(fields: dict[str, object]) -> str:
    """Compute a deterministic plan digest."""
    return framed_digest("guard.oci-execution-plan.v1", fields)


def _build_digest_fields(
    bundle_version: str,
    minimum_boundary: GuardExecutionAssuranceBoundary,
    available_boundary: GuardExecutionAssuranceBoundary,
    namespace: OCIPlanNamespace,
    network: OCIPlanNetwork,
    seccomp_profile: str,
    seccomp_enforced: bool,
    lsm_enabled: bool,
    cgroup_v2: bool,
    rootfs_readonly: bool,
    non_root: bool,
    violations_count: int,
    forbidden_capabilities_count: int,
    mounts: tuple[OCIPlanMount, ...] = (),
    capabilities: tuple[str, ...] = (),
    rootfs_path: str = "",
) -> dict[str, object]:
    """Build deterministic field mapping for plan digest."""
    return {
        "bundle_version": bundle_version,
        "minimum_boundary": minimum_boundary.value,
        "available_boundary": available_boundary.value,
        "namespace_pid_isolated": namespace.pid_isolated,
        "namespace_net_isolated": namespace.net_isolated,
        "namespace_ipc_isolated": namespace.ipc_isolated,
        "namespace_uts_isolated": namespace.uts_isolated,
        "namespace_user_isolated": namespace.user_isolated,
        "network_mode": network.mode,
        "network_loopback_only": network.loopback_only,
        "seccomp_profile": seccomp_profile,
        "seccomp_enforced": seccomp_enforced,
        "lsm_enabled": lsm_enabled,
        "cgroup_v2": cgroup_v2,
        "rootfs_readonly": rootfs_readonly,
        "non_root": non_root,
        "violations_count": violations_count,
        "forbidden_capabilities_count": forbidden_capabilities_count,
        "mounts": tuple(
            (
                mount.container_path,
                mount.mount_type,
                mount.readonly,
                mount.source,
                mount.options,
                mount.classification,
            )
            for mount in mounts
        ),
        "capabilities": capabilities,
        "rootfs_path": rootfs_path,
    }


# --- Plan generator ---


class OCIPlanGenerator:
    """Generate deterministic execution plans from OCI bundle specs.

    Does NOT execute any workspace code. Validates the spec and
    produces deny-by-default guarantees.
    """

    @staticmethod
    def generate(
        context: object,
        minimum_boundary: GuardExecutionAssuranceBoundary,
        bundle: object = None,
        rootfs: dict[str, object] | None = None,
        process: dict[str, object] | None = None,
        linux: dict[str, object] | None = None,
    ) -> OCIExecutionPlan:
        """Generate an execution plan from an OCI bundle spec.

        Args:
            context: The decision context.
            minimum_boundary: Desired minimum isolation boundary.
            bundle: OCI bundle spec dict (``bundle.json`` contents).
            rootfs: Optional rootfs override.
            process: Optional process override.
            linux: Optional linux spec override.

        Returns:
            A fully validated ``OCIExecutionPlan``.

        Raises:
            ProviderPlanError: On malformed spec or hostile inputs.
        """
        if not isinstance(context, DecisionContext):
            raise ProviderPlanError("context must be a DecisionContext")

        bundle_map = _object_map(bundle)
        if bundle_map is None:
            raise ProviderPlanError("bundle must be a dict")
        bundle = bundle_map
        rootfs = rootfs or _object_map(bundle.get("root")) or {}
        process = process or _object_map(bundle.get("process")) or {}
        linux = linux or _object_map(bundle.get("linux")) or {}

        # --- Extract bundle version ---
        version = bundle.get("ociVersion", "0.0.0")
        if not isinstance(version, str):
            version = str(version)

        # --- Validate bundle has required fields ---
        if "ociVersion" not in bundle:
            raise ProviderPlanError("malformed OCI spec: missing ociVersion")

        # --- Analyze mounts ---
        mounts_list = _object_list(bundle.get("mounts")) or []
        plan_mounts, mount_violations, has_forbidden_mounts, has_hostile_mounts = _analyze_mounts(mounts_list)

        # --- Analyze capabilities ---
        caps_spec = _object_map(linux.get("capabilities")) or {}
        all_caps, dangerous_caps, has_dangerous_caps = _analyze_capabilities(caps_spec)

        # --- Reject dangerous capabilities ---
        if has_dangerous_caps:
            raise ProviderPlanError("refusing plan: dangerous capabilities " + ", ".join(dangerous_caps))

        # --- Reject forbidden host mounts ---
        if has_forbidden_mounts:
            raise ProviderPlanError("refusing plan: forbidden host mounts")

        # --- Reject hostile mounts ---
        if has_hostile_mounts:
            raise ProviderPlanError("refusing plan: hostile mount configuration")

        # --- Analyze namespaces ---
        ns_list = _object_list(linux.get("namespaces")) or []
        namespace = _parse_namespaces(ns_list)

        # --- Analyze network ---
        network = _analyze_network(linux or {}, namespace)

        # --- Analyze seccomp ---
        seccomp_profile, seccomp_enforced = _analyze_seccomp(linux or {})

        # --- Analyze LSM ---
        lsm_enabled, lsm_profile = _analyze_lsm(linux or {})

        # --- Analyze cgroup ---
        cgroup_v2, cgroup_path = _analyze_cgroup(linux or {})

        # --- Analyze rootfs ---
        rootfs_path, rootfs_readonly = _analyze_rootfs(rootfs or {})

        # --- Analyze user ---
        _, _, non_root = _analyze_user(process)

        # --- Collect all violations ---
        all_violations_codes = list(mount_violations)

        # Namespace host violations
        if namespace.host_namespaces:
            for ns in namespace.host_namespaces:
                all_violations_codes.append(f"host-namespace:{ns}")

        # Network violations
        if network.mode in _HOST_NETWORK_MODES:
            all_violations_codes.append("host-network-mode")

        # Seccomp violation
        if seccomp_profile == "none":
            all_violations_codes.append("seccomp-none")

        if not seccomp_enforced:
            all_violations_codes.append("seccomp-not-enforced")
        all_violations_codes.extend(
            f"unsupported-linux-field:{key}" for key in sorted(set(linux) - _KNOWN_LINUX_FIELDS)
        )
        # --- Compute guaranteed boundary ---
        violations_present = len(all_violations_codes) > 0

        boundary_lowered = (
            violations_present
            or not namespace.pid_isolated
            or not namespace.net_isolated
            or not rootfs_readonly
            or not seccomp_enforced
        )

        available_boundary = (
            GuardExecutionAssuranceBoundary.OS_ISOLATED
            if not boundary_lowered
            else GuardExecutionAssuranceBoundary.OBSERVED_HOST
        )

        # Reject if minimum boundary not achievable
        if minimum_boundary is GuardExecutionAssuranceBoundary.HARDWARE_ISOLATED:
            raise ProviderPlanError("OCI bundle isolation cannot provide hardware isolation")

        if minimum_boundary is GuardExecutionAssuranceBoundary.OS_ISOLATED and (
            not namespace.pid_isolated
            or not namespace.net_isolated
            or not rootfs_readonly
            or not seccomp_enforced
            or violations_present
        ):
            raise ProviderPlanError(f"required boundary {minimum_boundary.value} not achievable")

        if minimum_boundary is GuardExecutionAssuranceBoundary.CONTROLLED_HOST and (
            not rootfs_readonly or violations_present
        ):
            raise ProviderPlanError(f"required boundary {minimum_boundary.value} not achievable")

        # --- Map to guarantees ---
        enforced, denied = _map_guarantees(
            all_violations_codes,
            namespace,
            rootfs_readonly,
            non_root,
            network.loopback_only,
            has_hostile_mounts,
        )

        # --- Build violations list ---
        violation_entries: list[OCIPlanViolation] = []
        for code in sorted(set(all_violations_codes)):
            severity = "refuse" if code.startswith(("host-namespace:", "forbidden-")) else "lower"
            description = code.replace(":", " - ")
            violation_entries.append(OCIPlanViolation(code=code, description=description, severity=severity))

        # --- Compute deterministic plan digest ---
        digest_fields = _build_digest_fields(
            bundle_version=version,
            minimum_boundary=minimum_boundary,
            available_boundary=available_boundary,
            namespace=namespace,
            network=network,
            seccomp_profile=seccomp_profile,
            seccomp_enforced=seccomp_enforced,
            lsm_enabled=lsm_enabled,
            cgroup_v2=cgroup_v2,
            rootfs_readonly=rootfs_readonly,
            non_root=non_root,
            violations_count=len(all_violations_codes),
            forbidden_capabilities_count=len(dangerous_caps),
            mounts=tuple(plan_mounts),
            capabilities=tuple(all_caps),
            rootfs_path=rootfs_path,
        )
        plan_digest = _plan_digest(digest_fields)

        # --- Build input/output structures ---
        inputs: list[OCIPlanInput] = []
        outputs: list[OCIPlanOutput] = []
        secrets: list[OCIPlanSecret] = []

        for pm in plan_mounts:
            if pm.classification == "secret":
                secrets.append(
                    OCIPlanSecret(
                        container_path=pm.container_path,
                        secret_handle=f"secret:{pm.container_path}",
                        readonly=True,
                    )
                )
            elif pm.classification == "host":
                inputs.append(
                    OCIPlanInput(
                        path=pm.container_path,
                        source=pm.source,
                        readonly=pm.readonly,
                        mount_type=pm.mount_type,
                    )
                )
            elif pm.classification == "output":
                outputs.append(
                    OCIPlanOutput(
                        path=pm.container_path,
                        source=pm.source,
                    )
                )

        # --- Build plan ---
        return OCIExecutionPlan(
            plan_digest=plan_digest,
            bundle_version=version,
            minimum_boundary=minimum_boundary,
            available_boundary=available_boundary,
            boundary_lowered=boundary_lowered,
            inputs=tuple(inputs),
            outputs=tuple(outputs),
            secrets=tuple(secrets),
            mounts=tuple(plan_mounts),
            network=network,
            namespaces=namespace,
            capabilities=tuple(all_caps),
            forbidden_capabilities=tuple(dangerous_caps),
            seccomp_profile=seccomp_profile,
            seccomp_enforced=seccomp_enforced,
            lsm_enabled=lsm_enabled,
            lsm_profile=lsm_profile,
            cgroup_v2=cgroup_v2,
            cgroup_path=cgroup_path,
            rootfs_path=rootfs_path,
            rootfs_readonly=rootfs_readonly,
            non_root=non_root,
            violations=tuple(violation_entries),
            enforced_guarantees=enforced,
            denied_guarantees=denied,
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


__all__ = [
    "OCIExecutionPlan",
    "OCIGuaranteeEntry",
    "OCIPlanGenerator",
    "OCIPlanInput",
    "OCIPlanMount",
    "OCIPlanNamespace",
    "OCIPlanNetwork",
    "OCIPlanOutput",
    "OCIPlanSecret",
    "OCIPlanViolation",
]
