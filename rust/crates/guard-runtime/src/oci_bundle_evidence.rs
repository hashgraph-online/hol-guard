//! OCI bundle evidence (`oci_isolation_provider.py` `_build_evidence` and its
//! `_read_*` helpers): isolation-relevant facts read conservatively from a
//! runtime-spec bundle. Unrecognised fields are ignored (deny-by-default).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::cloud_request_text::{is_py_int, py_truthy};
use super::oci_bundle_mounts::{read_mounts, read_network};
use super::oci_path::{resolve_bundle_path, ROOTFS_LABEL};

pub(super) const HOST_NETWORK_MODES: [&str; 3] = ["host", "host.network", "HostNetwork"];
const DANGEROUS_CAPABILITIES: [&str; 6] = [
    "CAP_SYS_ADMIN",
    "SYS_ADMIN",
    "CAP_SYS_PTRACE",
    "SYS_PTRACE",
    "CAP_NET_ADMIN",
    "NET_ADMIN",
];
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn zero_digest() -> String {
    ZERO_DIGEST.to_owned()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct SeccompEvidence {
    pub profile_kind: String,
    pub profile_json_digest: String,
}

impl Default for SeccompEvidence {
    fn default() -> Self {
        Self {
            profile_kind: "unset".to_owned(),
            profile_json_digest: zero_digest(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct LsmEvidence {
    pub enabled: bool,
    pub profile_name: String,
    pub profile_verified: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct CgroupEvidence {
    pub v2: bool,
    pub path: String,
    pub controller_bound: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct NamespaceEvidence {
    pub pid_isolated: bool,
    pub net_isolated: bool,
    pub ipc_isolated: bool,
    pub uts_isolated: bool,
    pub user_isolated: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct MountEvidence {
    pub readonly_rootfs: bool,
    pub host_bind_mounts: Vec<String>,
    pub secret_mounts: Vec<String>,
    pub output_mounts: Vec<String>,
    pub forbidden_bind_sources: Vec<String>,
    pub unverified_bind_sources: Vec<String>,
    pub resolved_bind_sources: Vec<String>,
    pub world_writable_binds: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct NetworkEvidence {
    pub mode: String,
    pub port_mappings: Vec<String>,
    pub loopback_only: bool,
}

impl Default for NetworkEvidence {
    fn default() -> Self {
        Self {
            mode: "default".to_owned(),
            port_mappings: Vec::new(),
            loopback_only: false,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct CapabilityEvidence {
    pub effective: Vec<String>,
    pub permitted: Vec<String>,
    pub ambient: Vec<String>,
    pub bounding_set: Vec<String>,
    pub dangerous_capabilities: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct RootfsEvidence {
    pub path: String,
    pub readonly: bool,
    pub absolute: bool,
    pub containment_verified: bool,
    pub resolved_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct UserEvidence {
    pub uid: Value,
    pub gid: Value,
    pub non_root: bool,
}

impl Default for UserEvidence {
    fn default() -> Self {
        Self {
            uid: Value::from(0),
            gid: Value::from(0),
            non_root: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct BundleEvidence {
    pub bundle_version: String,
    pub bundle_valid: bool,
    pub binary_digest: String,
    pub binary_verified: bool,
    pub seccomp: SeccompEvidence,
    pub lsm: LsmEvidence,
    pub cgroup: CgroupEvidence,
    pub namespaces: NamespaceEvidence,
    pub mounts: MountEvidence,
    pub network: NetworkEvidence,
    pub capabilities: CapabilityEvidence,
    pub rootfs: RootfsEvidence,
    pub user: UserEvidence,
}

impl Default for BundleEvidence {
    fn default() -> Self {
        Self {
            bundle_version: "1.0.0".to_owned(),
            bundle_valid: false,
            binary_digest: zero_digest(),
            binary_verified: false,
            seccomp: SeccompEvidence::default(),
            lsm: LsmEvidence::default(),
            cgroup: CgroupEvidence::default(),
            namespaces: NamespaceEvidence::default(),
            mounts: MountEvidence::default(),
            network: NetworkEvidence::default(),
            capabilities: CapabilityEvidence::default(),
            rootfs: RootfsEvidence::default(),
            user: UserEvidence::default(),
        }
    }
}

/// The spec dicts and authoritative root one evidence build reads.
pub(super) struct Sources<'a> {
    pub bundle: &'a Map<String, Value>,
    pub rootfs: Option<&'a Value>,
    pub process: Option<&'a Value>,
    pub linux: Option<&'a Value>,
    pub bundle_root: Option<&'a str>,
}

/// `object_map(value) or {}`.
fn map_or_empty<'a>(
    value: Option<&'a Value>,
    empty: &'a Map<String, Value>,
) -> &'a Map<String, Value> {
    value.and_then(Value::as_object).unwrap_or(empty)
}

/// `payload_coercion.string_tuple`.
pub(super) fn string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn present(value: Option<&Value>) -> Option<&Value> {
    value.filter(|candidate| !candidate.is_null())
}

fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn read_rootfs(spec: &Map<String, Value>, bundle_root: Option<&str>) -> RootfsEvidence {
    let path = spec
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let readonly = spec.get("readonly") == Some(&Value::Bool(true));
    let resolved = resolve_bundle_path(&path, bundle_root, ROOTFS_LABEL, true);
    RootfsEvidence {
        absolute: path.starts_with('/'),
        readonly,
        containment_verified: resolved.is_ok(),
        resolved_path: resolved.unwrap_or_default(),
        path,
    }
}

/// `isinstance(value, int)`: the value itself (a bool stays a bool).
fn py_int(value: Option<&Value>) -> Option<Value> {
    value.filter(|candidate| is_py_int(candidate)).cloned()
}

fn is_zero(value: &Value) -> bool {
    match value {
        Value::Bool(flag) => !flag,
        other => other
            .to_string()
            .trim_start_matches('-')
            .bytes()
            .all(|byte| byte == b'0'),
    }
}

fn read_process(spec: &Map<String, Value>) -> UserEvidence {
    let mut user = UserEvidence::default();
    if let Some(map) = spec.get("user").and_then(Value::as_object) {
        if let Some(uid) = py_int(map.get("uid")) {
            user.uid = uid;
        }
        if let Some(gid) = py_int(map.get("gid")) {
            user.gid = gid;
        }
    }
    user.non_root = !is_zero(&user.uid);
    user
}

pub(super) struct LinuxEvidence {
    seccomp: SeccompEvidence,
    lsm: LsmEvidence,
    cgroup: CgroupEvidence,
    pub(super) namespaces: NamespaceEvidence,
    capabilities: CapabilityEvidence,
    pub(super) network_spec: Option<Value>,
}

fn read_seccomp(spec: &Map<String, Value>) -> SeccompEvidence {
    let mut seccomp = SeccompEvidence::default();
    let Some(map) = spec.get("seccomp").and_then(Value::as_object) else {
        return seccomp;
    };
    let action = map.get("defaultAction");
    let rule = action
        .and_then(Value::as_str)
        .map(str::to_uppercase)
        .unwrap_or_default();
    let action_blank = match action {
        None | Some(Value::Null) => true,
        Some(Value::String(text)) => text.is_empty(),
        Some(_) => false,
    };
    seccomp.profile_kind =
        if rule == "SCMP_ACT_ERRNO" || map.get("strict") == Some(&Value::Bool(true)) {
            "strict"
        } else if rule == "SCMP_ACT_ALLOW" {
            "default"
        } else if action_blank {
            "none"
        } else {
            "custom"
        }
        .to_owned();
    if let Some(path) = map
        .get("path")
        .and_then(Value::as_str)
        .filter(|p| !p.is_empty())
    {
        seccomp.profile_json_digest = sha256_hex(path);
    }
    seccomp
}

fn read_lsm(spec: &Map<String, Value>) -> LsmEvidence {
    let mut lsm = LsmEvidence::default();
    if let Some(profile) = spec
        .get("apparmor")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
    {
        lsm.enabled = true;
        lsm.profile_name = profile.to_owned();
    }
    if let Some(selinux) = spec
        .get("selinux")
        .and_then(Value::as_object)
        .filter(|map| !map.is_empty())
    {
        lsm.enabled = true;
        lsm.profile_name = selinux
            .get("label")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
    }
    lsm
}

fn read_namespaces(spec: &Map<String, Value>) -> NamespaceEvidence {
    let mut namespaces = NamespaceEvidence::default();
    let mut any_shared = false;
    for entry in spec
        .get("namespaces")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let Some(map) = entry.as_object() else {
            continue;
        };
        let kind = map
            .get("type")
            .and_then(Value::as_str)
            .map(str::to_lowercase)
            .unwrap_or_default();
        // An OCI namespace `path` joins an existing namespace: it is shared.
        let shared = map.get("host") == Some(&Value::Bool(true))
            || map
                .get("path")
                .and_then(Value::as_str)
                .is_some_and(|path| !path.is_empty());
        any_shared |= shared;
        if shared {
            continue;
        }
        match kind.as_str() {
            "pid" => namespaces.pid_isolated = true,
            "net" => namespaces.net_isolated = true,
            "ipc" => namespaces.ipc_isolated = true,
            "uts" => namespaces.uts_isolated = true,
            "user" => namespaces.user_isolated = true,
            _ => {}
        }
    }
    if any_shared {
        return NamespaceEvidence::default();
    }
    namespaces
}

fn read_capabilities(spec: &Map<String, Value>) -> CapabilityEvidence {
    let empty = Map::new();
    let map = map_or_empty(spec.get("capabilities"), &empty);
    let effective = string_list(map.get("effective"));
    let permitted = string_list(map.get("permitted"));
    let ambient = string_list(map.get("ambient"));
    let bounding_set = string_list(map.get("bounding"));
    let mut all: Vec<&String> = effective
        .iter()
        .chain(&permitted)
        .chain(&ambient)
        .chain(&bounding_set)
        .collect();
    all.sort_unstable();
    all.dedup();
    let dangerous_capabilities = all
        .into_iter()
        .filter(|capability| DANGEROUS_CAPABILITIES.contains(&capability.to_uppercase().as_str()))
        .cloned()
        .collect();
    CapabilityEvidence {
        effective,
        permitted,
        ambient,
        bounding_set,
        dangerous_capabilities,
    }
}

fn read_linux(spec: &Map<String, Value>) -> LinuxEvidence {
    let cgroup_path = spec.get("cgroupsPath");
    let cgroup_text = cgroup_path.and_then(Value::as_str);
    LinuxEvidence {
        seccomp: read_seccomp(spec),
        lsm: read_lsm(spec),
        cgroup: CgroupEvidence {
            v2: cgroup_text.is_some_and(|path| path.starts_with("/sys/fs/cgroup/unified")),
            path: cgroup_text.unwrap_or_default().to_owned(),
            controller_bound: cgroup_path.is_some_and(py_truthy),
        },
        namespaces: read_namespaces(spec),
        capabilities: read_capabilities(spec),
        network_spec: spec.get("network").cloned(),
    }
}

/// `_build_evidence`.
pub(super) fn build_evidence(sources: &Sources<'_>) -> Result<BundleEvidence, &'static str> {
    let empty = Map::new();
    let version = sources
        .bundle
        .get("ociVersion")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .unwrap_or("0.0.0");
    let rootfs_source = present(sources.rootfs).or_else(|| sources.bundle.get("root"));
    let rootfs = read_rootfs(map_or_empty(rootfs_source, &empty), sources.bundle_root);
    let process_source = present(sources.process).or_else(|| sources.bundle.get("process"));
    let user = read_process(map_or_empty(process_source, &empty));
    let linux_source = present(sources.linux).or_else(|| sources.bundle.get("linux"));
    let linux = read_linux(map_or_empty(linux_source, &empty));
    let mounts = read_mounts(
        sources
            .bundle
            .get("mounts")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default(),
        sources.bundle_root,
    );
    let network = read_network(&linux)?;
    Ok(BundleEvidence {
        bundle_version: version.to_owned(),
        bundle_valid: version != "0.0.0",
        binary_digest: sources
            .bundle
            .get("_binary_digest")
            .and_then(Value::as_str)
            .map_or_else(zero_digest, str::to_owned),
        binary_verified: false,
        seccomp: linux.seccomp,
        lsm: linux.lsm,
        cgroup: linux.cgroup,
        namespaces: linux.namespaces,
        mounts,
        network,
        capabilities: linux.capabilities,
        rootfs,
        user,
    })
}
