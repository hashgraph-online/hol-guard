//! OCI bundle mount and network evidence (`oci_isolation_provider.py`
//! `_read_mounts` and `_read_network`), split from the bundle reader.

use serde_json::Value;

use super::cloud_request_text::is_py_int;
use super::oci_bundle_evidence::{
    string_list, LinuxEvidence, MountEvidence, NetworkEvidence, HOST_NETWORK_MODES,
};
use super::oci_path::{
    is_host_path_mount, match_forbidden, normalize_bind_source, resolve_bind_source,
    FORBIDDEN_BIND_SOURCES,
};
use super::runner_authority_op::ERR_INVALID;

const WORLD_WRITABLE_OPTIONS: [&str; 3] = ["world-writable", "world_writable", "o+w"];
const SECRET_KEYWORDS: [&str; 6] = [".env", ".ssh", "secret", "credential", "private", "token"];
const OUTPUT_KEYWORDS: [&str; 5] = [".hol-guard", "guard", "output", "result", "report"];

/// Path components that matter for classification (`PurePosixPath.parts`).
fn has_keyword(destination: &str, keywords: &[&str]) -> bool {
    destination
        .split('/')
        .any(|part| !part.is_empty() && part != "." && keywords.contains(&part))
}

pub(super) fn read_mounts(mounts: &[Value], bundle_root: Option<&str>) -> MountEvidence {
    let mut evidence = MountEvidence::default();
    for raw in mounts {
        let Some(mount) = raw.as_object() else {
            continue;
        };
        let text = |key: &str| {
            mount
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let (source, destination, kind) = (text("source"), text("destination"), text("type"));
        let options = match mount.get("options") {
            Some(Value::String(single)) => vec![single.clone()],
            other => string_list(other),
        };
        let is_bind = is_host_path_mount(&kind, &options, &source);
        if is_bind && source.is_empty() {
            evidence
                .forbidden_bind_sources
                .push("<empty-bind-source>".to_owned());
            continue;
        }
        if !is_bind && source.is_empty() && destination == "/" {
            if options
                .iter()
                .any(|option| option == "readonly" || option == "ro")
            {
                evidence.readonly_rootfs = true;
            }
            continue;
        }
        if !is_bind {
            continue;
        }
        let (normalized, escapes) = normalize_bind_source(&source);
        let mut resolved = normalized.clone();
        let verified = match resolve_bind_source(&source, bundle_root) {
            Ok(found) => {
                resolved = found;
                evidence.resolved_bind_sources.push(resolved.clone());
                true
            }
            Err(_) => false,
        };
        let forbidden = escapes
            || [&normalized, &resolved]
                .iter()
                .any(|candidate| match_forbidden(candidate, &FORBIDDEN_BIND_SOURCES).is_some());
        if forbidden {
            evidence.forbidden_bind_sources.push(source.clone());
        } else if options
            .iter()
            .any(|option| WORLD_WRITABLE_OPTIONS.contains(&option.as_str()))
        {
            evidence.world_writable_binds.push(destination.clone());
        }
        if !verified {
            evidence.unverified_bind_sources.push(source);
        }
        if has_keyword(&destination, &SECRET_KEYWORDS) {
            evidence.secret_mounts.push(destination);
        } else if has_keyword(&destination, &OUTPUT_KEYWORDS) {
            evidence.output_mounts.push(destination);
        } else {
            evidence.host_bind_mounts.push(destination);
        }
    }
    evidence
}

/// `str(port)` for a scalar port entry; containers are refused.
fn port_text(port: &Value) -> Result<String, &'static str> {
    match port {
        Value::String(text) => Ok(text.clone()),
        Value::Bool(flag) => Ok(if *flag { "True" } else { "False" }.to_owned()),
        Value::Null => Ok("None".to_owned()),
        Value::Number(number) => {
            let text = number.to_string();
            if is_py_int(port) {
                return Ok(text);
            }
            let float: f64 = text.parse().map_err(|_| ERR_INVALID)?;
            Ok(guard_contracts::python_float_repr(float))
        }
        Value::Array(_) | Value::Object(_) => Err(ERR_INVALID),
    }
}

pub(super) fn read_network(linux: &LinuxEvidence) -> Result<NetworkEvidence, &'static str> {
    let mut network = NetworkEvidence {
        loopback_only: linux.namespaces.net_isolated,
        ..NetworkEvidence::default()
    };
    let Some(spec) = linux.network_spec.as_ref().and_then(Value::as_object) else {
        return Ok(network);
    };
    network.mode = spec
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("default")
        .to_owned();
    if let Some(ports) = spec.get("ports").and_then(Value::as_array) {
        network.port_mappings = ports.iter().map(port_text).collect::<Result<_, _>>()?;
    }
    if HOST_NETWORK_MODES.contains(&network.mode.as_str()) {
        network.loopback_only = false;
    }
    Ok(network)
}
