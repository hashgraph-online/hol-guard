//! `runner_authority` kinds for the OCI isolation provider
//! (`oci_isolation_provider.py`): bundle evidence, the violation and
//! guarantee verdict, the bundle-spec digest and the side-effect-free plan
//! digest. A refusal the provider raised as `ProviderPlanError` is returned
//! as a `refusal` message, never as an allow.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::oci_bundle_evidence::{build_evidence, BundleEvidence, Sources, HOST_NETWORK_MODES};
use super::oci_path::{require_bundle_relative, ROOTFS_LABEL};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const RECOGNISED_KEYS: [&str; 6] = [
    "ociVersion",
    "root",
    "process",
    "mounts",
    "linux",
    "hostname",
];
const ENFORCED_KINDS: [&str; 9] = [
    "filesystem",
    "network",
    "process",
    "secret",
    "output",
    "cleanup",
    "identity",
    "resource",
    "privilege",
];
const ABSENT_KINDS: [&str; 2] = ["kernel_hardware", "tenant"];
const OS_ISOLATED: &str = "os_isolated";
const OBSERVED_HOST: &str = "observed_host";

fn host_network(evidence: &BundleEvidence) -> bool {
    HOST_NETWORK_MODES.contains(&evidence.network.mode.as_str())
}

/// `_validate_bundle`: every reason the bundle cannot claim isolation.
fn validate_bundle(evidence: &BundleEvidence) -> Vec<String> {
    let mut violations = Vec::new();
    if !evidence.bundle_valid {
        violations.push("bundle invalid".to_owned());
    }
    if matches!(evidence.seccomp.profile_kind.as_str(), "unset" | "none") {
        violations.push("seccomp profile unset or none".to_owned());
    }
    violations.extend(evidence.mounts.forbidden_bind_sources.iter().cloned());
    violations.extend(
        evidence
            .mounts
            .unverified_bind_sources
            .iter()
            .map(|source| format!("unverified bind source: {source}")),
    );
    violations.extend(evidence.mounts.world_writable_binds.iter().cloned());
    if !evidence.rootfs.containment_verified {
        violations.push("rootfs containment is unverified".to_owned());
    }
    violations.extend(evidence.capabilities.dangerous_capabilities.iter().cloned());
    if host_network(evidence) {
        violations.push("host network mode".to_owned());
    }
    if !evidence.namespaces.pid_isolated {
        violations.push("pid namespace not isolated".to_owned());
    }
    if !evidence.namespaces.net_isolated {
        violations.push("net namespace not isolated".to_owned());
    }
    if !evidence.user.non_root {
        violations.push("running as root (uid=0)".to_owned());
    }
    violations
}

fn guarantee(kind: &str, enforced: bool, boundary: &str) -> Value {
    json!({"kind": kind, "enforced": enforced, "boundary": boundary, "evidence_refs": []})
}

/// `_map_guarantees`: deny-by-default. Hostile evidence is refused outright;
/// any violation lowers every enforceable guarantee to the observed host.
fn map_guarantees(evidence: &BundleEvidence, violations: &[String]) -> Vec<Value> {
    let hostile = !evidence.capabilities.dangerous_capabilities.is_empty()
        || !evidence.mounts.forbidden_bind_sources.is_empty()
        || host_network(evidence);
    let enforced = !hostile && violations.is_empty();
    let boundary = if enforced { OS_ISOLATED } else { OBSERVED_HOST };
    ENFORCED_KINDS
        .iter()
        .map(|kind| guarantee(kind, enforced, boundary))
        .chain(
            ABSENT_KINDS
                .iter()
                .map(|kind| guarantee(kind, false, OBSERVED_HOST)),
        )
        .collect()
}

/// `framed_digest`: sha256 over length-prefixed domain, keys and canonical
/// JSON values, keys in sorted order.
pub(super) fn framed_digest(
    domain: &str,
    fields: &Map<String, Value>,
) -> Result<String, &'static str> {
    let mut frame = Vec::new();
    let mut push = |bytes: &[u8]| {
        frame.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        frame.extend_from_slice(bytes);
    };
    push(domain.as_bytes());
    for (key, value) in fields {
        push(key.as_bytes());
        let mut encoded = Vec::new();
        guard_contracts::write_canonical_json(value, &mut encoded).map_err(|_| ERR_INVALID)?;
        push(&encoded);
    }
    Ok(hex::encode(Sha256::digest(&frame)))
}

/// `_compute_bundle_digest`: only recognised keys contribute.
fn bundle_digest(spec: &Map<String, Value>) -> Result<String, &'static str> {
    let filtered: Map<String, Value> = spec
        .iter()
        .filter(|(key, _)| RECOGNISED_KEYS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    framed_digest("guard.oci-bundle-spec.v1", &filtered)
}

fn evidence_value(evidence: &BundleEvidence) -> Result<Value, &'static str> {
    serde_json::to_value(evidence).map_err(|_| ERR_INVALID)
}

fn sources_from<'a>(args: &'a Map<String, Value>, bundle: &'a Map<String, Value>) -> Sources<'a> {
    Sources {
        bundle,
        rootfs: args.get("rootfs"),
        process: args.get("process"),
        linux: args.get("linux"),
        bundle_root: args.get("bundle_root").and_then(Value::as_str),
    }
}

fn bundle_arg(args: &Map<String, Value>) -> Result<&Map<String, Value>, &'static str> {
    args.get("bundle")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)
}

/// `build_oci_evidence`.
pub(crate) fn oci_bundle_evidence(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let evidence = build_evidence(&sources_from(args, bundle_arg(args)?))?;
    Ok(json!({"evidence": evidence_value(&evidence)?}))
}

/// `_validate_bundle` and `_map_guarantees` over supplied evidence; an
/// explicit `violations` list overrides the computed one.
pub(crate) fn oci_evidence_verdict(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let evidence: BundleEvidence =
        serde_json::from_value(args.get("evidence").cloned().ok_or(ERR_INVALID)?)
            .map_err(|_| ERR_INVALID)?;
    let violations = match args.get("violations") {
        None | Some(Value::Null) => validate_bundle(&evidence),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned).ok_or(ERR_INVALID))
            .collect::<Result<_, _>>()?,
        Some(_) => return Err(ERR_INVALID),
    };
    let guarantees = map_guarantees(&evidence, &violations);
    Ok(json!({"violations": violations, "guarantees": guarantees}))
}

/// `_compute_bundle_digest`.
pub(crate) fn oci_bundle_digest(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let spec = args
        .get("spec")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    Ok(json!({"digest": bundle_digest(spec)?}))
}

fn refusal(message: impl Into<String>) -> KindResult {
    Ok(json!({"refusal": message.into()}))
}

/// `OCIIsolationProvider.plan` after the caller-side context, input-path and
/// boundary checks: evidence, refusals and the deterministic plan digest.
pub(crate) fn oci_bundle_plan(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let bundle = bundle_arg(args)?;
    let minimum = args
        .get("minimum_boundary")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let context_digest = args
        .get("context_digest")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let os_isolated = minimum == OS_ISOLATED;
    if !matches!(bundle.get("hooks"), None | Some(Value::Null))
        && bundle.get("hooks") != Some(&Value::Object(Map::new()))
    {
        return refusal("OCI lifecycle hooks are unsupported");
    }
    let selected = match args.get("rootfs").filter(|value| !value.is_null()) {
        Some(value) => Some(value),
        None => bundle.get("root"),
    };
    if let Some(rootfs) = selected
        .and_then(Value::as_object)
        .filter(|map| !map.is_empty())
    {
        let path = rootfs
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if let Err(message) = require_bundle_relative(path, ROOTFS_LABEL) {
            if os_isolated {
                return refusal(message);
            }
        }
    }
    let sources = sources_from(args, bundle);
    let evidence = build_evidence(&sources)?;
    let violations = validate_bundle(&evidence);
    if !evidence.capabilities.dangerous_capabilities.is_empty() {
        return refusal(format!(
            "dangerous capabilities detected: {}",
            evidence.capabilities.dangerous_capabilities.join(", ")
        ));
    }
    if !evidence.mounts.forbidden_bind_sources.is_empty() {
        return refusal(format!(
            "forbidden host bind mounts: {}",
            evidence.mounts.forbidden_bind_sources.join(", ")
        ));
    }
    if host_network(&evidence) {
        return refusal("host network mode rejected");
    }
    if !evidence.bundle_valid {
        return refusal("malformed OCI bundle spec");
    }
    let guarantees = map_guarantees(&evidence, &violations);
    if os_isolated
        && guarantees.iter().any(|entry| {
            ENFORCED_KINDS.contains(&entry["kind"].as_str().unwrap_or_default())
                && (entry["enforced"] != true || entry["boundary"] != OS_ISOLATED)
        })
    {
        return refusal("required boundary is unavailable on this host");
    }
    const DIGEST_INPUT: &str = "malformed OCI bundle digest input";
    let canonical_root = match sources.bundle_root {
        Some(root) => match std::fs::canonicalize(root) {
            Ok(path) => path.to_string_lossy().into_owned(),
            Err(_) => return refusal(DIGEST_INPUT),
        },
        None => String::new(),
    };
    let Ok(spec_digest) = bundle_digest(bundle) else {
        return refusal(DIGEST_INPUT);
    };
    let mut fields = Map::new();
    fields.insert("context_digest".to_owned(), json!(context_digest));
    fields.insert("minimum_boundary".to_owned(), json!(minimum));
    fields.insert("bundle_digest".to_owned(), json!(spec_digest));
    fields.insert("bundle_version".to_owned(), json!(evidence.bundle_version));
    fields.insert("bundle_root".to_owned(), json!(canonical_root));
    fields.insert(
        "rootfs_resolved_path".to_owned(),
        json!(evidence.rootfs.resolved_path),
    );
    fields.insert(
        "resolved_bind_sources".to_owned(),
        json!(evidence.mounts.resolved_bind_sources),
    );
    fields.insert("violations_count".to_owned(), json!(violations.len()));
    let plan_digest = framed_digest("guard.oci-plan.v1", &fields)?;
    Ok(json!({
        "plan_digest": plan_digest,
        "plan_fields": fields,
        "evidence": evidence_value(&evidence)?,
        "violations": violations,
        "guarantees": guarantees,
    }))
}
