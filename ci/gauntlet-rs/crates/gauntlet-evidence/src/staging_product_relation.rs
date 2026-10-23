//! Join a signed control's product identity to a separately authenticated
//! kernel sample. This relation alone is neither a Guard verdict nor proof
//! of every effect: the caller must authenticate the sample and file writes.

use crate::crypto::{decode_hex, is_sha256, sha256};
use crate::staging_control_record::read_one;
use crate::{
    verify_controller_envelope, verify_private_cell_mount_relation, EvidenceError, Result,
};
use gauntlet_contracts::{canonicalize, is_git_sha};
use serde_json::{json, Value};

const INVALID: EvidenceError = EvidenceError::Invalid("signed product differs from kernel sample");

#[derive(Clone, Copy)]
pub struct StagingProductRelationPins<'a> {
    pub run_id: &'a str,
    pub role: &'a str,
    pub source_sha: &'a str,
    pub controller_public_key_hex: &'a str,
}

fn validate_pins(pins: &StagingProductRelationPins<'_>) -> Result<()> {
    if pins.run_id.len() != 16
        || !pins
            .run_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !matches!(
            pins.role,
            "success" | "input-binding" | "injection" | "boundary" | "timeout" | "cancel"
        )
        || !is_git_sha(pins.source_sha)
        || !is_sha256(pins.controller_public_key_hex)
    {
        return Err(INVALID);
    }
    Ok(())
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field].as_str().ok_or(INVALID)
}

fn one<'a>(rows: &'a [Value], kind: &str) -> Result<&'a Value> {
    let mut found = rows.iter().filter(|r| r["kind"] == kind);
    let row = found.next().ok_or(INVALID)?;
    if found.next().is_some() {
        return Err(INVALID);
    }
    Ok(row)
}

/// Check signatures before using the reported process and mounts. The kernel
/// sample is an outside input, not a field taken from this signed record.
pub fn verify_staging_product_relation_ineligible(
    raw: &[u8],
    pins: &StagingProductRelationPins<'_>,
    sample: &Value,
) -> Result<Value> {
    validate_pins(pins)?;
    if raw.len() > 8 * 1024 * 1024 {
        return Err(INVALID);
    }
    let canonical = canonicalize(raw).map_err(|_| INVALID)?;
    let record: Value = serde_json::from_slice(&canonical).map_err(|_| INVALID)?;
    let key = decode_hex(pins.controller_public_key_hex, 32).map_err(|_| INVALID)?;
    let runtime =
        verify_controller_envelope(record["developer_runtime"].to_string().as_bytes(), &key)?;
    let builtin =
        verify_controller_envelope(runtime["native_builtin_audit"].to_string().as_bytes(), &key)?;
    let plane = &builtin["product_plane"];
    if runtime["schema_version"] != "5.0"
        || runtime["controller_session_id"] != pins.role
        || runtime["settings"]["source_sha"] != pins.source_sha
        || plane["source_sha"] != pins.source_sha
        || record["plane"] != *plane
        || plane["workspace_path"] != "/runtime/home/project"
    {
        return Err(INVALID);
    }
    let rows = plane["cell_observations"].as_array().ok_or(INVALID)?;
    let identity = &one(rows, "filtered-cell")?["identity"];
    let pid = sample["pid"]
        .as_u64()
        .filter(|p| *p > 0 && *p <= i32::MAX as u64)
        .ok_or(INVALID)?;
    let start = sample["start_ticks"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or(INVALID)?;
    if identity["pid"].as_u64() != Some(pid)
        || text(identity, "start_time")? != start.to_string()
        || sample["uid"] != 10004
        || sample["gid"] != 10004
        || sample["namespace_pid"] != 1
        || sample["no_new_privileges"] != true
        || sample["seccomp_mode"] != 2
    {
        return Err(INVALID);
    }
    let status = &identity["status"];
    for name in ["Uid", "Gid"] {
        if text(status, name)?.split_whitespace().collect::<Vec<_>>() != ["10004"; 4] {
            return Err(INVALID);
        }
    }
    if text(status, "NSpid")?
        .split_whitespace()
        .collect::<Vec<_>>()
        != [pid.to_string(), "1".into()]
        || text(status, "NoNewPrivs")?.trim() != "1"
        || text(status, "Seccomp")?.trim() != "2"
    {
        return Err(INVALID);
    }
    let namespace_names = ["mnt", "pid", "net", "ipc", "uts", "cgroup"];
    if identity["namespaces"]
        .as_object()
        .is_none_or(|o| o.len() != namespace_names.len())
    {
        return Err(INVALID);
    }
    for name in namespace_names {
        let inode = sample["namespaces"][name]["inode"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or(INVALID)?;
        if identity["namespaces"][name] != format!("{name}:[{inode}]") {
            return Err(INVALID);
        }
    }
    let argv = identity["argv"].as_array().ok_or(INVALID)?;
    let mut cmdline = Vec::new();
    for arg in argv {
        let arg = arg.as_str().filter(|s| !s.contains('\0')).ok_or(INVALID)?;
        cmdline.extend_from_slice(arg.as_bytes());
        cmdline.push(0);
    }
    let mounts = text(identity, "mountinfo")?;
    if argv.is_empty()
        || sample["argv_sha256"] != sha256(&cmdline)
        || sample["mountinfo_sha256"] != sha256(mounts.as_bytes())
    {
        return Err(INVALID);
    }
    let base = format!("/home/hx-{}/{}/tasks", pins.run_id, pins.role);
    let workspace = format!("{base}/checkout");
    let providers = [format!("{base}/remote"), format!("{base}/home")];
    verify_private_cell_mount_relation(
        plane,
        &plane["cell_observations"],
        &workspace,
        &providers,
        pid,
        text(plane, "runtime_prefix")?,
        mounts,
    )?;
    let declared = plane["task_mounts"].as_array().ok_or(INVALID)?;
    let observed = sample["task_mounts"]
        .as_array()
        .filter(|a| a.len() == 3)
        .ok_or(INVALID)?;
    for task in declared {
        let matches: Vec<_> = observed
            .iter()
            .filter(|r| r["destination"] == task["destination"])
            .collect();
        if matches.len() != 1 {
            return Err(INVALID);
        }
        let measured = matches[0];
        if ["source", "destination", "device", "inode", "mode"]
            .iter()
            .any(|f| measured[*f] != task[*f])
            || measured["physical_uid"] != 10001
            || measured["physical_gid"] != 10001
            || measured["product_uid"] != 10004
            || measured["product_gid"] != 10004
        {
            return Err(INVALID);
        }
    }
    Ok(json!({
        "schema":"hol-gauntlet-staging-signed-product-relation.v1",
        "run_id":pins.run_id,"signed_session_id":pins.role,"source_sha":pins.source_sha,
        "record_sha256":sha256(raw),"controller_public_key_hex":pins.controller_public_key_hex,
        "product_pid":pid,"product_start_ticks":start,"task_mounts_matched":3,
        "namespaces_matched":6,"argv_sha256":sample["argv_sha256"],
        "mountinfo_sha256":sample["mountinfo_sha256"],"outside_control_key_matched":true,
        "guard_causality_verified":false,"execution_eligible":false,
    }))
}

/// Read only the fixed private control path. Recheck the same bytes after
/// signature/kernel comparison; the caller must separately recheck its pins.
pub fn observe_staging_product_relation_root_owned_ineligible(
    pins: &StagingProductRelationPins<'_>,
    sample: &Value,
) -> Result<Value> {
    validate_pins(pins)?;
    if !cfg!(target_os = "linux") || rustix::process::geteuid().as_raw() != 0 {
        return Err(EvidenceError::Invalid(
            "Linux Root product record custody required",
        ));
    }
    let raw = read_one(pins.run_id, pins.role)?;
    let relation = verify_staging_product_relation_ineligible(&raw, pins, sample)?;
    if raw != read_one(pins.run_id, pins.role)? {
        return Err(INVALID);
    }
    Ok(relation)
}
