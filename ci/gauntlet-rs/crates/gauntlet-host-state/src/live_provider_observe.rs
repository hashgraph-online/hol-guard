//! Read-only observation of the existing macOS model-provider admission inputs.
//! A successful observation is diagnostic, never permission to launch or spend.

use crate::evaluate_live_provider_preflight;
use crate::live_provider_preflight::{ALLOWANCE_SHA, CANDIDATE_SOURCE, TEMPLATE_SHA};
use gauntlet_contracts::canonicalize;
use gauntlet_evidence::read_provider_quota_snapshot;
use rustix::fs::{fstat, open, openat, FileType, Mode, OFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

const MAX_INPUT_BYTES: usize = 64 * 1024;

fn read_pinned_json(path: &Path, expected_sha256: &str) -> Result<Value, &'static str> {
    let literal = path.to_str().ok_or("noncanonical provider input path")?;
    let relative = literal
        .strip_prefix('/')
        .ok_or("absolute provider input path required")?;
    let parts: Vec<_> = relative.split('/').collect();
    if parts.is_empty()
        || parts.iter().any(|part| {
            part.is_empty()
                || *part == "."
                || *part == ".."
                || part.len() > 255
                || part.contains('\\')
        })
    {
        return Err("noncanonical provider input path");
    }
    let mut parent = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "provider input ancestry unavailable")?;
    for part in &parts[..parts.len() - 1] {
        parent = openat(
            &parent,
            *part,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "provider input ancestry unsafe or unavailable")?;
    }
    let fd = openat(
        &parent,
        parts[parts.len() - 1],
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "provider input file unsafe or unavailable")?;
    let before = fstat(&fd).map_err(|_| "provider input metadata unavailable")?;
    if !FileType::from_raw_mode(before.st_mode).is_file()
        || before.st_nlink != 1
        || before.st_size < 0
        || before.st_size as usize > MAX_INPUT_BYTES
    {
        return Err("provider input is not a bounded single-link file");
    }
    let mut file = File::from(fd);
    let mut raw = Vec::with_capacity(before.st_size as usize);
    file.by_ref()
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|_| "provider input could not be read")?;
    let after = fstat(&file).map_err(|_| "provider input metadata unavailable")?;
    if raw.len() != before.st_size as usize
        || raw.len() > MAX_INPUT_BYTES
        || after.st_dev != before.st_dev
        || after.st_ino != before.st_ino
        || after.st_size != before.st_size
        || after.st_nlink != 1
    {
        return Err("provider input changed while read");
    }
    if format!("{:x}", Sha256::digest(&raw)) != expected_sha256 {
        return Err("provider input differs from fixed SHA-256");
    }
    let canonical = canonicalize(&raw).map_err(|_| "provider input JSON invalid")?;
    serde_json::from_slice(&canonical).map_err(|_| "provider input JSON invalid")
}

/// Observe a source-bound preflight on the macOS host without modifying any
/// provider, allowance, quota journal or socket. This output is always ineligible.
pub fn observe_live_provider_preflight_shadow(
    job_id: &str,
    profile: &str,
    requested_candidate_source_sha: &str,
    template_binding_path: &Path,
    allowance_path: &Path,
) -> Result<Value, &'static str> {
    if !cfg!(target_os = "macos") {
        return Err("macOS provider preflight shadow required");
    }
    let mut input = json!({
        "job_id":job_id,
        "profile":profile,
        "requested_candidate_source_sha":requested_candidate_source_sha,
    });
    // The source mismatch must refuse before reading local provider inputs.
    if requested_candidate_source_sha != CANDIDATE_SOURCE {
        let reason = evaluate_live_provider_preflight(&input)
            .err()
            .ok_or("candidate source unexpectedly admitted")?;
        return Ok(json!({
            "schema":"hol-gauntlet-live-provider-preflight-shadow.v1",
            "preflight_accepted":false,
            "reason":reason.to_string(),
            "execution_eligible":false,
        }));
    }
    let template = read_pinned_json(template_binding_path, TEMPLATE_SHA)?;
    let allowance = read_pinned_json(allowance_path, ALLOWANCE_SHA)?;
    let quota_root = template
        .get("quota_root")
        .and_then(Value::as_str)
        .ok_or("provider template quota root missing")?;
    let config_digest = template
        .get("quota_config_digest")
        .and_then(Value::as_str)
        .ok_or("provider template quota config pin missing")?;
    let quota =
        read_provider_quota_snapshot(Path::new(quota_root), config_digest, Some(ALLOWANCE_SHA))
            .map_err(|_| "retained provider quota unavailable")?;
    let address: SocketAddr = "127.0.0.1:8002"
        .parse()
        .map_err(|_| "fixed provider port invalid")?;
    let port_busy = TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_ok();
    input["template_sha"] = json!(TEMPLATE_SHA);
    input["allowance_sha"] = json!(ALLOWANCE_SHA);
    input["allowance"] = allowance;
    input["quota"] = quota;
    input["port_busy"] = json!(port_busy);
    let decision = evaluate_live_provider_preflight(&input);
    Ok(match decision {
        Ok(details) => json!({
            "schema":"hol-gauntlet-live-provider-preflight-shadow.v1",
            "preflight_accepted":true,
            "known_tokens_before":details["known_tokens_before"],
            "reservation":details["reservation"],
            "execution_eligible":false,
        }),
        Err(error) => json!({
            "schema":"hol-gauntlet-live-provider-preflight-shadow.v1",
            "preflight_accepted":false,
            "reason":error.to_string(),
            "execution_eligible":false,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn different_candidate_refuses_without_opening_provider_inputs() {
        if !cfg!(target_os = "macos") {
            return;
        }
        let result = observe_live_provider_preflight_shadow(
            "0123456789abcdef",
            "feature-ai",
            &"b".repeat(40),
            Path::new("/missing/template.json"),
            Path::new("/missing/allowance.json"),
        )
        .unwrap();
        assert_eq!(result["preflight_accepted"], false);
        assert_eq!(result["execution_eligible"], false);
        assert_eq!(
            result["reason"],
            "candidate source identity differs from local model allowance"
        );
    }

    #[test]
    fn pinned_json_reader_refuses_wrong_digest_and_links() {
        let directory = tempfile::tempdir().unwrap();
        let parent = fs::canonicalize(directory.path()).unwrap();
        let path = parent.join("input.json");
        fs::write(&path, b"{\"ok\":true}").unwrap();
        let digest = format!("{:x}", Sha256::digest(b"{\"ok\":true}"));
        assert_eq!(read_pinned_json(&path, &digest).unwrap()["ok"], true);
        assert!(read_pinned_json(&path, &"a".repeat(64)).is_err());
        let linked = parent.join("linked.json");
        fs::hard_link(&path, &linked).unwrap();
        assert!(read_pinned_json(&path, &digest).is_err());
        fs::remove_file(&linked).unwrap();
        let symlink = parent.join("symlink.json");
        std::os::unix::fs::symlink(&path, &symlink).unwrap();
        assert!(read_pinned_json(&symlink, &digest).is_err());
        let linked_parent = parent.join("linked-parent");
        std::os::unix::fs::symlink(&parent, &linked_parent).unwrap();
        assert!(read_pinned_json(&linked_parent.join("input.json"), &digest).is_err());
        let duplicate = b"{\"ok\":true,\"ok\":false}";
        fs::write(&path, duplicate).unwrap();
        let duplicate_digest = format!("{:x}", Sha256::digest(duplicate));
        assert!(read_pinned_json(&path, &duplicate_digest).is_err());
        let oversized = vec![b' '; MAX_INPUT_BYTES + 1];
        fs::write(&path, &oversized).unwrap();
        let oversized_digest = format!("{:x}", Sha256::digest(&oversized));
        assert!(read_pinned_json(&path, &oversized_digest).is_err());
    }
}
