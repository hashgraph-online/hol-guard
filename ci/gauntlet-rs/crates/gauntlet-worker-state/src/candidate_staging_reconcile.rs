//! Read-only restart reconciliation for one Root-owned staging tap diagnostic.
//! A missing or changed artifact stays uncertain; this never repairs, retries,
//! constructs conformance, or promotes the diagnostic to an eligible result.

use crate::{
    hex, read_bounded_regular, read_sdk_tap_journal_ineligible, require_rust_job_slice_absent,
    ActiveLease, RunReservationJournal, TerminalOutcome,
};
use gauntlet_contracts::{canonicalize, is_git_sha};
use rustix::fs::{fstat, open, openat, statat, AtFlags, Dir, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

const STAGING_STATE: &str = "/var/lib/hol-gauntlet-rust/staging-state";
const CGROUP_PARENT: &str = "/sys/fs/cgroup/system.slice";
const MAX_STAGING_REPORT: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct StagingTapReadbackPins<'a> {
    pub run_id: &'a str,
    pub source_sha: &'a str,
    pub config_digest: &'a str,
    pub worker_generation_sha256: &'a str,
    pub started_marker_sha256: &'a str,
    pub controller_key_pin_sha256: &'a str,
    pub terminal_sha256: &'a str,
    pub report_sha256: &'a str,
    pub tap_journal_sha256: &'a str,
}

fn validate_pins(pins: &StagingTapReadbackPins<'_>) -> Result<(), String> {
    if !hex(pins.run_id, 16)
        || !is_git_sha(pins.source_sha)
        || [
            pins.config_digest,
            pins.worker_generation_sha256,
            pins.started_marker_sha256,
            pins.controller_key_pin_sha256,
            pins.terminal_sha256,
            pins.report_sha256,
            pins.tap_journal_sha256,
        ]
        .iter()
        .any(|pin| !hex(pin, 64))
    {
        return Err("exact outside staging readback pins required".to_owned());
    }
    Ok(())
}

fn validate_report(raw: &[u8], pins: &StagingTapReadbackPins<'_>) -> Result<Value, String> {
    if canonicalize(raw).map_err(|error| error.to_string())? != raw {
        return Err("staging report is not canonical".to_owned());
    }
    let value: Value = serde_json::from_slice(raw).map_err(|error| error.to_string())?;
    let tap = &value["sdk_tap_v2"];
    let journal = &tap["journal"];
    if value["schema"] != "hol-gauntlet-staging-control-run-report.v1"
        || value["run_id"] != pins.run_id
        || value["source_sha"] != pins.source_sha
        || value["provisional_config_digest"] != pins.config_digest
        || !matches!(
            value["role"].as_str(),
            Some("success" | "input-binding" | "injection" | "boundary" | "timeout" | "cancel")
        )
        || value["controller_public_key_hex"].as_str().is_none()
        || value["controller_and_product_slice_cleanup_verified"] != true
        || value["post_run_controller_custody"] != true
        || value["timed_out"] != false
        || value["record_scored"] != false
        || value["execution_eligible"] != false
        || tap["schema"] != "hol-gauntlet-staging-sdk-tap-summary.v3"
        || tap["root_forwarded"] != true
        || tap["native_peer_independently_observed_by_root"] != true
        || tap["execution_eligible"] != false
        || journal["schema"] != "hol-gauntlet-sdk-tap-journal-receipt.v2"
        || journal["run_id"] != pins.run_id
        || journal["sha256"] != pins.tap_journal_sha256
        || journal["root_forwarded"] != true
        || journal["execution_eligible"] != false
    {
        return Err("staging report or Root-forwarded tap summary differs from pins".to_owned());
    }
    Ok(value)
}

fn same_directory(a: &Stat, b: &Stat) -> bool {
    FileType::from_raw_mode(a.st_mode) == FileType::Directory
        && FileType::from_raw_mode(b.st_mode) == FileType::Directory
        && a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_mode == b.st_mode
}

fn require_tombstone(journal: &RunReservationJournal, run_id: &str) -> Result<(), String> {
    let name = format!("{run_id}.sdk-tap");
    let directory = openat(
        &journal.root,
        name.as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("one-use SDK tap tombstone unavailable: {error}"))?;
    let held = fstat(&directory).map_err(|error| error.to_string())?;
    let visible = statat(&journal.root, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| error.to_string())?;
    if !same_directory(&held, &visible)
        || held.st_uid != 0
        || held.st_gid != 10001
        || held.st_mode & 0o7777 != 0o710
    {
        return Err("one-use SDK tap tombstone identity changed".to_owned());
    }
    let mut entries = Dir::read_from(&directory).map_err(|error| error.to_string())?;
    for entry in &mut entries {
        let entry = entry.map_err(|error| error.to_string())?;
        if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
            return Err("one-use SDK tap tombstone still contains an entry".to_owned());
        }
    }
    let after = fstat(&directory).map_err(|error| error.to_string())?;
    let visible_after = statat(&journal.root, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| error.to_string())?;
    if !same_directory(&held, &after) || !same_directory(&held, &visible_after) {
        return Err("one-use SDK tap tombstone changed during readback".to_owned());
    }
    Ok(())
}

fn absent(parent: &impl std::os::fd::AsFd, name: &str) -> Result<(), String> {
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) => Ok(()),
        Ok(_) => Err(format!("staging cgroup remains: {name}")),
        Err(error) => Err(format!("staging cgroup observation unavailable: {error}")),
    }
}

fn require_cgroups_absent(run_id: &str) -> Result<(), String> {
    let parent = open(
        CGROUP_PARENT,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("system cgroup parent unavailable: {error}"))?;
    let before = fstat(&parent).map_err(|error| error.to_string())?;
    if before.st_uid != 0 || FileType::from_raw_mode(before.st_mode) != FileType::Directory {
        return Err("system cgroup parent is unsafe".to_owned());
    }
    let controller = format!("hol-gauntlet-rust-job-{run_id}");
    let tap = format!("hol-gauntlet-rust-tap-{run_id}");
    absent(&parent, &controller)?;
    absent(&parent, &tap)?;
    require_rust_job_slice_absent(run_id).map_err(|error| error.to_string())?;
    let after = fstat(&parent).map_err(|error| error.to_string())?;
    if !same_directory(&before, &after) {
        return Err("system cgroup parent changed during readback".to_owned());
    }
    absent(&parent, &controller)?;
    absent(&parent, &tap)?;
    Ok(())
}

/// Reopen a completed Root-forwarded diagnostic after the original worker is
/// gone. The caller supplies hashes retained outside the VM before readback.
/// An interrupted run cannot satisfy the terminal/journal/tombstone checks.
pub fn read_restarted_staging_tap_ineligible(
    pins: &StagingTapReadbackPins<'_>,
) -> Result<Value, String> {
    validate_pins(pins)?;
    let journal = RunReservationJournal::open_root_owned(Path::new(STAGING_STATE))
        .map_err(|error| error.to_string())?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|error| error.to_string())?;
    read_restarted_staging_tap_under_lease_ineligible(&journal, &lease, pins)
}

fn read_restarted_staging_tap_under_lease_ineligible(
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    pins: &StagingTapReadbackPins<'_>,
) -> Result<Value, String> {
    lease
        .verify(&journal.root)
        .map_err(|error| error.to_string())?;
    let started = journal
        .started(
            pins.run_id,
            pins.source_sha,
            pins.config_digest,
            pins.worker_generation_sha256,
        )
        .map_err(|error| error.to_string())?
        .ok_or("staging run has no keyed started marker")?;
    if started.sha256 != pins.started_marker_sha256 {
        return Err("started marker differs from outside host pin".to_owned());
    }
    let terminal = journal
        .terminal(
            pins.run_id,
            pins.source_sha,
            pins.config_digest,
            pins.worker_generation_sha256,
        )
        .map_err(|error| error.to_string())?
        .ok_or("staging run has no complete terminal")?;
    if terminal.status != TerminalOutcome::InvalidEvidence
        || terminal.sha256 != pins.terminal_sha256
        || terminal.report_sha256 != pins.report_sha256
        || terminal.started_marker_sha256 != pins.started_marker_sha256
        || terminal.controller_key_pin_sha256.as_deref() != Some(pins.controller_key_pin_sha256)
        || terminal.controller_public_key_hex != started.controller_public_key_hex
    {
        return Err("keyed staging terminal differs from outside host pins".to_owned());
    }
    let report = read_bounded_regular(
        &journal.root,
        &format!("{}.report.json", pins.run_id),
        MAX_STAGING_REPORT,
    )
    .map_err(|error| error.to_string())?
    .ok_or("staging report is missing")?;
    if format!("{:x}", Sha256::digest(&report)) != pins.report_sha256 {
        return Err("staging report differs from outside host pin".to_owned());
    }
    let value = validate_report(&report, pins)?;
    if value["controller_public_key_hex"].as_str() != terminal.controller_public_key_hex.as_deref()
        || value["exit_code"].as_i64() != Some(terminal.exit_code as i64)
        || value["process"]["pid"].as_u64() != Some(terminal.process.pid as u64)
        || value["process"]["start_ticks"].as_u64() != Some(terminal.process.start_ticks)
    {
        return Err("staging report differs from keyed terminal process".to_owned());
    }
    let tap = read_sdk_tap_journal_ineligible(journal, lease, &started, pins.tap_journal_sha256)?;
    let tap_value: Value = serde_json::from_slice(&tap).map_err(|error| error.to_string())?;
    if tap_value["schema"] != "hol-gauntlet-sdk-tap-journal.v2"
        || tap_value["wire_owner"] != "root-forwarded"
        || tap_value["root_forwarded"] != true
    {
        return Err("retained SDK tap journal is not Root-forwarded".to_owned());
    }
    require_tombstone(journal, pins.run_id)?;
    require_cgroups_absent(pins.run_id)?;
    lease
        .verify(&journal.root)
        .map_err(|error| error.to_string())?;
    if journal
        .terminal(
            pins.run_id,
            pins.source_sha,
            pins.config_digest,
            pins.worker_generation_sha256,
        )
        .map_err(|error| error.to_string())?
        .as_ref()
        != Some(&terminal)
        || read_bounded_regular(
            &journal.root,
            &format!("{}.report.json", pins.run_id),
            MAX_STAGING_REPORT,
        )
        .map_err(|error| error.to_string())?
        .as_deref()
            != Some(report.as_slice())
        || read_sdk_tap_journal_ineligible(journal, lease, &started, pins.tap_journal_sha256)?
            != tap
    {
        return Err("staging terminal, report or tap journal changed during readback".to_owned());
    }
    require_tombstone(journal, pins.run_id)?;
    Ok(json!({
        "schema":"hol-gauntlet-staging-tap-restart-readback.v1",
        "run_id":pins.run_id,
        "source_sha":pins.source_sha,
        "config_digest":pins.config_digest,
        "worker_generation_sha256":pins.worker_generation_sha256,
        "started_marker_sha256":pins.started_marker_sha256,
        "controller_key_pin_sha256":pins.controller_key_pin_sha256,
        "controller_public_key_hex":terminal.controller_public_key_hex,
        "terminal_sha256":pins.terminal_sha256,
        "report_sha256":pins.report_sha256,
        "tap_journal_sha256":pins.tap_journal_sha256,
        "role":value["role"],
        "state":"verified-ineligible-terminal",
        "one_use_tap_tombstone_empty":true,
        "controller_tap_and_product_cgroups_absent":true,
        "conformance_package_created":false,
        "execution_eligible":false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pins() -> StagingTapReadbackPins<'static> {
        StagingTapReadbackPins {
            run_id: "0123456789abcdef",
            source_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            config_digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            worker_generation_sha256:
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            started_marker_sha256:
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            controller_key_pin_sha256:
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            terminal_sha256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            report_sha256: "1111111111111111111111111111111111111111111111111111111111111111",
            tap_journal_sha256: "2222222222222222222222222222222222222222222222222222222222222222",
        }
    }

    #[test]
    fn report_requires_root_forwarded_ineligible_tap_and_exact_hash() {
        let pins = pins();
        let report = json!({
            "schema":"hol-gauntlet-staging-control-run-report.v1",
            "run_id":pins.run_id,
            "source_sha":pins.source_sha,
            "provisional_config_digest":pins.config_digest,
            "role":"success",
            "controller_public_key_hex":"3".repeat(64),
            "controller_and_product_slice_cleanup_verified":true,
            "post_run_controller_custody":true,
            "timed_out":false,
            "record_scored":false,
            "execution_eligible":false,
            "sdk_tap_v2":{
                "schema":"hol-gauntlet-staging-sdk-tap-summary.v3",
                "root_forwarded":true,
                "native_peer_independently_observed_by_root":true,
                "execution_eligible":false,
                "journal":{
                    "schema":"hol-gauntlet-sdk-tap-journal-receipt.v2",
                    "run_id":pins.run_id,
                    "sha256":pins.tap_journal_sha256,
                    "root_forwarded":true,
                    "execution_eligible":false,
                },
            },
        });
        let raw = canonicalize(report.to_string().as_bytes()).unwrap();
        assert!(validate_report(&raw, &pins).is_ok());
        let mut wrong = report.clone();
        wrong["sdk_tap_v2"]["journal"]["sha256"] = json!("9".repeat(64));
        assert!(
            validate_report(&canonicalize(wrong.to_string().as_bytes()).unwrap(), &pins).is_err()
        );
        wrong = report;
        wrong["controller_and_product_slice_cleanup_verified"] = json!(false);
        assert!(
            validate_report(&canonicalize(wrong.to_string().as_bytes()).unwrap(), &pins).is_err()
        );
    }

    #[test]
    fn outside_pins_refuse_paths_and_nonhex_hashes() {
        let mut candidate = pins();
        assert!(validate_pins(&candidate).is_ok());
        candidate.run_id = "../bad";
        assert!(validate_pins(&candidate).is_err());
        candidate = pins();
        candidate.tap_journal_sha256 = "Z";
        assert!(validate_pins(&candidate).is_err());
    }
}
