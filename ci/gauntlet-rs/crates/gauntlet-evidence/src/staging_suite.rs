//! Reconcile six distinct one-use staging roots against one host-pinned
//! manifest and Root-owned guest terminals. This cannot qualify a candidate.

use crate::crypto::{is_sha256, sha256};
use crate::io::open_absolute_directory;
use crate::public_files::PublicRootReader;
use crate::python_worker_files::{private_directory, read_private_file};
use crate::staging_agent_process::{
    matching_agent_process, matching_native_mcp_processes, matching_sdk_executable,
    matching_sdk_gate_process,
};
use crate::staging_control_record::read_one;
use crate::staging_sdk_tap_frames::{
    matching_sdk_tap_native_frames, source_bound_docs_records, SdkTapOutsidePins,
};
use crate::{
    observe_staging_physical_files_root_owned_ineligible, verify_controller_tree, EvidenceError,
    Result, StagingEvidencePins,
};
use gauntlet_contracts::{canonicalize, is_git_sha};
use rustix::fs::{fstat, statat, AtFlags, FileType, Stat};
use rustix::io::Errno;
use rustix::process::geteuid;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::Path;

const ROLES: [&str; 6] = [
    "success",
    "input-binding",
    "injection",
    "boundary",
    "timeout",
    "cancel",
];
const INVALID: EvidenceError = EvidenceError::Invalid("invalid host-pinned staging suite");
const STAGING: &str = "/var/lib/hol-gauntlet-rust/staging-state";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const SYSTEM_SLICE: &str = "/sys/fs/cgroup/system.slice";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingSuiteShadow {
    pub manifest_sha256: String,
    pub signed_records: usize,
    pub physical_files: usize,
    pub absent_effects: usize,
    pub cleanup_journals: usize,
    pub live_kernel_roles_sampled: usize,
    pub live_agent_roles_sampled: usize,
    pub live_sdk_gate_roles_sampled: usize,
    pub live_sdk_executable_roles_sampled: usize,
    pub live_native_mcp_roles_sampled: usize,
    pub live_sdk_tap_roles_matched: usize,
    pub live_sdk_tap_frames_matched: usize,
    pub source_bound_docs_roles_matched: usize,
    pub root_forwarded_sdk_tap_roles_matched: usize,
}

impl StagingSuiteShadow {
    pub fn to_json(&self) -> Value {
        let schema = if self.source_bound_docs_roles_matched == 6
            && self.root_forwarded_sdk_tap_roles_matched == 6
        {
            "hol-gauntlet-staging-sdk-docs-oracle-root-relay-suite-shadow.v1"
        } else if self.source_bound_docs_roles_matched == 6 {
            "hol-gauntlet-staging-sdk-docs-oracle-suite-shadow.v1"
        } else if self.live_sdk_tap_roles_matched == 6 {
            "hol-gauntlet-staging-sdk-tap-suite-shadow.v1"
        } else if self.live_native_mcp_roles_sampled == 6 {
            "hol-gauntlet-staging-native-mcp-suite-shadow.v1"
        } else if self.live_sdk_executable_roles_sampled == 6 {
            "hol-gauntlet-staging-suite-shadow.v5"
        } else if self.live_sdk_gate_roles_sampled == 6 {
            "hol-gauntlet-staging-suite-shadow.v4"
        } else if self.live_agent_roles_sampled == 6 {
            "hol-gauntlet-staging-suite-shadow.v3"
        } else if self.live_kernel_roles_sampled == 6 {
            "hol-gauntlet-staging-suite-shadow.v2"
        } else {
            "hol-gauntlet-staging-suite-shadow.v1"
        };
        let mut output = json!({
            "schema":schema,
            "manifest_sha256":self.manifest_sha256,
            "signed_records":self.signed_records,
            "physical_files":self.physical_files,
            "absent_effects":self.absent_effects,
            "cleanup_journals":self.cleanup_journals,
            "live_kernel_roles_sampled":self.live_kernel_roles_sampled,
            "host_prelaunch_key_pins_matched":true,
            "outside_cgroups_absent":true,
            "independent_kernel_sdk_effects_verified":false,
            "conformance_package_created":false,
            "execution_eligible":false,
        });
        if self.live_agent_roles_sampled == 6 {
            output["live_agent_roles_sampled"] = json!(6);
        }
        if self.live_sdk_gate_roles_sampled == 6 {
            output["live_sdk_gate_roles_sampled"] = json!(6);
        }
        if self.live_sdk_executable_roles_sampled == 6 {
            output["live_sdk_executable_roles_sampled"] = json!(6);
        }
        if self.live_native_mcp_roles_sampled == 6 {
            output["live_native_mcp_roles_sampled"] = json!(6);
            output["signed_native_mcp_proxy_processes_sampled"] = json!(12);
        }
        if self.live_sdk_tap_roles_matched == 6 {
            output["live_sdk_tap_roles_matched"] = json!(6);
            output["live_sdk_tap_frames_matched"] = json!(self.live_sdk_tap_frames_matched);
        }
        if self.source_bound_docs_roles_matched == 6 {
            output["source_bound_docs_roles_matched"] = json!(6);
        }
        if self.root_forwarded_sdk_tap_roles_matched == 6 {
            output["root_forwarded_sdk_tap_roles_matched"] = json!(6);
        }
        output
    }
}

fn lower_hex(raw: &str, len: usize) -> bool {
    raw.len() == len
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn exact_keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
    })
}

fn same_directory(first: &Stat, second: &Stat, owner: u32) -> bool {
    FileType::from_raw_mode(first.st_mode) == FileType::Directory
        && first.st_uid == owner
        && first.st_mode & 0o022 == 0
        && first.st_dev == second.st_dev
        && first.st_ino == second.st_ino
        && first.st_uid == second.st_uid
        && first.st_mode == second.st_mode
}

pub(crate) fn require_absent_cgroup(parent_path: &Path, name: &str, owner: u32) -> Result<()> {
    let parent = open_absolute_directory(parent_path)?;
    let before = fstat(&parent).map_err(|_| INVALID)?;
    if !same_directory(&before, &before, owner) {
        return Err(INVALID);
    }
    if !matches!(
        statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW),
        Err(Errno::NOENT)
    ) {
        return Err(INVALID);
    }
    let reopened = open_absolute_directory(parent_path)?;
    let after = fstat(&reopened).map_err(|_| INVALID)?;
    if !same_directory(&before, &after, owner)
        || !matches!(
            statat(&reopened, name, AtFlags::SYMLINK_NOFOLLOW),
            Err(Errno::NOENT)
        )
    {
        return Err(INVALID);
    }
    Ok(())
}

pub(crate) fn cgroup_targets(run: &str) -> [(&'static str, String); 2] {
    [
        (SYSTEM_SLICE, format!("hol-gauntlet-rust-job-{run}")),
        (CGROUP_ROOT, format!("holgauntletrust{run}.slice")),
    ]
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key].as_str().ok_or(INVALID)
}

fn checked_manifest(raw: &[u8], outside_sha256: &str, build_job_id: &str) -> Result<Value> {
    if raw.is_empty()
        || raw.len() > 8192
        || !lower_hex(build_job_id, 16)
        || !is_sha256(outside_sha256)
        || sha256(raw) != outside_sha256
        || canonicalize(raw).ok().as_deref() != Some(raw)
    {
        return Err(INVALID);
    }
    let manifest: Value = serde_json::from_slice(raw).map_err(|_| INVALID)?;
    let (live_kernel_required, agent_process_required, sdk_gate_required, sdk_executable_required) =
        match string(&manifest, "schema")? {
            "hol-gauntlet-staging-suite-pins.v1" => (false, false, false, false),
            "hol-gauntlet-staging-suite-pins.v2" => (true, false, false, false),
            "hol-gauntlet-staging-suite-pins.v3" => (true, true, false, false),
            "hol-gauntlet-staging-suite-pins.v4" => (true, true, true, false),
            "hol-gauntlet-staging-suite-pins.v5" => (true, true, true, true),
            _ => return Err(INVALID),
        };
    let mut fields = vec![
        "schema",
        "build_job_id",
        "source_sha",
        "version",
        "config_digest",
        "private_manifest_sha256",
        "prefix_tree_sha256",
        "worker_generation_sha256",
        "roles",
        "execution_eligible",
    ];
    if live_kernel_required {
        fields.push("live_kernel_samples_required");
    }
    if agent_process_required {
        fields.push("agent_process_samples_required");
    }
    if sdk_gate_required {
        fields.push("sdk_gate_process_samples_required");
    }
    if sdk_executable_required {
        fields.push("sdk_executable_samples_required");
        fields.push("sdk_bun_sha256");
    }
    if !exact_keys(&manifest, &fields)
        || (live_kernel_required && manifest["live_kernel_samples_required"] != true)
        || (agent_process_required && manifest["agent_process_samples_required"] != true)
        || (sdk_gate_required && manifest["sdk_gate_process_samples_required"] != true)
        || (sdk_executable_required
            && (manifest["sdk_executable_samples_required"] != true
                || !is_sha256(string(&manifest, "sdk_bun_sha256")?)))
        || manifest["build_job_id"] != build_job_id
        || manifest["execution_eligible"] != false
        || !is_git_sha(string(&manifest, "source_sha")?)
        || !crate::valid_package_version(string(&manifest, "version")?)
        || [
            "config_digest",
            "private_manifest_sha256",
            "prefix_tree_sha256",
            "worker_generation_sha256",
        ]
        .iter()
        .any(|key| !is_sha256(string(&manifest, key).unwrap_or("")))
        || !exact_keys(&manifest["roles"], &ROLES)
    {
        return Err(INVALID);
    }
    let mut runs = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for role in ROLES {
        let row = &manifest["roles"][role];
        if !exact_keys(
            row,
            &[
                "run_id",
                "record_sha256",
                "controller_public_key_hex",
                "host_record_sha256",
                "controller_key_pin_sha256",
                "started_marker_sha256",
            ],
        ) || !lower_hex(string(row, "run_id")?, 16)
            || !runs.insert(string(row, "run_id")?.to_owned())
            || [
                "record_sha256",
                "controller_public_key_hex",
                "host_record_sha256",
                "controller_key_pin_sha256",
                "started_marker_sha256",
            ]
            .iter()
            .any(|key| !is_sha256(string(row, key).unwrap_or("")))
            || !keys.insert(string(row, "controller_public_key_hex")?.to_owned())
        {
            return Err(INVALID);
        }
    }
    Ok(manifest)
}

struct TapReadout<'a> {
    journal_sha256: Option<&'a str>,
    expected_docs_record: Option<&'a Value>,
    root_forwarded: bool,
}

fn terminal_and_cleanup(
    journal: &std::os::fd::OwnedFd,
    role: &str,
    common: &Value,
    row: &Value,
    require_native_mcp: bool,
    tap: TapReadout<'_>,
) -> Result<(bool, bool, bool, bool, bool, usize)> {
    let run = string(row, "run_id")?;
    let report_name = format!("{run}.report.json");
    let terminal_name = format!("{run}.terminal.json");
    let report_raw = read_private_file(journal, &report_name, 0, 16 * 1024)?.ok_or(INVALID)?;
    let terminal_raw = read_private_file(journal, &terminal_name, 0, 16 * 1024)?.ok_or(INVALID)?;
    let report_canonical = canonicalize(&report_raw).map_err(|_| INVALID)?;
    let terminal_canonical = canonicalize(&terminal_raw).map_err(|_| INVALID)?;
    let report: Value = serde_json::from_slice(&report_canonical).map_err(|_| INVALID)?;
    let terminal: Value = serde_json::from_slice(&terminal_canonical).map_err(|_| INVALID)?;
    if report["schema"] != "hol-gauntlet-staging-control-run-report.v1"
        || report["source_sha"] != common["source_sha"]
        || report["build_job_id"] != common["build_job_id"]
        || report["run_id"] != run
        || report["role"] != role
        || report["provisional_config_digest"] != common["config_digest"]
        || report["controller_public_key_hex"] != row["controller_public_key_hex"]
        || report["exit_code"] != 0
        || report["timed_out"] != false
        || report["controller_and_product_slice_cleanup_verified"] != true
        || report["post_run_controller_custody"] != true
        || report["record_scored"] != false
        || report["execution_eligible"] != false
        || terminal["schema"] != "hol-gauntlet-worker-terminal.v2"
        || terminal["status"] != "invalid-evidence"
        || terminal["source_sha"] != common["source_sha"]
        || terminal["job_id"] != run
        || terminal["deployment_digest"] != common["config_digest"]
        || terminal["worker_generation"] != common["worker_generation_sha256"]
        || terminal["controller_public_key_hex"] != row["controller_public_key_hex"]
        || terminal["controller_key_pin_sha256"] != row["controller_key_pin_sha256"]
        || terminal["started_marker_sha256"] != row["started_marker_sha256"]
        || terminal["report_sha256"] != sha256(&report_raw)
        || terminal["exit_code"] != 0
    {
        return Err(INVALID);
    }
    let schema = string(common, "schema")?;
    let sdk_executable_required = schema == "hol-gauntlet-staging-suite-pins.v5";
    let sdk_gate_required =
        schema == "hol-gauntlet-staging-suite-pins.v4" || sdk_executable_required;
    let agent_process_required =
        schema == "hol-gauntlet-staging-suite-pins.v3" || sdk_gate_required;
    let live_kernel_required = schema != "hol-gauntlet-staging-suite-pins.v1";
    if live_kernel_required
        && !agent_process_required
        && !valid_live_kernel_samples(&report["live_kernel_activity"])
    {
        return Err(INVALID);
    }
    let mut tap_frames = 0;
    if agent_process_required {
        let record_raw = read_one(run, role)?;
        if sha256(&record_raw) != string(row, "record_sha256")? {
            return Err(INVALID);
        }
        let record: Value = serde_json::from_slice(&record_raw).map_err(|_| INVALID)?;
        if sdk_executable_required {
            matching_sdk_executable(
                &record,
                &report["live_kernel_activity"],
                string(common, "sdk_bun_sha256")?,
            )
            .map_err(|error| EvidenceError::Context("SDK executable", Box::new(error)))?;
        } else if sdk_gate_required {
            matching_sdk_gate_process(&record, &report["live_kernel_activity"])
                .map_err(|error| EvidenceError::Context("SDK gate", Box::new(error)))?;
        } else {
            matching_agent_process(&record, &report["live_kernel_activity"])
                .map_err(|error| EvidenceError::Context("SDK agent", Box::new(error)))?;
        }
        if require_native_mcp {
            matching_native_mcp_processes(
                &record,
                &report["live_kernel_activity"],
                string(row, "controller_public_key_hex")?,
                string(common, "source_sha")?,
                string(common, "prefix_tree_sha256")?,
                string(common, "version")?,
            )
            .map_err(|error| EvidenceError::Context("Native MCP", Box::new(error)))?;
        }
        if let Some(outside_sha) = tap.journal_sha256 {
            if !require_native_mcp {
                return Err(INVALID);
            }
            let name = format!("{run}.sdk-tap.json");
            let raw = read_private_file(journal, &name, 0, 1024 * 1024)?.ok_or(INVALID)?;
            tap_frames = matching_sdk_tap_native_frames(
                &record,
                &report,
                &terminal,
                &raw,
                &SdkTapOutsidePins {
                    journal_sha256: outside_sha,
                    source_sha: string(common, "source_sha")?,
                    started_marker_sha256: string(row, "started_marker_sha256")?,
                    controller_public_key_hex: string(row, "controller_public_key_hex")?,
                    expected_docs_record: tap.expected_docs_record,
                    root_forwarded: tap.root_forwarded,
                },
            )
            .map_err(|error| EvidenceError::Context("SDK tap", Box::new(error)))?;
            if raw != read_private_file(journal, &name, 0, 1024 * 1024)?.ok_or(INVALID)? {
                return Err(INVALID);
            }
        }
        if record_raw != read_one(run, role)? {
            return Err(INVALID);
        }
    }
    for (parent, name) in cgroup_targets(run) {
        require_absent_cgroup(Path::new(parent), &name, 0)?;
    }
    Ok((
        live_kernel_required,
        agent_process_required,
        sdk_gate_required,
        sdk_executable_required,
        require_native_mcp,
        tap_frames,
    ))
}

fn valid_live_kernel_samples(value: &Value) -> bool {
    exact_keys(
        value,
        &[
            "schema",
            "sample_count",
            "max_controller_tasks",
            "product_slice_observed",
            "product_slice_populated",
            "max_product_tasks",
            "control_processes_exhaustively_observed",
            "guard_causality_verified",
            "execution_eligible",
        ],
    ) && value["schema"] == "hol-gauntlet-staging-kernel-samples.v1"
        && value["sample_count"]
            .as_u64()
            .is_some_and(|count| (1..=10_000).contains(&count))
        && value["max_controller_tasks"]
            .as_u64()
            .is_some_and(|count| (1..=256).contains(&count))
        && value["product_slice_observed"] == true
        && value["product_slice_populated"] == true
        && value["max_product_tasks"]
            .as_u64()
            .is_some_and(|count| (1..=1_000_000).contains(&count))
        && value["control_processes_exhaustively_observed"] == false
        && value["guard_causality_verified"] == false
        && value["execution_eligible"] == false
}

/// Require a Root-owned copy of the exact host manifest, then open all six
/// distinct records, inspect retained files and reconcile guest journals.
/// Process sampling does not establish SDK traffic, Native effects or Guard
/// decisions, so every mode remains execution-ineligible.
fn observe_staging_suite(
    build_job_id: &str,
    outside_manifest_sha256: &str,
    require_native_mcp: bool,
    tap_journal_sha256: Option<&[String; 6]>,
    outside_controller_source_sha: Option<&str>,
    outside_controller_tree_sha256: Option<&str>,
    root_forwarded: bool,
) -> Result<StagingSuiteShadow> {
    if geteuid().as_raw() != 0
        || !lower_hex(build_job_id, 16)
        || !is_sha256(outside_manifest_sha256)
    {
        return Err(INVALID);
    }
    let relative = format!(
        "hol-gauntlet/rust-shadow-candidates/{build_job_id}/suite-pins-{}.json",
        &outside_manifest_sha256[..16]
    );
    let root = PublicRootReader::open(Path::new("/opt"))?;
    let metadata = root.file_inventory(&relative, false)?;
    if metadata.sha256 != outside_manifest_sha256
        || metadata.size == 0
        || metadata.size > 8192
        || metadata.uid != 0
        || metadata.mode != 0o444
    {
        return Err(INVALID);
    }
    let raw = root.read_file(&relative, 8192)?;
    let manifest = checked_manifest(&raw, outside_manifest_sha256, build_job_id)?;
    let controller_root = if let (Some(source), Some(digest)) = (
        outside_controller_source_sha,
        outside_controller_tree_sha256,
    ) {
        if !is_git_sha(source) || !is_sha256(digest) || tap_journal_sha256.is_none() {
            return Err(INVALID);
        }
        let path = format!("/opt/hol-gauntlet/controller-{}", &source[..16]);
        verify_controller_tree(Path::new(&path), digest)?;
        Some(path)
    } else {
        if outside_controller_source_sha.is_some() || outside_controller_tree_sha256.is_some() {
            return Err(INVALID);
        }
        None
    };
    let fixture_raw = if let Some(path) = &controller_root {
        Some(PublicRootReader::open(Path::new(path))?.read_file(
            "ci/gauntlet/benchmark/fixtures/python-cli-with-tests.json",
            32 * 1024,
        )?)
    } else {
        None
    };
    let fixture_records = fixture_raw
        .as_deref()
        .map(source_bound_docs_records)
        .transpose()?;
    if require_native_mcp && manifest["schema"] != "hol-gauntlet-staging-suite-pins.v5" {
        return Err(INVALID);
    }
    if tap_journal_sha256.is_some_and(|pins| {
        !require_native_mcp
            || !pins.iter().all(|pin| is_sha256(pin))
            || pins.iter().collect::<BTreeSet<_>>().len() != 6
    }) {
        return Err(INVALID);
    }
    if root_forwarded && tap_journal_sha256.is_none() {
        return Err(INVALID);
    }
    let journal = open_absolute_directory(Path::new(STAGING))?;
    private_directory(&journal, 0)?;
    let mut physical_files = 0;
    let mut absent_effects = 0;
    let mut live_kernel_roles_sampled = 0;
    let mut live_agent_roles_sampled = 0;
    let mut live_sdk_gate_roles_sampled = 0;
    let mut live_sdk_executable_roles_sampled = 0;
    let mut live_native_mcp_roles_sampled = 0;
    let mut live_sdk_tap_roles_matched = 0;
    let mut live_sdk_tap_frames_matched = 0;
    let mut source_bound_docs_roles_matched = 0;
    for (index, role) in ROLES.into_iter().enumerate() {
        let row = &manifest["roles"][role];
        let pins = StagingEvidencePins {
            build_job_id,
            run_id: string(row, "run_id")?,
            role,
            source_sha: string(&manifest, "source_sha")?,
            version: string(&manifest, "version")?,
            config_digest: string(&manifest, "config_digest")?,
            private_manifest_sha256: string(&manifest, "private_manifest_sha256")?,
            prefix_tree_sha256: string(&manifest, "prefix_tree_sha256")?,
            record_sha256: string(row, "record_sha256")?,
            controller_public_key_hex: string(row, "controller_public_key_hex")?,
        };
        let opened = observe_staging_physical_files_root_owned_ineligible(&pins)?;
        physical_files += opened.observed_files;
        absent_effects += opened.absent_effects;
        let (kernel, agent, sdk_gate, sdk_executable, native_mcp, tap_frames) =
            terminal_and_cleanup(
                &journal,
                role,
                &manifest,
                row,
                require_native_mcp,
                TapReadout {
                    journal_sha256: tap_journal_sha256.map(|pins| pins[index].as_str()),
                    expected_docs_record: fixture_records.as_ref().map(|(clean, injected)| {
                        if role == "injection" {
                            injected
                        } else {
                            clean
                        }
                    }),
                    root_forwarded,
                },
            )
            .map_err(|error| EvidenceError::Context(role, Box::new(error)))?;
        live_kernel_roles_sampled += usize::from(kernel);
        live_agent_roles_sampled += usize::from(agent);
        live_sdk_gate_roles_sampled += usize::from(sdk_gate);
        live_sdk_executable_roles_sampled += usize::from(sdk_executable);
        live_native_mcp_roles_sampled += usize::from(native_mcp);
        live_sdk_tap_roles_matched += usize::from(tap_frames > 0);
        live_sdk_tap_frames_matched += tap_frames;
        source_bound_docs_roles_matched += usize::from(fixture_records.is_some());
    }
    if root.read_file(&relative, 8192)? != raw {
        return Err(INVALID);
    }
    if let (Some(path), Some(before), Some(digest)) = (
        controller_root.as_deref(),
        fixture_raw.as_deref(),
        outside_controller_tree_sha256,
    ) {
        if PublicRootReader::open(Path::new(path))?.read_file(
            "ci/gauntlet/benchmark/fixtures/python-cli-with-tests.json",
            32 * 1024,
        )? != before
        {
            return Err(INVALID);
        }
        verify_controller_tree(Path::new(path), digest)?;
    }
    Ok(StagingSuiteShadow {
        manifest_sha256: outside_manifest_sha256.to_owned(),
        signed_records: 6,
        physical_files,
        absent_effects,
        cleanup_journals: 6,
        live_kernel_roles_sampled,
        live_agent_roles_sampled,
        live_sdk_gate_roles_sampled,
        live_sdk_executable_roles_sampled,
        live_native_mcp_roles_sampled,
        live_sdk_tap_roles_matched,
        live_sdk_tap_frames_matched,
        source_bound_docs_roles_matched,
        root_forwarded_sdk_tap_roles_matched: if root_forwarded {
            live_sdk_tap_roles_matched
        } else {
            0
        },
    })
}

pub fn observe_staging_suite_root_owned_ineligible(
    build_job_id: &str,
    outside_manifest_sha256: &str,
) -> Result<StagingSuiteShadow> {
    observe_staging_suite(
        build_job_id,
        outside_manifest_sha256,
        false,
        None,
        None,
        None,
        false,
    )
}

/// Opt-in stronger opening of the same immutable v5 host manifest. The
/// separate mode preserves v5 output while requiring six sampled Native MCP
/// product boundaries and twelve signed proxy-process identities.
pub fn observe_staging_suite_native_mcp_root_owned_ineligible(
    build_job_id: &str,
    outside_manifest_sha256: &str,
) -> Result<StagingSuiteShadow> {
    observe_staging_suite(
        build_job_id,
        outside_manifest_sha256,
        true,
        None,
        None,
        None,
        false,
    )
}

/// Add six outside host-pinned Root tap digests to the signed Native/SDK
/// process suite. The digests must be supplied in `ROLES` order.
pub fn observe_staging_suite_sdk_tap_root_owned_ineligible(
    build_job_id: &str,
    outside_manifest_sha256: &str,
    tap_journal_sha256: &[String; 6],
) -> Result<StagingSuiteShadow> {
    observe_staging_suite(
        build_job_id,
        outside_manifest_sha256,
        true,
        Some(tap_journal_sha256),
        None,
        None,
        false,
    )
}

/// Opt-in source-bound docs result oracle. The caller separately supplies the
/// complete Root controller-tree digest in addition to the six host tap pins.
/// This remains an ineligible observation, not a Guard or model verdict.
pub fn observe_staging_suite_sdk_docs_oracle_root_owned_ineligible(
    build_job_id: &str,
    outside_manifest_sha256: &str,
    outside_controller_source_sha: &str,
    outside_controller_tree_sha256: &str,
    tap_journal_sha256: &[String; 6],
) -> Result<StagingSuiteShadow> {
    observe_staging_suite(
        build_job_id,
        outside_manifest_sha256,
        true,
        Some(tap_journal_sha256),
        Some(outside_controller_source_sha),
        Some(outside_controller_tree_sha256),
        false,
    )
}

/// Separate opt-in reader for the Root-forwarded PID-namespace wire. The
/// outside CLI mode pins the expected journal ownership before opening bytes.
pub fn observe_staging_suite_sdk_docs_oracle_root_relay_ineligible(
    build_job_id: &str,
    outside_manifest_sha256: &str,
    outside_controller_source_sha: &str,
    outside_controller_tree_sha256: &str,
    tap_journal_sha256: &[String; 6],
) -> Result<StagingSuiteShadow> {
    observe_staging_suite(
        build_job_id,
        outside_manifest_sha256,
        true,
        Some(tap_journal_sha256),
        Some(outside_controller_source_sha),
        Some(outside_controller_tree_sha256),
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::process::getuid;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn product_slice_absence_is_checked_at_cgroup_root() {
        let targets = cgroup_targets("0123456789abcdef");
        assert_eq!(targets[0].0, "/sys/fs/cgroup/system.slice");
        assert_eq!(targets[0].1, "hol-gauntlet-rust-job-0123456789abcdef");
        assert_eq!(targets[1].0, "/sys/fs/cgroup");
        assert_eq!(targets[1].1, "holgauntletrust0123456789abcdef.slice");

        let parent = tempfile::tempdir().unwrap();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let name = &targets[1].1;
        let owner = getuid().as_raw();
        assert!(require_absent_cgroup(parent.path(), name, owner).is_ok());
        fs::create_dir(parent.path().join(name)).unwrap();
        assert!(require_absent_cgroup(parent.path(), name, owner).is_err());
        fs::remove_dir(parent.path().join(name)).unwrap();
        symlink("missing", parent.path().join(name)).unwrap();
        assert!(require_absent_cgroup(parent.path(), name, owner).is_err());
    }

    #[test]
    fn suite_pin_parser_requires_six_distinct_runs_and_keys() {
        let mut roles = serde_json::Map::new();
        for (index, role) in ROLES.iter().enumerate() {
            roles.insert(
                (*role).to_owned(),
                json!({
                    "run_id":format!("{index:016x}"),
                    "record_sha256":"1".repeat(64),
                    "controller_public_key_hex":format!("{:064x}",index+1),
                    "host_record_sha256":"2".repeat(64),
                    "controller_key_pin_sha256":"3".repeat(64),
                    "started_marker_sha256":"4".repeat(64),
                }),
            );
        }
        let mut value = json!({
            "schema":"hol-gauntlet-staging-suite-pins.v1",
            "build_job_id":"0123456789abcdef",
            "source_sha":"a".repeat(40),
            "version":"3.49.0",
            "config_digest":"b".repeat(64),
            "private_manifest_sha256":"c".repeat(64),
            "prefix_tree_sha256":"d".repeat(64),
            "worker_generation_sha256":"e".repeat(64),
            "roles":roles,
            "execution_eligible":false,
        });
        let raw = canonicalize(value.to_string().as_bytes()).unwrap();
        assert!(checked_manifest(&raw, &sha256(&raw), "0123456789abcdef").is_ok());
        value["schema"] = json!("hol-gauntlet-staging-suite-pins.v2");
        let missing_live = canonicalize(value.to_string().as_bytes()).unwrap();
        assert!(
            checked_manifest(&missing_live, &sha256(&missing_live), "0123456789abcdef").is_err()
        );
        value["live_kernel_samples_required"] = json!(true);
        let live = canonicalize(value.to_string().as_bytes()).unwrap();
        assert!(checked_manifest(&live, &sha256(&live), "0123456789abcdef").is_ok());
        value["schema"] = json!("hol-gauntlet-staging-suite-pins.v3");
        let missing_agent = canonicalize(value.to_string().as_bytes()).unwrap();
        assert!(
            checked_manifest(&missing_agent, &sha256(&missing_agent), "0123456789abcdef").is_err()
        );
        value["agent_process_samples_required"] = json!(true);
        let agent = canonicalize(value.to_string().as_bytes()).unwrap();
        assert!(checked_manifest(&agent, &sha256(&agent), "0123456789abcdef").is_ok());
        value["schema"] = json!("hol-gauntlet-staging-suite-pins.v4");
        let missing_sdk_gate = canonicalize(value.to_string().as_bytes()).unwrap();
        assert!(checked_manifest(
            &missing_sdk_gate,
            &sha256(&missing_sdk_gate),
            "0123456789abcdef"
        )
        .is_err());
        value["sdk_gate_process_samples_required"] = json!(true);
        let sdk_gate = canonicalize(value.to_string().as_bytes()).unwrap();
        assert!(checked_manifest(&sdk_gate, &sha256(&sdk_gate), "0123456789abcdef").is_ok());
        value["schema"] = json!("hol-gauntlet-staging-suite-pins.v5");
        value["sdk_executable_samples_required"] = json!(true);
        let missing_bun = canonicalize(value.to_string().as_bytes()).unwrap();
        assert!(checked_manifest(&missing_bun, &sha256(&missing_bun), "0123456789abcdef").is_err());
        value["sdk_bun_sha256"] = json!("f".repeat(64));
        let sdk_executable = canonicalize(value.to_string().as_bytes()).unwrap();
        assert!(checked_manifest(
            &sdk_executable,
            &sha256(&sdk_executable),
            "0123456789abcdef"
        )
        .is_ok());
        value["roles"]["cancel"]["run_id"] = value["roles"]["success"]["run_id"].clone();
        let duplicate = canonicalize(value.to_string().as_bytes()).unwrap();
        assert!(checked_manifest(&duplicate, &sha256(&duplicate), "0123456789abcdef").is_err());
    }

    #[test]
    fn live_kernel_samples_require_positive_root_cgroup_observations() {
        let mut sample = json!({
            "schema":"hol-gauntlet-staging-kernel-samples.v1",
            "sample_count":331,
            "max_controller_tasks":47,
            "product_slice_observed":true,
            "product_slice_populated":true,
            "max_product_tasks":109,
            "control_processes_exhaustively_observed":false,
            "guard_causality_verified":false,
            "execution_eligible":false,
        });
        assert!(valid_live_kernel_samples(&sample));
        sample["product_slice_populated"] = json!(false);
        assert!(!valid_live_kernel_samples(&sample));
        sample["product_slice_populated"] = json!(true);
        sample["sample_count"] = json!(0);
        assert!(!valid_live_kernel_samples(&sample));
        sample["sample_count"] = json!(331);
        sample["guard_causality_verified"] = json!(true);
        assert!(!valid_live_kernel_samples(&sample));
        let proof = StagingSuiteShadow {
            manifest_sha256: "a".repeat(64),
            signed_records: 6,
            physical_files: 32,
            absent_effects: 5,
            cleanup_journals: 6,
            live_kernel_roles_sampled: 6,
            live_agent_roles_sampled: 0,
            live_sdk_gate_roles_sampled: 0,
            live_sdk_executable_roles_sampled: 0,
            live_native_mcp_roles_sampled: 0,
            live_sdk_tap_roles_matched: 0,
            live_sdk_tap_frames_matched: 0,
            source_bound_docs_roles_matched: 0,
            root_forwarded_sdk_tap_roles_matched: 0,
        };
        assert_eq!(
            proof.to_json()["schema"],
            "hol-gauntlet-staging-suite-shadow.v2"
        );
        assert!(proof.to_json().get("live_agent_roles_sampled").is_none());
        let agent = StagingSuiteShadow {
            live_agent_roles_sampled: 6,
            ..proof
        };
        assert_eq!(
            agent.to_json()["schema"],
            "hol-gauntlet-staging-suite-shadow.v3"
        );
        assert_eq!(agent.to_json()["live_agent_roles_sampled"], 6);
        assert!(agent.to_json().get("live_sdk_gate_roles_sampled").is_none());
        let sdk_gate = StagingSuiteShadow {
            live_sdk_gate_roles_sampled: 6,
            ..agent
        };
        assert_eq!(
            sdk_gate.to_json()["schema"],
            "hol-gauntlet-staging-suite-shadow.v4"
        );
        assert_eq!(sdk_gate.to_json()["live_sdk_gate_roles_sampled"], 6);
        let sdk_executable = StagingSuiteShadow {
            live_sdk_executable_roles_sampled: 6,
            ..sdk_gate
        };
        assert_eq!(
            sdk_executable.to_json()["schema"],
            "hol-gauntlet-staging-suite-shadow.v5"
        );
        assert_eq!(
            sdk_executable.to_json()["live_sdk_executable_roles_sampled"],
            6
        );
        let native_mcp = StagingSuiteShadow {
            live_native_mcp_roles_sampled: 6,
            ..sdk_executable
        };
        assert_eq!(
            native_mcp.to_json()["schema"],
            "hol-gauntlet-staging-native-mcp-suite-shadow.v1"
        );
        assert_eq!(
            native_mcp.to_json()["signed_native_mcp_proxy_processes_sampled"],
            12
        );
        let sdk_tap = StagingSuiteShadow {
            live_sdk_tap_roles_matched: 6,
            live_sdk_tap_frames_matched: 144,
            source_bound_docs_roles_matched: 0,
            ..native_mcp
        };
        assert_eq!(
            sdk_tap.to_json()["schema"],
            "hol-gauntlet-staging-sdk-tap-suite-shadow.v1"
        );
        assert_eq!(sdk_tap.to_json()["live_sdk_tap_frames_matched"], 144);
        let docs_oracle = StagingSuiteShadow {
            source_bound_docs_roles_matched: 6,
            ..sdk_tap
        };
        assert_eq!(
            docs_oracle.to_json()["schema"],
            "hol-gauntlet-staging-sdk-docs-oracle-suite-shadow.v1"
        );
        assert_eq!(docs_oracle.to_json()["source_bound_docs_roles_matched"], 6);
        let root_relay = StagingSuiteShadow {
            root_forwarded_sdk_tap_roles_matched: 6,
            ..docs_oracle
        };
        assert_eq!(
            root_relay.to_json()["schema"],
            "hol-gauntlet-staging-sdk-docs-oracle-root-relay-suite-shadow.v1"
        );
    }
}
