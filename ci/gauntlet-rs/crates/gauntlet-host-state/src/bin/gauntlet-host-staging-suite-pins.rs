//! Assemble one host-owned, immutable six-role diagnostic pin manifest.
//! Each public key comes from a durable prelaunch host journal, never a
//! guest control record. Record SHA-256 pins remain caller-supplied.

use gauntlet_contracts::{canonicalize, is_git_sha};
use gauntlet_evidence::valid_package_version;
use gauntlet_host_state::HostControllerKeyPinJournal;
use serde_json::{json, Map, Value};
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

fn hex(raw: &str, len: usize) -> bool {
    raw.len() == len
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Copy)]
struct SuiteIdentity<'a> {
    build_job_id: &'a str,
    source_sha: &'a str,
    version: &'a str,
    config_digest: &'a str,
    private_manifest_sha256: &'a str,
    prefix_tree_sha256: &'a str,
    worker_generation_sha256: &'a str,
    sdk_bun_sha256: Option<&'a str>,
}

#[derive(Clone, Copy)]
enum SuiteMode {
    Kernel,
    Agent,
    SdkGate,
    SdkExecutable,
}

fn assemble(
    journal: &HostControllerKeyPinJournal,
    identity: &SuiteIdentity<'_>,
    selectors: &[(&str, &str); 6],
    mode: SuiteMode,
) -> Result<Vec<u8>, String> {
    if !hex(identity.build_job_id, 16)
        || !is_git_sha(identity.source_sha)
        || !valid_package_version(identity.version)
        || ![
            identity.config_digest,
            identity.private_manifest_sha256,
            identity.prefix_tree_sha256,
            identity.worker_generation_sha256,
        ]
        .iter()
        .all(|value| hex(value, 64))
    {
        return Err("invalid outside suite identity".to_owned());
    }
    if matches!(mode, SuiteMode::SdkExecutable)
        && identity.sdk_bun_sha256.is_none_or(|value| !hex(value, 64))
    {
        return Err("invalid outside SDK Bun digest".to_owned());
    }
    let mut runs = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut roles = Map::new();
    for (role, (run_id, record_sha256)) in ROLES.iter().zip(selectors) {
        if !hex(run_id, 16) || !hex(record_sha256, 64) || !runs.insert(*run_id) {
            return Err("duplicate or invalid one-use suite run/record pin".to_owned());
        }
        let pin = journal
            .read(run_id)
            .map_err(|error| format!("host key pin unavailable for {role}: {error}"))?;
        if pin.pins.job_id != *run_id
            || pin.pins.source_sha != identity.source_sha
            || pin.pins.deployment_digest != identity.config_digest
            || pin.pins.worker_generation != identity.worker_generation_sha256
            || !keys.insert(pin.pins.controller_public_key_hex.clone())
        {
            return Err("suite role differs from prelaunch host pin".to_owned());
        }
        roles.insert(
            (*role).to_owned(),
            json!({
                "run_id":run_id,
                "record_sha256":record_sha256,
                "controller_public_key_hex":pin.pins.controller_public_key_hex,
                "host_record_sha256":pin.raw_sha256,
                "controller_key_pin_sha256":pin.pins.controller_key_pin_sha256,
                "started_marker_sha256":pin.pins.started_marker_sha256,
            }),
        );
    }
    let schema = match mode {
        SuiteMode::Kernel => "hol-gauntlet-staging-suite-pins.v2",
        SuiteMode::Agent => "hol-gauntlet-staging-suite-pins.v3",
        SuiteMode::SdkGate => "hol-gauntlet-staging-suite-pins.v4",
        SuiteMode::SdkExecutable => "hol-gauntlet-staging-suite-pins.v5",
    };
    let mut manifest: Value = json!({
        "schema":schema,
        "build_job_id":identity.build_job_id,
        "source_sha":identity.source_sha,
        "version":identity.version,
        "config_digest":identity.config_digest,
        "private_manifest_sha256":identity.private_manifest_sha256,
        "prefix_tree_sha256":identity.prefix_tree_sha256,
        "worker_generation_sha256":identity.worker_generation_sha256,
        "roles":roles,
        "live_kernel_samples_required":true,
        "execution_eligible":false,
    });
    if matches!(
        mode,
        SuiteMode::Agent | SuiteMode::SdkGate | SuiteMode::SdkExecutable
    ) {
        manifest["agent_process_samples_required"] = json!(true);
    }
    if matches!(mode, SuiteMode::SdkGate | SuiteMode::SdkExecutable) {
        manifest["sdk_gate_process_samples_required"] = json!(true);
    }
    if matches!(mode, SuiteMode::SdkExecutable) {
        manifest["sdk_executable_samples_required"] = json!(true);
        manifest["sdk_bun_sha256"] = json!(identity.sdk_bun_sha256.unwrap());
    }
    canonicalize(manifest.to_string().as_bytes())
        .map_err(|_| "suite pin manifest could not be canonicalized".to_owned())
}

fn run() -> Result<Value, String> {
    if !cfg!(target_os = "macos") {
        return Err("macOS host suite pin artifact required".to_owned());
    }
    let args: Vec<String> = std::env::args().collect();
    if (args.len() != 21 && args.len() != 22 && args.len() != 23)
        || (args.len() == 22
            && args[21] != "--agent-processes"
            && args[21] != "--sdk-gate-processes")
        || (args.len() == 23 && args[21] != "--sdk-executable-sha256")
    {
        return Err("usage: gauntlet-host-staging-suite-pins PRIVATE_HOST_PIN_DIR BUILD_JOB SOURCE_SHA VERSION CONFIG_SHA PRIVATE_MANIFEST_SHA PREFIX_TREE_SHA WORKER_SHA SUCCESS_RUN SUCCESS_RECORD INPUT_RUN INPUT_RECORD INJECTION_RUN INJECTION_RECORD BOUNDARY_RUN BOUNDARY_RECORD TIMEOUT_RUN TIMEOUT_RECORD CANCEL_RUN CANCEL_RECORD [--agent-processes|--sdk-gate-processes|--sdk-executable-sha256 BUN_SHA256]".to_owned());
    }
    let identity = SuiteIdentity {
        build_job_id: &args[2],
        source_sha: &args[3],
        version: &args[4],
        config_digest: &args[5],
        private_manifest_sha256: &args[6],
        prefix_tree_sha256: &args[7],
        worker_generation_sha256: &args[8],
        sdk_bun_sha256: args.get(22).map(String::as_str),
    };
    let selectors = [
        (args[9].as_str(), args[10].as_str()),
        (args[11].as_str(), args[12].as_str()),
        (args[13].as_str(), args[14].as_str()),
        (args[15].as_str(), args[16].as_str()),
        (args[17].as_str(), args[18].as_str()),
        (args[19].as_str(), args[20].as_str()),
    ];
    let journal = HostControllerKeyPinJournal::open(Path::new(&args[1]))
        .map_err(|error| format!("private host pin directory unavailable: {error}"))?;
    let mode = match args.get(21).map(String::as_str) {
        Some("--agent-processes") => SuiteMode::Agent,
        Some("--sdk-gate-processes") => SuiteMode::SdkGate,
        Some("--sdk-executable-sha256") => SuiteMode::SdkExecutable,
        _ => SuiteMode::Kernel,
    };
    let bytes = assemble(&journal, &identity, &selectors, mode)?;
    let digest = journal
        .record_staging_suite_manifest(identity.build_job_id, selectors[0].0, &bytes)
        .map_err(|error| format!("one-use suite pin write failed: {error}"))?;
    Ok(json!({
        "schema":match mode {
            SuiteMode::Kernel => "hol-gauntlet-host-staging-suite-pins-diagnostic.v2",
            SuiteMode::Agent => "hol-gauntlet-host-staging-suite-pins-diagnostic.v3",
            SuiteMode::SdkGate => "hol-gauntlet-host-staging-suite-pins-diagnostic.v4",
            SuiteMode::SdkExecutable => "hol-gauntlet-host-staging-suite-pins-diagnostic.v5",
        },
        "path":format!("{}/{}.{}.staging-suite-pins.json",args[1],identity.build_job_id,selectors[0].0),
        "manifest_sha256":digest,
        "roles":ROLES,
        "execution_eligible":false,
    }))
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("host staging suite pins unavailable: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gauntlet_host_state::HostControllerKeyPins;

    #[test]
    fn host_journal_keys_must_match_one_source_config_and_generation() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            temp.path(),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
        let root = temp.path().canonicalize().unwrap();
        let journal = HostControllerKeyPinJournal::open(&root).unwrap();
        let source = "a".repeat(40);
        let config = "b".repeat(64);
        let worker = "c".repeat(64);
        let private = "d".repeat(64);
        let prefix = "e".repeat(64);
        let records: Vec<_> = (0..6)
            .map(|index| (format!("{index:016x}"), format!("{index:064x}")))
            .collect();
        for (index, (run, _)) in records.iter().enumerate() {
            journal
                .record(&HostControllerKeyPins {
                    job_id: run.clone(),
                    source_sha: source.clone(),
                    deployment_digest: config.clone(),
                    worker_generation: worker.clone(),
                    started_marker_sha256: "1".repeat(64),
                    controller_key_pin_sha256: "2".repeat(64),
                    controller_public_key_hex: format!("{:064x}", index + 1),
                })
                .unwrap();
        }
        let identity = SuiteIdentity {
            build_job_id: "0123456789abcdef",
            source_sha: &source,
            version: "3.49.0",
            config_digest: &config,
            private_manifest_sha256: &private,
            prefix_tree_sha256: &prefix,
            worker_generation_sha256: &worker,
            sdk_bun_sha256: None,
        };
        let selectors: [(&str, &str); 6] =
            std::array::from_fn(|index| (records[index].0.as_str(), records[index].1.as_str()));
        assert!(hex(identity.build_job_id, 16));
        assert!(is_git_sha(identity.source_sha));
        assert!(valid_package_version(identity.version));
        assert!(hex(identity.config_digest, 64));
        assert!(hex(identity.private_manifest_sha256, 64));
        assert!(hex(identity.prefix_tree_sha256, 64));
        assert!(hex(identity.worker_generation_sha256, 64));
        let raw = assemble(&journal, &identity, &selectors, SuiteMode::Kernel).unwrap();
        let value: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(value["schema"], "hol-gauntlet-staging-suite-pins.v2");
        assert_eq!(value["live_kernel_samples_required"], true);
        assert_eq!(value["roles"]["cancel"]["run_id"], records[5].0);
        assert_eq!(value["execution_eligible"], false);
        let agent_raw = assemble(&journal, &identity, &selectors, SuiteMode::Agent).unwrap();
        let agent: Value = serde_json::from_slice(&agent_raw).unwrap();
        assert_eq!(agent["schema"], "hol-gauntlet-staging-suite-pins.v3");
        assert_eq!(agent["agent_process_samples_required"], true);
        let sdk_raw = assemble(&journal, &identity, &selectors, SuiteMode::SdkGate).unwrap();
        let sdk: Value = serde_json::from_slice(&sdk_raw).unwrap();
        assert_eq!(sdk["schema"], "hol-gauntlet-staging-suite-pins.v4");
        assert_eq!(sdk["agent_process_samples_required"], true);
        assert_eq!(sdk["sdk_gate_process_samples_required"], true);
        let bun = "f".repeat(64);
        let sdk_identity = SuiteIdentity {
            sdk_bun_sha256: Some(&bun),
            ..identity
        };
        let exe_raw = assemble(
            &journal,
            &sdk_identity,
            &selectors,
            SuiteMode::SdkExecutable,
        )
        .unwrap();
        let exe: Value = serde_json::from_slice(&exe_raw).unwrap();
        assert_eq!(exe["schema"], "hol-gauntlet-staging-suite-pins.v5");
        assert_eq!(exe["sdk_executable_samples_required"], true);
        assert_eq!(exe["sdk_bun_sha256"], bun);
        assert!(assemble(
            &journal,
            &identity,
            &[
                selectors[0],
                selectors[0],
                selectors[2],
                selectors[3],
                selectors[4],
                selectors[5]
            ],
            SuiteMode::Kernel,
        )
        .is_err());
        let wrong = SuiteIdentity {
            worker_generation_sha256: &"f".repeat(64),
            ..identity
        };
        assert!(assemble(&journal, &wrong, &selectors, SuiteMode::Kernel).is_err());
        let digest = journal
            .record_staging_suite_manifest("0123456789abcdef", selectors[0].0, &raw)
            .unwrap();
        assert!(hex(&digest, 64));
        assert!(journal
            .record_staging_suite_manifest("0123456789abcdef", selectors[0].0, &raw)
            .is_err());
        assert!(journal
            .record_staging_suite_manifest("0123456789abcdef", selectors[1].0, &raw)
            .is_err());
    }
}
