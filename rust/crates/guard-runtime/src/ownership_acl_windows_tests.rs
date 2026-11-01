use std::collections::VecDeque;
use std::io;

use base64::Engine;
use serde_json::{json, Value};

use super::super::{managed_file_payload, windows_payload, WindowsPaths, PROBE_FAILED, VALID};
use super::{probe, Runner, SCRIPT_HEAD, SCRIPT_TAIL};

const MANAGED_FILE: &str = r"C:\ProgramData\HOL\Guard\policy.json";

/// A stand-in PowerShell that records each run.
struct FakePowershell {
    answers: VecDeque<io::Result<Vec<u8>>>,
    calls: Vec<(String, Vec<String>, String, Vec<(String, String)>)>,
}

impl FakePowershell {
    fn answering(answers: Vec<io::Result<Vec<u8>>>) -> Self {
        Self {
            answers: answers.into(),
            calls: Vec::new(),
        }
    }
}

impl Runner for FakePowershell {
    fn run(
        &mut self,
        program: &str,
        arguments: &[&str],
        cwd: &str,
        environment: &[(&str, &str)],
    ) -> io::Result<Vec<u8>> {
        self.calls.push((
            program.to_owned(),
            arguments.iter().map(|item| (*item).to_owned()).collect(),
            cwd.to_owned(),
            environment
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
        ));
        self.answers
            .pop_front()
            .unwrap_or_else(|| Err(io::Error::other("no answer queued")))
    }
}

/// One row per payload item: SYSTEM owns it and users may only read.
fn healthy_rows(file: &str) -> Vec<u8> {
    let rows: Vec<Value> = managed_file_payload(file)
        .expect("payload")
        .iter()
        .map(|item| {
            json!({
                "Name": item.name,
                "Kind": item.kind.as_str(),
                "ExpectedContainer": item.expected_container,
                "Leaf": item.leaf,
                "Exists": true,
                "Owner": "S-1-5-18",
                "Attributes": if item.expected_container { 16 } else { 0 },
                "Container": item.expected_container,
                "NullDacl": false,
                "Truncated": false,
                "Rules": [{"Sid": "S-1-5-32-545", "Type": "Allow", "Rights": 1_179_817, "Propagation": "None"}],
            })
        })
        .collect();
    serde_json::to_vec(&rows).expect("rows")
}

#[test]
fn the_probe_runs_pinned_powershell_with_the_payload_encoded() {
    let mut powershell = FakePowershell::answering(vec![Ok(healthy_rows(MANAGED_FILE))]);

    let verdict = probe(
        managed_file_payload(MANAGED_FILE),
        r"D:\Windows",
        &mut powershell,
    );

    assert_eq!((verdict.status, verdict.reason_code), ("healthy", VALID));
    let (program, arguments, cwd, environment) = &powershell.calls[0];
    assert_eq!(
        program,
        r"D:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    );
    assert_eq!(cwd, r"D:\Windows\System32");
    assert_eq!(
        environment,
        &[
            (
                "ComSpec".to_owned(),
                r"D:\Windows\System32\cmd.exe".to_owned()
            ),
            ("SystemRoot".to_owned(), r"D:\Windows".to_owned()),
            ("WINDIR".to_owned(), r"D:\Windows".to_owned()),
        ]
    );
    assert_eq!(
        arguments[..3],
        ["-NoProfile", "-NonInteractive", "-Command"]
    );
    let script = &arguments[3];
    assert!(!script.contains("ProgramData"));
    let encoded = script
        .strip_prefix(SCRIPT_HEAD)
        .and_then(|rest| rest.strip_suffix(SCRIPT_TAIL))
        .expect("script frame");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("base64");
    let items: Value = serde_json::from_slice(&decoded).expect("json");
    assert_eq!(items[0]["path"], r"C:\");
    assert_eq!(items[4]["path"], MANAGED_FILE);
    assert_eq!(items[4]["leaf"], true);
    assert_eq!(items.as_array().map(Vec::len), Some(5));
}

#[test]
fn rows_missing_from_the_probe_fail_it() {
    let paths: WindowsPaths = serde_json::from_value(json!({
        "runtime_root": r"C:\Program Files\HOL Guard",
        "manifest_path": r"C:\Program Files\HOL Guard\release-manifest.json",
        "state_root": r"C:\ProgramData\HOL\Guard",
        "log_root": r"C:\ProgramData\HOL\Guard\logs",
    }))
    .expect("paths");
    let mut powershell = FakePowershell::answering(vec![Ok(b"[]".to_vec())]);

    let verdict = probe(windows_payload(&paths), r"C:\Windows", &mut powershell);

    assert_eq!(verdict, super::super::probe_failed());
    assert_eq!(powershell.calls.len(), 1);
}

#[test]
fn a_failed_or_unreadable_probe_never_reports_health() {
    for answer in [
        Err(io::ErrorKind::TimedOut.into()),
        Err(io::Error::other("probe failed")),
        Ok(Vec::new()),
        Ok(b"not json".to_vec()),
        Ok(b"{\"Name\": \"managed-file-000\"}".to_vec()),
    ] {
        let mut powershell = FakePowershell::answering(vec![answer]);

        let verdict = probe(
            managed_file_payload(MANAGED_FILE),
            r"C:\Windows",
            &mut powershell,
        );

        assert_eq!(verdict.reason_code, PROBE_FAILED);
        assert_eq!(powershell.calls.len(), 1);
    }
}

#[test]
fn a_drive_less_windows_directory_or_payload_never_runs_the_probe() {
    for directory in [r"\Windows", "", "Windows", r"\\server\share\Windows"] {
        let mut powershell = FakePowershell::answering(Vec::new());
        let verdict = probe(
            managed_file_payload(MANAGED_FILE),
            directory,
            &mut powershell,
        );
        assert_eq!(verdict, super::super::probe_failed());
        assert!(powershell.calls.is_empty());
    }
    let mut powershell = FakePowershell::answering(Vec::new());
    let verdict = probe(
        managed_file_payload("policy.json"),
        r"C:\Windows",
        &mut powershell,
    );
    assert_eq!(verdict, super::super::probe_failed());
    assert!(powershell.calls.is_empty());
}

#[test]
fn probe_ops_require_the_windows_directory() {
    for request in [
        json!({"schema": "ownership-acl.v1", "op": "windows-file-probe", "managed_file": MANAGED_FILE}),
        json!({"schema": "ownership-acl.v1", "op": "windows-probe", "windows_paths": {
            "runtime_root": r"C:\Program Files\HOL Guard",
            "manifest_path": r"C:\Program Files\HOL Guard\release-manifest.json",
            "state_root": r"C:\ProgramData\HOL\Guard",
            "log_root": r"C:\ProgramData\HOL\Guard\logs",
        }}),
    ] {
        let bytes = serde_json::to_vec(&request).expect("request");
        assert_eq!(
            super::super::run_command(bytes.as_slice()),
            Err("ownership_acl_request_invalid".to_owned())
        );
    }
}

/// The real probe reads every item of a temporary file's chain; whatever
/// the runner's account makes of its ACLs, the rows must match the payload.
#[cfg(windows)]
#[test]
fn the_installed_powershell_probes_a_real_file_chain() {
    let directory = tempfile::tempdir().expect("tempdir");
    let file = directory.path().join("managed.json");
    std::fs::write(&file, b"{}").expect("file");
    let file = file.to_string_lossy().into_owned();
    let windows_directory = std::env::var("SystemRoot").expect("SystemRoot");

    let verdict = probe(
        managed_file_payload(&file),
        &windows_directory,
        &mut super::SystemRunner,
    );

    assert_ne!(verdict.reason_code, PROBE_FAILED, "{verdict:?}");
    assert_eq!(
        verdict.surfaces.len(),
        managed_file_payload(&file).expect("payload").len()
    );
}
