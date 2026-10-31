use std::collections::VecDeque;
use std::io;
use std::path::Path;

use serde_json::{json, Value};

use super::{macos_verify, parse_plist, windows_context, windows_verify, Runner};
use crate::supervisor_verdict::tests::task_xml;
use crate::supervisor_verdict::{Probe, Request};

const MAC_EXECUTABLE: &str = "/Library/Application Support/HOL Guard/hol-guard/hol-guard";
const PLIST_PATH: &str = "/Library/LaunchDaemons/org.hol.guard.machine-health.plist";
const WINDOWS_EXECUTABLE: &str = r"C:\Program Files\HOL Guard\hol-guard\hol-guard.exe";
const NOT_DISABLED: &str = r#"disabled services = { "other" => true }"#;
/// The property list `scripts/mdm/macos` installs.
const INSTALLED_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>org.hol.guard.machine-health</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Library/Application Support/HOL Guard/hol-guard/hol-guard</string>
    <string>mdm</string>
    <string>health-report</string>
    <string>--scope</string>
    <string>machine</string>
    <string>--json</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key><string>/var/root</string>
    <key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin</string>
    <key>TMPDIR</key><string>/var/tmp</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>StartInterval</key><integer>300</integer>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>/Library/Logs/HOL Guard/machine-health.log</string>
  <key>StandardErrorPath</key><string>/Library/Logs/HOL Guard/machine-health-error.log</string>
</dict>
</plist>
"#;

type Call = (String, Vec<String>, String, Vec<(String, String)>);

/// Answers each run from a queue and records what it was asked to run.
#[derive(Default)]
struct FakeRunner {
    answers: VecDeque<io::Result<Probe>>,
    calls: Vec<Call>,
}

impl FakeRunner {
    fn answering(answers: Vec<io::Result<Probe>>) -> Self {
        Self {
            answers: answers.into(),
            calls: Vec::new(),
        }
    }
}

impl Runner for FakeRunner {
    fn run(
        &mut self,
        program: &str,
        arguments: &[&str],
        cwd: &str,
        environment: &[(&str, &str)],
    ) -> io::Result<Probe> {
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

fn completed(returncode: i64, stdout: &str) -> io::Result<Probe> {
    Ok(Probe {
        returncode,
        stdout: stdout.to_owned(),
    })
}

fn loaded_print() -> String {
    format!(
        "system/org.hol.guard.machine-health = {{\n    path = {PLIST_PATH}\n    state = running\n    program = {MAC_EXECUTABLE}\n    arguments = {{\n        {MAC_EXECUTABLE}\n        mdm\n        health-report\n        --scope\n        machine\n        --json\n    }}\n    run interval = 300 seconds\n}}"
    )
}

fn request(value: Value) -> Request {
    serde_json::from_value(value).expect("a well-formed request")
}

fn macos_request(plist_file: &Path) -> Request {
    request(json!({
        "schema": "supervisor-verdict.v1",
        "op": "macos-verify",
        "executable": MAC_EXECUTABLE,
        "plist_file": plist_file.to_str().expect("utf-8 path"),
        "plist_path": PLIST_PATH,
        "stdout_log": "/Library/Logs/HOL Guard/machine-health.log",
        "stderr_log": "/Library/Logs/HOL Guard/machine-health-error.log",
    }))
}

fn write_plist(directory: &Path, text: &str) -> std::path::PathBuf {
    let target = directory.join("org.hol.guard.machine-health.plist");
    std::fs::write(&target, text).expect("write plist");
    target
}

fn macos_reason(plist_text: Option<&str>, runner: &mut FakeRunner) -> String {
    let directory = tempfile::tempdir().expect("tempdir");
    let plist_file = match plist_text {
        Some(text) => write_plist(directory.path(), text),
        None => directory.path().join("missing.plist"),
    };
    let answer = macos_verify(macos_request(&plist_file), runner).expect("a verdict");
    answer["reason_code"]
        .as_str()
        .expect("a reason code")
        .to_owned()
}

fn launchctl_environment() -> Vec<(String, String)> {
    [
        ("HOME", "/var/root"),
        ("LC_ALL", "C"),
        ("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
        ("TMPDIR", "/var/tmp"),
    ]
    .iter()
    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
    .collect()
}

#[test]
fn macos_verify_reads_the_registration_and_runs_each_launchctl_probe_in_turn() {
    let mut runner = FakeRunner::answering(vec![
        completed(0, NOT_DISABLED),
        completed(0, &loaded_print()),
    ]);

    assert_eq!(
        macos_reason(Some(INSTALLED_PLIST), &mut runner),
        "supervisor_running"
    );
    let expected = |arguments: [&str; 2]| -> Call {
        (
            "/bin/launchctl".to_owned(),
            arguments.iter().map(|item| (*item).to_owned()).collect(),
            "/".to_owned(),
            launchctl_environment(),
        )
    };
    assert_eq!(
        runner.calls,
        vec![
            expected(["print-disabled", "system"]),
            expected(["print", "system/org.hol.guard.machine-health"]),
        ]
    );
}

#[test]
fn an_idle_periodic_job_is_running() {
    let idle = loaded_print().replace("state = running", "state = not running");
    let mut runner = FakeRunner::answering(vec![completed(0, NOT_DISABLED), completed(0, &idle)]);

    assert_eq!(
        macos_reason(Some(INSTALLED_PLIST), &mut runner),
        "supervisor_running"
    );
}

#[test]
fn a_missing_registration_is_absent_without_running_launchctl() {
    let mut runner = FakeRunner::default();
    let directory = tempfile::tempdir().expect("tempdir");

    let answer = macos_verify(
        macos_request(&directory.path().join("missing.plist")),
        &mut runner,
    )
    .expect("a verdict");

    assert_eq!(
        answer,
        json!({"ok": true, "state": "absent", "reason_code": "supervisor_absent"})
    );
    assert!(runner.calls.is_empty());
}

#[test]
fn a_modified_registration_is_refused_before_launchctl_runs() {
    let cases = [
        (
            "<string>/Library/Application Support/HOL Guard/hol-guard/hol-guard</string>",
            "<string>/tmp/hol-guard</string>",
            "supervisor_executable_mismatch",
        ),
        (
            "<integer>300</integer>",
            "<integer>3600</integer>",
            "supervisor_schedule_invalid",
        ),
        (
            "<key>HOME</key><string>/var/root</string>",
            "",
            "supervisor_registration_invalid",
        ),
    ];
    for (old, new, reason) in cases {
        let mut runner = FakeRunner::default();
        let modified = INSTALLED_PLIST.replacen(old, new, 1);
        assert_eq!(macos_reason(Some(&modified), &mut runner), reason, "{old}");
        assert!(runner.calls.is_empty(), "{old}");
    }
}

#[test]
fn launchctl_separates_disabled_stopped_and_failed_probes() {
    let mut disabled = FakeRunner::answering(vec![completed(
        0,
        r#""org.hol.guard.machine-health" => true"#,
    )]);
    assert_eq!(
        macos_reason(Some(INSTALLED_PLIST), &mut disabled),
        "supervisor_disabled"
    );
    assert_eq!(disabled.calls.len(), 1);

    let mut stopped = FakeRunner::answering(vec![completed(0, NOT_DISABLED), completed(113, "")]);
    assert_eq!(
        macos_reason(Some(INSTALLED_PLIST), &mut stopped),
        "supervisor_stopped"
    );

    let mut failed = FakeRunner::answering(vec![Err(io::ErrorKind::TimedOut.into())]);
    assert_eq!(
        macos_reason(Some(INSTALLED_PLIST), &mut failed),
        "supervisor_probe_failed"
    );
    assert_eq!(failed.calls.len(), 1);
}

#[test]
fn an_unreadable_registration_is_a_failed_probe() {
    let unreadable = [
        "bplist00\u{1}\u{2}".to_owned(),
        r#"<!DOCTYPE plist [<!ENTITY e "x">]><plist><string>&e;</string></plist>"#.to_owned(),
        INSTALLED_PLIST.replace("<key>RunAtLoad</key><true/>", "<key>RunAtLoad</key>"),
        INSTALLED_PLIST.replace("</plist>", ""),
        "x".repeat(256 * 1024 + 1),
    ];
    for text in unreadable {
        let mut runner = FakeRunner::default();
        assert_eq!(
            macos_reason(Some(&text), &mut runner),
            "supervisor_probe_failed",
            "{}",
            &text[..text.len().min(40)]
        );
        assert!(runner.calls.is_empty());
    }
}

#[cfg(unix)]
#[test]
fn a_linked_registration_is_a_failed_probe() {
    let directory = tempfile::tempdir().expect("tempdir");
    let real = directory.path().join("real.plist");
    std::fs::write(&real, INSTALLED_PLIST).expect("write plist");
    let link = directory.path().join("org.hol.guard.machine-health.plist");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let mut runner = FakeRunner::default();

    let answer = macos_verify(macos_request(&link), &mut runner).expect("a verdict");

    assert_eq!(answer["reason_code"], "supervisor_probe_failed");
    assert!(runner.calls.is_empty());
}

#[test]
fn the_property_list_reads_like_plistlib() {
    let parsed = parse_plist(INSTALLED_PLIST.as_bytes()).expect("the installed plist");
    assert_eq!(parsed["StartInterval"], json!(300));
    assert_eq!(parsed["RunAtLoad"], json!(true));
    assert_eq!(parsed["ProgramArguments"][2], json!("health-report"));

    let values = parse_plist(
        br#"<plist><dict>
            <key>hex</key><integer>0x12C</integer>
            <key>dup</key><integer>1</integer>
            <key>real</key><real>300.0</real>
            <key>blob</key><data>AAEC</data>
            <key>when</key><date>2026-01-01T00:00:00Z</date>
            <key>escaped</key><string>a &amp; <!-- note -->b</string>
            <key>dup</key><integer>7</integer>
            <key>empty</key><string/>
            <key>off</key><false/>
        </dict></plist>"#,
    )
    .expect("a property list");
    assert_eq!(values["hex"], json!(300));
    assert_eq!(values["dup"], json!(7));
    assert_eq!(values["real"].as_f64(), Some(300.0));
    assert_eq!(values["blob"], Value::Null);
    assert_eq!(values["when"], Value::Null);
    assert_eq!(values["escaped"], json!("a & b"));
    assert_eq!(values["empty"], json!(""));
    assert_eq!(values["off"], json!(false));
    assert_eq!(parse_plist(b"<plist/>"), Some(Value::Null));

    for refused in [
        &b"<dict/>"[..],
        b"<plist><dict><key>a</key></dict></plist>",
        b"<plist><dict><string>a</string><string>b</string></dict></plist>",
        b"<plist><integer>nine</integer></plist>",
        b"<plist><real>nan</real></plist>",
        b"<plist><unknown/></plist>",
        b"<plist><string><b/></string></plist>",
        b"<plist><string>a</string><string>b</string></plist>",
    ] {
        assert_eq!(
            parse_plist(refused),
            None,
            "{}",
            String::from_utf8_lossy(refused)
        );
    }
}

fn windows_request(windows_directory: &str) -> Request {
    request(json!({
        "schema": "supervisor-verdict.v1",
        "op": "windows-verify",
        "executable": WINDOWS_EXECUTABLE,
        "windows_directory": windows_directory,
    }))
}

#[test]
fn windows_verify_runs_the_pinned_schtasks_with_a_bounded_context() {
    let mut runner = FakeRunner::answering(vec![completed(0, &task_xml())]);

    let answer = windows_verify(&windows_request(r"D:\Windows"), &mut runner).expect("a verdict");

    assert_eq!(
        answer,
        json!({"ok": true, "state": "running", "reason_code": "supervisor_running"})
    );
    let environment: Vec<(String, String)> = [
        ("ComSpec", r"D:\Windows\System32\cmd.exe"),
        ("SystemDrive", "D:"),
        ("SystemRoot", r"D:\Windows"),
        ("WINDIR", r"D:\Windows"),
    ]
    .iter()
    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
    .collect();
    assert_eq!(
        runner.calls,
        vec![(
            r"D:\Windows\System32\schtasks.exe".to_owned(),
            [
                "/Query",
                "/TN",
                r"\HOL Guard\Machine Health",
                "/XML",
                "/HRESULT"
            ]
            .iter()
            .map(|item| (*item).to_owned())
            .collect(),
            r"D:\Windows\System32".to_owned(),
            environment,
        )]
    );
}

#[test]
fn schtasks_separates_absence_from_a_failed_probe() {
    let reason = |answer: io::Result<Probe>| {
        let mut runner = FakeRunner::answering(vec![answer]);
        windows_verify(&windows_request(r"C:\Windows"), &mut runner).expect("a verdict")
            ["reason_code"]
            .as_str()
            .expect("a reason code")
            .to_owned()
    };

    assert_eq!(reason(completed(0x8007_0002, "")), "supervisor_absent");
    assert_eq!(reason(completed(-2_147_024_894, "")), "supervisor_absent");
    assert_eq!(reason(completed(5, "")), "supervisor_probe_failed");
    assert_eq!(
        reason(Err(io::ErrorKind::TimedOut.into())),
        "supervisor_probe_failed"
    );
}

#[test]
fn a_windows_directory_without_a_drive_never_runs_schtasks() {
    for directory in [r"\Windows", r"\\server\share\Windows", "", "1:\\Windows"] {
        let mut runner = FakeRunner::default();
        let answer = windows_verify(&windows_request(directory), &mut runner).expect("a verdict");
        assert_eq!(
            answer["reason_code"], "supervisor_probe_failed",
            "{directory}"
        );
        assert!(runner.calls.is_empty());
    }
    let (system_directory, _) = windows_context(r"C:\Windows\").expect("a drive");
    assert_eq!(system_directory, r"C:\Windows\System32");
}

#[test]
fn a_verify_request_never_takes_the_callers_evidence() {
    let directory = tempfile::tempdir().expect("tempdir");
    let plist_file = write_plist(directory.path(), INSTALLED_PLIST);
    let mut with_probe = json!({
        "schema": "supervisor-verdict.v1",
        "op": "macos-verify",
        "executable": MAC_EXECUTABLE,
        "plist_file": plist_file.to_str().expect("utf-8 path"),
        "plist_path": PLIST_PATH,
        "stdout_log": "/Library/Logs/HOL Guard/machine-health.log",
        "stderr_log": "/Library/Logs/HOL Guard/machine-health-error.log",
    });
    with_probe["loaded"] = json!({"returncode": 0, "stdout": loaded_print()});
    let mut runner = FakeRunner::default();
    assert_eq!(macos_verify(request(with_probe), &mut runner), None);

    let mut with_task = json!({
        "schema": "supervisor-verdict.v1",
        "op": "windows-verify",
        "executable": WINDOWS_EXECUTABLE,
        "windows_directory": r"C:\Windows",
    });
    with_task["task"] = json!({"returncode": 0, "stdout": task_xml()});
    assert_eq!(windows_verify(&request(with_task), &mut runner), None);
    assert!(runner.calls.is_empty());
}
