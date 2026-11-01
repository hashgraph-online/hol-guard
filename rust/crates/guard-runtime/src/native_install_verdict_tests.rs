use std::collections::VecDeque;
use std::io;
use std::time::Duration;

use serde_json::{json, Value};

use super::{run_command, verify, Invocation, Ran, Request, Runner, WindowsContext};

const PIN: &str = "0123456789ABCDEF0123456789ABCDEF01234567";

struct FakeRunner {
    answers: VecDeque<io::Result<Ran>>,
    calls: Vec<Invocation>,
}

impl FakeRunner {
    fn answering(answers: Vec<io::Result<Ran>>) -> Self {
        Self {
            answers: answers.into(),
            calls: Vec::new(),
        }
    }
}

impl Runner for FakeRunner {
    fn run(&mut self, invocation: &Invocation) -> io::Result<Ran> {
        self.calls.push(Invocation {
            program: invocation.program.clone(),
            arguments: invocation.arguments.clone(),
            context: invocation.context.as_ref().map(|context| WindowsContext {
                cwd: context.cwd.clone(),
                environment: context.environment.clone(),
            }),
            timeout: invocation.timeout,
        });
        self.answers
            .pop_front()
            .unwrap_or_else(|| Err(io::Error::other("no answer queued")))
    }
}

fn ran(success: bool, stdout: &str, stderr: &str) -> io::Result<Ran> {
    Ok(Ran {
        success,
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
    })
}

fn receipt(version: Option<&str>) -> io::Result<Ran> {
    let entry = version.map_or_else(String::new, |value| {
        format!("<key>pkg-version</key><string>{value}</string>")
    });
    ran(
        true,
        &format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict><key>pkgid</key><string>org.hol.guard</string>\
             {entry}<key>install-time</key><integer>1</integer></dict></plist>\n"
        ),
        "",
    )
}

fn request(value: Value) -> Request {
    serde_json::from_value(value).expect("request")
}

fn macos(team_id: Option<&str>) -> Request {
    request(json!({
        "schema": "native-install-verdict.v1",
        "platform": "macos",
        "runtime_root": "/Library/Application Support/HOL Guard",
        "macos_team_id": team_id,
    }))
}

fn windows(pins: &[&str]) -> Request {
    request(json!({
        "schema": "native-install-verdict.v1",
        "platform": "windows",
        "runtime_root": r"C:\Program Files\HOL Guard",
        "windows_signer_thumbprints": pins,
        "windows_directory": r"D:\Windows",
    }))
}

fn answer(request: &Request, runner: &mut FakeRunner) -> Value {
    verify(request, runner).expect("verdict").to_json()
}

fn expected(status: &str, reason: &str, identity: &str, signature: &str, version: Value) -> Value {
    json!({
        "ok": true,
        "status": status,
        "reason_code": reason,
        "package_identity": identity,
        "signature_state": signature,
        "version": version,
    })
}

#[test]
fn macos_requires_the_receipt_a_strict_signature_and_the_pinned_team() {
    let mut runner = FakeRunner::answering(vec![
        receipt(Some("3.0.0a1")),
        ran(true, "", ""),
        ran(
            true,
            "",
            "Executable=/path/hol-guard\nTeamIdentifier=TEAM123\n",
        ),
    ]);

    assert_eq!(
        answer(&macos(Some("TEAM123")), &mut runner),
        expected(
            "healthy",
            "native_install_valid",
            "org.hol.guard",
            "valid",
            json!("3.0.0a1")
        )
    );
    let executable = "/Library/Application Support/HOL Guard/hol-guard/hol-guard";
    let calls: Vec<(&str, Vec<&str>, Duration)> = runner
        .calls
        .iter()
        .map(|call| {
            assert!(call.context.is_none());
            (
                call.program.as_str(),
                call.arguments.iter().map(String::as_str).collect(),
                call.timeout,
            )
        })
        .collect();
    assert_eq!(
        calls,
        [
            (
                "/usr/sbin/pkgutil",
                vec!["--pkg-info-plist", "org.hol.guard"],
                Duration::from_secs(5)
            ),
            (
                "/usr/bin/codesign",
                vec!["--verify", "--deep", "--strict", executable],
                Duration::from_secs(10)
            ),
            (
                "/usr/bin/codesign",
                vec!["-d", "--verbose=4", executable],
                Duration::from_secs(10)
            ),
        ]
    );
}

#[test]
fn macos_without_a_team_pin_never_runs_a_probe() {
    let mut runner = FakeRunner::answering(Vec::new());

    assert_eq!(
        answer(&macos(None), &mut runner),
        expected(
            "unknown",
            "native_publisher_pin_absent",
            "org.hol.guard",
            "unverified",
            Value::Null
        )
    );
    assert!(runner.calls.is_empty());
}

#[test]
fn macos_without_a_readable_receipt_reports_the_package_absent() {
    let absent = expected(
        "absent",
        "native_package_receipt_absent",
        "org.hol.guard",
        "unknown",
        Value::Null,
    );
    for first in [
        ran(false, "", "No receipt for 'org.hol.guard' found"),
        Err(io::ErrorKind::TimedOut.into()),
        ran(true, "not a property list", ""),
        ran(true, "<html/>", ""),
    ] {
        let mut runner = FakeRunner::answering(vec![first]);
        assert_eq!(answer(&macos(Some("TEAM123")), &mut runner), absent);
        assert_eq!(runner.calls.len(), 1);
    }
    let mut runner = FakeRunner::answering(vec![
        receipt(Some("3.0.0")),
        ran(true, "", ""),
        Err(io::ErrorKind::TimedOut.into()),
    ]);
    assert_eq!(answer(&macos(Some("TEAM123")), &mut runner), absent);
}

#[test]
fn macos_rejects_a_receipt_without_a_valid_version() {
    for version in [None, Some(""), Some("   "), Some("not-a-version")] {
        let mut runner = FakeRunner::answering(vec![
            receipt(version),
            ran(true, "", ""),
            ran(true, "", "TeamIdentifier=TEAM123\n"),
        ]);
        assert_eq!(
            answer(&macos(Some("TEAM123")), &mut runner),
            expected(
                "tampered",
                "native_package_version_invalid",
                "org.hol.guard",
                "invalid",
                Value::Null
            )
        );
    }
    let mut runner = FakeRunner::answering(vec![
        receipt(Some(" 3.1.0 ")),
        ran(true, "", ""),
        ran(true, "", "TeamIdentifier=TEAM123\n"),
    ]);
    assert_eq!(
        answer(&macos(Some("TEAM123")), &mut runner)["version"],
        json!("3.1.0")
    );
}

#[test]
fn macos_rejects_a_failed_signature_or_another_team() {
    for (signature, details) in [
        (
            ran(false, "", ""),
            ran(true, "", "TeamIdentifier=TEAM123\n"),
        ),
        (
            ran(true, "", ""),
            ran(false, "", "TeamIdentifier=TEAM123\n"),
        ),
        (
            ran(true, "", ""),
            ran(true, "", "Executable=/path/hol-guard\n"),
        ),
        (ran(true, "", ""), ran(true, "", "TeamIdentifier=OTHER\n")),
        (
            ran(true, "", ""),
            ran(true, "", " TeamIdentifier=TEAM123\n"),
        ),
    ] {
        let mut runner = FakeRunner::answering(vec![receipt(Some("3.0.0a1")), signature, details]);
        assert_eq!(
            answer(&macos(Some("TEAM123")), &mut runner),
            expected(
                "tampered",
                "native_publisher_signature_invalid",
                "org.hol.guard",
                "invalid",
                json!("3.0.0a1")
            )
        );
    }
}

#[test]
fn windows_uses_pinned_powershell_and_a_clean_process_context() {
    let mut runner = FakeRunner::answering(vec![ran(
        true,
        &format!("{{\"Status\":\"Valid\",\"Thumbprint\":\"{PIN}\",\"Version\":\"3.0.0a1\"}}\r\n"),
        "",
    )]);

    assert_eq!(
        answer(&windows(&[PIN]), &mut runner),
        expected(
            "healthy",
            "native_install_valid",
            "HOLGuardMachine",
            "valid",
            json!("3.0.0a1")
        )
    );
    let call = &runner.calls[0];
    assert_eq!(
        call.program,
        r"D:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    );
    assert_eq!(call.timeout, Duration::from_secs(15));
    assert_eq!(
        call.arguments[..3],
        ["-NoProfile", "-NonInteractive", "-Command"]
    );
    let executable = r"C:\Program Files\HOL Guard\hol-guard\hol-guard.exe";
    assert_eq!(
        call.arguments[3],
        format!(
            "$s=Get-AuthenticodeSignature -LiteralPath '{executable}';\
             $v=(Get-Item -LiteralPath '{executable}').VersionInfo.ProductVersion;\
             @{{Status=$s.Status.ToString();Thumbprint=if($s.SignerCertificate)\
             {{$s.SignerCertificate.Thumbprint}}else{{$null}};Version=$v}}|ConvertTo-Json -Compress"
        )
    );
    assert_eq!(
        call.context,
        Some(WindowsContext {
            cwd: r"D:\Windows\System32".to_owned(),
            environment: vec![
                (
                    "ComSpec".to_owned(),
                    r"D:\Windows\System32\cmd.exe".to_owned()
                ),
                ("SystemRoot".to_owned(), r"D:\Windows".to_owned()),
                ("WINDIR".to_owned(), r"D:\Windows".to_owned()),
            ],
        })
    );
}

#[test]
fn windows_quotes_the_executable_for_powershell() {
    let mut case = windows(&[PIN]);
    case.runtime_root = r"C:\O'Brien\HOL Guard".to_owned();
    let mut runner = FakeRunner::answering(vec![Err(io::ErrorKind::TimedOut.into())]);

    answer(&case, &mut runner);

    assert!(runner.calls[0].arguments[3]
        .starts_with(r"$s=Get-AuthenticodeSignature -LiteralPath 'C:\O''Brien\HOL Guard\hol-guard\hol-guard.exe';"));
}

#[test]
fn windows_without_a_pin_never_runs_powershell() {
    let mut runner = FakeRunner::answering(Vec::new());

    assert_eq!(
        answer(&windows(&[]), &mut runner),
        expected(
            "unknown",
            "native_publisher_pin_absent",
            "HOLGuardMachine",
            "unverified",
            Value::Null
        )
    );
    assert!(runner.calls.is_empty());
}

#[test]
fn windows_without_an_answer_reports_the_identity_absent() {
    let absent = expected(
        "absent",
        "native_package_identity_absent",
        "HOLGuardMachine",
        "unknown",
        Value::Null,
    );
    for first in [
        ran(false, "{\"Status\":\"Valid\"}", ""),
        Err(io::ErrorKind::TimedOut.into()),
        ran(true, "not json", ""),
    ] {
        let mut runner = FakeRunner::answering(vec![first]);
        assert_eq!(answer(&windows(&[PIN]), &mut runner), absent);
    }
    let mut without_directory = windows(&[PIN]);
    without_directory.windows_directory = None;
    let mut runner = FakeRunner::answering(Vec::new());
    assert_eq!(answer(&without_directory, &mut runner), absent);
    assert!(runner.calls.is_empty());
}

#[test]
fn windows_rejects_an_unpinned_or_invalid_signer() {
    let spaced = "01234567 89abcdef 01234567 89ABCDEF 01234567";
    let mut runner = FakeRunner::answering(vec![ran(
        true,
        &format!("{{\"Status\":\"Valid\",\"Thumbprint\":\"{spaced}\",\"Version\":\"3.0.0\"}}"),
        "",
    )]);
    assert_eq!(answer(&windows(&[PIN]), &mut runner)["status"], "healthy");
    let mut runner = FakeRunner::answering(vec![ran(
        true,
        &format!("{{\"Status\":\"Valid\",\"Thumbprint\":\"{PIN}\",\"Version\":\"3.0.0\"}}"),
        "",
    )]);
    let lower_pin = PIN.to_lowercase();
    assert_eq!(
        answer(&windows(&[lower_pin.as_str()]), &mut runner)["status"],
        "healthy"
    );

    for payload in [
        json!({"Status": "Valid", "Thumbprint": "A".repeat(40), "Version": "3.0.0a1"}),
        json!({"Status": "HashMismatch", "Thumbprint": PIN, "Version": "3.0.0a1"}),
        json!({"Status": "Valid", "Thumbprint": null, "Version": "3.0.0a1"}),
        json!({"Status": "Valid", "Thumbprint": PIN, "Version": null}),
        json!({"Status": "Valid", "Thumbprint": PIN, "Version": "bogus"}),
        json!([PIN]),
    ] {
        let mut runner = FakeRunner::answering(vec![ran(true, &payload.to_string(), "")]);
        assert_eq!(
            answer(&windows(&["B".repeat(40).as_str(), PIN]), &mut runner),
            expected(
                "tampered",
                "native_publisher_signature_invalid",
                "HOLGuardMachine",
                "invalid",
                Value::Null
            )
        );
    }
}

#[test]
fn another_platform_is_unsupported_and_mixed_requests_are_refused() {
    let mut runner = FakeRunner::answering(Vec::new());
    let mut linux = macos(None);
    linux.platform = "linux".to_owned();
    assert_eq!(
        answer(&linux, &mut runner),
        expected(
            "unsupported",
            "native_platform_unsupported",
            "unknown",
            "unsupported",
            Value::Null
        )
    );
    let mut mac_with_pins = macos(Some("TEAM123"));
    mac_with_pins.windows_signer_thumbprints = vec![PIN.to_owned()];
    let mut windows_with_team = windows(&[PIN]);
    windows_with_team.macos_team_id = Some("TEAM123".to_owned());
    for case in [mac_with_pins, windows_with_team] {
        assert!(verify(&case, &mut runner).is_none());
    }
    assert!(runner.calls.is_empty());
}

#[test]
fn the_command_refuses_unknown_fields_and_schemas() {
    for body in [
        json!({"schema": "native-install-verdict.v0", "platform": "linux", "runtime_root": "/"}),
        json!({"schema": "native-install-verdict.v1", "platform": "linux", "runtime_root": "/", "extra": 1}),
    ] {
        assert_eq!(
            run_command(body.to_string().as_bytes()).err().as_deref(),
            Some("native_install_request_invalid")
        );
    }
    let linux =
        json!({"schema": "native-install-verdict.v1", "platform": "linux", "runtime_root": "/"});
    let response: Value =
        serde_json::from_slice(&run_command(linux.to_string().as_bytes()).expect("answer"))
            .expect("json");
    assert_eq!(response["reason_code"], "native_platform_unsupported");
}
