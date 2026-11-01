use serde_json::{json, Value};

use super::{answer, nt_normcase_normpath, security_descriptor_valid};

const MAC_EXECUTABLE: &str = "/Library/Application Support/HOL Guard/hol-guard/hol-guard";
const PLIST_PATH: &str = "/Library/LaunchDaemons/org.hol.guard.machine-health.plist";
const STDOUT_LOG: &str = "/Library/Logs/HOL Guard/machine-health.log";
const STDERR_LOG: &str = "/Library/Logs/HOL Guard/machine-health-error.log";
const WINDOWS_EXECUTABLE: &str = r"C:\Program Files/HOL Guard/hol-guard/hol-guard.exe";
const NOT_DISABLED: &str = r#"disabled services = { "other" => true }"#;

fn plist() -> Value {
    json!({
        "Label": "org.hol.guard.machine-health",
        "ProgramArguments": [MAC_EXECUTABLE, "mdm", "health-report", "--scope", "machine", "--json"],
        "EnvironmentVariables": {"HOME": "/var/root", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": "/var/tmp"},
        "RunAtLoad": true,
        "StartInterval": 300,
        "ProcessType": "Background",
        "StandardOutPath": STDOUT_LOG,
        "StandardErrorPath": STDERR_LOG,
    })
}

fn loaded_print() -> String {
    format!(
        "system/org.hol.guard.machine-health = {{\n    path = {PLIST_PATH}\n    state = running\n    program = {MAC_EXECUTABLE}\n    arguments = {{\n        {MAC_EXECUTABLE}\n        mdm\n        health-report\n        --scope\n        machine\n        --json\n    }}\n    run interval = 300 seconds\n}}"
    )
}

fn probe(returncode: i64, stdout: &str) -> Value {
    json!({"returncode": returncode, "stdout": stdout})
}

fn run(request: Value) -> Value {
    answer(&serde_json::to_vec(&request).expect("request")).expect("request is well formed")
}

fn macos(plist: Value, disabled: Option<Value>, loaded: Option<Value>) -> Value {
    let mut request = json!({
        "schema": "supervisor-verdict.v1",
        "op": "macos",
        "executable": MAC_EXECUTABLE,
        "plist": plist,
        "plist_path": PLIST_PATH,
        "stdout_log": STDOUT_LOG,
        "stderr_log": STDERR_LOG,
    });
    if let Some(disabled) = disabled {
        request["disabled"] = disabled;
    }
    if let Some(loaded) = loaded {
        request["loaded"] = loaded;
    }
    run(request)
}

fn reason(answer: &Value) -> &str {
    answer["reason_code"].as_str().expect("a verdict")
}

fn loaded_reason(loaded: &str) -> String {
    let answer = macos(
        plist(),
        Some(probe(0, NOT_DISABLED)),
        Some(probe(0, loaded)),
    );
    reason(&answer).to_owned()
}

#[test]
fn a_macos_verdict_asks_for_each_probe_in_turn_and_accepts_the_exact_job() {
    assert_eq!(
        macos(plist(), None, None),
        json!({"ok": true, "next": "disabled"})
    );
    assert_eq!(
        macos(plist(), Some(probe(0, NOT_DISABLED)), None),
        json!({"ok": true, "next": "loaded"})
    );
    assert_eq!(
        macos(
            plist(),
            Some(probe(0, NOT_DISABLED)),
            Some(probe(0, &loaded_print()))
        ),
        json!({"ok": true, "state": "running", "reason_code": "supervisor_running"})
    );
    let idle = loaded_print().replace("state = running", "state = not running");
    assert_eq!(loaded_reason(&idle), "supervisor_running");
}

#[test]
fn a_modified_registration_is_refused_before_any_probe() {
    let cases: [(&str, Value, &str); 9] = [
        ("Label", json!("other"), "supervisor_registration_invalid"),
        (
            "ProgramArguments",
            json!(["/tmp/hol-guard"]),
            "supervisor_executable_mismatch",
        ),
        (
            "EnvironmentVariables",
            json!({"PATH": "/tmp"}),
            "supervisor_registration_invalid",
        ),
        ("RunAtLoad", json!(1), "supervisor_schedule_invalid"),
        ("StartInterval", json!(3600), "supervisor_schedule_invalid"),
        ("StartInterval", json!(true), "supervisor_schedule_invalid"),
        (
            "ProcessType",
            json!("Interactive"),
            "supervisor_schedule_invalid",
        ),
        (
            "StandardOutPath",
            json!("/tmp/out.log"),
            "supervisor_registration_invalid",
        ),
        (
            "StandardErrorPath",
            Value::Null,
            "supervisor_registration_invalid",
        ),
    ];
    for (key, value, expected) in cases {
        let mut payload = plist();
        payload[key] = value;
        let answer = macos(payload, None, None);
        assert_eq!(answer["state"], json!("stopped"), "{key}");
        assert_eq!(reason(&answer), expected, "{key}");
    }
    let mut extra_variable = plist();
    extra_variable["EnvironmentVariables"]["DYLD_INSERT_LIBRARIES"] = json!("/tmp/x.dylib");
    assert_eq!(
        reason(&macos(extra_variable, None, None)),
        "supervisor_registration_invalid"
    );
    assert_eq!(
        reason(&macos(json!([]), None, None)),
        "supervisor_registration_invalid"
    );
    assert_eq!(
        reason(&macos(Value::Null, None, None)),
        "supervisor_registration_invalid"
    );
}

#[test]
fn a_real_start_interval_of_three_hundred_matches_like_python() {
    let mut payload = plist();
    payload["StartInterval"] = serde_json::from_str("300.0").expect("number");
    assert_eq!(macos(payload, None, None)["next"], json!("disabled"));
}

#[test]
fn launchctl_separates_disabled_stopped_and_failed_probes() {
    let disabled = probe(0, r#""ORG.HOL.GUARD.MACHINE-HEALTH" =>   true"#);
    assert_eq!(
        macos(plist(), Some(disabled), None),
        json!({"ok": true, "state": "disabled", "reason_code": "supervisor_disabled"})
    );
    let failed = macos(plist(), Some(probe(1, "")), None);
    assert_eq!(
        (failed["state"].as_str(), reason(&failed)),
        (Some("unknown"), "supervisor_probe_failed")
    );
    let stopped = macos(plist(), Some(probe(0, NOT_DISABLED)), Some(probe(113, "")));
    assert_eq!(reason(&stopped), "supervisor_stopped");
}

#[test]
fn a_modified_loaded_job_is_refused() {
    let print = loaded_print();
    let cases = [
        (
            format!("program = {MAC_EXECUTABLE}"),
            "program = /tmp/evil".to_owned(),
            "supervisor_executable_mismatch",
        ),
        (
            "        --json".to_owned(),
            "        --version".to_owned(),
            "supervisor_executable_mismatch",
        ),
        (
            "run interval = 300 seconds".to_owned(),
            "run interval = 3600 seconds".to_owned(),
            "supervisor_schedule_invalid",
        ),
        (
            "state = running".to_owned(),
            "state = waiting".to_owned(),
            "supervisor_stopped",
        ),
        (
            format!("path = {PLIST_PATH}"),
            "path = /tmp/evil.plist".to_owned(),
            "supervisor_registration_invalid",
        ),
    ];
    for (old, new, expected) in cases {
        assert_eq!(
            loaded_reason(&print.replacen(&old, &new, 1)),
            expected,
            "{new}"
        );
    }
    let extra_argument = print.replace("        --json\n", "        --json\n        --debug\n");
    assert_eq!(
        loaded_reason(&extra_argument),
        "supervisor_executable_mismatch"
    );
}

pub(super) fn task_xml() -> String {
    format!(
        "<?xml version='1.0' encoding='utf-16'?>\n<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\" version=\"1.4\"><RegistrationInfo><URI>\\HOL Guard\\Machine Health</URI><SecurityDescriptor>D:P(A;;FA;;;SY)(A;;FA;;;BA)</SecurityDescriptor></RegistrationInfo><Triggers><TimeTrigger><Enabled>true</Enabled><StartBoundary>2000-01-01T00:00:00</StartBoundary><Repetition><Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition></TimeTrigger></Triggers><Principals><Principal id=\"System\"><UserId>S-1-5-18</UserId><LogonType>ServiceAccount</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><Enabled>true</Enabled><Hidden>true</Hidden><ExecutionTimeLimit>PT5M</ExecutionTimeLimit></Settings><Actions Context=\"System\"><Exec><Command>{}</Command><Arguments>mdm health-report --scope machine --json</Arguments></Exec></Actions></Task>",
        r"C:\Program Files\HOL Guard\hol-guard\hol-guard.exe"
    )
}

fn windows(returncode: i64, stdout: &str) -> Value {
    run(json!({
        "schema": "supervisor-verdict.v1",
        "op": "windows",
        "executable": WINDOWS_EXECUTABLE,
        "task": probe(returncode, stdout),
    }))
}

fn windows_reason(xml: &str) -> String {
    reason(&windows(0, xml)).to_owned()
}

#[test]
fn the_exact_system_task_is_running() {
    assert_eq!(
        windows(0, &task_xml()),
        json!({"ok": true, "state": "running", "reason_code": "supervisor_running"})
    );
    let with_bom = format!("\u{feff}{}", task_xml());
    assert_eq!(windows_reason(&with_bom), "supervisor_running");
    let spelled = task_xml().replace(
        r"C:\Program Files\HOL Guard\hol-guard\hol-guard.exe",
        r"c:/program files/HOL Guard/./bin/../hol-guard/HOL-GUARD.EXE",
    );
    assert_eq!(windows_reason(&spelled), "supervisor_running");
}

#[test]
fn a_modified_task_is_refused() {
    let cases = [
        (
            "<Settings><MultipleInstancesPolicy>",
            "<Settings><Enabled>FALSE</Enabled><MultipleInstancesPolicy>",
            "supervisor_disabled",
        ),
        (
            r"C:\Program Files\HOL Guard\hol-guard\hol-guard.exe",
            r"C:\Users\attacker\hol-guard.exe",
            "supervisor_executable_mismatch",
        ),
        (
            "--scope machine --json</Arguments>",
            "--scope machine</Arguments>",
            "supervisor_executable_mismatch",
        ),
        (
            "<UserId>S-1-5-18</UserId>",
            "<UserId>S-1-5-32-545</UserId>",
            "supervisor_registration_invalid",
        ),
        (
            "<LogonType>ServiceAccount",
            "<LogonType>Password",
            "supervisor_registration_invalid",
        ),
        (
            "<Interval>PT5M</Interval>",
            "<Interval>PT1H</Interval>",
            "supervisor_schedule_invalid",
        ),
        (
            "<StopAtDurationEnd>false",
            "<StopAtDurationEnd>true",
            "supervisor_schedule_invalid",
        ),
        (
            "<StartBoundary>2000-01-01T00:00:00",
            "<StartBoundary>2999-01-01T00:00:00",
            "supervisor_schedule_invalid",
        ),
        (
            "</StartBoundary>",
            "</StartBoundary><EndBoundary>2001-01-01T00:00:00</EndBoundary>",
            "supervisor_schedule_invalid",
        ),
        (
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)",
            "D:(A;;FA;;;WD)",
            "supervisor_registration_invalid",
        ),
        (
            "<Hidden>true",
            "<Hidden>false",
            "supervisor_schedule_invalid",
        ),
        (
            "<DisallowStartIfOnBatteries>false",
            "<DisallowStartIfOnBatteries>true",
            "supervisor_schedule_invalid",
        ),
        (
            "<URI>\\HOL Guard\\Machine Health",
            "<URI>\\Other",
            "supervisor_registration_invalid",
        ),
        (
            "<TimeTrigger>",
            "<BootTrigger/><TimeTrigger>",
            "supervisor_schedule_invalid",
        ),
        (
            "</Principals>",
            "<Principal id=\"Other\"/></Principals>",
            "supervisor_registration_invalid",
        ),
        (
            "</Exec>",
            "</Exec><Exec/>",
            "supervisor_registration_invalid",
        ),
    ];
    for (old, new, expected) in cases {
        let xml = task_xml().replacen(old, new, 1);
        assert_ne!(xml, task_xml(), "{old}");
        assert_eq!(windows_reason(&xml), expected, "{new}");
    }
}

#[test]
fn the_wrong_trigger_wins_over_the_wrong_action_context() {
    let both = task_xml()
        .replace("TimeTrigger>", "CalendarTrigger>")
        .replace("Context=\"System\"", "Context=\"InteractiveUsers\"");
    assert_eq!(windows_reason(&both), "supervisor_schedule_invalid");
    let context = task_xml().replace("Context=\"System\"", "Context=\"InteractiveUsers\"");
    assert_eq!(windows_reason(&context), "supervisor_registration_invalid");
}

#[test]
fn task_text_reads_like_element_tree() {
    let commented = task_xml().replace("<UserId>S-1-5-18", "<UserId>S-1-5<!-- note -->-18");
    assert_eq!(windows_reason(&commented), "supervisor_running");
    let long_s = task_xml().replace("<UserId>S-1-5-18", "<UserId>NT AUTHORITY\\ſYSTEM");
    assert_eq!(windows_reason(&long_s), "supervisor_running");
    let prefixed = task_xml()
        .replace("<Task xmlns=", "<t:Task xmlns:t=")
        .replace("</Task>", "</t:Task>");
    assert_eq!(windows_reason(&prefixed), "supervisor_registration_invalid");
    let wrong_root = task_xml().replace("mit/task\"", "mit/other\"");
    assert_eq!(
        windows_reason(&wrong_root),
        "supervisor_registration_invalid"
    );
}

#[test]
fn schtasks_separates_absence_from_probe_failure() {
    for absent in [2, 0x8007_0002, -2_147_024_894] {
        assert_eq!(
            windows(absent, ""),
            json!({"ok": true, "state": "absent", "reason_code": "supervisor_absent"})
        );
    }
    assert_eq!(windows(5, "")["state"], json!("unknown"));
    assert_eq!(
        windows(0, "<Task")["reason_code"],
        json!("supervisor_probe_failed")
    );
}

#[test]
fn the_security_descriptor_admits_only_the_protected_spellings() {
    for valid in [
        "D:P(A;;FA;;;SY)(A;;FA;;;BA)",
        "O:S-1-5-32-544G:S-1-5-18D:P(A;;FA;;;S-1-5-32-544)(A;;FA;;;S-1-5-18)",
        "o:bag:syd:p(a;;fa;;;ba)(a;;fa;;;sy)",
    ] {
        assert!(security_descriptor_valid(valid), "{valid}");
    }
    for invalid in [
        "D:(A;;FA;;;SY)(A;;FA;;;BA)",
        "D:P(A;;FA;;;SY)",
        "D:P(A;;FA;;;SY)(A;;FA;;;SY)",
        "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)",
        "O:WDD:P(A;;FA;;;SY)(A;;FA;;;BA)",
        "D:P(A;;FA;;SY)(A;;FA;;;BA)",
    ] {
        assert!(!security_descriptor_valid(invalid), "{invalid}");
    }
}

#[test]
fn nt_paths_normalize_like_ntpath() {
    let cases = [
        (
            r"C:\Program Files/HOL Guard/hol-guard/hol-guard.exe",
            r"c:\program files\hol guard\hol-guard\hol-guard.exe",
        ),
        (r"C:\a\..\..\b", r"c:\b"),
        (r"C:a\..\..\b", r"c:..\b"),
        (r"..\a", r"..\a"),
        ("", "."),
        (r"\\server\share\x\..\y", r"\\server\share\y"),
    ];
    for (path, expected) in cases {
        assert_eq!(nt_normcase_normpath(path), expected, "{path}");
    }
}

#[test]
fn malformed_requests_fail_the_command() {
    let requests = [
        json!({"op": "windows", "executable": "x", "task": probe(0, "")}),
        json!({"schema": "supervisor-verdict.v1", "op": "linux", "executable": "x"}),
        json!({"schema": "supervisor-verdict.v1", "op": "windows", "executable": "x"}),
        json!({"schema": "supervisor-verdict.v1", "op": "macos", "executable": "x", "plist": {}}),
        json!({"schema": "supervisor-verdict.v1", "op": "windows", "executable": "x", "task": {"returncode": "0", "stdout": ""}}),
        json!({"schema": "supervisor-verdict.v1", "op": "windows", "executable": "x", "task": probe(0, ""), "extra": 1}),
    ];
    for request in requests {
        let bytes = serde_json::to_vec(&request).expect("request");
        assert_eq!(
            answer(&bytes),
            Err("supervisor_verdict_request_invalid".to_owned()),
            "{request}"
        );
    }
    assert!(answer(b"[]").is_err());
}
