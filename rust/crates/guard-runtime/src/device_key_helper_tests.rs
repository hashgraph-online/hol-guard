use super::*;

const GENERATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct FakeRunner {
    answer: Option<(i32, Vec<u8>, Vec<u8>)>,
    seen: Vec<Invocation>,
}

impl FakeRunner {
    fn answering(code: i32, stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            answer: Some((code, stdout.into(), Vec::new())),
            seen: Vec::new(),
        }
    }
}

impl Runner for FakeRunner {
    fn run(&mut self, invocation: &Invocation) -> io::Result<Ran> {
        self.seen.push(Invocation {
            program: invocation.program.clone(),
            arguments: invocation.arguments.clone(),
            cwd: invocation.cwd.clone(),
            environment: invocation.environment.clone(),
            input: invocation.input.clone(),
        });
        let (code, stdout, stderr) = self
            .answer
            .clone()
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
        Ok(Ran {
            code: Some(code),
            stdout,
            stderr,
        })
    }
}

fn request(platform: &str, verb: &str, payload: Option<&str>) -> Request {
    Request {
        schema: SCHEMA.to_owned(),
        platform: platform.to_owned(),
        runtime_root: "/Library/HOL Guard".to_owned(),
        verb: verb.to_owned(),
        generation: GENERATION.to_owned(),
        payload: payload.map(str::to_owned),
    }
}

fn no_windows_directory() -> Option<String> {
    None
}

fn probe_output(ok: bool, state: &str, public_key: Value, reason: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "ok": ok,
        "state": state,
        "protectionLevel": "os-protected",
        "publicKeyX963": public_key,
        "reasonCode": reason,
    }))
    .unwrap()
}

fn public_key() -> String {
    let mut key = vec![4u8];
    key.extend([7u8; 64]);
    STANDARD.encode(key)
}

fn der_integer(value: &[u8]) -> Vec<u8> {
    let mut content = value.to_vec();
    if content.first().is_some_and(|byte| byte & 0x80 != 0) {
        content.insert(0, 0);
    }
    let mut out = vec![0x02, content.len() as u8];
    out.extend(content);
    out
}

fn der_signature(r: &[u8], s: &[u8]) -> Vec<u8> {
    let body = [der_integer(r), der_integer(s)].concat();
    let mut out = vec![0x30, body.len() as u8];
    out.extend(body);
    out
}

fn signing_output(signature: &[u8], changes: Value) -> Vec<u8> {
    let mut object = json!({
        "ok": true,
        "signature": STANDARD.encode(signature),
        "signatureAlgorithm": "ecdsa-p256-sha256",
        "signatureEncoding": "asn1-der",
    });
    for (key, value) in changes.as_object().unwrap() {
        object[key] = value.clone();
    }
    serde_json::to_vec(&object).unwrap()
}

fn run(request: &Request, runner: &mut FakeRunner) -> Value {
    answer(request, runner, no_windows_directory).unwrap()
}

#[test]
fn macos_runs_the_runtime_helper_with_a_fixed_environment() {
    let mut runner = FakeRunner::answering(
        0,
        probe_output(true, "active", json!(public_key()), "device_key_active"),
    );

    let answer = run(&request("macos", "inspect", None), &mut runner);

    assert_eq!(
        answer,
        json!({
            "ok": true,
            "state": "active",
            "protection_level": "os-protected",
            "public_key_x963": public_key(),
            "reason_code": "device_key_active",
        })
    );
    assert_eq!(
        runner.seen,
        [Invocation {
            program: "/Library/HOL Guard/hol-guard-device-key".to_owned(),
            arguments: vec!["inspect".to_owned(), GENERATION.to_owned()],
            cwd: "/".to_owned(),
            environment: vec![
                ("HOME".to_owned(), "/var/root".to_owned()),
                ("LC_ALL".to_owned(), "C".to_owned()),
                (
                    "PATH".to_owned(),
                    "/usr/bin:/bin:/usr/sbin:/sbin".to_owned()
                ),
                ("TMPDIR".to_owned(), "/var/tmp".to_owned()),
            ],
            input: String::new(),
        }]
    );
}

#[test]
fn windows_runs_the_helper_script_under_the_system_powershell() {
    let mut runner = FakeRunner::answering(
        0,
        probe_output(true, "absent", Value::Null, "device_key_absent"),
    );
    let mut windows = request("windows", "delete", None);
    windows.runtime_root = r"C:\Program Files\HOL Guard".to_owned();

    let answer = answer(&windows, &mut runner, || Some(r"C:\Windows".to_owned())).unwrap();

    assert_eq!(answer["state"], "absent");
    let invocation = &runner.seen[0];
    assert_eq!(
        invocation.program,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    );
    assert_eq!(
        invocation.arguments,
        [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            r"C:\Program Files\HOL Guard\hol-guard\device-key-helper.ps1",
            "-Verb",
            "delete",
            "-Generation",
            GENERATION,
        ]
    );
    assert_eq!(invocation.cwd, r"C:\Windows\System32");
    assert_eq!(
        invocation.environment,
        vec![
            (
                "ComSpec".to_owned(),
                r"C:\Windows\System32\cmd.exe".to_owned()
            ),
            ("SystemDrive".to_owned(), "C:".to_owned()),
            ("SystemRoot".to_owned(), r"C:\Windows".to_owned()),
            ("WINDIR".to_owned(), r"C:\Windows".to_owned()),
        ]
    );
}

#[test]
fn an_unknown_windows_directory_or_platform_runs_nothing() {
    let refused = json!({"ok": false, "reason_code": "device_key_probe_failed"});
    for (platform, directory) in [
        ("windows", None),
        ("windows", Some(r"\\server\share".to_owned())),
        ("linux", None),
    ] {
        let mut runner = FakeRunner::answering(0, Vec::new());
        let answer = answer(&request(platform, "inspect", None), &mut runner, || {
            directory.clone()
        })
        .unwrap();
        assert_eq!(answer, refused, "{platform}");
        assert!(runner.seen.is_empty(), "{platform}");
    }
}

#[test]
fn an_absent_key_is_success_only_for_delete() {
    let mut inspect = FakeRunner::answering(
        1,
        probe_output(false, "absent", Value::Null, "device_key_absent"),
    );
    assert_eq!(
        run(&request("macos", "inspect", None), &mut inspect)["state"],
        "absent"
    );
    let mut delete = FakeRunner::answering(
        0,
        probe_output(true, "absent", Value::Null, "device_key_absent"),
    );
    assert_eq!(
        run(&request("macos", "delete", None), &mut delete)["state"],
        "absent"
    );
}

#[test]
fn helper_answers_that_break_the_contract_are_refused() {
    let refused = json!({"ok": false, "reason_code": "device_key_probe_failed"});
    let active = || json!(public_key());
    let cases = [
        // The success marker disagrees with the state.
        ("inspect", 0, probe_output(false, "active", Value::Null, "device_key_active")),
        // Another operation's result.
        ("delete", 0, probe_output(true, "active", active(), "device_key_active")),
        ("create", 1, probe_output(false, "absent", Value::Null, "device_key_absent")),
        // The exit code disagrees with the state.
        ("inspect", 2, probe_output(false, "absent", Value::Null, "device_key_absent")),
        // A public key that is not base64 or not an uncompressed P-256 point.
        ("inspect", 0, probe_output(true, "active", json!("not-base64"), "device_key_active")),
        ("inspect", 0, probe_output(true, "active", json!(STANDARD.encode([4u8; 33])), "device_key_active")),
        ("inspect", 0, probe_output(true, "active", json!("A".repeat(260)), "device_key_active")),
        // Unknown values and keys.
        ("inspect", 0, probe_output(true, "active", active(), "device_key_other")),
        ("inspect", 0, probe_output(true, "missing", active(), "device_key_active")),
        ("inspect", 0, br#"{"ok":true,"state":"active","protectionLevel":"os-protected","reasonCode":"device_key_active"}"#.to_vec()),
        ("inspect", 0, b"not json".to_vec()),
        ("inspect", 0, vec![b' '; MAX_STDOUT_BYTES + 1]),
    ];
    for (verb, code, stdout) in cases {
        let mut runner = FakeRunner::answering(code, stdout);
        assert_eq!(
            run(&request("macos", verb, None), &mut runner),
            refused,
            "{verb} {code}"
        );
    }
    let mut noisy = FakeRunner::answering(
        0,
        probe_output(true, "active", active(), "device_key_active"),
    );
    noisy.answer.as_mut().unwrap().2 = vec![b'x'; MAX_STDERR_BYTES + 1];
    assert_eq!(run(&request("macos", "inspect", None), &mut noisy), refused);
    let mut stalled = FakeRunner {
        answer: None,
        seen: Vec::new(),
    };
    assert_eq!(
        run(&request("macos", "inspect", None), &mut stalled),
        refused
    );
}

#[test]
fn signing_passes_the_payload_on_stdin_and_returns_the_signature() {
    let signature = der_signature(&[1], &[2]);
    let payload = r#"{"claims":{},"schemaVersion":"protection-lease.v1"}"#;
    let mut runner = FakeRunner::answering(0, signing_output(&signature, json!({})));

    let answer = run(
        &request("macos", "sign-protection-lease", Some(payload)),
        &mut runner,
    );

    assert_eq!(
        answer,
        json!({"ok": true, "signature": STANDARD.encode(signature)})
    );
    assert_eq!(
        runner.seen[0].arguments,
        ["sign-protection-lease", GENERATION]
    );
    assert_eq!(runner.seen[0].input, payload);
}

#[test]
fn signing_answers_that_break_the_contract_are_refused() {
    let refused = json!({"ok": false, "reason_code": "device_key_probe_failed"});
    let signature = der_signature(&[1], &[2]);
    let cases = [
        (0, signing_output(&signature, json!({"extra": true}))),
        (
            0,
            signing_output(&signature, json!({"signatureAlgorithm": "ecdsa-p256"})),
        ),
        (
            0,
            signing_output(&signature, json!({"signatureEncoding": "p1363"})),
        ),
        (
            0,
            signing_output(&signature, json!({"signature": "not-base64"})),
        ),
        (0, signing_output(&signature, json!({"ok": false}))),
        (
            0,
            signing_output(&signature, json!({"signature": "A".repeat(132)})),
        ),
        (2, signing_output(&signature, json!({}))),
        (0, vec![b'x'; MAX_STDOUT_BYTES + 1]),
    ];
    for (index, (code, stdout)) in cases.into_iter().enumerate() {
        let mut runner = FakeRunner::answering(code, stdout);
        let answer = run(
            &request("macos", "sign-health-lease", Some("{}")),
            &mut runner,
        );
        assert_eq!(answer, refused, "case {index}");
    }
}

#[test]
fn only_a_canonical_in_range_der_signature_is_accepted() {
    let order_minus_one = {
        let mut value = P256_ORDER;
        value[31] -= 1;
        value
    };
    assert!(is_canonical_p256_signature(&der_signature(&[1], &[2])));
    assert!(is_canonical_p256_signature(&der_signature(
        &order_minus_one,
        &order_minus_one
    )));
    // Zero, the group order and anything wider are out of range.
    assert!(!is_canonical_p256_signature(&der_signature(&[0], &[2])));
    assert!(!is_canonical_p256_signature(&der_signature(
        &P256_ORDER,
        &[2]
    )));
    assert!(!is_canonical_p256_signature(&der_signature(&[1; 33], &[2])));
    // A leading zero the value does not need, a negative value, trailing
    // bytes and a long-form length do not re-encode to the same bytes.
    assert!(!is_canonical_p256_signature(&[
        0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x02
    ]));
    assert!(!is_canonical_p256_signature(&[
        0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x02
    ]));
    assert!(!is_canonical_p256_signature(&[
        0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00, 0x00
    ]));
    assert!(!is_canonical_p256_signature(&[
        0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02
    ]));
    assert!(!is_canonical_p256_signature(&[]));
}

#[test]
fn requests_no_helper_may_run_are_errors() {
    let mut cases = vec![
        request("macos", "sign", None),
        request("macos", "inspect", Some("{}")),
        request("macos", "sign-health-lease", None),
        request("macos", "sign-health-lease", Some("")),
        request(
            "macos",
            "sign-health-lease",
            Some(&"x".repeat(MAX_PAYLOAD_BYTES + 1)),
        ),
    ];
    let mut short = request("macos", "inspect", None);
    short.generation = "-Verb".to_owned();
    cases.push(short);
    let mut upper = request("macos", "inspect", None);
    upper.generation = GENERATION.to_uppercase();
    cases.push(upper);
    let mut schema = request("macos", "inspect", None);
    schema.schema = "device-key-helper.v2".to_owned();
    cases.push(schema);
    for case in cases {
        let mut runner = FakeRunner::answering(0, Vec::new());
        assert_eq!(
            answer(&case, &mut runner, no_windows_directory),
            Err("device_key_request_invalid".to_owned()),
            "{} {}",
            case.verb,
            case.generation
        );
        assert!(runner.seen.is_empty());
    }
    assert_eq!(
        run_command(&br#"{"schema":"device-key-helper.v1","platform":"macos","runtime_root":"/r","verb":"inspect","generation":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":1}"#[..]),
        Err("device_key_request_invalid".to_owned())
    );
}
