use super::*;

fn request(program: &str, arguments: &[&str], input: &[u8]) -> Value {
    json!({
        "schema": SCHEMA,
        "program": program,
        "arguments": arguments,
        "input": Base64::encode_string(input),
    })
}

fn run(request: &Value) -> Result<Value, String> {
    run_command(request.to_string().as_bytes())
        .map(|bytes| serde_json::from_slice(&bytes).expect("answer is JSON"))
}

fn stdout(answer: &Value) -> Vec<u8> {
    Base64::decode_vec(answer["stdout"].as_str().expect("stdout is text")).expect("base64")
}

#[test]
fn requests_are_validated() {
    let base = request("grep", &["a"], b"a\n");
    let mut cases = Vec::new();
    for (field, value) in [
        ("schema", json!("contained-output-match.v0")),
        ("program", json!("sed")),
        ("program", json!("head")),
        ("arguments", json!("a")),
        ("input", json!("not base64!")),
        ("unknown", json!(true)),
    ] {
        let mut case = base.clone();
        case[field] = value;
        cases.push(case);
    }
    for case in cases {
        assert_eq!(
            run(&case).expect_err("refused"),
            "contained_output_match_request_invalid",
            "{case}"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_matcher_prints_back_the_pipeline_bytes() {
    if !std::path::Path::new("/usr/bin/grep").is_file()
        && !std::path::Path::new("/bin/grep").is_file()
    {
        return;
    }
    let answer = run(&request(
        "grep",
        &["-c", "passed"],
        b"passed\nfailed\npassed\n",
    ))
    .expect("answer");
    assert_eq!(stdout(&answer), b"2\n");
    assert_eq!(answer["status"], 0);
    assert_eq!(answer["stderr"], "");
    // A byte bound earlier in the chain can cut a character in half; the
    // matcher's bytes come back as they were, not as a replacement character.
    // `-a` keeps GNU grep from reporting the line as a binary match.
    let answer = run(&request("grep", &["-a", "h"], b"h\xc3\n")).expect("answer");
    assert_eq!(stdout(&answer), b"h\xc3\n");
    let answer = run(&request("fgrep", &["b"], b"a\n")).expect("answer");
    assert_eq!(
        (stdout(&answer), answer["status"].clone()),
        (Vec::new(), json!(1))
    );
}

#[cfg(unix)]
fn ripgrep_installed() -> bool {
    crate::contained_workspace_sink::matched(b"", "rg", &[])
        .is_ok_and(|(_, _, status)| status != 127)
}

#[cfg(not(unix))]
fn ripgrep_installed() -> bool {
    false
}

#[test]
fn a_missing_matcher_exits_as_a_missing_program() {
    if ripgrep_installed() {
        return;
    }
    let answer = run(&request("rg", &["a"], b"a\n")).expect("answer");
    assert_eq!(
        answer,
        json!({ "stdout": "", "stderr": "hol-guard: rg: not found\n", "status": 127 })
    );
}
