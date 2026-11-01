use super::*;

use crate::native_install_verdict::Ran;

const SEALED_DISPLAY: &str = "Executable=/x/hol-guard\n\
    Format=app bundle with Mach-O thin (arm64)\n\
    Sealed Resources version=2 rules=10 files=148\n\
    TeamIdentifier=TEAMID\n";

/// Answers each `codesign` call from the path it names: `verify` decides
/// whether `--verify` succeeds and `display` is the `--display` stderr.
struct FakeRunner {
    verify: fn(&str) -> bool,
    display: fn(&str) -> Option<String>,
    calls: Vec<Invocation>,
}

impl FakeRunner {
    fn new(verify: fn(&str) -> bool, display: fn(&str) -> Option<String>) -> Self {
        Self {
            verify,
            display,
            calls: Vec::new(),
        }
    }
}

impl Runner for FakeRunner {
    fn run(&mut self, invocation: &Invocation) -> io::Result<Ran> {
        self.calls.push(Invocation {
            program: invocation.program.clone(),
            arguments: invocation.arguments.clone(),
            context: None,
            timeout: invocation.timeout,
        });
        let path = invocation.arguments.last().expect("a path").as_str();
        if invocation.arguments[0] == "--verify" {
            return Ok(Ran {
                success: (self.verify)(path),
                stdout: Vec::new(),
                stderr: Vec::new(),
            });
        }
        let display = (self.display)(path).ok_or(io::ErrorKind::TimedOut)?;
        Ok(Ran {
            success: true,
            stdout: Vec::new(),
            stderr: display.into_bytes(),
        })
    }
}

fn team_display(_path: &str) -> Option<String> {
    Some(SEALED_DISPLAY.to_owned())
}

fn verified(_path: &str) -> bool {
    true
}

fn request(op: &str, path: &str) -> Request {
    Request {
        schema: SCHEMA.to_owned(),
        op: op.to_owned(),
        path: Some(path.to_owned()),
        deep: false,
        timeout_ms: None,
        expected_team: None,
    }
}

fn team_request(path: &str, deep: bool) -> Request {
    Request {
        deep,
        timeout_ms: Some(5_000),
        ..request("team", path)
    }
}

#[test]
fn requests_are_validated() {
    for request in [
        json!({ "schema": "macos-code-signing.v0", "op": "sealed", "path": "/a" }),
        json!({ "schema": SCHEMA, "op": "sealed", "path": "relative" }),
        json!({ "schema": SCHEMA, "op": "sealed" }),
        json!({ "schema": SCHEMA, "op": "sealed", "path": "/a", "deep": true }),
        json!({ "schema": SCHEMA, "op": "team", "path": "/a" }),
        json!({ "schema": SCHEMA, "op": "team", "path": "/a", "timeout_ms": 0 }),
        json!({ "schema": SCHEMA, "op": "team", "path": "/a", "timeout_ms": 120_001 }),
        json!({ "schema": SCHEMA, "op": "tree", "path": "/a" }),
        json!({ "schema": SCHEMA, "op": "tree", "path": "/a", "expected_team": "" }),
        json!({ "schema": SCHEMA, "op": "unknown", "path": "/a" }),
        json!({ "schema": SCHEMA, "op": "sealed", "path": "/a", "extra": 1 }),
    ] {
        assert_eq!(
            run_command(request.to_string().as_bytes()).expect_err("refused"),
            "macos_code_signing_request_invalid",
            "{request}"
        );
    }
    let oversized = vec![b' '; usize::try_from(MAX_REQUEST_BYTES).expect("fits") + 1];
    assert_eq!(
        run_command(oversized.as_slice()).expect_err("refused"),
        "macos_code_signing_request_too_large"
    );
}

#[test]
fn a_verified_signature_answers_its_team() {
    let mut runner = FakeRunner::new(verified, team_display);
    let answer = answer(&team_request("/Applications/Guard.app", true), &mut runner);
    assert_eq!(answer, Ok(json!({ "team": "TEAMID" })));
    assert_eq!(
        runner.calls[0].arguments,
        ["--verify", "--deep", "--strict", "/Applications/Guard.app"]
    );
    assert_eq!(
        runner.calls[1].arguments,
        ["--display", "--verbose=4", "/Applications/Guard.app"]
    );
    assert!(runner
        .calls
        .iter()
        .all(|call| call.program == CODESIGN && call.timeout == Duration::from_secs(5)));
}

#[test]
fn a_signature_without_a_verified_team_has_none() {
    let mut runner = FakeRunner::new(|_| false, team_display);
    let rejected = answer(&team_request("/x", false), &mut runner);
    assert_eq!(rejected, Ok(json!({ "team": null })));
    let displays: [fn(&str) -> Option<String>; 4] = [
        |_| Some("TeamIdentifier=not set\n".to_owned()),
        |_| Some("TeamIdentifier=  \n".to_owned()),
        |_| Some("Identifier=x\n".to_owned()),
        |_| None,
    ];
    for display in displays {
        let mut runner = FakeRunner::new(verified, display);
        assert_eq!(
            answer(&team_request("/x", false), &mut runner),
            Ok(json!({ "team": null }))
        );
    }
    let mut runner = FakeRunner::new(verified, |_| {
        Some(" TeamIdentifier=A\r\nTeamIdentifier= B \n".to_owned())
    });
    assert_eq!(
        answer(&team_request("/x", false), &mut runner),
        Ok(json!({ "team": "B" })),
        "only a line that starts with the field names the team"
    );
}

fn launcher(directory: &Path) -> PathBuf {
    let signature = directory.join("hol-guard").join("_CodeSignature");
    fs::create_dir_all(&signature).expect("signature directory");
    fs::write(signature.join("CodeResources"), "<resources/>").expect("resources");
    let launcher = directory.join("hol-guard").join("hol-guard");
    fs::write(&launcher, b"launcher").expect("launcher");
    launcher
}

fn sealed_answer(launcher: &Path, display: fn(&str) -> Option<String>) -> Value {
    let mut runner = FakeRunner::new(verified, display);
    let path = launcher.to_str().expect("utf-8 path");
    answer(&request("sealed", path), &mut runner).expect("answer")["sealed"].clone()
}

#[test]
fn only_a_sealed_app_bundle_signature_is_sealed() {
    let directory = tempfile::tempdir().expect("tempdir");
    let launcher = launcher(directory.path());
    assert_eq!(sealed_answer(&launcher, team_display), true);
    let displays: [fn(&str) -> Option<String>; 3] = [
        |_| Some("Format=app bundle with Mach-O thin (arm64)\n".to_owned()),
        |_| {
            Some(
                "Format=Mach-O thin (arm64)\nSealed Resources version=2 rules=10 files=1\n"
                    .to_owned(),
            )
        },
        |_| None,
    ];
    for display in displays {
        assert_eq!(sealed_answer(&launcher, display), false);
    }
    let resources = launcher
        .parent()
        .expect("parent")
        .join("_CodeSignature")
        .join("CodeResources");
    fs::remove_file(resources).expect("remove resources");
    assert_eq!(sealed_answer(&launcher, team_display), false);
}

fn tree(directory: &Path) -> PathBuf {
    let tree = directory.join("hol-guard");
    fs::create_dir_all(tree.join("_internal")).expect("internal");
    fs::write(tree.join("hol-guard"), b"\xcf\xfa\xed\xfelauncher").expect("launcher");
    fs::write(
        tree.join("_internal").join("libx.dylib"),
        b"\xcf\xfa\xed\xfelib",
    )
    .expect("lib");
    fs::write(tree.join("_internal").join("data.txt"), b"plain text").expect("data");
    tree
}

fn tree_answer(tree: &Path, display: fn(&str) -> Option<String>) -> (Value, Vec<String>) {
    let mut runner = FakeRunner::new(verified, display);
    let path = tree.to_str().expect("utf-8 path");
    let request = Request {
        expected_team: Some("TEAMID".to_owned()),
        ..request("tree", path)
    };
    let failure = answer(&request, &mut runner).expect("answer")["failure"].clone();
    let checked = runner
        .calls
        .iter()
        .filter(|call| call.arguments[0] == "--verify")
        .map(|call| call.arguments.last().expect("path").clone())
        .collect();
    (failure, checked)
}

#[test]
fn every_macho_file_in_the_tree_carries_the_team() {
    let directory = tempfile::tempdir().expect("tempdir");
    let tree = tree(directory.path());
    fs::write(tree.join("tool"), b"\xca\xfe\xba\xbetool").expect("tool");
    let (failure, checked) = tree_answer(&tree, team_display);
    assert_eq!(failure, Value::Null);
    let expected: Vec<String> = [
        tree.join("_internal").join("libx.dylib"),
        tree.join("hol-guard"),
        tree.join("tool"),
    ]
    .iter()
    .map(|path| path.to_string_lossy().into_owned())
    .collect();
    assert_eq!(checked, expected, "Mach-O files only, in path order");
}

#[test]
fn a_macho_file_of_another_team_or_none_fails_the_tree() {
    let directory = tempfile::tempdir().expect("tempdir");
    let tree = tree(directory.path());
    fs::write(tree.join("tool"), b"\xcf\xfa\xed\xfetool").expect("tool");
    let (failure, _) = tree_answer(&tree, |path| {
        Some(if path.ends_with("/tool") {
            "TeamIdentifier=OTHERTEAM\n".to_owned()
        } else {
            SEALED_DISPLAY.to_owned()
        })
    });
    assert_eq!(failure, json!(SIGNATURE_MISMATCH));
    let (failure, checked) = tree_answer(&tree, |path| {
        (!path.ends_with("libx.dylib")).then(|| SEALED_DISPLAY.to_owned())
    });
    assert_eq!(failure, json!(SIGNATURE_INVALID));
    assert_eq!(checked.len(), 1, "the walk stops at the first failure");
}

#[test]
fn a_tree_without_internal_fails_to_install() {
    let directory = tempfile::tempdir().expect("tempdir");
    let tree = directory.path().join("hol-guard");
    fs::create_dir_all(&tree).expect("tree");
    fs::write(tree.join("hol-guard"), b"\xcf\xfa\xed\xfelauncher").expect("launcher");
    let (failure, checked) = tree_answer(&tree, team_display);
    assert_eq!(failure, json!(INSTALL_FAILED));
    assert!(checked.is_empty());
}

#[cfg(unix)]
#[test]
fn linked_files_and_directories_are_not_followed() {
    let directory = tempfile::tempdir().expect("tempdir");
    let tree = tree(directory.path());
    let outside = directory.path().join("outside");
    fs::create_dir_all(&outside).expect("outside");
    fs::write(outside.join("foreign"), b"\xcf\xfa\xed\xfeforeign").expect("foreign");
    std::os::unix::fs::symlink(&outside, tree.join("_internal").join("linked")).expect("dir link");
    std::os::unix::fs::symlink(outside.join("foreign"), tree.join("foreign")).expect("file link");
    let (failure, checked) = tree_answer(&tree, team_display);
    assert_eq!(failure, Value::Null);
    assert_eq!(checked.len(), 2, "{checked:?}");
}
