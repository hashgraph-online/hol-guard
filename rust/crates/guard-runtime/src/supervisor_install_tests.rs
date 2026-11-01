use std::collections::VecDeque;
use std::io;
use std::path::Path;

use serde_json::{json, Value};

use super::{task_xml, windows_install, windows_remove};
use crate::supervisor_verdict::probe::Runner;
use crate::supervisor_verdict::{tests, Probe, Request};

const WINDOWS_EXECUTABLE: &str = r"C:\Program Files\HOL Guard\hol-guard\hol-guard.exe";

/// A stand-in `schtasks` that records each run and the task definition file
/// as it was while `schtasks` ran.
struct FakeSchtasks {
    answers: VecDeque<io::Result<Probe>>,
    calls: Vec<(String, Vec<String>, String)>,
    definitions: Vec<Option<Vec<u8>>>,
}

impl FakeSchtasks {
    fn answering(answers: Vec<io::Result<Probe>>) -> Self {
        Self {
            answers: answers.into(),
            calls: Vec::new(),
            definitions: Vec::new(),
        }
    }
}

impl Runner for FakeSchtasks {
    fn run(
        &mut self,
        program: &str,
        arguments: &[&str],
        cwd: &str,
        environment: &[(&str, &str)],
    ) -> io::Result<Probe> {
        assert_eq!(
            environment,
            [
                ("ComSpec", r"D:\Windows\System32\cmd.exe"),
                ("SystemDrive", "D:"),
                ("SystemRoot", r"D:\Windows"),
                ("WINDIR", r"D:\Windows"),
            ]
        );
        self.calls.push((
            program.to_owned(),
            arguments.iter().map(|item| (*item).to_owned()).collect(),
            cwd.to_owned(),
        ));
        self.definitions.push(
            arguments
                .get(4)
                .filter(|_| arguments.first() == Some(&"/Create"))
                .and_then(|file| std::fs::read(file).ok()),
        );
        self.answers
            .pop_front()
            .unwrap_or_else(|| Err(io::Error::other("no answer queued")))
    }
}

fn completed(returncode: i64) -> io::Result<Probe> {
    Ok(Probe {
        returncode,
        stdout: String::new(),
    })
}

fn request(value: Value) -> Request {
    serde_json::from_value(value).expect("request")
}

/// A machine layout with the runtime executable and the state root present.
fn installed(root: &Path) -> (String, String) {
    let executable = root.join("runtime").join("hol-guard.exe");
    std::fs::create_dir_all(executable.parent().expect("parent")).expect("runtime");
    std::fs::write(&executable, b"exe").expect("executable");
    let state_root = root.join("state");
    std::fs::create_dir(&state_root).expect("state root");
    (
        executable.to_string_lossy().into_owned(),
        state_root.to_string_lossy().into_owned(),
    )
}

fn install_request(executable: &str, state_root: &str) -> Request {
    request(json!({
        "schema": "supervisor-verdict.v1",
        "op": "windows-install",
        "executable": executable,
        "windows_directory": r"D:\Windows",
        "state_root": state_root,
    }))
}

fn remove_request() -> Request {
    request(json!({
        "schema": "supervisor-verdict.v1",
        "op": "windows-remove",
        "executable": WINDOWS_EXECUTABLE,
        "windows_directory": r"D:\Windows",
    }))
}

fn utf16_text(bytes: &[u8]) -> String {
    assert_eq!(&bytes[..2], [0xFF, 0xFE]);
    let units: Vec<u16> = bytes[2..]
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16(&units).expect("utf-16")
}

#[test]
fn the_task_definition_is_the_one_elementtree_wrote() {
    assert_eq!(utf16_text(&task_xml(WINDOWS_EXECUTABLE)), tests::task_xml());
    let spelled = utf16_text(&task_xml(
        r"C:/Program Files/HOL Guard/./bin/../hol-guard/hol-guard.exe",
    ));
    assert_eq!(spelled, tests::task_xml());
    let escaped = utf16_text(&task_xml(r"C:\R&D <x>\hol-guard.exe"));
    assert!(escaped.contains(r"<Command>C:\R&amp;D &lt;x&gt;\hol-guard.exe</Command>"));
}

#[test]
fn install_registers_a_temporary_definition_and_removes_it() {
    let directory = tempfile::tempdir().expect("tempdir");
    let (executable, state_root) = installed(directory.path());
    let mut schtasks = FakeSchtasks::answering(vec![completed(0)]);

    let answer = windows_install(&install_request(&executable, &state_root), &mut schtasks);

    assert_eq!(
        answer,
        Some(json!({"ok": true, "state": "running", "reason_code": "supervisor_running"}))
    );
    let (program, arguments, cwd) = &schtasks.calls[0];
    assert_eq!(program, r"D:\Windows\System32\schtasks.exe");
    assert_eq!(cwd, r"D:\Windows\System32");
    assert_eq!(
        arguments[..4],
        ["/Create", "/TN", r"\HOL Guard\Machine Health", "/XML"]
    );
    assert_eq!(arguments[5..], ["/F", "/HRESULT"]);
    let temporary = Path::new(&arguments[4]);
    assert_eq!(temporary.parent(), Some(Path::new(&state_root)));
    let name = temporary.file_name().expect("name").to_string_lossy();
    assert!(name.starts_with("health-task-") && name.ends_with(".xml"));
    assert_eq!(
        schtasks.definitions[0].as_deref(),
        Some(task_xml(&executable).as_slice())
    );
    assert!(!temporary.exists());
    assert_eq!(std::fs::read_dir(&state_root).expect("list").count(), 0);
}

#[test]
fn a_refused_registration_still_removes_the_definition() {
    for answer in [completed(1), Err(io::ErrorKind::TimedOut.into())] {
        let directory = tempfile::tempdir().expect("tempdir");
        let (executable, state_root) = installed(directory.path());
        let mut schtasks = FakeSchtasks::answering(vec![answer]);

        let answer = windows_install(&install_request(&executable, &state_root), &mut schtasks);

        assert_eq!(
            answer,
            Some(json!({"ok": false, "error": "supervisor_registration_failed"}))
        );
        assert_eq!(schtasks.calls.len(), 1);
        assert_eq!(std::fs::read_dir(&state_root).expect("list").count(), 0);
    }
}

#[test]
fn install_refuses_a_missing_runtime_before_schtasks_runs() {
    let directory = tempfile::tempdir().expect("tempdir");
    let (executable, state_root) = installed(directory.path());
    let missing = directory.path().join("missing");
    let missing = missing.to_string_lossy();
    for case in [
        install_request(&missing, &state_root),
        install_request(&executable, &missing),
        install_request(&state_root, &state_root),
    ] {
        assert_runtime_absent(&case);
    }
}

#[cfg(unix)]
#[test]
fn install_refuses_a_linked_runtime() {
    let directory = tempfile::tempdir().expect("tempdir");
    let (executable, state_root) = installed(directory.path());
    let link = directory.path().join("linked.exe");
    std::os::unix::fs::symlink(&executable, &link).expect("symlink");

    assert_runtime_absent(&install_request(&link.to_string_lossy(), &state_root));
}

fn assert_runtime_absent(case: &Request) {
    let mut schtasks = FakeSchtasks::answering(Vec::new());
    assert_eq!(
        windows_install(case, &mut schtasks),
        Some(json!({"ok": false, "error": "supervisor_runtime_absent"}))
    );
    assert!(schtasks.calls.is_empty());
}

#[test]
fn install_refuses_a_drive_less_windows_directory() {
    let directory = tempfile::tempdir().expect("tempdir");
    let (executable, state_root) = installed(directory.path());
    let mut case = install_request(&executable, &state_root);
    case.windows_directory = Some(r"\Windows".to_owned());
    let mut schtasks = FakeSchtasks::answering(Vec::new());

    assert_eq!(
        windows_install(&case, &mut schtasks),
        Some(json!({"ok": false, "error": "windows_system_drive_unavailable"}))
    );
    assert!(schtasks.calls.is_empty());
    assert_eq!(std::fs::read_dir(&state_root).expect("list").count(), 0);
}

#[test]
fn remove_treats_an_absent_task_as_removed() {
    for (answer, removed) in [
        (completed(0), true),
        (completed(2), true),
        (completed(0x8007_0002), true),
        (completed(-2_147_024_894), true),
        (completed(5), false),
        (Err(io::ErrorKind::TimedOut.into()), false),
    ] {
        let mut schtasks = FakeSchtasks::answering(vec![answer]);

        let answer = windows_remove(&remove_request(), &mut schtasks);

        let expected = if removed {
            json!({"ok": true, "state": "absent"})
        } else {
            json!({"ok": false, "error": "supervisor_removal_failed"})
        };
        assert_eq!(answer, Some(expected));
        let (program, arguments, cwd) = &schtasks.calls[0];
        assert_eq!(program, r"D:\Windows\System32\schtasks.exe");
        assert_eq!(cwd, r"D:\Windows\System32");
        assert_eq!(
            arguments,
            &[
                "/Delete",
                "/TN",
                r"\HOL Guard\Machine Health",
                "/F",
                "/HRESULT"
            ]
        );
    }
}

#[test]
fn task_ops_refuse_requests_carrying_other_fields() {
    let directory = tempfile::tempdir().expect("tempdir");
    let (executable, state_root) = installed(directory.path());
    let mut with_plist = install_request(&executable, &state_root);
    with_plist.plist_file = Some("/tmp/x.plist".to_owned());
    let mut with_task = install_request(&executable, &state_root);
    with_task.task = Some(Probe {
        returncode: 0,
        stdout: String::new(),
    });
    let mut without_root = install_request(&executable, &state_root);
    without_root.state_root = None;
    for case in [with_plist, with_task, without_root] {
        let mut schtasks = FakeSchtasks::answering(Vec::new());
        assert_eq!(windows_install(&case, &mut schtasks), None);
        assert!(schtasks.calls.is_empty());
    }
    let mut remove_with_root = remove_request();
    remove_with_root.state_root = Some(state_root);
    let mut schtasks = FakeSchtasks::answering(Vec::new());
    assert_eq!(windows_remove(&remove_with_root, &mut schtasks), None);
    assert!(schtasks.calls.is_empty());
}
