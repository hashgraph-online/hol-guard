//! Proofs for bubblewrap's private execution-status channel: only the
//! exec-success report attests execution, and application output never can.

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};

use super::process::{bwrap_execution_completed, status_report_confirms};
use super::vector_support::Workspace;

/// Write `payload` into a real file and rewind it, so the reader sees the same
/// descriptor shape bubblewrap hands back.
fn status_file(workspace: &Workspace, payload: &[u8]) -> File {
    let path = workspace.path.join("status");
    let mut file = File::options()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .expect("status file");
    file.write_all(payload).expect("write status");
    file.seek(SeekFrom::Start(0)).expect("rewind");
    file
}

#[test]
fn an_executed_child_exit_is_accepted() {
    let workspace = Workspace::new();
    for code in [0, 1, 17, 255] {
        let payload =
            format!("{{\"child-pid\":42,\"mnt-namespace\":100}}\n{{\"exit-code\":{code}}}\n");
        let mut status = status_file(&workspace, payload.as_bytes());
        assert!(
            bwrap_execution_completed(&mut status, Some(code)),
            "exit code {code}"
        );
    }
}

#[test]
fn an_incomplete_or_invalid_report_fails_closed() {
    let workspace = Workspace::new();
    let oversized = {
        let mut payload = b"{\"child-pid\":42}\n{\"exit-code\":0}\n".to_vec();
        payload.resize(payload.len() + 8192, b' ');
        payload
    };
    for (payload, code) in [
        (b"".as_slice(), Some(0)),
        // A forked sandbox process is not an exec.
        (b"{\"child-pid\":42}\n".as_slice(), Some(1)),
        (b"{\"exit-code\":0}\n".as_slice(), Some(0)),
        (
            b"{\"exit-code\":0}\n{\"child-pid\":42}\n".as_slice(),
            Some(0),
        ),
        // The reported status must be the status the caller observed.
        (
            b"{\"child-pid\":42}\n{\"exit-code\":1}\n".as_slice(),
            Some(0),
        ),
        (
            b"{\"child-pid\":true}\n{\"exit-code\":0}\n".as_slice(),
            Some(0),
        ),
        (
            b"{\"child-pid\":-1}\n{\"exit-code\":0}\n".as_slice(),
            Some(0),
        ),
        (
            b"{\"child-pid\":42}\n{\"exit-code\":false}\n".as_slice(),
            Some(0),
        ),
        (
            b"{\"child-pid\":42}\n{\"exit-code\":0}\n{\"exit-code\":0}\n".as_slice(),
            Some(0),
        ),
        (
            b"{\"child-pid\":42}\n{\"child-pid\":43}\n{\"exit-code\":0}\n".as_slice(),
            Some(0),
        ),
        (
            b"{\"child-pid\":42}\n{\"exit-code\":0}\n[]\n".as_slice(),
            Some(0),
        ),
        (
            b"{\"child-pid\":42}\n{\"exit-code\":0}\ninvalid".as_slice(),
            Some(0),
        ),
        (oversized.as_slice(), Some(0)),
        // A signalled or absent status is not an exit code.
        (b"{\"child-pid\":42}\n{\"exit-code\":0}\n".as_slice(), None),
        (
            b"{\"child-pid\":42}\n{\"exit-code\":0}\n".as_slice(),
            Some(-9),
        ),
    ] {
        let mut status = status_file(&workspace, payload);
        assert!(
            !bwrap_execution_completed(&mut status, code),
            "{:?} with {code:?}",
            String::from_utf8_lossy(payload)
        );
    }
}

/// A backend that fails to apply its sandbox can still print a convincing
/// report on stdout. Only the private descriptor attests execution, so an
/// untouched status channel stays unconfirmed however complete that output is.
#[test]
fn application_output_cannot_attest_startup() {
    let workspace = Workspace::new();
    let application_stdout = b"{\"child-pid\":42}\n{\"exit-code\":0}\n";
    assert!(status_report_confirms(application_stdout, 0));

    let mut untouched = status_file(&workspace, b"");
    assert!(!bwrap_execution_completed(&mut untouched, Some(0)));
}
