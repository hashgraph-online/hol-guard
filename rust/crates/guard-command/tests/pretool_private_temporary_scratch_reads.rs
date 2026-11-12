//! A session stages work in a directory it makes in the per-user temporary
//! directory and reads it back from the repository it is working in. The other
//! files there already read; the scratch folder's leading dot used to hold the
//! listing for review.
#![cfg(target_os = "macos")]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

fn decision(home: &std::path::Path, cwd: &std::path::Path, command: &str) -> String {
    evaluate_pre_tool_envelope_with_context(
        "codex",
        "PreToolUse",
        &json!({"tool_name":"Bash", "tool_input":{"command":command}}),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    )
    .minimum_action
}

#[test]
fn staged_scratch_output_in_the_private_temporary_directory_reads() {
    let temporary = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    assert!(
        temporary.starts_with("/private/var/folders"),
        "expected the per-user temporary directory, got {}",
        temporary.display()
    );
    let nonce = crate::unique_nanos::unique_nanos();
    let staged = temporary.join(format!("guard-temp-scratch-{}-{nonce}", std::process::id()));
    let project = staged.join("org/signup-funnel");
    std::fs::create_dir(&staged).unwrap();
    let _cleanup = Cleanup(staged.clone());
    std::fs::create_dir_all(project.join(".tmp/report")).unwrap();
    std::fs::create_dir_all(project.join(".ssh")).unwrap();
    std::fs::create_dir_all(project.join(".tmp/.ssh")).unwrap();
    std::fs::create_dir_all(project.join("node_modules")).unwrap();
    std::fs::write(project.join(".tmp/log.txt"), "fixture\n").unwrap();
    std::fs::write(project.join(".tmp/.ssh/id_ed25519"), "fixture\n").unwrap();
    std::fs::write(project.join(".ssh/id_ed25519"), "fixture\n").unwrap();

    let home = std::path::PathBuf::from(std::env::var_os("HOME").unwrap());
    // The session runs in its repository and names the staged output by path.
    let cwd = std::env::current_dir().unwrap();
    let path = |relative: &str| project.join(relative).to_str().unwrap().to_owned();

    for command in [
        format!("ls {}", path(".tmp")),
        format!("ls {}", path(".tmp/report")),
        format!("cat {}", path(".tmp/log.txt")),
    ] {
        assert_eq!(decision(&home, &cwd, &command), "allow", "{command}");
    }

    // Other hidden state staged in the same directory keeps its review, below
    // the scratch folder as well as beside it.
    for command in [
        format!("ls {}", path(".ssh")),
        format!("cat {}", path(".ssh/id_ed25519")),
        format!("cat {}", path(".tmp/.ssh/id_ed25519")),
    ] {
        assert_ne!(decision(&home, &cwd, &command), "allow", "{command}");
    }

    // A hidden name the host does not spell in UTF-8 cannot be read for its
    // leading dot, so a link that resolves onto one refuses the read rather
    // than letting the scratch folder stand as the only hidden part. APFS
    // rejects such a name outright, so the case only runs where the volume
    // accepts it.
    use std::os::unix::ffi::OsStrExt;
    let opaque = project
        .join(".tmp")
        .join(std::ffi::OsStr::from_bytes(b".\xff\xfestate"));
    if std::fs::create_dir(&opaque).is_ok() {
        std::fs::write(opaque.join("id_ed25519"), "fixture\n").unwrap();
        std::os::unix::fs::symlink(&opaque, project.join(".tmp/staged")).unwrap();
        let command = format!("cat {}", path(".tmp/staged/id_ed25519"));
        assert_ne!(decision(&home, &cwd, &command), "allow", "{command}");
    }
}

struct Cleanup(std::path::PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
