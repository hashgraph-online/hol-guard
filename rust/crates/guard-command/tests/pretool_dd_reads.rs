#![cfg(unix)]

//! `dd if=FILE bs=N count=N` reads a slice of one file to standard output, so
//! an agent that inspects the first bytes of a scratch file or a workspace
//! source file is not stopped. Every operand that names an output, converts or
//! seeks, and every input outside the proven read scope, keeps review.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
    scratch: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.scratch);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn fixture(name: &str) -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-dd-reads")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::write(project.join("src/a.ts"), "export const a = 1;\n").unwrap();
    std::fs::write(project.join(".env"), "TOKEN=synthetic\n").unwrap();
    std::fs::write(home.join(".ssh/id_rsa"), "synthetic key\n").unwrap();
    std::fs::write(home.join(".zshrc"), "# synthetic\n").unwrap();
    let scratch = PathBuf::from(format!("/tmp/hg-dd-reads-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir(&scratch).unwrap();
    std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(scratch.join("a.ts"), "export const a = 1;\n").unwrap();
    Fixture {
        home: std::fs::canonicalize(&home).unwrap(),
        project: std::fs::canonicalize(&project).unwrap(),
        root,
        scratch,
    }
}

fn permitted(fixture: &Fixture, command: &str) -> bool {
    let evaluate = |harness| {
        let result = evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"toolName": "Bash", "toolInput": {"command": command}}),
            None,
            None,
            fixture.home.to_str(),
            fixture.project.to_str(),
        );
        result.decision == "allow" && matches!(result.minimum_action.as_str(), "allow" | "warn")
    };
    let zcode = evaluate("zcode");
    assert_eq!(zcode, evaluate("omp"), "host policy drift: {command}");
    zcode
}

#[test]
fn dd_prints_a_slice_of_a_readable_file() {
    let fixture = fixture("allowed");
    let scratch = fixture.scratch.display();
    for command in [
        format!("dd if={scratch}/a.ts bs=1 skip=0 count=100 2>/dev/null | od -c | head -3"),
        format!("dd if={scratch}/a.ts bs=4k count=1 status=none | head -2"),
        "dd if=src/a.ts bs=1 count=20 2>/dev/null | od -c | head -3".to_owned(),
        format!("dd if={scratch}/a.ts bs=16 count=1 skip=1"),
        format!("dd if={scratch}/a.ts bs=16M count=1 status=none | head -2"),
        format!("dd if={scratch}/a.ts ibs=1M skip=2 count=1 | od -c | head -2"),
    ] {
        assert!(permitted(&fixture, &command), "{command}");
    }
}

#[test]
fn dd_keeps_review_for_outputs_conversions_and_unreadable_inputs() {
    let fixture = fixture("reviewed");
    let scratch = fixture.scratch.display();
    let home = fixture.home.display();
    for command in [
        // An output file, a seek, a conversion or a device input.
        format!("dd if={scratch}/a.ts of={scratch}/b.ts"),
        format!("dd if={scratch}/a.ts of={home}/.zshrc bs=1 count=4"),
        format!("dd if={scratch}/a.ts bs=1 count=4 seek=2 conv=notrunc"),
        format!("dd if={scratch}/a.ts bs=1 count=4 conv=ucase"),
        "dd if=/dev/zero bs=1M count=1".to_owned(),
        "dd if=/dev/urandom bs=16 count=1".to_owned(),
        // No input names a file, or a second input is named.
        "dd bs=1 count=4".to_owned(),
        format!("dd if={scratch}/a.ts if={scratch}/a.ts bs=1 count=4"),
        // Unknown operands and malformed sizes.
        format!("dd if={scratch}/a.ts bs=1 count=4 iflag=direct"),
        format!("dd if={scratch}/a.ts bs=-1 count=4"),
        // A block size that would allocate a large buffer.
        format!("dd if={scratch}/a.ts bs=17M count=1"),
        format!("dd if={scratch}/a.ts bs=1G count=1"),
        format!("dd if={scratch}/a.ts ibs=999999999999 count=1"),
        format!("dd if={scratch}/a.ts bs=999999999999G count=1"),
        format!("dd if={scratch}/a.ts bs=$(echo 1) count=4"),
        // Credentials and files outside the read scope.
        format!("dd if={home}/.ssh/id_rsa bs=1 count=20"),
        format!("dd if={home}/.zshrc bs=1 count=20"),
        "dd if=.env bs=1 count=20".to_owned(),
        "dd if=/etc/passwd bs=1 count=20".to_owned(),
        // An output redirect lands the bytes in another file.
        format!("dd if={scratch}/a.ts bs=1 count=4 > {home}/.zshrc"),
    ] {
        assert!(!permitted(&fixture, &command), "{command}");
    }
}
