use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::shell_secret_reads::assess_shell_reads;

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

const TEMPLATE: &str = "APP_PORT=\nAPP_HOST=\n";

/// A home holding one repository whose index lists `tracked`, under the build
/// tree so the location screens treat it as an ordinary workspace.
fn fixture(tracked: &[&str]) -> (PathBuf, PathBuf) {
    let nonce = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "guard-template-reads-{}-{nonce}",
            std::process::id()
        ));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(project.join(".git/info")).unwrap();
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("src/app.ts"), "export const port = 3000;\n").unwrap();
    std::fs::write(project.join(".env.example"), TEMPLATE).unwrap();
    std::fs::write(project.join(".env.sample"), TEMPLATE).unwrap();
    std::fs::write(project.join(".env"), "APP_PORT=3000\n").unwrap();
    write_index(&project.join(".git"), tracked);
    (
        std::fs::canonicalize(home).unwrap(),
        std::fs::canonicalize(project).unwrap(),
    )
}

/// A version 2 index at `git_dir` listing `names`, as `git add` writes it.
fn write_index(git_dir: &Path, names: &[&str]) {
    let mut bytes = b"DIRC".to_vec();
    bytes.extend_from_slice(&2_u32.to_be_bytes());
    bytes.extend_from_slice(&(names.len() as u32).to_be_bytes());
    for name in names {
        let entry = (62 + name.len() + 8) & !7;
        let start = bytes.len();
        bytes.resize(start + 60, 0);
        bytes.extend_from_slice(&(name.len() as u16).to_be_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.resize(start + entry, 0);
    }
    std::fs::write(git_dir.join("index"), bytes).unwrap();
}

fn sensitive(command: &str, home: &Path, project: &Path) -> Vec<String> {
    assess_shell_reads(command, Some(project), Some(home)).sensitive_paths
}

const TRACKED: &[&str] = &[".env.example", "src/app.ts"];

#[test]
fn a_plain_read_of_a_committed_template_is_relieved() {
    let (home, project) = fixture(TRACKED);
    for command in [
        "grep -n APP_PORT .env.example",
        "cat .env.example",
        "head -5 .env.example",
        "tail -n 3 ./.env.example",
        "wc -l .env.example",
        "rg -n APP_ .env.example",
        "grep -n port src/app.ts | head -8; grep -n APP_PORT .env.example",
        "cat .env.example 2>/dev/null || echo missing",
    ] {
        assert!(
            sensitive(command, &home, &project).is_empty(),
            "{command} should read the committed template quietly"
        );
    }
}

#[test]
fn the_live_dotenv_file_keeps_its_review() {
    let (home, project) = fixture(TRACKED);
    for command in [
        "cat .env",
        "grep -n APP_PORT .env",
        "cat .env.example .env",
        "grep -n APP_PORT .env.example; cat .env",
    ] {
        assert!(
            !sensitive(command, &home, &project).is_empty(),
            "{command} must keep the dotenv review"
        );
    }
}

#[test]
fn an_untracked_template_keeps_its_review() {
    let (home, project) = fixture(TRACKED);
    assert!(!sensitive("cat .env.sample", &home, &project).is_empty());
}

#[test]
fn a_template_holding_a_value_keeps_its_review() {
    let (home, project) = fixture(TRACKED);
    let header = concat!("-----BEGIN RSA PRIVATE", " KEY-----");
    std::fs::write(
        project.join(".env.example"),
        format!("SIGNING_KEY=\"{header}\n  MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo\"\n"),
    )
    .unwrap();
    assert!(!sensitive("cat .env.example", &home, &project).is_empty());
}

#[test]
fn a_chain_that_could_change_or_reroute_the_template_keeps_its_review() {
    let (home, project) = fixture(TRACKED);
    for command in [
        "cp .env .env.example; cat .env.example",
        "mv .env .env.example && cat .env.example",
        "ln -sf .env .env.example; cat .env.example",
        "git checkout -- .env.example; cat .env.example",
        "cat .env.example > copy.txt",
        "cat .env.example | tee copy.txt",
        "cat .env.example $(echo .env)",
        "rg --pre sh APP .env.example",
        "rg -z APP .env.example",
        "PATH=/tmp/bin cat .env.example",
        "env cat .env.example",
        "sh -c 'cat .env.example'",
        "source .env.example",
        ". .env.example",
    ] {
        assert!(
            !sensitive(command, &home, &project).is_empty(),
            "{command} must keep the template review"
        );
    }
}
