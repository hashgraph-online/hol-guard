use super::{bounded_file_read_target, bounded_structured_file_read_target};
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A checkout holding a committed template beside the local dotenv file it
/// documents, the way a repository actually keeps the pair.
fn checkout_with_template() -> std::path::PathBuf {
    let nonce = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "guard-read-template-{}-{nonce}",
            std::process::id()
        ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join(".git/info")).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    for name in TEMPLATES {
        std::fs::write(root.join(name), "API_BASE_URL=\nFEATURE_FLAGS=\n").unwrap();
    }
    for name in LOCAL_FILES {
        std::fs::write(root.join(name), "API_BASE_URL=\n").unwrap();
    }
    std::fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
    let mut tracked: Vec<&str> = TEMPLATES.to_vec();
    tracked.extend_from_slice(LOCAL_FILES);
    tracked.push("src/main.rs");
    write_index(&root.join(".git"), &tracked);
    root
}

/// The committed templates the fixture tracks.
const TEMPLATES: &[&str] = &[".env.example", ".env.sample", ".env.template"];

/// The local environment files beside them. The fixture tracks these too, so
/// index membership alone cannot be what admits a template.
const LOCAL_FILES: &[&str] = &[".env", ".env.local", ".env.examples"];

/// A version 2 index at `git_dir` listing `names`, as `git add` writes it.
fn write_index(git_dir: &std::path::Path, names: &[&str]) {
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

#[test]
fn a_structured_read_of_a_committed_template_is_admitted() {
    let root = checkout_with_template();
    let cwd = root.to_string_lossy().into_owned();
    for name in TEMPLATES {
        let target = root.join(name).to_string_lossy().into_owned();
        assert!(
            bounded_structured_file_read_target(&target, None, Some(&cwd)),
            "the read tool should admit the committed template {name}"
        );
    }
}

#[test]
fn a_structured_read_of_the_local_dotenv_file_is_not_admitted() {
    let root = checkout_with_template();
    let cwd = root.to_string_lossy().into_owned();
    for name in LOCAL_FILES {
        let target = root.join(name).to_string_lossy().into_owned();
        assert!(
            !bounded_structured_file_read_target(&target, None, Some(&cwd)),
            "the local environment file {name} stays unproved"
        );
    }
}

#[test]
fn a_shell_operand_naming_a_template_stays_unproved() {
    let root = checkout_with_template();
    let cwd = root.to_string_lossy().into_owned();
    let target = root.join(".env.example").to_string_lossy().into_owned();
    assert!(
        !bounded_file_read_target(&target, None, Some(&cwd)),
        "what a command does with a template keeps the whole dotenv family"
    );
}

#[test]
fn an_untracked_template_stays_unproved() {
    let root = checkout_with_template();
    let cwd = root.to_string_lossy().into_owned();
    let path = root.join(".env.dist");
    std::fs::write(&path, "API_BASE_URL=\n").unwrap();
    let target = path.to_string_lossy().into_owned();
    assert!(
        !bounded_structured_file_read_target(&target, None, Some(&cwd)),
        "a template the repository does not track has no proof behind its name"
    );
}

#[test]
fn a_template_holding_a_real_value_stays_unproved() {
    let root = checkout_with_template();
    let cwd = root.to_string_lossy().into_owned();
    let path = root.join(".env.example");
    // Built at run time so the repository's own secret scanners read no
    // literal credential in this file.
    let value = format!("gh{}_{}", "p", "Ab3kQ9rT2wX7yL5nV8mC1pD4sF6hJ0gK2zR9");
    std::fs::write(&path, format!("GITHUB_TOKEN={value}\n")).unwrap();
    let target = path.to_string_lossy().into_owned();
    assert!(
        !bounded_structured_file_read_target(&target, None, Some(&cwd)),
        "a template that holds a real value keeps its review"
    );
}
