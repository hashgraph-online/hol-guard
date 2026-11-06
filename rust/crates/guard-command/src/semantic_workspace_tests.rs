use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{capture_workspace, sanitize_tool_path, stage_workspace, write_atomic};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Tmp(PathBuf);

impl Tmp {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |value| value.as_nanos());
        let dir = std::env::temp_dir().join(format!(
            "hg-sem-ws-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).expect("tempdir");
        Tmp(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn workspace() -> Tmp {
    let dir = Tmp::new();
    fs::create_dir_all(dir.path().join("src")).expect("src");
    fs::write(dir.path().join("src/a.py"), b"x = 1\n").expect("a.py");
    fs::write(dir.path().join("patch.diff"), b"diff\n").expect("patch");
    dir
}

fn canonical(dir: &Tmp) -> PathBuf {
    dir.path().canonicalize().expect("canonical")
}

#[test]
fn capture_skips_git_state_and_digests_content() {
    let dir = workspace();
    fs::create_dir_all(dir.path().join(".git")).expect("git");
    fs::write(dir.path().join(".git/HEAD"), b"ref").expect("head");
    let root = canonical(&dir);
    let first = capture_workspace(&root).expect("capture");
    fs::write(root.join(".git/HEAD"), b"other").expect("head");
    let second = capture_workspace(&root).expect("capture");
    assert_eq!(first.digest, second.digest);
    fs::write(root.join("src/a.py"), b"x = 2\n").expect("edit");
    let third = capture_workspace(&root).expect("capture");
    assert_ne!(first.digest, third.digest);
}

#[test]
fn git_history_is_never_staged() {
    let dir = workspace();
    fs::create_dir_all(dir.path().join(".git/objects")).expect("objects");
    fs::write(dir.path().join(".git/objects/pack"), b"history").expect("pack");
    let home = Tmp::new();
    let root = canonical(&dir);
    let (stage, _capture) = stage_workspace(&root, home.path(), "run").expect("stage");
    assert!(stage.0.join("src/a.py").is_file());
    assert!(!stage.0.join(".git").exists());
}

#[test]
fn protected_files_symlinks_and_hardlinks_make_the_workspace_ineligible() {
    for name in [".env", ".env.local", "id_rsa", "server.pem", "api_key.txt"] {
        let dir = workspace();
        fs::write(dir.path().join(name), b"secret").expect("secret");
        let error = capture_workspace(&canonical(&dir)).expect_err("rejected");
        assert_eq!(error, "workspace_stage_protected", "{name}");
    }
    let dir = workspace();
    symlink("src/a.py", dir.path().join("alias.py")).expect("symlink");
    let error = capture_workspace(&canonical(&dir)).expect_err("rejected");
    assert_eq!(error, "workspace_stage_symlink");
    let dir = workspace();
    fs::hard_link(dir.path().join("src/a.py"), dir.path().join("twin.py")).expect("hardlink");
    let error = capture_workspace(&canonical(&dir)).expect_err("rejected");
    assert_eq!(error, "workspace_stage_hardlink");
}

#[test]
fn stage_copies_only_eligible_files_and_removes_itself() {
    let dir = workspace();
    let home = Tmp::new();
    let root = canonical(&dir);
    let stage_path = {
        let (stage, capture) = stage_workspace(&root, home.path(), "run").expect("stage");
        assert_eq!(
            fs::read(stage.0.join("src/a.py")).expect("a.py"),
            b"x = 1\n"
        );
        assert_eq!(
            capture.digest,
            capture_workspace(&root).expect("again").digest
        );
        stage.0.clone()
    };
    assert!(!stage_path.exists());
}

#[test]
fn stage_inside_the_workspace_is_refused() {
    let dir = workspace();
    let root = canonical(&dir);
    let error = stage_workspace(&root, &root.join("home"), "run").expect_err("refused");
    assert_eq!(error, "workspace_stage_inside_workspace");
}

#[test]
fn tool_path_drops_relative_workspace_and_duplicate_entries() {
    let dir = workspace();
    let root = canonical(&dir);
    let planted = root.join("bin");
    fs::create_dir_all(&planted).expect("bin");
    let raw = format!("relative/bin::/usr/bin:{}:/usr/bin:/bin", planted.display());
    assert_eq!(
        sanitize_tool_path(Some(&raw), &[root.as_path()]),
        "/usr/bin:/bin"
    );
    assert_eq!(
        sanitize_tool_path(None, &[]),
        "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"
    );
    assert_eq!(
        sanitize_tool_path(Some("rel"), &[]),
        "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"
    );
}

#[test]
fn atomic_write_preserves_the_target_mode() {
    let dir = workspace();
    let target = canonical(&dir).join("src/a.py");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).expect("chmod");
    write_atomic(&target, b"x = 2\n", None).expect("write");
    assert_eq!(fs::read(&target).expect("read"), b"x = 2\n");
    let mode = fs::metadata(&target).expect("meta").permissions().mode() & 0o777;
    assert_eq!(mode, 0o755);
    let created = canonical(&dir).join("src/new.py");
    write_atomic(&created, b"y\n", None).expect("create");
    assert_eq!(
        fs::metadata(&created).expect("meta").permissions().mode() & 0o777,
        0o644
    );
}

#[test]
fn atomic_write_never_follows_a_planted_temporary_link() {
    let dir = workspace();
    let outside = Tmp::new();
    let victim = outside.path().join("victim");
    fs::write(&victim, b"keep").expect("victim");
    let target = canonical(&dir).join("src/a.py");
    symlink(&victim, canonical(&dir).join("src/a.py.contained.tmp")).expect("planted");
    symlink(&victim, canonical(&dir).join("src/.a.py.contained.tmp")).expect("planted");
    write_atomic(&target, b"x = 2\n", None).expect("write");
    assert_eq!(fs::read(&victim).expect("victim"), b"keep");
    assert_eq!(fs::read(&target).expect("read"), b"x = 2\n");
}

#[test]
fn atomic_write_refuses_a_symlink_or_directory_target() {
    let dir = workspace();
    let root = canonical(&dir);
    let outside = Tmp::new();
    symlink(outside.path().join("elsewhere"), root.join("link.py")).expect("link");
    assert_eq!(
        write_atomic(&root.join("link.py"), b"x", None).expect_err("refused"),
        "write_target_not_regular"
    );
    assert_eq!(
        write_atomic(&root.join("src"), b"x", None).expect_err("refused"),
        "write_target_not_regular"
    );
    assert!(!Path::new(&outside.path().join("elsewhere")).exists());
}

fn policy(
    action: crate::contained_execution::ContainmentAction,
    writes: Vec<String>,
) -> crate::contained_execution::ContainmentPolicy {
    crate::contained_execution::ContainmentPolicy {
        schema_version: "containment-contract-v1".to_owned(),
        action,
        workspace_read_paths: vec!["/tmp/ws".to_owned()],
        workspace_write_paths: writes,
        env_allowlist: vec![],
        allowed_domains: vec![],
        timeout_seconds: 1,
        max_processes: 8,
        max_open_files: 256,
        max_file_size_bytes: 1024,
        max_write_bytes_total: 1024,
        max_output_bytes: 1024,
        memory_mb: 64,
        additional_read_paths: vec![],
        allow_outbound_network: false,
    }
}

#[test]
fn only_a_read_policy_may_omit_the_write_scope() {
    use crate::contained_execution::{validate_containment_policy, ContainmentAction};
    assert!(validate_containment_policy(&policy(ContainmentAction::Read, vec![])).is_ok());
    assert_eq!(
        validate_containment_policy(&policy(ContainmentAction::Write, vec![])).expect_err("write"),
        "policy_write_paths"
    );
    assert!(validate_containment_policy(&policy(
        ContainmentAction::Write,
        vec!["/tmp/ws".to_owned()]
    ))
    .is_ok());
}

#[test]
fn staged_copy_of_a_read_only_file_is_owner_writable() {
    let dir = workspace();
    let root = canonical(&dir);
    fs::set_permissions(root.join("src/a.py"), fs::Permissions::from_mode(0o444)).expect("chmod");
    let home = Tmp::new();
    let (stage, _capture) = stage_workspace(&root, home.path(), "run").expect("stage");
    let mode = fs::metadata(stage.0.join("src/a.py"))
        .expect("meta")
        .permissions()
        .mode();
    assert_ne!(mode & 0o200, 0, "staged copy must be owner-writable");
}
