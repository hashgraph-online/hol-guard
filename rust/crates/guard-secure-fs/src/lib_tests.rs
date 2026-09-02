use super::*;
#[cfg(unix)]
use std::{fs::File, io::Write};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
fn fixture_root(name: &str) -> PathBuf {
    #[cfg(unix)]
    let temporary_root =
        fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir());
    #[cfg(not(unix))]
    let temporary_root = std::env::temp_dir();
    temporary_root.join(format!("guard-secure-fs-{name}-{}", std::process::id()))
}

#[cfg(unix)]
#[test]
fn bounded_read_hashes_regular_file() {
    let dir = fixture_root("read");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("sample.rs");
    let mut file = File::create(&path).unwrap();
    file.write_all(b"fn main() {}\n").unwrap();
    drop(file);
    let read = read_bounded(&path, MAX_SCAN_BYTES).unwrap();
    assert_eq!(read.bytes, b"fn main() {}\n");
    assert_eq!(read.sha256.len(), 64);
    let _ = fs::remove_dir_all(dir);
}

#[cfg(windows)]
#[test]
fn bounded_read_fails_closed_on_windows_without_descriptor_path_walk() {
    let dir = fixture_root("read");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("sample.rs");
    fs::write(&path, b"fn main() {}\n").unwrap();
    assert!(matches!(
        read_bounded(&path, MAX_SCAN_BYTES),
        Err(SecureReadError::PathChanged)
    ));
    let _ = fs::remove_dir_all(dir);
}

#[cfg(all(not(unix), not(windows)))]
#[test]
fn bounded_read_fails_closed_without_descriptor_path_walk() {
    let dir = fixture_root("read");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("sample.rs");
    fs::write(&path, b"fn main() {}\n").unwrap();
    assert!(matches!(
        read_bounded(&path, MAX_SCAN_BYTES),
        Err(SecureReadError::PathChanged)
    ));
    let _ = fs::remove_dir_all(dir);
}

#[cfg(windows)]
#[test]
fn bounded_read_rejects_oversized_windows_file_before_path_walk() {
    let dir = fixture_root("oversized");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("sample.rs");
    fs::write(&path, vec![b'x'; MAX_SCAN_BYTES + 1]).unwrap();
    let result = read_bounded(&path, MAX_SCAN_BYTES);
    let _ = fs::remove_dir_all(dir);
    assert!(matches!(result, Err(SecureReadError::TooLarge)));
}

#[cfg(unix)]
#[test]
fn bounded_read_rejects_hard_linked_source() {
    let dir = fixture_root("hard-link");
    fs::create_dir_all(&dir).unwrap();
    let source = dir.join("source.rs");
    let alias = dir.join("alias.rs");
    fs::write(&source, b"fn source() {}\n").unwrap();
    fs::hard_link(&source, &alias).unwrap();
    assert!(matches!(
        read_bounded(&alias, MAX_SCAN_BYTES),
        Err(SecureReadError::HardLinkedFile)
    ));
    let _ = fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn bounded_read_rejects_file_without_read_permission_even_for_root() {
    let dir = fixture_root("permissions");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("source.rs");
    fs::write(&path, b"fn source() {}\n").unwrap();
    let original_mode = path.metadata().unwrap().permissions().mode();
    let mut permissions = path.metadata().unwrap().permissions();
    permissions.set_mode(original_mode & !0o444);
    fs::set_permissions(&path, permissions).unwrap();
    assert!(matches!(
        read_bounded(&path, MAX_SCAN_BYTES),
        Err(SecureReadError::PermissionDenied)
    ));
    let mut permissions = path.metadata().unwrap().permissions();
    permissions.set_mode(original_mode);
    fs::set_permissions(&path, permissions).unwrap();
    let _ = fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn bounded_read_rejects_symlink_source() {
    let dir = fixture_root("symlink");
    fs::create_dir_all(&dir).unwrap();
    let target = dir.join("target.rs");
    let link = dir.join("source.rs");
    fs::write(&target, b"fn target() {}\n").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(matches!(
        read_bounded(&link, MAX_SCAN_BYTES),
        Err(SecureReadError::SymlinkInPath)
    ));
    let _ = fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn bounded_read_rejects_parent_symlink_source_replacement() {
    let dir = fixture_root("parent-replacement");
    let real = dir.join("real");
    let alias = dir.join("alias");
    fs::create_dir_all(&real).unwrap();
    fs::write(real.join("source.rs"), b"fn source() {}\n").unwrap();
    std::os::unix::fs::symlink(&real, &alias).unwrap();

    assert!(matches!(
        read_bounded(&alias.join("source.rs"), MAX_SCAN_BYTES),
        Err(SecureReadError::SymlinkInPath)
    ));
    let _ = fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn file_identity_changes_when_source_permissions_change() {
    let dir = fixture_root("identity-permissions");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("source.rs");
    fs::write(&path, b"fn source() {}\n").unwrap();
    let before = identity(&path.metadata().unwrap());
    let original_mode = before.mode;

    let mut permissions = path.metadata().unwrap().permissions();
    permissions.set_mode(original_mode ^ 0o001);
    fs::set_permissions(&path, permissions).unwrap();
    let after = identity(&path.metadata().unwrap());

    assert_ne!(before, after);
    assert_ne!(before.mode, after.mode);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn sensitive_paths_are_classified() {
    assert_eq!(
        sensitive_path_family(Path::new("/home/u/.aws/credentials"))
            .unwrap()
            .0,
        "AWS shared credentials file"
    );
    assert_eq!(
        sensitive_path_family(Path::new(".env.local")).unwrap().1,
        "critical"
    );
}

#[test]
fn source_classifier_rejects_hidden_sensitive_and_escape_paths() {
    let root = fixture_root("classifier");
    let home = root.join("home");
    let workspace = home.join("workspace");
    fs::create_dir_all(workspace.join("src")).unwrap();
    fs::create_dir_all(workspace.join(".secret")).unwrap();
    fs::write(workspace.join("src/main.rs"), "fn main() {}\n").unwrap();
    fs::write(workspace.join(".secret/config.ts"), "value = 1\n").unwrap();
    fs::write(workspace.join(".env"), "fixture=value\n").unwrap();
    let skill = home.join(".claude/skills/safe");
    fs::create_dir_all(skill.join("credentials")).unwrap();
    fs::write(skill.join("SKILL.md"), "# Safe\n").unwrap();
    fs::write(skill.join("credentials/config.ts"), "value = 1\n").unwrap();

    assert!(classify_source_path("src/main.rs", &workspace, Some(&home), false).allowed);
    assert_eq!(
        classify_source_path(".secret/config.ts", &workspace, Some(&home), false).reason_code,
        "unsafe_hidden_dir"
    );
    assert_eq!(
        classify_source_path(".env", &workspace, Some(&home), false).reason_code,
        "sensitive_basename"
    );
    assert_eq!(
        classify_source_path("../../outside.rs", &workspace, Some(&home), true).reason_code,
        "path_traversal"
    );
    assert_eq!(
        classify_source_path(
            "~/.claude/skills/safe/../../src/app.py",
            &workspace,
            Some(&home),
            false,
        )
        .reason_code,
        "path_traversal"
    );
    assert_eq!(
        classify_source_path(
            "~/.claude/skills/safe/credentials/config.ts",
            &workspace,
            Some(&home),
            false,
        )
        .reason_code,
        "sensitive_basename"
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn source_classifier_allows_workflow_and_sibling_git_source() {
    let root = fixture_root("external");
    let home = root.join("home");
    let workspace = home.join("workspace");
    let workflow = workspace.join(".github/workflows/publish.yml");
    fs::create_dir_all(workflow.parent().unwrap()).unwrap();
    fs::write(&workflow, "jobs: {}\n").unwrap();
    let sibling = home.join("sibling");
    let sibling_file = sibling.join("src/main.py");
    fs::create_dir_all(sibling_file.parent().unwrap()).unwrap();
    fs::create_dir_all(sibling.join(".git")).unwrap();
    fs::write(&sibling_file, "value = 1\n").unwrap();

    assert!(
        classify_source_path(
            ".github/workflows/publish.yml",
            &workspace,
            Some(&home),
            false
        )
        .allowed
    );
    let external = classify_source_path(
        sibling_file.to_str().unwrap(),
        &workspace,
        Some(&home),
        true,
    );
    assert!(external.allowed);
    assert_eq!(external.reason_code, "external_source_path");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn source_classifier_rejects_sensitive_external_filename_without_substring_false_positive() {
    let root = fixture_root("external-sensitive");
    let home = root.join("home");
    let workspace = home.join("workspace");
    fs::create_dir_all(&workspace).unwrap();
    let sibling = home.join("sibling");
    fs::create_dir_all(sibling.join(".git")).unwrap();
    let sensitive = sibling.join("auth_token.ts");
    let benign = sibling.join("authentication.ts");
    fs::write(&sensitive, "value = 1\n").unwrap();
    fs::write(&benign, "value = 1\n").unwrap();

    assert_eq!(
        classify_source_path(sensitive.to_str().unwrap(), &workspace, Some(&home), true)
            .reason_code,
        "sensitive_basename"
    );
    assert!(classify_source_path(benign.to_str().unwrap(), &workspace, Some(&home), true).allowed);
    let _ = fs::remove_dir_all(root);
}
