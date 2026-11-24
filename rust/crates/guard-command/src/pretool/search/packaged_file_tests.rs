use super::{packaged_file, root_owned_readable, system_tree};
use std::path::Path;

#[test]
fn only_root_owned_world_readable_unshared_files_qualify() {
    assert!(root_owned_readable(0, 0o100644));
    assert!(root_owned_readable(0, 0o100755));
    assert!(!root_owned_readable(1000, 0o100644));
    assert!(!root_owned_readable(0, 0o100600));
    assert!(!root_owned_readable(0, 0o100640));
    assert!(!root_owned_readable(0, 0o100664));
    assert!(!root_owned_readable(0, 0o100666));
}

#[test]
fn system_tree_is_usr_without_local() {
    assert!(system_tree(Path::new("/usr/lib/python3/dist-packages")));
    assert!(system_tree(Path::new("/usr/include/c++/14")));
    assert!(system_tree(Path::new(
        "/usr/share/doc/git/contrib/credential"
    )));
    assert!(!system_tree(Path::new("/usr")));
    assert!(!system_tree(Path::new("/usr/local/lib/python3.13")));
    assert!(!system_tree(Path::new("/usr/local")));
    assert!(!system_tree(Path::new("/usrx/lib")));
    assert!(!system_tree(Path::new("/etc/ssl/private")));
    assert!(!system_tree(Path::new("/home/dev/usr/lib")));
}

#[test]
fn a_file_the_user_owns_is_never_packaged() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("credentials.json");
    std::fs::write(&file, "{}").unwrap();
    assert!(!packaged_file(&file));
    assert!(!packaged_file(&dir.path().join("missing.pem")));
}

/// Headers and documentation that distributions install with a name the
/// credential screen refuses. Whichever exists on this host must be admitted
/// when Guard does not run as root.
#[test]
fn installed_system_files_with_credential_names_are_packaged() {
    if nix::unistd::geteuid().is_root() {
        return;
    }
    let mut candidates: Vec<std::path::PathBuf> = [
        "/usr/share/doc/git/contrib/credential/netrc/test.netrc",
        "/usr/share/doc/git/contrib/credential/libsecret/Makefile",
    ]
    .iter()
    .map(std::path::PathBuf::from)
    .collect();
    if let Ok(versions) = std::fs::read_dir("/usr/include/c++") {
        candidates.extend(
            versions
                .flatten()
                .map(|entry| entry.path().join("stop_token")),
        );
    }
    for candidate in candidates.iter().filter(|path| path.is_file()) {
        let root = candidate.parent().unwrap().parent().unwrap();
        assert!(
            super::super::tree::descendant_allowed(candidate, root, true),
            "{} should be searchable",
            candidate.display()
        );
    }
}
