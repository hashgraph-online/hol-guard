use std::io;
use std::path::{Path, PathBuf};

use super::super::{aggregate, PROBE_FAILED};
#[cfg(unix)]
use super::super::{ABSENT, PATH_ESCAPE, USER_WRITABLE, VALID, WRONG_OWNER};
use super::{acl_text_is_mutable, lstat, verify_surfaces, Fingerprint, MacosSurface, Probe};

/// The real `lstat`, with hooks standing in for `ls -lde` and for a
/// filesystem that changes between two reads.
struct Staged<A, L>
where
    A: FnMut(&Path) -> io::Result<bool>,
    L: FnMut(&Path, Fingerprint) -> Fingerprint,
{
    acl: A,
    reread: L,
    queried: Vec<PathBuf>,
}

impl<A, L> Probe for Staged<A, L>
where
    A: FnMut(&Path) -> io::Result<bool>,
    L: FnMut(&Path, Fingerprint) -> Fingerprint,
{
    fn lstat(&mut self, path: &Path) -> io::Result<Fingerprint> {
        lstat(path).map(|fingerprint| (self.reread)(path, fingerprint))
    }

    fn acl_is_mutable(&mut self, path: &Path) -> io::Result<bool> {
        self.queried.push(path.to_path_buf());
        (self.acl)(path)
    }
}

#[cfg(unix)]
fn staged<A, L>(acl: A, reread: L) -> Staged<A, L>
where
    A: FnMut(&Path) -> io::Result<bool>,
    L: FnMut(&Path, Fingerprint) -> Fingerprint,
{
    Staged {
        acl,
        reread,
        queried: Vec::new(),
    }
}

fn no_entries(_: &Path) -> io::Result<bool> {
    Ok(false)
}

fn as_read(_: &Path, fingerprint: Fingerprint) -> Fingerprint {
    fingerprint
}

type Plain = Staged<fn(&Path) -> io::Result<bool>, fn(&Path, Fingerprint) -> Fingerprint>;

fn no_acl() -> Plain {
    Staged {
        acl: no_entries,
        reread: as_read,
        queried: Vec::new(),
    }
}

fn surface(name: &str, path: PathBuf, directory: bool, root: &Path) -> MacosSurface {
    MacosSurface {
        name: name.to_owned(),
        path: path.to_string_lossy().into_owned(),
        directory,
        trust_root: root.to_string_lossy().into_owned(),
    }
}

fn surfaces(root: &Path) -> Vec<MacosSurface> {
    vec![
        surface("runtime", root.join("runtime"), true, root),
        surface(
            "manifest",
            root.join("runtime/release-manifest.json"),
            false,
            root,
        ),
        surface("machineState", root.join("state"), true, root),
        surface("managedPolicy", root.join("policy.json"), false, root),
        surface("logs", root.join("logs"), true, root),
        surface(
            "serviceRegistration",
            root.join("service.plist"),
            false,
            root,
        ),
    ]
}

fn verdict(root: &Path, uid: u32, probe: &mut impl Probe) -> (&'static str, &'static str) {
    let verdict = aggregate(verify_surfaces(&surfaces(root), uid, probe));
    (verdict.status, verdict.reason_code)
}

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    use super::*;

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// The protected tree `acl.py`'s tests built, owned by the test account.
    fn protected_tree() -> (tempfile::TempDir, PathBuf, u32) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap().join("root");
        for name in ["", "runtime", "state", "logs"] {
            let path = root.join(name);
            fs::create_dir_all(&path).unwrap();
            set_mode(&path, 0o755);
        }
        for name in [
            "runtime/release-manifest.json",
            "policy.json",
            "service.plist",
        ] {
            let path = root.join(name);
            fs::write(&path, b"{}").unwrap();
            set_mode(&path, 0o644);
        }
        let uid = fs::metadata(&root).unwrap().uid();
        (directory, root, uid)
    }

    #[test]
    fn owned_surfaces_nobody_else_may_change_are_healthy() {
        let (_directory, root, uid) = protected_tree();
        let results = verify_surfaces(&surfaces(&root), uid, &mut no_acl());

        assert!(results
            .iter()
            .all(|result| result.state == "healthy" && result.reason_code == VALID));
        assert_eq!(verdict(&root, uid, &mut no_acl()), ("healthy", VALID));
    }

    #[test]
    fn a_shared_ancestor_is_queried_once() {
        let (_directory, root, uid) = protected_tree();
        let mut probe = no_acl();

        verdict(&root, uid, &mut probe);

        assert_eq!(
            probe.queried.iter().filter(|path| **path == root).count(),
            1
        );
    }

    #[test]
    fn a_surface_others_may_write_is_tampered() {
        let (_directory, root, uid) = protected_tree();
        set_mode(&root.join("state"), 0o777);

        assert_eq!(
            verdict(&root, uid, &mut no_acl()),
            ("tampered", USER_WRITABLE)
        );
    }

    #[test]
    fn an_acl_that_lets_another_account_write_is_tampered() {
        let (_directory, root, uid) = protected_tree();
        let state = root.join("state");
        let mut probe = staged(|path: &Path| Ok(path == state), as_read);

        assert_eq!(verdict(&root, uid, &mut probe), ("tampered", USER_WRITABLE));
    }

    #[test]
    fn a_surface_owned_by_another_account_is_tampered() {
        let (_directory, root, uid) = protected_tree();

        assert_eq!(
            verdict(&root, uid.wrapping_add(1), &mut no_acl()),
            ("tampered", WRONG_OWNER)
        );
    }

    #[test]
    fn a_linked_surface_escapes_and_a_missing_one_is_absent() {
        let (_directory, root, uid) = protected_tree();
        let manifest = root.join("runtime/release-manifest.json");
        fs::remove_file(&manifest).unwrap();
        std::os::unix::fs::symlink(root.join("policy.json"), &manifest).unwrap();

        assert_eq!(
            verdict(&root, uid, &mut no_acl()),
            ("tampered", PATH_ESCAPE)
        );
        fs::remove_file(&manifest).unwrap();
        assert_eq!(verdict(&root, uid, &mut no_acl()), ("absent", ABSENT));
    }

    #[test]
    fn a_surface_of_the_wrong_type_escapes() {
        let (_directory, root, uid) = protected_tree();
        fs::remove_dir(root.join("logs")).unwrap();
        fs::write(root.join("logs"), b"").unwrap();
        set_mode(&root.join("logs"), 0o644);

        assert_eq!(
            verdict(&root, uid, &mut no_acl()),
            ("tampered", PATH_ESCAPE)
        );
    }

    #[test]
    fn a_component_changed_while_it_was_read_fails_the_probe() {
        let (_directory, root, uid) = protected_tree();
        let mut probe = staged(
            |path: &Path| {
                if path == root {
                    set_mode(path, 0o700);
                }
                Ok(false)
            },
            as_read,
        );

        assert_eq!(verdict(&root, uid, &mut probe), ("unknown", PROBE_FAILED));
    }

    #[test]
    fn a_surface_swapped_before_the_final_read_fails_the_probe() {
        let (_directory, root, uid) = protected_tree();
        let target = root.join("service.plist");
        let mut reads = 0;
        let mut probe = staged(no_entries, |path: &Path, mut fingerprint: Fingerprint| {
            if path == target {
                reads += 1;
                if reads == 4 {
                    fingerprint.inode += 1;
                }
            }
            fingerprint
        });
        let only = [surface("serviceRegistration", target.clone(), false, &root)];

        let results = verify_surfaces(&only, uid, &mut probe);

        assert_eq!(results[0].state, "unknown");
        assert_eq!(results[0].reason_code, PROBE_FAILED);
    }

    #[test]
    fn a_failed_acl_query_fails_the_probe() {
        let (_directory, root, uid) = protected_tree();
        let mut probe = staged(|_: &Path| Err(io::Error::other("ls failed")), as_read);

        assert_eq!(verdict(&root, uid, &mut probe), ("unknown", PROBE_FAILED));
    }

    #[test]
    fn a_path_outside_its_root_or_spelled_relative_fails_the_probe() {
        let (_directory, root, uid) = protected_tree();
        let outside = root.parent().unwrap().to_path_buf();
        let rejected = [
            surface("outside", outside, true, &root),
            surface("relative", PathBuf::from("root/state"), true, &root),
            surface("dotdot", root.join("state/../logs"), true, &root),
        ];

        for result in verify_surfaces(&rejected, uid, &mut no_acl()) {
            assert_eq!(
                (result.state.as_str(), result.reason_code.as_str()),
                ("unknown", PROBE_FAILED),
                "{}",
                result.name
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_system_acl_query_reads_a_private_directory() {
        let (_directory, root, _uid) = protected_tree();

        let text = super::super::list_acl(&root).unwrap();

        assert!(!acl_text_is_mutable(&text));
    }
}

#[cfg(not(unix))]
#[test]
fn without_unix_metadata_every_surface_fails_the_probe() {
    let root = std::env::temp_dir();

    assert_eq!(verdict(&root, 0, &mut no_acl()), ("unknown", PROBE_FAILED));
}

#[test]
fn an_acl_entry_granting_another_account_a_write_right_is_mutable() {
    let header = "-rw-r--r--+ 1 root wheel 0 Jul 17 00:00 policy\n";
    for entry in [
        " 0: user:developer allow read,writeattr,delete\n",
        " 0: group:wheel allow read,writeattr\n",
        " 1: group:everyone allow add_file\n",
        " 0: user:developer allow read,WRITE\n",
        " 0: user:developer inherited allow add_\u{17f}ubdirectory\n",
    ] {
        assert!(acl_text_is_mutable(&format!("{header}{entry}")), "{entry}");
    }
}

#[test]
fn root_read_and_deny_entries_leave_the_listing_immutable() {
    let header = "-rw-r--r--+ 1 root wheel 0 Jul 17 00:00 policy\n";
    for entry in [
        "",
        " 0: user:root inherited allow read,writeattr\n",
        " 0: USER:ROOT allow write\n",
        " 0: user:developer allow read,readattr\n",
        " 0: user:developer deny write,delete\n",
        " x: user:developer allow write\n",
        "user:developer allow write\n",
    ] {
        assert!(!acl_text_is_mutable(&format!("{header}{entry}")), "{entry}");
    }
    assert!(!acl_text_is_mutable(" 0: user:developer allow write\n"));
}
