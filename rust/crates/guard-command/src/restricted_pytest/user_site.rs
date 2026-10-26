//! The user's own Python packages, read-only, for contained pytest on macOS.
//!
//! The sandbox gives Python a private HOME, so packages installed with
//! `pip install --user` disappear and a pytest that depends on one cannot
//! start. Homebrew's pytest often takes pygments from there. The launcher links
//! `~/Library/Python` into the private HOME and the profile lets the sandbox
//! read it. Nothing there becomes writable, and the same packages already load
//! whenever the user runs Python outside the sandbox.

use super::*;
use std::collections::BTreeMap;

/// The user site root to link, when the user's Python would load it: macOS,
/// and neither `PYTHONNOUSERSITE` nor `PYTHONUSERBASE` in the caller's
/// environment. The root comes from the account's home, not the caller's HOME.
pub(super) fn link_target(source: &BTreeMap<String, String>) -> Option<PathBuf> {
    if !cfg!(target_os = "macos")
        || source
            .get("PYTHONNOUSERSITE")
            .is_some_and(|value| !value.is_empty())
        || source.contains_key("PYTHONUSERBASE")
    {
        return None;
    }
    account_root()
}

/// A profile may grant only the root `link_target` would have chosen.
pub(super) fn grantable(root: &Path) -> bool {
    cfg!(target_os = "macos") && account_root().as_deref() == Some(root)
}

fn account_root() -> Option<PathBuf> {
    let user = nix::unistd::User::from_uid(nix::unistd::getuid()).ok()??;
    owned_root(&user.dir)
}

/// `<home>/Library/Python` when `Library` and `Python` are real directories
/// that the current user owns and nobody else can write.
fn owned_root(home: &Path) -> Option<PathBuf> {
    let home = fs::canonicalize(home).ok()?;
    let library = home.join("Library");
    let root = library.join("Python");
    let private = |path: &Path| {
        fs::symlink_metadata(path).is_ok_and(|metadata| {
            metadata.is_dir()
                && metadata.uid() == nix::unistd::getuid().as_raw()
                && metadata.mode() & 0o022 == 0
        })
    };
    (private(&library) && private(&root)).then_some(root)
}

#[cfg(test)]
mod tests {
    use super::{grantable, link_target, owned_root};
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    #[test]
    fn the_user_site_stays_off_unless_linked() {
        let directory = Path::new("/tmp");
        let environment = |linked| {
            super::super::environment::filter(
                &BTreeMap::new(),
                directory,
                directory,
                directory,
                directory,
                &[],
                linked,
            )
            .unwrap()
        };
        assert_eq!(
            environment(false)
                .get("PYTHONNOUSERSITE")
                .map(String::as_str),
            Some("1")
        );
        assert!(!environment(true).contains_key("PYTHONNOUSERSITE"));
    }

    #[test]
    fn the_caller_can_switch_the_user_site_off_or_move_it() {
        for (name, value) in [
            ("PYTHONNOUSERSITE", "1"),
            ("PYTHONUSERBASE", "/tmp/elsewhere"),
        ] {
            let source = BTreeMap::from([(name.to_owned(), value.to_owned())]);
            assert_eq!(link_target(&source), None, "{name}");
        }
    }

    #[test]
    fn a_profile_grants_no_other_directory() {
        for root in ["/tmp", "/", "/Library/Python"] {
            assert!(!grantable(Path::new(root)), "{root}");
        }
    }

    #[test]
    fn only_a_private_real_directory_is_linked() {
        let home = std::env::temp_dir().join(format!("guard-user-site-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let home = std::fs::canonicalize(&home).unwrap();
        let library = home.join("Library");
        let root = library.join("Python");
        assert_eq!(owned_root(&home), None);

        std::fs::create_dir_all(&root).unwrap();
        for path in [&library, &root] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert_eq!(owned_root(&home), Some(root.clone()));

        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(owned_root(&home), None);

        std::fs::remove_dir(&root).unwrap();
        let elsewhere = home.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &root).unwrap();
        assert_eq!(owned_root(&home), None);

        let _ = std::fs::remove_dir_all(&home);
    }
}
