//! Git for macOS as shipped with Xcode and the Command Line Tools.
//!
//! `/usr/bin/git` is a shim that runs the Git of the developer directory
//! `xcode-select` chose, and only an administrator can change that choice.
//! A helper Git bundles beside its own programs, such as
//! `git-credential-osxkeychain`, is then as trusted as the Git the shim
//! already runs, provided nothing on its path is writable by anyone but root.
//! The probes clear the environment, so a `DEVELOPER_DIR` or `TOOLCHAINS`
//! the agent's shell sets would make the shim run a different Git than the
//! one probed; such a shell keeps its review.

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::path::{Component, Path};

/// Variables the `/usr/bin` shims read to pick another developer directory
/// or toolchain, which may be user-writable.
const SHIM_SELECTORS: &[&str] = &["DEVELOPER_DIR", "TOOLCHAINS"];
const SHIM: &str = "/usr/bin/git";
/// macOS gives the `admin` group write access to `/Applications`.
const ADMIN_GID: u32 = 80;

/// Whether `binary` is the macOS Git shim and the agent's environment
/// redirects it away from the developer directory the probe would use.
pub(crate) fn selection_overridden(
    binary: &Path,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    if !cfg!(target_os = "macos") || binary != Path::new(SHIM) {
        return false;
    }
    match execution_environment {
        Some(environment) => names_select_shim(environment.environment_names.iter()),
        None => SHIM_SELECTORS
            .iter()
            .any(|name| std::env::var_os(name).is_some()),
    }
}

fn names_select_shim<'a>(mut names: impl Iterator<Item = &'a String>) -> bool {
    names.any(|name| {
        SHIM_SELECTORS
            .iter()
            .any(|selector| name.eq_ignore_ascii_case(selector))
    })
}

/// Whether the canonical `helper` sits directly in the canonical `exec_path`
/// of an Apple developer directory, with root owning every component and
/// nobody else able to write to any of them.
pub(crate) fn bundled_helper(helper: &Path, exec_path: &Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt;
        sealed(helper, exec_path, |path| {
            let metadata = std::fs::symlink_metadata(path).ok()?;
            Some(Entry {
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: metadata.mode(),
                directory: metadata.file_type().is_dir(),
                file: metadata.file_type().is_file(),
            })
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (helper, exec_path);
        false
    }
}

struct Entry {
    uid: u32,
    gid: u32,
    mode: u32,
    directory: bool,
    file: bool,
}

fn sealed(helper: &Path, exec_path: &Path, lookup: impl Fn(&Path) -> Option<Entry>) -> bool {
    if helper.parent() != Some(exec_path) || !developer_directory(exec_path) {
        return false;
    }
    if !lookup(helper).is_some_and(|entry| entry.file && root_only(&entry)) {
        return false;
    }
    exec_path.ancestors().all(|directory| {
        lookup(directory).is_some_and(|entry| {
            entry.directory
                && (root_only(&entry)
                    // Admins can already administer the machine; anyone
                    // else would need root to replace the bundle below.
                    || directory == Path::new("/Applications")
                        && entry.uid == 0
                        && entry.gid == ADMIN_GID
                        && entry.mode & 0o002 == 0)
        })
    })
}

fn root_only(entry: &Entry) -> bool {
    entry.uid == 0 && entry.mode & 0o022 == 0
}

/// Inside `/Library/Developer/CommandLineTools` or an app bundle's
/// `Contents/Developer` directly under `/Applications`.
fn developer_directory(path: &Path) -> bool {
    if path.starts_with("/Library/Developer/CommandLineTools") {
        return true;
    }
    let Ok(rest) = path.strip_prefix("/Applications") else {
        return false;
    };
    let mut components = rest.components();
    matches!(
        (components.next(), components.next(), components.next()),
        (
            Some(Component::Normal(bundle)),
            Some(Component::Normal(contents)),
            Some(Component::Normal(developer)),
        ) if Path::new(bundle).extension().is_some_and(|extension| extension == "app")
            && contents == "Contents"
            && developer == "Developer"
    )
}

#[cfg(test)]
#[path = "apple_developer_tools_tests.rs"]
mod tests;
