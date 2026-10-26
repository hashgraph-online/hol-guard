//! Content reads of installed dependency and toolchain source kept below a
//! hidden home directory.
//!
//! Agents read the code of an installed tool or library while debugging it:
//! `~/.local/pipx/venvs/<tool>/lib/python3.12/site-packages/<pkg>/<mod>.py`,
//! `~/.cargo/registry/src/<index>/<crate>/src/lib.rs`, the standard library
//! below `~/.rustup/toolchains/<t>/lib/rustlib/src`, or a global package in
//! `~/.nvm/versions/node/<v>/lib/node_modules`. The same read below the
//! visible `~/go/pkg/mod` already passes; only the hidden home component made
//! these ask.
//!
//! The tree is recognised by its install root, not by a list of tools:
//!
//! * a `node_modules` component;
//! * a `site-packages` or `dist-packages` component whose parent is a Python
//!   library directory (`lib`, `python3.12`, `pypy3.10`);
//! * `~/.cargo/registry/src` and `~/.cargo/git/checkouts`, Cargo's unpacked
//!   source caches;
//! * `~/.rustup/toolchains/<toolchain>/lib/rustlib/src`.
//!
//! The target must sit at or below that root. Files beside it, such as
//! `~/.cargo/credentials.toml`, `~/.cargo/config.toml`, `~/.npmrc`, or a
//! tool's download cache, never qualify. The spelled path must be the
//! resolved one, so a link inside a package tree that points elsewhere keeps
//! its review, and so does a package tree reached through a linked directory.
//! No component above the root may carry a credential name (`.ssh`, `.aws`,
//! `secrets`, `credentials`), and only the first component below home may be
//! hidden. Below the root, hidden entries other than benign project dotfiles,
//! key and certificate containers, and every sensitive name family
//! (`.env*`, `.npmrc`, `.pypirc`, `*.key`, `credentials*`) stay reviewed.
//! This only proves reads: every write screen is separate and unchanged.

use std::path::{Component, Path, PathBuf};

/// Whether `canonical`, the resolved form of the read target `spelled`, is
/// installed dependency or toolchain source below the home directory.
pub(super) fn installed_package_source(
    spelled: &Path,
    canonical: &Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let Some(home) = home_dir
        .map(str::trim)
        .filter(|home| !home.is_empty() && Path::new(home).is_absolute())
    else {
        return false;
    };
    let Ok(resolved_home) = std::fs::canonicalize(home) else {
        return false;
    };
    let Some(names) = canonical
        .strip_prefix(&resolved_home)
        .ok()
        .and_then(normal_names)
    else {
        return false;
    };
    let spelled_names = spelled
        .strip_prefix(home)
        .or_else(|_| spelled.strip_prefix(&resolved_home))
        .ok()
        .and_then(normal_names);
    if spelled_names.is_none_or(|spelled| spelled != names) {
        return false;
    }
    let Some(root) = install_root(&names) else {
        return false;
    };
    above_root_allowed(&names[..root])
        && below_root_allowed(&names[root + 1..])
        && super::resolved_location_allowed(canonical, home_dir, cwd, false)
}

/// The path's names, or `None` when it holds anything but plain names.
fn normal_names(path: &Path) -> Option<Vec<&str>> {
    path.components()
        .map(|component| match component {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect()
}

/// Index of the outermost install root among `names`, the path below home.
fn install_root(names: &[&str]) -> Option<usize> {
    match names {
        [".cargo", "registry", "src", ..] | [".cargo", "git", "checkouts", ..] => {
            return Some(2);
        }
        [".rustup", "toolchains", toolchain, "lib", "rustlib", "src", ..]
            if !toolchain.starts_with('.') =>
        {
            return Some(5);
        }
        _ => {}
    }
    names.iter().enumerate().find_map(|(index, name)| {
        let root = match *name {
            "node_modules" => true,
            "site-packages" | "dist-packages" => index
                .checked_sub(1)
                .is_some_and(|parent| python_library_directory(names[parent])),
            _ => false,
        };
        root.then_some(index)
    })
}

/// `lib` (`Lib` in a Windows environment), or a versioned interpreter
/// directory such as `python3.12` or `pypy3.10`.
fn python_library_directory(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    lowered == "lib"
        || ["python", "pypy"].iter().any(|prefix| {
            lowered.strip_prefix(prefix).is_some_and(|version| {
                !version.is_empty()
                    && version
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || byte == b'.')
            })
        })
}

/// The tool directories between home and the install root: one hidden
/// directory at most, directly below home, no download cache, and no
/// credential name.
fn above_root_allowed(above: &[&str]) -> bool {
    above
        .iter()
        .skip(1)
        .all(|name| !name.starts_with('.') && !download_cache(name))
        && above
            .iter()
            .all(|name| !guard_secure_fs::sensitive_external_filename(Path::new(name)))
        // A plain final entry makes every listed name a directory, so this
        // applies the credential-directory screen to each of them.
        && !guard_secure_fs::credential_named_path(
            &above.iter().collect::<PathBuf>().join("entry"),
        )
}

/// A package manager's download or tarball cache, such as
/// `~/.bun/install/cache` or `~/.npm/_cacache`, is tool state rather than an
/// installed tree. The platform cache roots are not: Poetry keeps its
/// virtualenvs below `~/Library/Caches/pypoetry` on macOS just as it does
/// below `~/.cache/pypoetry` on Linux, so `Caches` is not a download cache.
fn download_cache(name: &str) -> bool {
    matches!(name.to_ascii_lowercase().as_str(), "cache" | "_cacache")
}

/// The path inside the install root: only benign project dotfiles may be
/// hidden, and no key or certificate container is read.
fn below_root_allowed(below: &[&str]) -> bool {
    let relative = below.iter().collect::<PathBuf>();
    let extension = relative
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    guard_secure_fs::hidden_read_parts_allowed(&relative)
        && !crate::pretool::search::SECRET_EXTENSIONS.contains(&extension.as_str())
        && guard_secure_fs::sensitive_path_family(&relative).is_none()
}

#[cfg(test)]
mod tests {
    use super::install_root;

    #[test]
    fn install_roots_are_recognised_by_layout() {
        for (path, root) in [
            (
                ".local/pipx/venvs/tool/lib/python3.12/site-packages/pkg/mod.py",
                Some(6),
            ),
            (".local/lib/python3.12/site-packages/pkg", Some(3)),
            (".venv/Lib/site-packages/pkg/mod.py", Some(2)),
            (".cargo/registry/src/index/serde-1.0.0/src/lib.rs", Some(2)),
            (".cargo/git/checkouts/repo/abc/src/lib.rs", Some(2)),
            (
                ".rustup/toolchains/stable/lib/rustlib/src/rust/library/core/src/lib.rs",
                Some(5),
            ),
            (
                ".bun/install/global/node_modules/vite/package.json",
                Some(3),
            ),
            (".cargo/credentials.toml", None),
            (".cargo/config.toml", None),
            (".cargo/registry/index/x", None),
            (".rustup/toolchains/stable/lib/rustlib/etc/x", None),
            (".config/tool/site-packages/x.py", None),
            (".bun/install/cache/vite/package.json", None),
        ] {
            let names: Vec<&str> = path.split('/').collect();
            assert_eq!(install_root(&names), root, "{path}");
        }
    }

    #[test]
    fn download_caches_above_the_root_do_not_qualify() {
        assert!(super::above_root_allowed(&[".bun", "install", "global"]));
        assert!(!super::above_root_allowed(&[".bun", "install", "cache"]));
        assert!(!super::above_root_allowed(&[".npm", "_cacache"]));
    }

    #[test]
    fn platform_cache_roots_hold_virtualenvs_on_every_host() {
        for path in [
            "Library/Caches/pypoetry/virtualenvs/app-py3.12/lib/python3.12/site-packages",
            ".cache/pypoetry/virtualenvs/app-py3.12/lib/python3.12/site-packages",
        ] {
            let names: Vec<&str> = path.split('/').collect();
            let root = super::install_root(&names).expect(path);
            assert!(super::above_root_allowed(&names[..root]), "{path}");
        }
    }
}
