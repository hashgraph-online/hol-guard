//! Version queries for `cargo` and `rustc` through the rustup proxy.
//!
//! A lone `--version` or `-V` prints a banner and exits, but the rustup proxy
//! that usually stands in for `cargo` and `rustc` first picks a toolchain. It
//! reads the nearest `rust-toolchain` or `rust-toolchain.toml` in the working
//! directory or one of its ancestors. A `path` entry there makes the proxy run
//! that directory's binary, which the workspace controls. A channel name only
//! selects an official toolchain, which rustup downloads and verifies itself.
//!
//! The probe is admitted when no toolchain file is found, or when the nearest
//! one names an official channel and nothing else that can select a binary.
//! Any file that cannot be read or parsed, is a symlink, or is unusually large
//! keeps the normal review path. So does an inherited `RUSTUP_TOOLCHAIN` or
//! `RUSTUP_HOME`, which rustup reads before any toolchain file.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

const TOOLCHAIN_FILES: [&str; 2] = ["rust-toolchain", "rust-toolchain.toml"];
const MAX_TOOLCHAIN_FILE_BYTES: u64 = 4096;
const TOOLCHAIN_KEYS: [&str; 4] = ["channel", "components", "targets", "profile"];

pub(super) fn safe_version_probe(arguments: &[String], context: super::PathContext<'_>) -> bool {
    matches!(arguments, [flag] if matches!(flag.as_str(), "--version" | "-V"))
        && proxy_selects_official_toolchain(context)
}

/// Whether the rustup proxy started from the working directory can only pick
/// an official toolchain: no override in the environment and no toolchain
/// file above the directory that could select another binary.
pub(super) fn proxy_selects_official_toolchain(context: super::PathContext<'_>) -> bool {
    if !context.rustup_override_absent {
        return false;
    }
    let Some(cwd) = context.cwd.map(Path::new) else {
        return false;
    };
    if !cwd.is_absolute() {
        return false;
    }
    // rustup searches the physical working directory, so a symlinked path
    // must not hide a toolchain file above its target.
    let Ok(physical) = fs::canonicalize(cwd) else {
        return false;
    };
    ancestors_inert(cwd) && ancestors_inert(&physical)
}

/// Rustfmt changes files, so unlike a version banner it also needs proof
/// that rustup's persistent default and directory override table cannot
/// select a linked custom formatter. Never execute rustup during this check.
pub(super) fn rustfmt_proxy_is_official(context: super::PathContext<'_>) -> bool {
    proxy_selects_official_toolchain(context)
        && context
            .home_dir
            .map(Path::new)
            .is_some_and(rustup_settings_only_official)
}

fn rustup_settings_only_official(home: &Path) -> bool {
    if !home.is_absolute() {
        return false;
    }
    let rustup = home.join(".rustup");
    if !fs::symlink_metadata(&rustup).is_ok_and(|metadata| metadata.is_dir()) {
        return false;
    }
    let path = rustup.join("settings.toml");
    if !fs::symlink_metadata(&path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.len() <= 32 * 1024)
    {
        return false;
    }
    let Ok(contents) = fs::read_to_string(&path) else {
        return false;
    };
    let Ok(settings) = contents.parse::<toml::Table>() else {
        return false;
    };
    let default_is_official = settings
        .get("default_toolchain")
        .and_then(toml::Value::as_str)
        .is_some_and(official_channel);
    // Directory overrides live outside the repository. Until their exact
    // precedence and destination can be proven, any override keeps review.
    let no_directory_overrides = match settings.get("overrides") {
        None => true,
        Some(toml::Value::Table(paths)) => paths.is_empty(),
        _ => false,
    };
    default_is_official && no_directory_overrides
}

fn ancestors_inert(cwd: &Path) -> bool {
    for directory in cwd.ancestors() {
        match nearest_toolchain(directory) {
            Lookup::Absent => continue,
            Lookup::Inert => return true,
            Lookup::Unsafe => return false,
        }
    }
    true
}

enum Lookup {
    Absent,
    Inert,
    Unsafe,
}

fn nearest_toolchain(directory: &Path) -> Lookup {
    let mut found = false;
    for name in TOOLCHAIN_FILES {
        let path = directory.join(name);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(_) => return Lookup::Unsafe,
        };
        if !metadata.is_file() || metadata.len() > MAX_TOOLCHAIN_FILE_BYTES {
            return Lookup::Unsafe;
        }
        let Ok(contents) = fs::read_to_string(&path) else {
            return Lookup::Unsafe;
        };
        if !inert_toolchain(&contents) {
            return Lookup::Unsafe;
        }
        found = true;
    }
    if found {
        Lookup::Inert
    } else {
        Lookup::Absent
    }
}

fn inert_toolchain(contents: &str) -> bool {
    let trimmed = contents.trim();
    if !trimmed.contains(['\n', '=', '[']) {
        return official_channel(trimmed);
    }
    let Ok(document) = trimmed.parse::<toml::Table>() else {
        return false;
    };
    let mut entries = document.iter();
    let Some(("toolchain", toml::Value::Table(toolchain))) =
        entries.next().map(|(key, value)| (key.as_str(), value))
    else {
        return false;
    };
    entries.next().is_none()
        && toolchain
            .keys()
            .all(|key| TOOLCHAIN_KEYS.contains(&key.as_str()))
        && toolchain
            .get("channel")
            .is_some_and(|channel| channel.as_str().is_some_and(official_channel))
}

/// rustup's official toolchain names: `stable`, `beta`, `nightly` or a
/// `major.minor[.patch]` release, then an optional `-YYYY-MM-DD` archive date
/// and an optional known host triple. rustup will not link a custom toolchain
/// under such a name, so it cannot point at a local directory.
fn official_channel(name: &str) -> bool {
    let tokens: Vec<&str> = name.split('-').collect();
    let Some((channel, mut rest)) = tokens.split_first() else {
        return false;
    };
    if !matches!(*channel, "stable" | "beta" | "nightly") && !release_version(channel) {
        return false;
    }
    if let [year, month, day, tail @ ..] = rest {
        if digits(year, 4) && digits(month, 2) && digits(day, 2) {
            rest = tail;
        }
    }
    rest.is_empty() || host_triple(&rest.join("-"))
}

/// rustup parses a name as official only when its tail is a known
/// architecture, operating system and optional environment. Any other tail
/// is a valid custom toolchain name, which `rustup toolchain link` can point
/// at a local directory.
fn host_triple(tail: &str) -> bool {
    const ARCHS: &[&str] = &[
        "aarch64",
        "arm",
        "armv7",
        "i586",
        "i686",
        "loongarch64",
        "powerpc64le",
        "riscv64gc",
        "s390x",
        "x86_64",
    ];
    const SYSTEMS: &[&str] = &[
        "apple-darwin",
        "pc-windows",
        "unknown-freebsd",
        "unknown-illumos",
        "unknown-linux",
        "unknown-netbsd",
    ];
    const ENVIRONMENTS: &[&str] = &["gnu", "gnueabihf", "gnullvm", "msvc", "musl", "musleabihf"];
    ARCHS.iter().any(|arch| {
        tail.strip_prefix(arch)
            .and_then(|rest| rest.strip_prefix('-'))
            .is_some_and(|rest| {
                SYSTEMS.iter().any(|system| {
                    rest.strip_prefix(system).is_some_and(|rest| {
                        rest.is_empty()
                            || rest
                                .strip_prefix('-')
                                .is_some_and(|environment| ENVIRONMENTS.contains(&environment))
                    })
                })
            })
    })
}

fn release_version(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    (2..=3).contains(&parts.len())
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}

fn digits(value: &str, length: usize) -> bool {
    value.len() == length && value.chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::{inert_toolchain, rustup_settings_only_official};
    use std::path::Path;

    #[test]
    fn admits_plain_channels_only() {
        for contents in [
            "stable",
            "1.85.0\n",
            "nightly-2025-01-01",
            "1.85",
            "stable-aarch64-apple-darwin",
            "nightly-2025-01-01-x86_64-unknown-linux-gnu",
            "stable-x86_64-pc-windows-msvc",
            "1.85.0-aarch64-unknown-linux-musl",
            "[toolchain]\nchannel = \"1.85.0\"\n",
            "[toolchain]\nchannel = \"stable\"\ncomponents = [\"clippy\", \"rustfmt\"]\nprofile = \"minimal\"\n",
        ] {
            assert!(inert_toolchain(contents), "{contents}");
        }
        for contents in [
            "",
            "../toolchain",
            "/opt/toolchain",
            "C:\\toolchain",
            "[toolchain]\npath = \"/opt/toolchain\"\n",
            "[toolchain]\nchannel = \"stable\"\npath = \"tools\"\n",
            "[toolchain]\nchannel = \"../tools\"\n",
            "my-toolchain",
            "custom",
            "stable-",
            "1",
            "1.85.0.1",
            "nightly-2025-01-01-Evil",
            // Lowercase tails that are not known triples are valid custom
            // names that rustup can link to a local directory.
            "stable-evil-thing",
            "nightly-2025-01-01-my-build",
            "stable-x86_64-evil",
            "stable-x86_64-unknown-linux-evil",
            "stable-x86_64-unknown-linux-gnu-extra",
            "[toolchain]\nchannel = \"workspace-linked\"\n",
            "[toolchain]\ncomponents = [\"clippy\"]\n",
            "[toolchain]\nchannel = \"stable\"\n[other]\nkey = 1\n",
            "path = \"/opt/toolchain\"\n",
            "[toolchain\n",
        ] {
            assert!(!inert_toolchain(contents), "{contents}");
        }
    }

    #[test]
    fn formatter_requires_official_default_and_no_directory_overrides() {
        let root = std::env::temp_dir().join(format!(
            "guard-rustfmt-settings-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let directory = root.join(".rustup");
        std::fs::create_dir_all(&directory).unwrap();
        let settings = directory.join("settings.toml");
        std::fs::write(
            &settings,
            "version = \"12\"\ndefault_toolchain = \"stable-x86_64-unknown-linux-gnu\"\n[overrides]\n",
        )
        .unwrap();
        assert!(rustup_settings_only_official(Path::new(&root)));
        std::fs::write(
            &settings,
            "default_toolchain = \"custom-formatter\"\n[overrides]\n",
        )
        .unwrap();
        assert!(!rustup_settings_only_official(Path::new(&root)));
        std::fs::write(
            &settings,
            "default_toolchain = \"stable\"\n[overrides]\n\"/tmp/project\" = \"custom-formatter\"\n",
        )
        .unwrap();
        assert!(!rustup_settings_only_official(Path::new(&root)));
        std::fs::write(&settings, "default_toolchain = \"stable\"\n").unwrap();
        assert!(rustup_settings_only_official(Path::new(&root)));
        std::fs::remove_dir_all(root).unwrap();
    }
}
