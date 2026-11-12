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
//! `RUSTUP_HOME`, which rustup reads before any toolchain file, and
//! `RUSTUP_DIST_SERVER` or `RUSTUP_UPDATE_ROOT`, which name where a channel
//! the file selects but the host has not installed is downloaded from.
//!
//! A `cargo search` query also contacts a registry, so it carries a second
//! proof of which one: see [`registry_is_official`].

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

const TOOLCHAIN_FILES: [&str; 2] = ["rust-toolchain", "rust-toolchain.toml"];
const MAX_TOOLCHAIN_FILE_BYTES: u64 = 4096;
const TOOLCHAIN_KEYS: [&str; 4] = ["channel", "components", "targets", "profile"];
const MAX_CARGO_CONFIG_BYTES: u64 = 64 * 1024;

pub(super) fn safe_version_probe(arguments: &[String], context: super::PathContext<'_>) -> bool {
    matches!(arguments, [flag] if matches!(flag.as_str(), "--version" | "-V"))
        && proxy_selects_official_toolchain(context)
}

/// `cargo --version` or a `cargo search` query of the registry.
///
/// The query reads an endpoint, so it also needs proof of which endpoint.
/// The version banner contacts nothing and keeps the toolchain proof alone.
pub(super) fn safe_cargo_probe(arguments: &[String], context: super::PathContext<'_>) -> bool {
    if !proxy_selects_official_toolchain(context) {
        return false;
    }
    if matches!(arguments, [flag] if matches!(flag.as_str(), "--version" | "-V")) {
        return true;
    }
    registry_query(arguments) && registry_is_official(context)
}

/// `cargo search <term>`, optionally bounded by `--limit`.
///
/// The subcommand asks the registry which crates match a word and prints the
/// answer. It resolves nothing, writes no lockfile, unpacks no crate and runs
/// no `build.rs`, which is the whole reason the package review exists for
/// `cargo`. `npm search`, `npm view` and `brew search` already read their
/// registries without review; this is the same reading.
///
/// A user alias cannot turn the word into another subcommand: Cargo ignores
/// an `[alias]` entry that shadows a built-in command, and `search` is built
/// in. The endpoint the query contacts is proven separately, by
/// [`registry_is_official`].
///
/// Only `--limit` and plain search words are read. A `+toolchain` word makes
/// the rustup proxy install a toolchain before the query, and every other
/// option -- `--registry`, `--index`, `--config`, `-Z` -- either names a
/// different endpoint or sets configuration the review should still see.
fn registry_query(arguments: &[String]) -> bool {
    let Some((subcommand, rest)) = arguments.split_first() else {
        return false;
    };
    if subcommand.as_str() != "search" {
        return false;
    }
    let mut rest = rest.iter();
    while let Some(argument) = rest.next() {
        match argument.as_str() {
            "--limit" => {
                if !rest
                    .next()
                    .is_some_and(|value| bounded_limit(value.as_str()))
                {
                    return false;
                }
            }
            value if value.starts_with("--limit=") => {
                if !bounded_limit(&value["--limit=".len()..]) {
                    return false;
                }
            }
            value if value.starts_with(['-', '+']) => return false,
            value if !word_stays_one_word(value) => return false,
            _ => {}
        }
    }
    true
}

/// Whether the shell hands Cargo this word as written.
///
/// A search term is read as a term because it carries no leading dash, but
/// the shell decides what Cargo actually receives. `{--config,evil.toml}`
/// is one word here and two words -- an option and its value -- by the time
/// Cargo parses them, which is how a workspace file would be loaded and its
/// credential provider started. A pathname wildcard is the same story
/// wherever a matching name begins with a dash. Both spellings, and the
/// expansions this proof never resolves, keep their review.
fn word_stays_one_word(value: &str) -> bool {
    !value.is_empty() && !value.contains(['$', '`', '\n', '\r', '{', '}', '*', '?', '[', ']', '~'])
}

/// The value `--limit` accepts: Cargo refuses anything outside 1..=100.
fn bounded_limit(value: &str) -> bool {
    value
        .parse::<u32>()
        .is_ok_and(|limit| (1..=100).contains(&limit))
}

/// Whether the rustup proxy started from the working directory can only pick
/// an official toolchain: no override in the environment and no toolchain
/// file above the directory that could select another binary.
pub(super) fn proxy_selects_official_toolchain(context: super::PathContext<'_>) -> bool {
    if !context.rustup_override_absent {
        return false;
    }
    // rustup reads its own settings before it looks for a toolchain file, and
    // a `default_toolchain` or directory override there can name a toolchain
    // `rustup toolchain link` pointed at any directory. A host with no rustup
    // home has nothing to read, so the proxy is whatever `cargo` the session
    // already found on `PATH`.
    let Some(home) = context.home_dir.map(Path::new) else {
        return false;
    };
    if !home.is_absolute() || matches!(rustup_settings(home), RustupSettings::Unproven) {
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

/// What rustup's persistent settings select, as far as reading them can tell.
enum RustupSettings {
    /// There is no rustup home, or the home carries no settings file. Nothing
    /// stored selects a toolchain, so the proxy runs whichever toolchain the
    /// rest of this proof accounts for.
    Absent,
    /// A settings file whose default, where it names one, and whose every
    /// directory override are official channels. `default_named` says
    /// whether a default was there at all, because a file that names none
    /// selects no toolchain: rustup stops with its own error instead of
    /// running one, which answers a query but is not the positive proof a
    /// command that writes files asks for.
    Official { default_named: bool },
    /// Anything else: a custom default, a directory override naming a custom
    /// toolchain, or a file this proof could not read or parse.
    Unproven,
}

/// Read `<home>/.rustup/settings.toml`.
///
/// Only a file that is absent answers [`RustupSettings::Absent`]. A directory
/// or file that exists but cannot be read, a symlink, and an oversized file
/// are all [`RustupSettings::Unproven`], because what they select is exactly
/// what this read failed to learn.
fn rustup_settings(home: &Path) -> RustupSettings {
    let rustup = home.join(".rustup");
    match fs::symlink_metadata(&rustup) {
        Ok(metadata) if metadata.is_dir() => {}
        Err(error) if error.kind() == ErrorKind::NotFound => return RustupSettings::Absent,
        _ => return RustupSettings::Unproven,
    }
    let path = rustup.join("settings.toml");
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && metadata.len() <= 32 * 1024 => {}
        Err(error) if error.kind() == ErrorKind::NotFound => return RustupSettings::Absent,
        _ => return RustupSettings::Unproven,
    }
    let Ok(contents) = fs::read_to_string(&path) else {
        return RustupSettings::Unproven;
    };
    let Ok(settings) = contents.parse::<toml::Table>() else {
        return RustupSettings::Unproven;
    };
    // A settings file with no default names no toolchain either: rustup stops
    // with its own error rather than running one.
    let default = settings.get("default_toolchain");
    let default_is_official = match default {
        None => true,
        Some(value) => value.as_str().is_some_and(official_channel),
    };
    // `rustup override set` stores a toolchain name per directory. Which
    // entry wins for the working directory does not matter when every entry
    // names an official channel: rustup will not link a custom toolchain
    // under such a name, so whichever one applies is downloaded and verified
    // by rustup, exactly like the default above. A custom name, or a value
    // that is not a name, keeps the review.
    let overrides_are_official = match settings.get("overrides") {
        None => true,
        Some(toml::Value::Table(paths)) => paths
            .values()
            .all(|value| value.as_str().is_some_and(official_channel)),
        _ => false,
    };
    if default_is_official && overrides_are_official {
        RustupSettings::Official {
            default_named: default.is_some(),
        }
    } else {
        RustupSettings::Unproven
    }
}

/// Whether rustup carries a settings file that names an official default.
///
/// `rustfmt` writes the files it is given, so unlike a query it asks for the
/// stronger answer: a rustup home that is there and names a channel, not a
/// host where the file's absence leaves nothing to read.
fn rustup_settings_only_official(home: &Path) -> bool {
    home.is_absolute()
        && fs::symlink_metadata(home.join(".rustup").join("settings.toml"))
            .is_ok_and(|metadata| metadata.is_file())
        && matches!(
            rustup_settings(home),
            RustupSettings::Official {
                default_named: true
            }
        )
}

/// Whether the registry a query contacts is still crates.io, and whether
/// reaching it can start a program.
///
/// Cargo merges every `.cargo/config.toml` from the working directory up to
/// the filesystem root with the one in `CARGO_HOME`, so the nearest file is
/// not the whole answer -- each one is read. A `[source]` replacement or a
/// `registry.default` entry sends `cargo search` somewhere else, and an index
/// that answers `auth-required` makes Cargo fetch a token by running the
/// `credential-provider` the same file names. That is a workspace file
/// choosing a program to run, which is the outcome the package review exists
/// to catch, so any of those tables keeps the review.
///
/// `[build]`, `[target]` and `[profile]` are read and left alone: a search
/// compiles nothing, links nothing and starts no build program, so the
/// settings they carry never reach a process. Refusing them would cost the
/// reading in most real workspaces and buy nothing.
fn registry_is_official(context: super::PathContext<'_>) -> bool {
    if !context.cargo_config_inert {
        return false;
    }
    let Some(cwd) = context.cwd.map(Path::new) else {
        return false;
    };
    let Ok(physical) = fs::canonicalize(cwd) else {
        return false;
    };
    // `CARGO_HOME` is either unset or names `<home>/.cargo` -- the context
    // flag proves that -- so Cargo's own configuration lives at its default
    // place under the home directory either way.
    let Some(home) = context.home_dir.map(Path::new) else {
        return false;
    };
    if !home.is_absolute() {
        return false;
    }
    cwd.ancestors()
        .chain(physical.ancestors())
        .chain(std::iter::once(home))
        .all(cargo_config_inert)
}

/// The tables that can move the endpoint, name the index behind it, or pick
/// the credential program Cargo starts for it.
const REDIRECTING_TABLES: [&str; 6] = [
    "registry",
    "registries",
    "source",
    "http",
    "net",
    "credential-alias",
];

/// Whether this directory's `.cargo` configuration leaves the query alone.
fn cargo_config_inert(directory: &Path) -> bool {
    for name in ["config.toml", "config"] {
        let path = directory.join(".cargo").join(name);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(_) => return false,
        };
        if !metadata.is_file() || metadata.len() > MAX_CARGO_CONFIG_BYTES {
            return false;
        }
        let Ok(contents) = fs::read_to_string(&path) else {
            return false;
        };
        let Ok(table) = contents.parse::<toml::Table>() else {
            return false;
        };
        if REDIRECTING_TABLES
            .iter()
            .any(|name| table.contains_key(*name))
        {
            return false;
        }
        // `[env]` sets variables for the processes Cargo starts, and the
        // same names this proof screens in the inherited environment.
        if table.contains_key("env") {
            return false;
        }
        // An unstable table can turn on a feature whose behaviour this
        // reading has not been written against.
        if table.contains_key("unstable") {
            return false;
        }
    }
    true
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

/// rustup's channel grammar for a release: a one-digit major, a one- to
/// three-digit minor and an optional one- or two-digit patch. Any other
/// numeric name, such as `10.0` or `1.85.100`, is a valid custom toolchain
/// name that `rustup toolchain link` can point at a local directory.
fn release_version(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    let lengths: &[(usize, usize)] = match parts.len() {
        2 => &[(1, 1), (1, 3)],
        3 => &[(1, 1), (1, 3), (1, 2)],
        _ => return false,
    };
    parts.iter().zip(lengths).all(|(part, (low, high))| {
        (*low..=*high).contains(&part.len()) && part.chars().all(|c| c.is_ascii_digit())
    })
}

fn digits(value: &str, length: usize) -> bool {
    value.len() == length && value.chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
#[path = "rust_toolchain_tests.rs"]
mod tests;
