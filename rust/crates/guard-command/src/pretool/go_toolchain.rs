//! Version and environment queries for the `go` command.
//!
//! `go version` prints a banner. Named `go env` setting queries can be
//! inert reads, but a full dump or compiler-related setting can invoke the
//! configured C compiler just to calculate the value. Those are not reads.
//! The `go` on `PATH` is not always the toolchain that answers them, though:
//! since Go 1.21 the command reads `GOTOOLCHAIN`, and under its default
//! `auto` a `go.mod` or `go.work` that asks for a newer release makes the
//! command fetch that release and re-exec it. The query is then answered by a
//! program the workspace chose, which is why `version_probes` and
//! `help_probes` leave `go` out and send both spellings to review.
//!
//! What a workspace can choose is narrow. A `toolchain` line, and the `go`
//! line it falls back to, name a release -- `go1.25.3` -- and nothing else:
//! the go command refuses a name that is not a release, so the file cannot
//! point at a directory the way a `rust-toolchain.toml` `path` entry can.
//! A release the command has to fetch arrives as the module
//! `golang.org/toolchain` and is checked against the checksum database
//! before it runs, the same way rustup downloads and verifies a channel that
//! a toolchain file selects, which [`super::rust_toolchain`] already admits.
//!
//! Before fetching, the command looks on `PATH` for a program named after
//! the release. That lookup picks among the session's installed programs by
//! a name the go command itself constrains to a release spelling, and `PATH`
//! is already what decides which `go` runs at all: a directory that could
//! plant a `go1.25.3` there could plant a `go`. So the workspace file
//! selects between the user's own toolchains, not between a toolchain and
//! arbitrary code, and the proof below is about the settings that can break
//! that chain rather than about the workspace file:
//!
//! - `GOTOOLCHAIN=path` runs a `go1.N` found on `PATH`, which is a local
//!   binary and not a verified download, and `GOTOOLCHAIN=go1.N` names one
//!   outright.
//! - `GOROOT` and `GOTOOLDIR` name the toolchain tree directly.
//! - `GOPROXY` moves where the toolchain module is fetched from, and
//!   `GOSUMDB`, `GONOSUMDB`, `GONOSUMCHECK`, `GOPRIVATE` and `GOINSECURE`
//!   decide whether what arrives is checked at all.
//! - `GOPATH` and `GOMODCACHE` name the module cache. A toolchain already in
//!   the cache is used as it is found, so the cache's location chooses the
//!   binary just as surely as the download does.
//! - `GOFLAGS` adds options to every invocation, including ones that name a
//!   program, `GOCACHEPROG` names a program the command runs as its build
//!   cache, and `GOAUTH=command <prog>` runs one to sign the requests a
//!   toolchain download makes.
//! - `GONOPROXY`, `GOVCS` and `GOWORK` move the same decisions: the first
//!   two choose which fetches skip the proxy and which may run a
//!   version-control tool, and the third names the workspace file the switch
//!   is read from.
//! - `GOENV`, `XDG_CONFIG_HOME` on the platforms that use it, and `APPDATA`
//!   on Windows, move the file below, so a redirected one is a second place
//!   every setting above could come from.
//!
//! The same settings have a stored spelling: `go env -w` writes them to the
//! go environment file under the user configuration directory, which the
//! command reads before it decides anything. That file is read here for the
//! same names, and a file that cannot be read, is a symlink or is unusually
//! large keeps the review, because what it sets is exactly what the read
//! failed to learn.
//!
//! Deliberately absent:
//! - `go env -w` and `go env -u`: they write the file this proof reads.
//! - `go help`: it is a read, but `go` takes a verb and admitting one verb's
//!   usage text is a question for `help_probes`, which reads each manager's
//!   built-ins against the manager that owns them.
//! - `go version -m <file>` and `go version <file>`: they open the named
//!   executables and print the build information inside them, so they are
//!   file reads and belong to the read proof, not to a banner.
//! - every building verb -- `go build`, `go run`, `go test`, `go generate`,
//!   `go list` -- compiles the workspace's own code, and `go install` is the
//!   package lane's.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

const MAX_GO_ENV_FILE_BYTES: u64 = 32 * 1024;

/// A lone `go version` or a read-only `go env` query.
pub(super) fn safe_go_probe(arguments: &[String], context: super::PathContext<'_>) -> bool {
    read_only_query(arguments) && toolchain_selection_is_official(context)
}

/// The two spellings that print and exit.
///
/// `go env` needs at least one explicitly named, compiler-inert setting;
/// dumping all settings can execute the configured C compiler. `-json` only
/// changes the output shape. `-w` and `-u` write the stored file, and every
/// other option or operand after `version` stays outside this read proof.
fn read_only_query(arguments: &[String]) -> bool {
    let Some((verb, rest)) = arguments.split_first() else {
        return false;
    };
    match verb.as_str() {
        "version" => rest.is_empty(),
        "env" => {
            let names: Vec<_> = rest.iter().filter(|arg| arg.as_str() != "-json").collect();
            !names.is_empty()
                && names
                    .iter()
                    .all(|name| setting_name(name) && !env_setting_runs_compiler(name))
        }
        _ => false,
    }
}

/// A `go env` operand that selects a line of the answer.
///
/// The command's own settings are upper-case words, so a name with a dash, a
/// separator or an `=` in it is not one of them and keeps the review.
fn setting_name(argument: &str) -> bool {
    !argument.is_empty()
        && argument
            .chars()
            .all(|letter| letter.is_ascii_uppercase() || letter.is_ascii_digit() || letter == '_')
}

/// Values whose computation can run `CC` even for a `go env` read.
/// Verified with an inert CC marker on Go 1.23.2; keep these under review,
/// including when they are selected after `-json`.
fn env_setting_runs_compiler(name: &str) -> bool {
    matches!(
        name,
        "CGO_CFLAGS"
            | "CGO_CPPFLAGS"
            | "CGO_CXXFLAGS"
            | "CGO_FFLAGS"
            | "CGO_LDFLAGS"
            | "PKG_CONFIG"
            | "GOGCCFLAGS"
    )
}

/// Whether the toolchain that answers the query can only be the one on
/// `PATH` or a release the go command downloads and verifies itself.
///
/// The stored file below is read under the home the hook reported, so a
/// shell whose own `HOME` names somewhere else is not proved by reading it:
/// the go command would read a file this proof never opened.
fn toolchain_selection_is_official(context: super::PathContext<'_>) -> bool {
    if !context.go_toolchain_inert || !context.shell_home_matches {
        return false;
    }
    let Some(home) = context.home_dir.map(Path::new) else {
        return false;
    };
    if !home.is_absolute() {
        return false;
    }
    go_env_files(home).iter().all(|path| go_env_inert(path))
}

/// Where the go command keeps the settings `go env -w` writes.
///
/// `GOENV` would move the file and `XDG_CONFIG_HOME`, or `APPDATA` on
/// Windows, would move the directory holding it; all are screened in the
/// environment, so the defaults below are the only places left. Both Unix spellings are read on
/// every host rather than behind a target switch, because a file at either
/// path is a file the go command on that host would read.
fn go_env_files(home: &Path) -> Vec<PathBuf> {
    let mut paths = vec![
        home.join("Library")
            .join("Application Support")
            .join("go")
            .join("env"),
        home.join(".config").join("go").join("env"),
    ];
    if cfg!(windows) {
        paths.push(home.join("AppData").join("Roaming").join("go").join("env"));
    }
    paths
}

/// Whether this stored environment file leaves the toolchain choice alone.
///
/// An absent file answers yes: there is nothing stored. Anything that exists
/// but is not a plain readable file of ordinary size answers no, and so does
/// a file that sets one of the names the environment screen covers -- with
/// one exception, `GOTOOLCHAIN=local`, which is the setting that turns the
/// switch off entirely.
fn go_env_inert(path: &Path) -> bool {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return true,
        Err(_) => return false,
    };
    if !metadata.is_file() || metadata.len() > MAX_GO_ENV_FILE_BYTES {
        return false;
    }
    let Ok(contents) = fs::read_to_string(path) else {
        return false;
    };
    contents.lines().all(|line| {
        let line = line.trim_end_matches('\r');
        let Some((name, value)) = line.split_once('=') else {
            return true;
        };
        let name = name.trim();
        let value = value.trim();
        if value.is_empty() {
            return true;
        }
        if name.eq_ignore_ascii_case("GOTOOLCHAIN") {
            return value == "local";
        }
        !go_toolchain_selector(name)
    })
}

/// The settings that decide which toolchain binary answers a query, where it
/// is fetched from, and whether what arrives is checked.
pub(crate) fn go_toolchain_selector(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    matches!(
        name.as_str(),
        "GOTOOLCHAIN"
            | "GOROOT"
            | "GOTOOLDIR"
            | "GOENV"
            | "GOFLAGS"
            | "GOPROXY"
            | "GOSUMDB"
            | "GONOSUMDB"
            | "GONOSUMCHECK"
            | "GOPRIVATE"
            | "GOINSECURE"
            | "GOPATH"
            | "GOMODCACHE"
            | "GOCACHEPROG"
            | "GOAUTH"
            | "GONOPROXY"
            | "GOVCS"
            | "GOWORK"
            | "XDG_CONFIG_HOME"
    ) || (cfg!(windows) && name == "APPDATA")
}

#[cfg(test)]
#[path = "go_toolchain_tests.rs"]
mod tests;
