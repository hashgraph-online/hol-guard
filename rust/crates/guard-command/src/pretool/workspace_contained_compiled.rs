//! Compiled-toolchain work admitted to the workspace sandbox.
//!
//! [`super::package`] decides the managers that fetch what they run. `go`,
//! `cargo` and `mvn` are the ones whose local verbs compile what the
//! workspace already has, so they are read here.
//!
//! `go` is admitted with its module cache and toolchain read-only beside the
//! workspace. A verb only counts as local inside a module the directory it
//! runs in holds, since outside one go resolves imports through the proxy.
//! An argument naming a version, and `go list`'s `-u` and `-versions`,
//! reach that proxy even inside a module, so each
//! keeps the admission it has.
//!
//! Cargo is admitted for the verbs that compile what the workspace already
//! has. Its `build.rs` scripts and proc macros run dependency code like npm
//! scripts, which is what the sandbox bounds. The crate sources it reads live
//! in `~/.cargo/registry` and `~/.cargo/git` and its toolchain in `~/.rustup`,
//! each granted read-only; the run gets its own `CARGO_HOME`, with those two
//! caches linked in, so cargo takes its locks and writes its own state inside
//! the private tree. `~/.cargo/config.toml` and `~/.cargo/credentials.toml`
//! stay out, which keeps registry tokens out of the run, and the fetching
//! verbs keep the admission they have today.
//!
//! Maven is admitted for the lifecycle phases that build and test the project
//! the directory holds. Its plugins run dependency code the way `build.rs`
//! does, which is what the sandbox bounds. The artifacts it resolves live in
//! `~/.m2/repository`, granted read-only; the run gets its own local
//! repository with that one linked in, so Maven takes its locks and writes
//! its own state inside the private tree, and runs offline, which turns an
//! artifact the host has not fetched into an immediate error rather than a
//! download the firewall never saw. A `mvnw` run executes the Maven the
//! project pins, which the wrapper looks for below its Maven user home: the
//! run gets its own, holding a link to each distribution the host has already
//! unpacked in `~/.m2/wrapper/dists`, also granted read-only.

use std::path::Path;

// A Go build compiles the sources the module cache already holds and writes
// its objects to a private build cache. Only the verbs that stay there are
// local: `get`, `install`, `mod` and `work` reach a registry, and `tool` and
// `clean` are neither a build nor a read.
const GO_LOCAL_VERBS: &[&str] = &[
    "build", "test", "vet", "fmt", "list", "doc", "env", "version", "run", "generate",
];
// A cargo build compiles the crate sources the registry cache already holds
// into a target directory the workspace owns. Only the verbs that stay there
// are local: `install`, `add`, `update`, `publish` and the rest reach a
// registry, and `vendor` and `fetch` exist to populate a cache.
const CARGO_LOCAL_VERBS: &[&str] = &[
    "build", "b", "test", "t", "check", "c", "clippy", "fmt", "doc", "d", "run", "r", "bench",
    "tree", "metadata", "version", "nextest",
];

/// Whether `go` runs a local verb inside a module that `directory` holds.
/// Outside a module these verbs read the wider GOPATH, and the sandbox has no
/// network to resolve a package by import path, so they keep the admission
/// they have. A version an argument names is one go resolves through the
/// module proxy, and `go list`'s `-u` and `-versions` ask the proxy what else
/// a module has, as does `-retracted`, so each of those keeps that admission
/// too.
pub(super) fn local_go_work(arguments: &[&str], directory: &Path) -> bool {
    let Some((verb, rest)) = arguments.split_first() else {
        return false;
    };
    GO_LOCAL_VERBS.contains(&verb.to_ascii_lowercase().as_str())
        && !rest
            .iter()
            .any(|argument| names_a_go_fetch(argument) || argument.contains('@'))
        && directory.join("go.mod").is_file()
}

/// Whether `cargo` runs a local verb against a package that `directory`
/// holds. A leading `+toolchain` selects a rustup toolchain, which the run
/// may read. Outside a package cargo has nothing to compile and would search
/// upward out of the workspace, so those commands keep the admission they
/// have.
pub(super) fn local_cargo_work(arguments: &[&str], directory: &Path) -> bool {
    arguments
        .iter()
        .find(|argument| !argument.starts_with('+'))
        .is_some_and(|verb| CARGO_LOCAL_VERBS.contains(&verb.to_ascii_lowercase().as_str()))
        && directory.join("Cargo.toml").is_file()
}

/// Whether an argument names one of the flags that send a Go verb to a module
/// proxy. Go's flag package reads one dash or two alike and takes a boolean's
/// value either as the next argument or behind an `=`, so the name is read
/// the same way here. A flag turned off by its value still keeps the command
/// out: a run that names it is one the sandbox has no reason to decide for.
fn names_a_go_fetch(argument: &str) -> bool {
    let name = argument.trim_start_matches('-');
    if !(1..=2).contains(&(argument.len() - name.len())) {
        return false;
    }
    matches!(
        name.split_once('=').map_or(name, |(name, _)| name),
        "u" | "versions" | "retracted"
    )
}

// A Maven lifecycle phase compiles and tests the sources the project holds,
// resolving its dependencies from the local repository the host has already
// filled. Only the phases that stay inside the build directory are local:
// `install` and `deploy` publish what they built, and every other word here
// would be a plugin goal.
const MAVEN_LOCAL_PHASES: &[&str] = &[
    "clean",
    "compile",
    "package",
    "process-classes",
    "process-resources",
    "process-test-resources",
    "resources",
    "test",
    "test-compile",
    "validate",
    "verify",
];
// Maven options that take their value as the next argument. The value is not
// a phase, so it must not be read as one.
const MAVEN_VALUE_OPTIONS: &[&str] = &[
    "--activate-profiles",
    "--builder",
    "--file",
    "--global-settings",
    "--log-file",
    "--projects",
    "--settings",
    "--threads",
    "--toolchains",
    "-b",
    "-f",
    "-gs",
    "-l",
    "-P",
    "-p",
    "-pl",
    "-s",
    "-t",
    "-T",
];
// Options that tell Maven to go to a remote repository. A build that names
// one is asking for the fetch the package firewall exists to review.
const MAVEN_FETCH_OPTIONS: &[&str] = &["--update-snapshots", "-u", "-U"];

/// Whether `mvn` runs lifecycle phases against a project that `directory`
/// holds. A phase compiles and tests what the checkout already has, reading
/// its dependencies from the local repository the sandbox grants read-only,
/// so there is nothing left for the firewall to decide. A plugin goal
/// (`dependency:get`, `versions:use-latest-releases`) carries a colon and
/// keeps the admission it has, as does a run with no `pom.xml` to build,
/// since outside a project Maven resolves everything it needs from a remote
/// repository.
pub(super) fn local_maven_work(arguments: &[&str], directory: &Path) -> bool {
    let mut named_a_phase = false;
    let mut skip_value = false;
    for argument in arguments {
        if skip_value {
            skip_value = false;
            continue;
        }
        if argument.starts_with('-') {
            let name = argument.split_once('=').map_or(*argument, |(name, _)| name);
            if MAVEN_FETCH_OPTIONS.contains(&name) {
                return false;
            }
            skip_value = MAVEN_VALUE_OPTIONS.contains(&name) && !argument.contains('=');
            continue;
        }
        if !MAVEN_LOCAL_PHASES.contains(&argument.to_ascii_lowercase().as_str()) {
            return false;
        }
        named_a_phase = true;
    }
    named_a_phase && !skip_value && directory.join("pom.xml").is_file()
}
