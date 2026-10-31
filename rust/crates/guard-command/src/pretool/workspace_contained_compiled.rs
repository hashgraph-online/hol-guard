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
//! Cargo reads its own options in front of that verb, and a developer spells
//! them there without changing what the run does: `cargo --offline test` and
//! `cargo -q test` run the test the bare verb runs, and `--locked`,
//! `--offline` and `--frozen` each ask for less than it does. They are read
//! past, up to the first option this module does not know, so an option that
//! names a config key, an unstable flag or another directory keeps the
//! admission it has.
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
//
// The second group is the subcommands cargo resolves to a `cargo-NAME`
// program the host already has. Each one named here drives cargo's own build
// of the workspace and reads what it produced -- a coverage run of the test
// suite, a snapshot suite, an expansion, a read of which dependencies the
// crate uses -- so the work reaches no further than `test` and `build`
// already do. A name that is not on this list keeps its review, because
// cargo would run whatever program carries it.
const CARGO_LOCAL_VERBS: &[&str] = &[
    "build",
    "b",
    "test",
    "t",
    "check",
    "c",
    "clippy",
    "fmt",
    "doc",
    "d",
    "run",
    "r",
    "bench",
    "tree",
    "metadata",
    "version",
    "nextest",
    "llvm-cov",
    "tarpaulin",
    "insta",
    "expand",
    "machete",
    "udeps",
];
// Cargo's own options stand in front of the verb. These say only how cargo
// reports what it does, and how strictly it treats the lockfile and the
// network: each of the last three narrows what a run may reach, so a line
// carrying one asks for less than the bare verb does. Everything else cargo
// reads there -- `--config`, `-Z`, `-C` -- changes what the run resolves or
// where it looks for it, which is what the rest of this decision rests on.
const CARGO_INERT_OPTIONS: &[&str] = &[
    "-q",
    "--quiet",
    "-v",
    "-vv",
    "--verbose",
    "--locked",
    "--offline",
    "--frozen",
];
// The one inert option that takes its value as the next word.
const CARGO_COLOR_OPTION: &str = "--color";

/// Whether `go` runs a local verb inside a module that `directory` holds.
/// A module the directory holds is the one go finds by ascending from it, as
/// go itself does, stopping at the workspace root. Outside a module these
/// verbs read the wider GOPATH, and the sandbox has no network to resolve a
/// package by import path, so they keep the admission they have. A version an
/// argument names is one go resolves through the module proxy, and `go
/// list`'s `-u` and `-versions` ask the proxy what else a module has, as does
/// `-retracted`, so each of those keeps that admission too.
pub(super) fn local_go_work(arguments: &[&str], directory: &Path, workspace: &Path) -> bool {
    let Some((verb, rest)) = arguments.split_first() else {
        return false;
    };
    GO_LOCAL_VERBS.contains(&verb.to_ascii_lowercase().as_str())
        && !rest
            .iter()
            .any(|argument| names_a_go_fetch(argument) || argument.contains('@'))
        && super::cd::first_from(directory, workspace, |probe| probe.join("go.mod").is_file())
            .is_some()
}

/// Whether `cargo` runs a local verb against a package reachable from
/// `directory`. Cargo finds the manifest by ascending, and the search here
/// ascends with it as far as the workspace root, which is what a run inside a
/// crate of a workspace needs. A leading `+toolchain` selects a rustup
/// toolchain, which the run may read. With no manifest anywhere below the
/// workspace root cargo has nothing to compile and would search upward out of
/// the workspace, so those commands keep the admission they have.
///
/// `--manifest-path` replaces that search with the manifest it names, which
/// must be a `Cargo.toml` inside the workspace, spelled without a parent step.
pub(super) fn local_cargo_work(arguments: &[&str], directory: &Path, workspace: &Path) -> bool {
    let local_verb = cargo_verb(arguments)
        .is_some_and(|verb| CARGO_LOCAL_VERBS.contains(&verb.to_ascii_lowercase().as_str()));
    local_verb
        && match manifest_path(arguments) {
            Some(Some(manifest)) => manifest_within(&directory.join(manifest), workspace),
            Some(None) => false,
            None => super::cd::first_from(directory, workspace, |probe| {
                probe.join("Cargo.toml").is_file()
            })
            .is_some(),
        }
}

/// The verb cargo runs, read the way cargo reads it: past a `+toolchain`,
/// past the options above, and stopping at the first word that is neither.
/// `None` when an option this walk does not read stands in front of the verb,
/// because what such an option sets -- a config key, an unstable flag, the
/// directory cargo starts from -- is what the rest of this decision rests on.
fn cargo_verb<'a>(arguments: &[&'a str]) -> Option<&'a str> {
    let mut words = arguments.iter();
    while let Some(word) = words.next() {
        if word.starts_with('+') {
            continue;
        }
        let Some(option) = word.strip_prefix('-') else {
            return Some(word);
        };
        if option.is_empty() {
            return None;
        }
        if CARGO_INERT_OPTIONS.contains(word) {
            continue;
        }
        if *word == CARGO_COLOR_OPTION {
            words.next()?;
            continue;
        }
        if word.starts_with(&format!("{CARGO_COLOR_OPTION}=")) {
            continue;
        }
        return None;
    }
    None
}

/// The manifest cargo's `--manifest-path` names, as the next argument or
/// behind an `=`. `Some(None)` when the flag has no value or appears twice,
/// which leaves no one manifest to judge.
pub(super) fn manifest_path<'a>(arguments: &[&'a str]) -> Option<Option<&'a str>> {
    let mut named = arguments.iter().enumerate().filter(|(_, argument)| {
        **argument == "--manifest-path" || argument.starts_with("--manifest-path=")
    });
    let (index, flag) = named.next()?;
    if named.next().is_some() {
        return Some(None);
    }
    Some(match flag.split_once('=') {
        Some((_, value)) => Some(value).filter(|value| !value.is_empty()),
        None => arguments.get(index + 1).copied(),
    })
}

/// Whether `manifest` is an existing `Cargo.toml` that resolves inside
/// `workspace`.
fn manifest_within(manifest: &Path, workspace: &Path) -> bool {
    manifest
        .file_name()
        .is_some_and(|name| name == "Cargo.toml")
        && manifest.is_file()
        && !manifest
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        && workspace.canonicalize().is_ok_and(|root| {
            manifest
                .canonicalize()
                .is_ok_and(|manifest| manifest.starts_with(root))
        })
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
