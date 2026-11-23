//! The Go verbs admitted to the workspace sandbox.
//!
//! `go` is admitted with its module cache and toolchain read-only beside the
//! workspace. A verb only counts as local inside a module the directory it
//! runs in holds, since outside one go resolves imports through the proxy.
//! An argument naming a version, and `go list`'s `-u` and `-versions`,
//! reach that proxy even inside a module, so each
//! keeps the admission it has.
//!
//! A Go run reaches this module through [`go_chdir`] and [`local_go_work`];
//! [`super`] reads the other compiled toolchains.

use std::path::Path;

// A Go build compiles the sources the module cache already holds and writes
// its objects to a private build cache. Only the verbs that stay there are
// local: `get`, `install` and `work` reach a registry, and `clean` deletes
// rather than builds. `tool` and `mod` are launchers for a whole second set
// of work, so neither is on this list; the few subcommands of each that only
// report on what the workspace already holds are read below.
const GO_LOCAL_VERBS: &[&str] = &[
    "build", "test", "vet", "fmt", "list", "doc", "env", "version", "run", "generate",
];

/// Whether `go` runs a local verb inside a module that `directory` holds.
/// A module the directory holds is the one go finds by ascending from it, as
/// go itself does, stopping at the workspace root. Outside a module these
/// verbs read the wider GOPATH, and the sandbox has no network to resolve a
/// package by import path, so they keep the admission they have. A version an
/// argument names is one go resolves through the module proxy, and `go
/// list`'s `-u` and `-versions` ask the proxy what else a module has, as does
/// `-retracted`, so each of those keeps that admission too.
///
/// A leading `-C` is read by the caller, which moves `directory` to the one it
/// names before this decision, because where the run stands is what the module
/// search below rests on.
/// The directory go's `-C` moves to, and how many words it takes.
///
/// go reads this flag only as the first word of the command and chdirs before
/// it reads anything else, in either spelling, so the verb behind it is the
/// work `cd <dir> && go <verb>` is. go itself ignores a `-C` with nothing
/// behind it, and so does this.
pub(in crate::pretool) fn go_chdir<'a>(arguments: &[&'a str]) -> Option<(&'a str, usize)> {
    match arguments {
        ["-C", target, rest @ ..] if !rest.is_empty() => Some((target, 2)),
        [first, rest @ ..] if !rest.is_empty() => first
            .strip_prefix("-C=")
            .filter(|target| !target.is_empty())
            .map(|target| (target, 1)),
        _ => None,
    }
}

pub(in crate::pretool) fn local_go_work(
    arguments: &[&str],
    directory: &Path,
    workspace: &Path,
) -> bool {
    let Some((verb, rest)) = arguments.split_first() else {
        return false;
    };
    let verb = verb.to_ascii_lowercase();
    (GO_LOCAL_VERBS.contains(&verb.as_str())
        || (verb == "tool" && local_go_tool(rest))
        || (verb == "mod" && local_go_mod(rest)))
        && !rest
            .iter()
            .any(|argument| names_a_go_fetch(argument) || argument.contains('@'))
        && super::super::cd::first_from(directory, workspace, |probe| {
            probe.join("go.mod").is_file()
        })
        .is_some()
}

/// The `go mod` subcommands that only report on the module already resolved.
///
/// Most of what `go mod` carries either reaches a registry or rewrites the
/// module files: `download` and `tidy` fetch, `init` and `edit` write
/// `go.mod`, and `vendor` copies a tree of dependencies into the workspace.
/// Three of them only report. `graph` prints the requirement graph, `verify`
/// rehashes the modules the cache already holds against `go.sum`, and `why`
/// names the import that pulls a package in. Each reads the build list that
/// the admitted `go build` and `go list` runs already read and writes
/// nothing, so a contained run of one reaches no further than those do --
/// including when the cache is short of a dependency, where all of them alike
/// fail against a sandbox that has no network.
///
/// Only the flags those three carry themselves are accepted, in the spelling
/// that keeps the value attached, because a word this does not know is one go
/// reads for something else.
fn local_go_mod(arguments: &[&str]) -> bool {
    let Some((subcommand, rest)) = arguments.split_first() else {
        return false;
    };
    let flags: &[&str] = match subcommand.to_ascii_lowercase().as_str() {
        // `-go` picks the version the graph is pruned for, `-x` echoes the
        // work as it goes.
        "graph" => &["-go", "-x"],
        "verify" => &[],
        // `-m` reads the operands as modules rather than packages, and
        // `-vendor` answers from the vendor directory instead of the cache.
        "why" => &["-m", "-vendor"],
        _ => return false,
    };
    rest.iter().all(|word| {
        !word.starts_with('-')
            || flags.contains(&word.split_once('=').map_or(*word, |(flag, _)| flag))
    })
}

/// The `go tool` subcommands that read what a run inside the workspace has
/// already produced.
///
/// `go tool` is a launcher: the name behind it selects a program the
/// toolchain carries, and most of them do more than read. `pprof` serves a
/// web interface and fetches a profile over the network, `test2json` runs the
/// test binary it is given, and `compile`, `link` and `objdump` are build
/// steps that take their own paths. `cover` is the exception: it reads a
/// coverage profile the admitted `go test -coverprofile` run just wrote and
/// renders it, which reaches no further than that run did.
fn local_go_tool(arguments: &[&str]) -> bool {
    let Some((name, rest)) = arguments.split_first() else {
        return false;
    };
    name.eq_ignore_ascii_case("cover") && cover_renders_a_profile(rest)
}

/// Whether `go tool cover`'s arguments only render a profile to a file.
///
/// Each flag here takes a value, in either of go's spellings (`-func=x` and
/// `-func x`), and nothing else is accepted, so a word this does not know
/// keeps the review the launcher has. `-html` with no `-o` starts a local
/// web server and opens a browser on it, which is not the file render this
/// admits, so it is refused as well.
fn cover_renders_a_profile(arguments: &[&str]) -> bool {
    let mut renders = false;
    let mut html = false;
    let mut output = false;
    let mut index = 0;
    while let Some(word) = arguments.get(index) {
        let (flag, attached) = match word.split_once('=') {
            Some((flag, value)) => (flag, Some(value)),
            None => (*word, None),
        };
        let value = match attached {
            Some(value) => {
                index += 1;
                value
            }
            None => {
                let Some(value) = arguments.get(index + 1) else {
                    return false;
                };
                index += 2;
                *value
            }
        };
        if value.is_empty() || value.starts_with('-') {
            return false;
        }
        match flag {
            "-func" => renders = true,
            "-html" => {
                renders = true;
                html = true;
            }
            "-o" => output = true,
            _ => return false,
        }
    }
    renders && (!html || output)
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
