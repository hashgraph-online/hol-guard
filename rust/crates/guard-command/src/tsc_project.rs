//! Whether a `tsc` run emits nothing, read from the project it names.
//!
//! `tsc --noEmit` says so on the command line, and the contained route has
//! always read it there. A project that keeps the same answer in its own
//! config says it just as plainly: a generated type-check config is written
//! `"noEmit": true` and then run as `tsc -p tsconfig.check.json`, which
//! carries no option at all. That run reached ordinary review for a mode the
//! project had already declared.
//!
//! The reading is conservative in both directions. It answers only for a
//! config inside the directory the run starts in, reached without a symlink
//! and without a `..` step, and it refuses anything it cannot settle: a
//! missing or unreadable file, a document it cannot parse, a value that is
//! not a boolean, an `extends` it cannot resolve inside the same tree. A
//! refusal costs the run nothing it had before — it keeps the review it
//! already had.
//!
//! `noEmit` is not the whole question. `incremental`, `composite` and
//! `tsBuildInfoFile` each make tsc write a build-info file next to the
//! project even when no JavaScript is emitted, and `-b` builds outright, so
//! any of them anywhere in the chain gives no verdict. The admission and the
//! sink both read this one answer, so neither can admit a run the other
//! would plan differently.

#[cfg(test)]
#[path = "tsc_project_tests.rs"]
mod tests;

use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::jsonc::loads_jsonc;

/// The largest config this reading opens. A project that keeps a larger one
/// gets no verdict rather than an unbounded read in the shared resident.
const MAX_CONFIG_BYTES: u64 = 256 * 1024;

/// How many `extends` links the reading follows before giving up. A chain
/// longer than a base, a preset and a project override is one this reading
/// does not settle.
const MAX_EXTENDS_DEPTH: usize = 4;

/// Command-line options that make tsc write whatever the config says.
/// `-b` runs a build, the three build-info options write a `.tsbuildinfo`
/// beside the project even under `--noEmit`, and the two diagnostic options
/// write their trace and profile wherever they are pointed.
///
/// tsc reads an option's name without regard to case, so this reading does
/// too: an option that reaches the compiler under any spelling has to reach
/// this check under the same one.
fn emitting_argument(arguments: &[String]) -> bool {
    arguments.iter().any(|word| {
        let lowered = word.to_ascii_lowercase();
        let name = lowered.split('=').next().unwrap_or(lowered.as_str());
        matches!(
            name,
            "-b" | "--build"
                | "-i"
                | "--incremental"
                | "--composite"
                | "--tsbuildinfofile"
                | "--generatetrace"
                | "--generatecpuprofile"
        )
    })
}

/// The config file a run reads, as a path relative to the run directory.
///
/// `-p`/`--project` names it, in either the separated or the attached
/// spelling; a run that names none reads `tsconfig.json`. A value naming a
/// directory is the directory's own `tsconfig.json`, which is how tsc reads
/// it.
fn config_path(arguments: &[String], directory: &Path) -> Option<PathBuf> {
    let mut words = arguments.iter();
    let mut named = None;
    while let Some(word) = words.next() {
        let value = match word.as_str() {
            "-p" | "--project" => words.next()?.as_str(),
            other => match other.strip_prefix("--project=") {
                Some(value) => value,
                None => continue,
            },
        };
        if value.is_empty() || value.starts_with('-') || named.is_some() {
            return None;
        }
        named = Some(value.to_owned());
    }
    let named = named.unwrap_or_else(|| "tsconfig.json".to_owned());
    let relative = Path::new(&named);
    // A run naming its own directory writes `.` or `./name`, which Rust keeps
    // as a leading component. Only a step out of the run directory, or a name
    // rooted elsewhere, is one this reading refuses.
    if relative.is_absolute()
        || relative.components().any(|part| {
            !matches!(
                part,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
    {
        return None;
    }
    let path = directory.join(relative);
    // tsc reads a directory's own `tsconfig.json`; a path naming neither a
    // file nor a directory is a run that will not start at all. The name is
    // resolved before it is read, so a link anywhere along it, and not only
    // at the file itself, has to land back inside the run directory.
    if let Some(config) = contained_file(&path, directory) {
        return Some(config);
    }
    contained_file(&path.join("tsconfig.json"), directory)
}

/// `path` when every link along it lands on a readable config inside `root`,
/// under the name that survived them.
fn contained_file(path: &Path, root: &Path) -> Option<PathBuf> {
    let resolved = std::fs::canonicalize(path).ok()?;
    let inside = std::fs::canonicalize(root).ok()?;
    resolved.strip_prefix(&inside).ok()?;
    resolved_file(&resolved).map(|_| resolved)
}

/// `path` when it is a regular file reached without a symlink, and its size
/// is within the bound this reading keeps.
fn resolved_file(path: &Path) -> Option<u64> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    (metadata.is_file() && metadata.len() <= MAX_CONFIG_BYTES).then_some(metadata.len())
}

/// The config at `path` as a JSON object. tsconfig is JSONC, so it is read
/// with the same decoder the lockfile evidence uses.
fn read_object(path: &Path) -> Option<Map<String, Value>> {
    let size = resolved_file(path)?;
    let mut text = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(size.saturating_add(1))
        .read_to_string(&mut text)
        .ok()?;
    match loads_jsonc(&text).ok()? {
        Value::Object(object) => Some(object),
        _ => None,
    }
}

/// The config an `extends` string names, resolved the way tsc resolves it:
/// relative to the directory of the config that declares it.
///
/// Only a relative path is followed. A bare module specifier
/// (`@tsconfig/node20/tsconfig.json`) resolves through Node's lookup into a
/// package this reading does not walk, so it gives no verdict. The resolved
/// path must stay inside `root`, which is the directory the run starts in.
fn extends_path(from: &Path, specifier: &str, root: &Path) -> Option<PathBuf> {
    if !(specifier.starts_with("./") || specifier.starts_with("../")) {
        return None;
    }
    // tsc opens the name as written and appends `.json` only when no file is
    // there, so a directory holding both `base` and `base.json` is read in
    // that order here too. `contained_file` follows the links the containment
    // check needs to see, so the base is opened under the name that survived
    // them.
    let directory = from.parent()?;
    if let Some(base) = contained_file(&directory.join(specifier), root) {
        return Some(base);
    }
    if specifier.ends_with(".json") {
        return None;
    }
    contained_file(&directory.join(format!("{specifier}.json")), root)
}

/// Records a declared boolean, keeping the first answer seen. The chain is
/// walked from the project outwards, so the first answer is the one that
/// overrides. A value that is not a boolean is one this reading does not
/// settle.
fn record(slot: &mut Option<bool>, value: Option<&Value>) -> bool {
    match value {
        None => true,
        Some(Value::Bool(flag)) => {
            slot.get_or_insert(*flag);
            true
        }
        Some(_) => false,
    }
}

/// Whether the config at `path`, together with every config it extends,
/// declares a run that emits nothing and writes no build-info file.
fn chain_declares_no_emit(path: &Path, root: &Path) -> bool {
    let mut no_emit = None;
    let mut incremental = None;
    let mut composite = None;
    let mut current = Some(path.to_path_buf());
    let mut depth = 0;
    while let Some(file) = current {
        depth += 1;
        if depth > MAX_EXTENDS_DEPTH {
            return false;
        }
        let Some(document) = read_object(&file) else {
            return false;
        };
        if let Some(options) = document.get("compilerOptions") {
            let Some(options) = options.as_object() else {
                return false;
            };
            if options.contains_key("tsBuildInfoFile") {
                return false;
            }
            if !record(&mut no_emit, options.get("noEmit"))
                || !record(&mut incremental, options.get("incremental"))
                || !record(&mut composite, options.get("composite"))
            {
                return false;
            }
        }
        current = match document.get("extends") {
            None => None,
            Some(Value::String(specifier)) => match extends_path(&file, specifier, root) {
                Some(base) => Some(base),
                None => return false,
            },
            // A list of bases (TypeScript 5) and any other shape are chains
            // this reading does not walk.
            Some(_) => return false,
        };
    }
    no_emit == Some(true) && incremental != Some(true) && composite != Some(true)
}

/// Whether a `tsc` run started in `directory` emits nothing because the
/// project it reads says so.
pub(crate) fn declares_no_emit(arguments: &[String], directory: Option<&Path>) -> bool {
    let Some(directory) = directory else {
        return false;
    };
    if emitting_argument(arguments) {
        return false;
    }
    config_path(arguments, directory)
        .is_some_and(|config| chain_declares_no_emit(&config, directory))
}
