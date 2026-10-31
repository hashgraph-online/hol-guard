//! Possible shell working directories for literal command segments.

use crate::CanonicalCommandV1;
use std::path::{Component, Path, PathBuf};

const MAX_STATES: usize = 64;

/// One shell the command could be running in by the time a segment is read.
///
/// `succeeded` is how the segment before it ended, which is what `&&` and
/// `||` select on. `prev` is the directory this shell moved out of last,
/// which is what `cd -` returns to, and is unset until the walk has seen a
/// move. `descent_failed` records that this directory is the one a `cd` left
/// behind when the walk modelled it as failing, and `left` that a later move
/// from such a branch reached somewhere the walk never bounded. A branch that
/// only exists because a descent failed may spend its climb outside, since
/// nothing the command actually runs is read from there; the walk gives up as
/// soon as such a shell would execute a segment.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Shell {
    cwd: PathBuf,
    prev: Option<PathBuf>,
    succeeded: bool,
    descent_failed: bool,
    left: bool,
}

/// Whether this segment is the shell builtin that moves the shell itself.
///
/// Only the bare spelling counts. `cd` and `pushd` change the directory of the
/// shell that reads them, which is why a proven descent may spend a `..` step
/// later in the same command; a program at `./tools/cd` or `/usr/local/bin/cd`
/// is an ordinary child process that cannot move its parent, so reading it by
/// basename would credit the walk with a descent the real shell never made and
/// let the next `..` leave the workspace.
fn moves_the_shell(executable: Option<&str>) -> bool {
    matches!(executable, Some("cd") | Some("pushd"))
}

/// The builtin a segment really runs, with every `builtin` keyword spent.
///
/// The parser leaves `builtin` where it stands, so `builtin cd app` arrives
/// with `builtin` as the executable and `cd` as its first argument. The shell
/// still moves, and reading only the executable would leave the walk tracking
/// a directory the shell has left: a later `..` would then be credited to a
/// descent the walk never saw, and a later `cd -` would return to a `prev`
/// the shell no longer holds. `command cd` is not this shape -- `command`
/// runs an external program, which cannot move its parent.
fn spends_builtin_keyword<'a>(name: &'a str, arguments: &'a [String]) -> (&'a str, &'a [String]) {
    let mut name = name;
    let mut arguments = arguments;
    while name == "builtin" {
        let Some((first, rest)) = arguments.split_first() else {
            return (name, arguments);
        };
        name = first.as_str();
        arguments = rest;
    }
    (name, arguments)
}

/// Whether this run names `OLDPWD` anywhere once the shell's quoting is gone.
///
/// The shell removes quoting before it reads an assignment, so the source
/// text hides the name: `export OLD""PWD=/etc` and `OLD\PWD=/etc` both write
/// it. The parser's words carry the spelling the shell would act on, so they
/// are what the check reads. The source text is read as well, for a run whose
/// quoting the tokenizer could not take apart.
fn names_the_previous_directory(model: &CanonicalCommandV1) -> bool {
    let names = |word: &str| word.to_ascii_lowercase().contains("oldpwd");
    names(&model.normalized_text)
        || model
            .segments
            .iter()
            .any(|segment| segment.tokens.iter().any(|token| names(token)))
}

/// The directory a shell says it is in after `cd target`, which is the one it
/// resolves the next `..` against. A shell without `cd -P` spends a parent
/// step on the name it last printed rather than on what that name points to,
/// so `cd deep` into a link to `a/b` leaves the shell in `deep`, and the
/// `../..` after it climbs out of the workspace while resolving the link
/// first would land back inside it. `None` where the steps climb past the
/// root, which no directory answers to.
fn logical_join(cwd: &Path, target: &str) -> Option<PathBuf> {
    let mut walked = PathBuf::new();
    for component in cwd.join(target).components() {
        match component {
            Component::Prefix(_) | Component::RootDir => walked.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !walked.pop() {
                    return None;
                }
            }
            Component::Normal(part) => walked.push(part),
        }
    }
    Some(walked)
}

pub(super) fn locations(model: &CanonicalCommandV1, workspace: &Path) -> Option<Vec<Vec<PathBuf>>> {
    let root = workspace.canonicalize().ok()?;
    let mut states = vec![Shell {
        cwd: workspace.to_path_buf(),
        prev: None,
        succeeded: true,
        descent_failed: false,
        left: false,
    }];
    let mut result = Vec::new();
    // The operator that decided whether the pipeline now being read runs at
    // all. A `|` joins a segment to the one before it rather than to the list,
    // so the `&&` or `||` at the head of the pipeline is what governs every
    // element of it.
    let mut opened_pipeline = String::new();
    for (index, segment) in model.segments.iter().enumerate() {
        let connector: String = if index == 0 {
            String::new()
        } else {
            let before = &model.segments[index - 1];
            model
                .normalized_text
                .chars()
                .skip(before.span.end)
                .take(segment.span.start.checked_sub(before.span.end)?)
                .collect()
        };
        let connector = connector.trim();
        if !matches!(connector, "" | "&&" | "||" | ";" | "|" | "\n") {
            return None;
        }
        // `false && work | tail` runs neither element, so reading `tail` as
        // unconditional would resume the directory the failed `cd` left and
        // credit a later climb to a shell that never descended.
        if connector != "|" {
            opened_pipeline = connector.to_owned();
        }
        let connector = if connector == "|" {
            opened_pipeline.as_str()
        } else {
            connector
        };
        let name = segment.executable.as_deref()?;
        let (name, arguments) = spends_builtin_keyword(name, segment.arguments.as_slice());
        let mut executing = Vec::new();
        let mut next = Vec::new();
        for shell in states {
            if (connector == "&&" && !shell.succeeded) || (connector == "||" && shell.succeeded) {
                next.push(shell);
                continue;
            }
            // A shell that climbed out on a failed-descent branch reads this
            // segment from a directory the walk never bounded, so the reading
            // that let the climb pass no longer holds.
            if shell.left {
                return None;
            }
            let Shell {
                cwd,
                prev,
                descent_failed,
                ..
            } = shell;
            executing.push(cwd.clone());
            if moves_the_shell(Some(name)) {
                let [target] = arguments else {
                    return None;
                };
                // `cd -` is the directory this shell moved out of last, which
                // the walk followed and so can follow back. Every other
                // stand-in names a place the walk never joined.
                let returning = name == "cd" && target == "-";
                if !returning && target.starts_with(['-', '~', '+']) {
                    return None;
                }
                // `cd -` is `$OLDPWD`, not wherever the walk last saw the
                // shell. The two agree only while nothing else writes that
                // variable, and nothing here reads the assignments that
                // would: a run that names it at all is one the walk cannot
                // follow back.
                if returning && names_the_previous_directory(model) {
                    return None;
                }
                // bash's `lastpipe` and zsh's default both run the last
                // element of a pipeline in the shell that read it, so a `cd`
                // inside one may move the shell the rest of the command runs
                // in. The walk cannot tell which shell read this text, and
                // taking the reading where nothing moved would credit a later
                // climb to a descent that did happen.
                if model
                    .segments
                    .iter()
                    .filter(|other| other.execution_context == segment.execution_context)
                    .count()
                    > 1
                {
                    return None;
                }
                // The sandbox hands the run no CDPATH to search, and
                // `cd::sets_search_path` refuses the shape of a run that sets
                // one itself, so a name that exists here is where the run
                // lands. A name that does not exist has nowhere to land at
                // all, so don't invent a cwd the real shell never reaches.
                //
                // The shell is tracked by the spelling it carries, since that
                // is what its next `..` is spent on; where that spelling
                // points has to stay inside the workspace too, so a link out
                // of it is still refused.
                //
                // A shell whose descent failed never moved, so its `-` is the
                // `OLDPWD` the run inherited: a directory the walk never
                // bounded, carried exactly like a climb out of such a branch.
                let moved = if returning {
                    prev.clone()
                } else {
                    logical_join(&cwd, target)
                };
                if moved.as_deref().is_some_and(|moved| !moved.is_dir()) {
                    return None;
                }
                let inside = moved.as_deref().is_some_and(|moved| {
                    moved.starts_with(workspace)
                        && moved
                            .canonicalize()
                            .ok()
                            .is_some_and(|real| real.starts_with(&root))
                });
                // `cd app && work; cd ..` climbs back to the workspace root on
                // every branch the command really takes. The one branch that
                // would land above it is the one where the first `cd` failed,
                // which is also a branch where the shell never descended — so
                // the climb is the step out, not the work. Carry it rather
                // than giving up on the whole walk; the check above stops it
                // as soon as anything would run from there.
                //
                // Only a climb is carried that way. A branch whose descent
                // failed is still a shell, and a move that names somewhere
                // else is that shell leaving for it, not stepping back out of
                // a descent that never happened.
                let climbs = returning
                    || Path::new(target.as_str()).components().all(|component| {
                        matches!(component, Component::ParentDir | Component::CurDir)
                    });
                if !(inside || (descent_failed && climbs)) {
                    return None;
                }
                // A failed cd leaves the old cwd. &&/|| choose the corresponding
                // state; a later semicolon resumes both, rather than guessing.
                next.extend([
                    Shell {
                        cwd: moved.unwrap_or_else(|| cwd.clone()),
                        prev: Some(cwd.clone()),
                        succeeded: true,
                        descent_failed,
                        left: !inside,
                    },
                    Shell {
                        cwd,
                        prev,
                        succeeded: false,
                        descent_failed: true,
                        left: false,
                    },
                ]);
            } else if name == "popd" {
                return None;
            } else {
                next.extend([
                    Shell {
                        cwd: cwd.clone(),
                        prev: prev.clone(),
                        succeeded: true,
                        descent_failed,
                        left: false,
                    },
                    Shell {
                        cwd,
                        prev,
                        succeeded: false,
                        descent_failed,
                        left: false,
                    },
                ]);
            }
        }
        next.sort();
        next.dedup();
        if next.len() > MAX_STATES {
            return None;
        }
        executing.sort();
        executing.dedup();
        result.push(executing);
        states = next;
    }
    Some(result)
}

/// Whether the walk reads every directory move this command makes and each
/// one lands inside the workspace. A chain that goes in, works and comes back
/// — `cd app && cargo test && cd ..` — ends where the sandbox already bounds
/// it, so the climb it spends is one the walk has accounted for rather than a
/// step out. Where a `CDPATH` could send a bare operand somewhere the walk
/// does not join it, or the walk cannot read a move at all, this is false and
/// the stricter literal reading of each operand decides on its own.
pub(super) fn moves_stay_inside(model: &CanonicalCommandV1, workspace: &Path) -> bool {
    model
        .segments
        .iter()
        .any(|segment| moves_the_shell(segment.executable.as_deref()))
        && !model
            .normalized_text
            .to_ascii_lowercase()
            .contains("cdpath")
        && locations(model, workspace).is_some()
}

/// How many directories below `workspace` every shell that could run each
/// segment stands, segment by segment. A segment that runs one directory down
/// resolves one leading `..` back inside the workspace, so the reach checks
/// may spend that many parent steps before a path leaves. Where the walk
/// cannot prove the directory — an unmodelled connector, a `popd`, a `cd`
/// whose target is not there yet — every segment keeps the root's zero, which
/// is what the checks assumed before.
pub(super) fn depths(model: &CanonicalCommandV1, workspace: &Path) -> Vec<usize> {
    let zeros = vec![0usize; model.segments.len()];
    // A command with no `cd` and no parent step cannot spend one, and the walk
    // reads the file system, so it is worth skipping.
    if !model.normalized_text.contains("..")
        // A `CDPATH` the command sets sends a bare relative `cd` wherever that
        // search finds the name first, which is not the directory `locations`
        // joins it onto, so no segment may spend a step. zsh ties the same
        // search to a lowercase `cdpath` array, and `export cdpath=...` in a
        // zsh harness sets both, so the name is matched without case.
        || model
            .normalized_text
            .to_ascii_lowercase()
            .contains("cdpath")
        || !model
            .segments
            .iter()
            .any(|segment| moves_the_shell(segment.executable.as_deref()))
    {
        return zeros;
    }
    let Some(locations) = locations(model, workspace) else {
        return zeros;
    };
    let canonical_workspace = workspace.canonicalize().ok();
    locations
        .iter()
        .map(|roots| {
            // The shallowest possible directory decides: a `;` after a `cd`
            // leaves both the moved and the unmoved shell, and only the steps
            // both can spend stay inside.
            roots
                .iter()
                .map(|cwd| {
                    // The walk carries the spelling the shell prints, since a
                    // later `cd ..` is spent on that. A `..` in an ordinary
                    // operand is resolved by the kernel instead, which spends
                    // it on whatever the spelling points to: with a link to
                    // its own directory in the way, `cd l/l` leaves the shell
                    // two names deep while the process stands at the root, and
                    // `cat ../../secret` then reads above the workspace. Only
                    // the steps both readings grant may be spent.
                    let printed = cwd
                        .strip_prefix(workspace)
                        .map_or(0, |rest| rest.components().count());
                    let resolved = cwd
                        .canonicalize()
                        .ok()
                        .zip(canonical_workspace.as_deref())
                        .and_then(|(moved, root)| {
                            moved
                                .strip_prefix(root)
                                .ok()
                                .map(|rest| rest.components().count())
                        })
                        .unwrap_or(0);
                    printed.min(resolved)
                })
                .min()
                .unwrap_or(0)
        })
        .collect()
}

// The tests spell the workspace path inside POSIX shell text, which a
// Windows `\\?\C:\...` path cannot be written in.
#[cfg(all(test, unix))]
#[path = "workspace_contained_cwd_tests.rs"]
mod tests;
