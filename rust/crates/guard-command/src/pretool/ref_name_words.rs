//! Branch, tag and refspec names a Git or GitHub command spells.
//!
//! `git checkout -b fix/secret-scan-gate` creates a branch and `gh run list
//! --branch feat/password-reset` lists workflow runs. Neither opens a file,
//! but the credential-word screen reads the whole command text, so the word
//! inside the name sent ordinary branch work to review. A token is set aside
//! only where the command's own grammar fixes it as a ref name: the command
//! stays in one directory, the token carries no `:` (so `git show
//! main:config/secrets.json` keeps its screen), it is not spelled as a path,
//! and nothing of that name exists next to the session.

use crate::CanonicalCommandV1;
use std::collections::BTreeSet;
use std::path::Path;

/// Git verbs whose bare operands are revisions, branches or refspecs rather
/// than files. `checkout` and `clone` are not among them: their operands can
/// name a path, so only their explicit branch options count.
const REF_POSITIONAL_VERBS: &[&str] = &[
    "branch", "fetch", "merge", "pull", "push", "rebase", "switch", "tag",
];

/// `git log` revisions are ref names, but only before `--`, which starts its
/// paths. The verb is listed apart so the walk knows to stop there.
const LOG_VERB: &str = "log";

/// Options whose value `gh` reads as a branch or ref name.
const GH_REF_OPTIONS: &[&str] = &["-B", "-H", "-b", "--base", "--branch", "--head", "--ref"];

/// Options whose value `git log` reads as something other than a ref: search
/// patterns, formats and counts. Their values are stepped over rather than
/// taken, so an unlisted one only costs a mask.
const LOG_VALUE_OPTIONS: &[&str] = &[
    "--after",
    "--author",
    "--before",
    "--committer",
    "--date",
    "--decorate-refs",
    "--decorate-refs-exclude",
    "--encoding",
    "--exclude",
    "--format",
    "--glob",
    "--grep",
    "--max-count",
    "--output",
    "--pretty",
    "--since",
    "--skip",
    "--until",
    "-G",
    "-L",
    "-S",
    "-n",
];

/// Verbs whose short options carry a message, a file or a strategy, so the
/// walk steps over their values. `branch` and `switch` are left out: there
/// `-m` moves a branch and merges a worktree, and the name follows as an
/// operand.
const MESSAGE_VERBS: &[&str] = &["fetch", "merge", "pull", "push", "rebase", "tag"];

/// Options of the ref-operand verbs whose value is a message, file, strategy
/// or count, so the walk steps over it instead of reading a ref.
const OPERAND_VERB_VALUE_OPTIONS: &[&str] = &[
    "--deepen",
    "--depth",
    "--exec",
    "--file",
    "--format",
    "--jobs",
    "--local-user",
    "--message",
    "--negotiation-tip",
    "--onto",
    "--push-option",
    "--receive-pack",
    "--repo",
    "--server-option",
    "--shallow-exclude",
    "--shallow-since",
    "--sort",
    "--strategy",
    "--strategy-option",
    "--upload-pack",
    "-F",
    "-X",
    "-j",
    "-m",
    "-o",
    "-s",
];

/// A candidate ref name together with the argument word that spells it.
/// The screen that consumes this set matches the words the model split, so
/// `--branch=feat/x` is one word there while the name to prove is only its
/// value.
struct RefWord {
    name: String,
    word: String,
}

impl RefWord {
    /// A ref name spelled as its own operand or as an option's separate
    /// value, where the word and the name are the same text.
    fn operand(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            word: name.to_owned(),
        }
    }

    /// A ref name spelled inside `--option=value`.
    fn attached(name: &str, word: &str) -> Self {
        Self {
            name: name.to_owned(),
            word: word.to_owned(),
        }
    }
}

/// The words `model` spells that carry a ref name, empty when nothing can
/// be proven: the command moves between directories, or there is no working
/// directory to read a candidate name against.
pub(in crate::pretool) fn ref_names(
    model: &CanonicalCommandV1,
    cwd: Option<&str>,
    moves: bool,
) -> BTreeSet<String> {
    let Some(cwd) = cwd.filter(|_| !moves) else {
        return BTreeSet::new();
    };
    let mut names = Vec::new();
    for segment in &model.segments {
        let Some(executable) = segment.executable.as_deref() else {
            continue;
        };
        match crate::pretool::executable_basename(executable) {
            "git" => git_refs(&segment.arguments, &mut names),
            "gh" => option_refs(&segment.arguments, GH_REF_OPTIONS, &mut names),
            _ => {}
        }
    }
    names
        .into_iter()
        .filter(|candidate| names_no_path(&candidate.name, cwd))
        .map(|candidate| candidate.word)
        .collect()
}

/// Whether `name` can be read as a ref alone: it spells no path, holds no
/// `rev:path` separator, and nothing of that name sits next to the session.
fn names_no_path(name: &str, cwd: &str) -> bool {
    !name.is_empty()
        && !name.contains(':')
        && !name.contains('\0')
        && !name.starts_with(['/', '~', '.', '-'])
        && std::fs::symlink_metadata(Path::new(cwd).join(name)).is_err()
}

/// The ref names a `git` segment's arguments spell.
fn git_refs(arguments: &[String], names: &mut Vec<RefWord>) {
    let Some(verb) = arguments.first().filter(|first| !first.starts_with('-')) else {
        return;
    };
    let verb = verb.as_str();
    let refs: &[&str] = match verb {
        "checkout" => &["-B", "-b"],
        "clone" => &["--branch", "-b"],
        "switch" => &["--create", "--force-create", "-C", "-c"],
        _ => &[],
    };
    let operands = REF_POSITIONAL_VERBS.contains(&verb);
    let values: &[&str] = match verb {
        LOG_VERB => LOG_VALUE_OPTIONS,
        _ if MESSAGE_VERBS.contains(&verb) => OPERAND_VERB_VALUE_OPTIONS,
        _ => &[],
    };
    let operands = operands || verb == LOG_VERB;
    let mut index = 1;
    while index < arguments.len() {
        let token = arguments[index].as_str();
        // `git log -- src` and `git branch -- name` start the path operands.
        if token == "--" {
            return;
        }
        if let Some((option, value)) = token.split_once('=') {
            if refs.contains(&option) {
                names.push(RefWord::attached(value, token));
            }
            index += 1;
            continue;
        }
        if index + 1 < arguments.len() && (refs.contains(&token) || values.contains(&token)) {
            if refs.contains(&token) {
                names.push(RefWord::operand(&arguments[index + 1]));
            }
            index += 2;
            continue;
        }
        if token.starts_with('-') && token != "-" {
            index += 1;
            continue;
        }
        if operands {
            names.push(RefWord::operand(token));
        }
        index += 1;
    }
}

/// The values of `options` in `arguments`, in both the separated and the
/// `--option=value` spelling.
fn option_refs(arguments: &[String], options: &[&str], names: &mut Vec<RefWord>) {
    let mut index = 0;
    while index < arguments.len() {
        let token = arguments[index].as_str();
        if let Some((option, value)) = token.split_once('=') {
            if options.contains(&option) {
                names.push(RefWord::attached(value, token));
            }
            index += 1;
            continue;
        }
        if options.contains(&token) && index + 1 < arguments.len() {
            names.push(RefWord::operand(&arguments[index + 1]));
            index += 2;
            continue;
        }
        index += 1;
    }
}

#[cfg(test)]
#[path = "ref_name_words_tests.rs"]
mod tests;
