//! A Python heredoc after plain readers.
//!
//! `python3 - <<'EOF'` with a body that imports modules runs in the workspace
//! sandbox when the interpreter is the whole command, because chained to
//! other commands the program could prepare what they run. Agents often look
//! before they probe: `git diff --check && git diff && python3 - <<'EOF'`,
//! `ls pkg; python3 - <<'EOF'`. The projection treated those like any other
//! chain and the command fell through to a block, harder than the review the
//! same program gets alone.
//!
//! Commands that run before the program have finished when it starts, so
//! they cannot run anything it prepares. Only readers are taken, so they also
//! write nothing the checks on the program's source and its local imports
//! would miss: `ls`, `cat`, `head`, `tail`, `wc`, `grep`, `rg`, `pwd` and
//! Git's read-only subcommands, joined by `;`, `&&`, a newline or a pipe, with
//! no redirect (in the raw text, not only the projection), substitution,
//! variable, assignment or option that writes a file or starts another
//! program. Options are read as the shell passes them, without quotes, and
//! Git's abbreviations of a blocked option count as the option. ripgrep is a
//! reader only when no inherited configuration file can add options to it.
//! A `cd` changes where the program's
//! imports resolve, so it is never a reader here. Anything after the program
//! keeps the chain's bar.

use serde_json::Value;

const READERS: &[&str] = &["ls", "cat", "head", "tail", "wc", "grep", "rg", "pwd"];

const GIT_READS: &[&str] = &[
    "diff",
    "status",
    "log",
    "show",
    "ls-files",
    "rev-parse",
    "blame",
];

/// Options that make Git's readers write a file or start an external diff.
/// Git also takes any unambiguous abbreviation of them (`--out=`).
const GIT_STARTS_OR_WRITES: &[&str] = &["--output", "--ext-diff"];

/// Options that make ripgrep start a preprocessor, a decompressor (also as
/// `-z` in a cluster of short options, `-nz`) or the hostname helper it runs
/// while setting up hyperlinks, whether or not hyperlinks are on.
const RG_STARTS: &[&str] = &["--pre", "--search-zip", "--hostname-bin"];

/// Whether the program in `projected` is Python alone after a `cd` into the
/// hook's directory or after plain readers, the two chains the projection
/// hands to the workspace route.
pub(super) fn python_after_lead(projected: &str) -> bool {
    super::cd::python_after_cd(projected) || program_after_readers(projected).is_some()
}

/// Whether the lead of `projected` leaves the program where the checks on
/// its imports looked: a `cd` proved to enter the hook's directory, or plain
/// readers, which never change directory. The projection drops redirects, so
/// the readers must also be exactly what `command` runs before the program:
/// `ls > pkg/__init__.py` would rewrite a module the checks already read.
pub(super) fn lead_admitted(
    projected: &str,
    command: &str,
    context: crate::pretool::PathContext<'_>,
) -> bool {
    match program_after_readers(projected) {
        Some(cut) => {
            command.trim_start().starts_with(&projected[..cut])
                && (context.ripgrep_config_absent || !runs_configured_ripgrep(&projected[..cut]))
        }
        None => super::cd::enters_cwd(projected, context),
    }
}

/// [`lead_admitted`] for the sandbox, which runs in `workspace` and has no
/// hook context: readers exactly as `command` runs them, or a `cd` to
/// `workspace` itself. The sandbox confines whatever the readers start, so the
/// ripgrep configuration the decision checked needs no second look here.
pub(super) fn lead_runs_in(projected: &str, command: &str, workspace: &std::path::Path) -> bool {
    match program_after_readers(projected) {
        Some(cut) => command.trim_start().starts_with(&projected[..cut]),
        None => super::cd::enters_workspace(projected, workspace),
    }
}

/// Whether a reader in `lead` is ripgrep reading its configuration file,
/// which can name a preprocessor (`--pre`) the words never show. Only a
/// `--no-config` right after `rg` is surely a flag: later it can be the value
/// of `-e` or `-g`, or a pattern after `--`, and ripgrep reads the file then.
fn runs_configured_ripgrep(lead: &str) -> bool {
    lead.split([';', '\n', '&', '|']).any(|segment| {
        let words = shell_words(segment);
        words.first().is_some_and(|program| program == "rg")
            && words.get(1).is_none_or(|word| word != "--no-config")
    })
}

/// The words of one command as the shell passes them: the lead holds no
/// escapes or substitutions, so only the quotes go.
fn shell_words(segment: &str) -> Vec<String> {
    segment
        .split_whitespace()
        .map(|word| word.replace(['\'', '"'], ""))
        .collect()
}

/// The byte offset where the program starts when `projected` is plain
/// readers followed by Python fed on standard input as the whole last
/// command.
pub(super) fn program_after_readers(projected: &str) -> Option<usize> {
    let bytes = projected.as_bytes();
    let (mut quote, mut start, mut cut, mut piped) = (None, 0usize, None, false);
    let mut lead: Vec<&str> = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(open) = quote {
            if byte == open {
                quote = None;
            } else if open == b'"' && matches!(byte, b'$' | b'`' | b'\\') {
                return None;
            }
            index += 1;
            continue;
        }
        let width = match byte {
            b'\'' | b'"' => {
                quote = Some(byte);
                0
            }
            b';' | b'\n' => 1,
            b'&' if bytes.get(index + 1) == Some(&b'&') => 2,
            b'|' if bytes.get(index + 1) != Some(&b'|') => 1,
            b'&' | b'|' | b'$' | b'`' | b'(' | b')' | b'<' | b'>' | b'{' | b'}' | b'\\' => {
                return None
            }
            _ => 0,
        };
        if width > 0 {
            lead.push(&projected[start..index]);
            start = index + width;
            piped = byte == b'|';
            if !piped {
                cut = Some(start);
            }
        }
        index += width.max(1);
    }
    let cut = cut.filter(|_| quote.is_none() && !piped)?;
    let program = projected[cut..].trim();
    (crate::native_command_controls::python_stdin(program)
        && lead.iter().all(|segment| reader(segment)))
    .then_some(cut)
}

/// Whether one command of the lead is a plain reader. Empty commands, as
/// between two separators, read nothing.
fn reader(segment: &str) -> bool {
    let words = shell_words(segment);
    let Some(program) = words.first().map(String::as_str) else {
        return true;
    };
    let blocked = match program {
        "git"
            if words
                .get(1)
                .is_some_and(|verb| GIT_READS.contains(&verb.as_str())) =>
        {
            GIT_STARTS_OR_WRITES
        }
        "rg" => RG_STARTS,
        _ if READERS.contains(&program) => &[],
        _ => return false,
    };
    !words.iter().skip(1).any(|word| {
        let name = word.split('=').next().unwrap_or_default();
        let long = name.len() > 2 && name.starts_with("--");
        (long && blocked.iter().any(|option| option.starts_with(name)))
            || (program == "rg"
                && !word.starts_with("--")
                && word.starts_with('-')
                && word.contains('z'))
    })
}

/// The payload the raw text is reviewed from. Once the readers are proved
/// plain, the raw text is the program after them, which earns the review the
/// same program earns alone. Anything else is reviewed as the `cd` route
/// decides.
pub(super) fn reviewed_payload(
    payload: &Value,
    command: &str,
    projected: &str,
    entered: bool,
) -> Value {
    let program = program_after_readers(projected)
        .filter(|_| entered)
        .and_then(|cut| command.trim_start().strip_prefix(&projected[..cut]))
        .map(str::trim_start);
    match program {
        Some(program) => {
            super::super::command_rewrite::payload_with_command(payload, command, program)
        }
        None => super::cd::reviewed_payload(payload, command, entered),
    }
}

#[cfg(test)]
mod tests {
    use super::{program_after_readers, runs_configured_ripgrep};

    #[test]
    fn readers_before_the_program_are_taken() {
        for projected in [
            "git diff --check && git diff && python3 -",
            "ls pkg; python3 -",
            "ls pkg\npython3 -",
            "git log --oneline -- pkg | head -20; python -",
            "rg -n 'def main' -g '*.py' && python3",
            "git status --short; cat pyproject.toml && python3 -I -",
            "git show HEAD:pkg/__init__.py | wc -l; pwd; python3 -",
            "git diff --name-only -z; python3 -",
            "git log --output-indicator-new=+ -1; python3 -",
            "grep -rz x pkg; python3 -",
        ] {
            assert!(program_after_readers(projected).is_some(), "{projected}");
        }
    }

    #[test]
    fn anything_that_writes_starts_programs_or_follows_keeps_the_chain_bar() {
        for projected in [
            "python3 -",
            "python3 - && ls",
            "python3 -\nls",
            "ls; python3 - | tee out.txt",
            "ls | python3 -",
            "cd pkg && python3 -",
            "cd pkg; ls; python3 -",
            "sed -i s/a/b/ pkg/__init__.py; python3 -",
            "git checkout main && python3 -",
            "git -c core.pager=x log; python3 -",
            "git diff --output=pkg/x.py; python3 -",
            "git diff --ext-diff; python3 -",
            "git grep x; python3 -",
            "rg --pre ./run x; python3 -",
            "rg -z x; python3 -",
            "rg -nz x; python3 -",
            "rg --p'r'e=./run x; python3 -",
            "git diff --\"out\"put=pkg/x.py; python3 -",
            "git diff --out=pkg/x.py; python3 -",
            "git diff --ext; python3 -",
            "'git' diff --o'utput'=pkg/x.py; python3 -",
            "ls $HOME; python3 -",
            "ls \"$HOME\"; python3 -",
            "ls `pwd`; python3 -",
            "ls $(pwd); python3 -",
            "ls > pkg/x.py; python3 -",
            "ls || python3 -",
            "ls & python3 -",
            "PYTHONPATH=x ls; python3 -",
            "ls 'a; python3 -",
            "ls; python3 -c 'import os'",
            "ls; sh -",
            "{ ls; }; python3 -",
        ] {
            assert_eq!(program_after_readers(projected), None, "{projected}");
        }
    }

    #[test]
    fn the_program_starts_after_the_last_separator() {
        let projected = "ls pkg; python3 -";
        assert_eq!(program_after_readers(projected), Some("ls pkg;".len()));
    }

    #[test]
    fn ripgrep_that_reads_its_configuration_file_is_seen() {
        for lead in [
            "ls; rg -n x pkg | head;",
            "git diff && 'rg' x;",
            "rg x -- --no-config;",
            "rg -e --no-config x;",
            "rg -g --no-config x;",
        ] {
            assert!(runs_configured_ripgrep(lead), "{lead}");
        }
        for lead in ["rg --no-config -n x;", "git diff && ls pkg;"] {
            assert!(!runs_configured_ripgrep(lead), "{lead}");
        }
    }
}
