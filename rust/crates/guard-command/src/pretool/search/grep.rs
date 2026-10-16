use super::{
    options, short_search_option, tree, unsafe_search_value, ReadContext, SearchValueRole,
};

/// Which missing operands a proof may accept.
#[derive(Clone, Copy)]
struct AbsentOperands {
    plain: bool,
    recursive: bool,
}

/// The operand proof alone, as if `grep` were the whole command.
pub(super) fn safe_grep_arguments(arguments: &[String], context: ReadContext<'_>) -> bool {
    let absent = AbsentOperands {
        plain: true,
        recursive: true,
    };
    safe_arguments(arguments, context, false, absent)
}

/// A `grep` segment inside its command. A missing operand is proven only
/// while it stays missing: no other segment may create a file, directory or
/// link there (`ln -s <dir> <repo>/cfg && grep -rn . <repo>/cfg/` reads through
/// the fresh link). A recursive search walks whatever appears at a missing
/// root, so it accepts one only beside `cd` and downstream stdin filters.
pub(crate) fn safe_grep_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: ReadContext<'_>,
) -> bool {
    let others: Vec<&crate::CommandSegmentV1> = model
        .segments
        .iter()
        .filter(|other| other.span != segment.span)
        .collect();
    let absent = AbsentOperands {
        plain: others.iter().all(|other| creates_nothing(other, false)),
        recursive: others.iter().all(|other| creates_nothing(other, true)),
    };
    safe_arguments(&segment.arguments, context, false, absent)
}

/// A peer that cannot create a filesystem entry: no output redirect beyond
/// `/dev/null`, and a command that only prints, filters or changes directory.
/// `strict` admits only `cd` and stdin filters after a pipe.
fn creates_nothing(segment: &crate::CommandSegmentV1, strict: bool) -> bool {
    let text = ["2>&1", "2>/dev/null", ">/dev/null"]
        .iter()
        .fold(segment.text.clone(), |text, quiet| text.replace(quiet, ""));
    if text.contains('>') || !segment.wrapper_chain.is_empty() || segment.path_overridden {
        return false;
    }
    match segment.executable.as_deref() {
        Some("cd") => true,
        Some(_) if strict => {
            segment.pipeline_index > 0
                && crate::pretool::segment_proof::stdin_filter_segment(segment)
        }
        Some(executable) => matches!(
            executable,
            "cat"
                | "cut"
                | "diff"
                | "echo"
                | "grep"
                | "head"
                | "jq"
                | "ls"
                | "nl"
                | "printf"
                | "pwd"
                | "rg"
                | "tail"
                | "test"
                | "tr"
                | "true"
                | "wc"
        ),
        None => false,
    }
}

pub(super) fn safe_stdin_arguments(arguments: &[String]) -> bool {
    let absent = AbsentOperands {
        plain: false,
        recursive: false,
    };
    safe_arguments(
        arguments,
        crate::pretool::PathContext::default(),
        true,
        absent,
    )
}

fn safe_arguments(
    arguments: &[String],
    context: ReadContext<'_>,
    stdin_only: bool,
    absent: AbsentOperands,
) -> bool {
    arguments_pass(arguments, context, stdin_only, absent, false)
}

/// One pass over `grep` arguments. With `pattern_from_option`, every
/// positional is a path, as it is when `-e` or `-f` appears anywhere.
fn arguments_pass(
    arguments: &[String],
    context: ReadContext<'_>,
    stdin_only: bool,
    absent: AbsentOperands,
    pattern_from_option: bool,
) -> bool {
    let mut pending_value: Option<SearchValueRole> = None;
    let mut pattern_supplied = pattern_from_option;
    let mut pattern_option_seen = false;
    let mut options_enabled = true;
    let mut recursive = false;
    let mut targets = Vec::new();
    let mut excluded_files = Vec::new();
    let mut excluded_directories = Vec::new();
    let mut pending_exclusion = None;
    let mut includes_present = false;
    let mut positional_started = false;
    for argument in arguments {
        if let Some(directory) = pending_exclusion.take() {
            if argument.is_empty() {
                return false;
            }
            if exact_exclusion(argument) {
                if directory {
                    excluded_directories.push(argument.as_str());
                } else {
                    excluded_files.push(argument.as_str());
                }
            }
            continue;
        }
        if let Some(role) = pending_value.take() {
            if matches!(role, SearchValueRole::DirectoryAction)
                && argument.eq_ignore_ascii_case("recurse")
            {
                recursive = true;
                continue;
            }
            if unsafe_search_value(role, argument, context) {
                return false;
            }
            // `-f FILE` supplies the patterns as `-e` does.
            if matches!(role, SearchValueRole::Pattern | SearchValueRole::Path) {
                pattern_supplied = true;
                pattern_option_seen = true;
            }
            continue;
        }
        if options_enabled && argument == "--" {
            options_enabled = false;
            continue;
        }
        if options_enabled && argument.starts_with("--") {
            let (name, attached) = argument.split_once('=').unwrap_or((argument.as_str(), ""));
            if matches!(name, "--exclude" | "--exclude-dir") {
                if positional_started {
                    return false;
                }
                let directory = name == "--exclude-dir";
                if attached.is_empty() {
                    if argument.contains('=') {
                        return false;
                    }
                    pending_exclusion = Some(directory);
                } else if exact_exclusion(attached) {
                    if directory {
                        excluded_directories.push(attached);
                    } else {
                        excluded_files.push(attached);
                    }
                }
                continue;
            }
            includes_present |= name == "--include";
            if matches!(name, "--recursive" | "--dereference-recursive") {
                if !attached.is_empty() {
                    return false;
                }
                recursive = true;
                continue;
            }
            if matches!(name, "--file" | "--exclude-from") {
                return false;
            }
            let role = options::grep_value_role(name);
            if role.is_none() && !options::safe_grep_flag(name) {
                return false;
            }
            if let Some(role) = role {
                if stdin_only && matches!(role, SearchValueRole::Path) {
                    return false;
                }
                if matches!(role, SearchValueRole::DirectoryAction)
                    && attached.eq_ignore_ascii_case("recurse")
                {
                    recursive = true;
                    continue;
                }
                if attached.is_empty() {
                    pending_value = Some(role);
                } else if unsafe_search_value(role, attached, context) {
                    return false;
                } else if matches!(role, SearchValueRole::Pattern) {
                    pattern_supplied = true;
                    pattern_option_seen = true;
                }
            }
            continue;
        }
        if options_enabled && argument.starts_with('-') && argument.len() > 1 {
            if stdin_only
                && argument[1..]
                    .chars()
                    .take_while(|option| !matches!(option, 'e' | 'd' | 'A' | 'B' | 'C' | 'm'))
                    .any(|option| option == 'f')
            {
                return false;
            }
            recursive |= argument[1..]
                .chars()
                .take_while(|option| !matches!(option, 'e' | 'f' | 'd' | 'A' | 'B' | 'C' | 'm'))
                .any(|option| matches!(option, 'r' | 'R'));
            let parsed = short_search_option(
                argument,
                &[],
                &[
                    ('e', SearchValueRole::Pattern),
                    ('f', SearchValueRole::Path),
                    ('d', SearchValueRole::DirectoryAction),
                    ('A', SearchValueRole::Other),
                    ('B', SearchValueRole::Other),
                    ('C', SearchValueRole::Other),
                    ('m', SearchValueRole::Other),
                ],
                context,
            );
            let Ok((next_value, supplied_pattern)) = parsed else {
                return false;
            };
            pending_value = next_value;
            pattern_supplied |= supplied_pattern;
            pattern_option_seen |= supplied_pattern;
            continue;
        }
        if pattern_supplied {
            if stdin_only {
                return false;
            }
            targets.push(argument.as_str());
            let proven = recursive
                || proven_glob(argument, context)
                || (absent.plain && absent_target(argument, context));
            if !proven && unsafe_search_value(SearchValueRole::Path, argument, context) {
                return false;
            }
        } else {
            pattern_supplied = true;
        }
        positional_started = true;
    }
    // GNU and BSD grep take the first positional as the pattern only when no
    // `-e` or `-f` supplies one, wherever that option appears: in
    // `grep .env -e KEY`, `.env` is a file. Check again with every
    // positional as a path.
    if pattern_option_seen && !pattern_from_option {
        return arguments_pass(arguments, context, stdin_only, absent, true);
    }
    pending_value.is_none()
        && pending_exclusion.is_none()
        // Include/exclude precedence differs across grep implementations. Do not
        // use exclusions as proof when an include could re-enable a file.
        && (!includes_present || (excluded_files.is_empty() && excluded_directories.is_empty()))
        && (!stdin_only || (pattern_supplied && !recursive))
        && (!recursive || {
            let proven = |target: &str| {
                tree::safe_recursive_target_excluding(
                    target,
                    context,
                    &excluded_files,
                    &excluded_directories,
                    true,
                ) || proven_glob(target, context)
            };
            recursive_targets_proven(&targets, proven, absent.recursive.then_some(context))
        })
}

/// Every recursive root is proven, or missing beside at least one proven
/// root (`grep -rn x src tests` with no `tests`): a search whose only roots
/// are missing (`grep -rn x src/missing.ts`) proves nothing it reads.
fn recursive_targets_proven(
    targets: &[&str],
    proven: impl Fn(&str) -> bool,
    absent: Option<ReadContext<'_>>,
) -> bool {
    let mut real = false;
    targets.iter().copied().all(|target| {
        if proven(target) {
            real = true;
            return true;
        }
        absent.is_some_and(|context| absent_target(target, context))
    }) && real
}

/// A missing operand only prints an error, as a probe `ls` of the same path
/// does: its nearest existing ancestor must be a readable directory and every
/// missing name visible and clear of the sensitive screens. Agents pass a
/// fixed list of roots (`src tests lib`) whether or not each one exists.
fn absent_target(value: &str, context: ReadContext<'_>) -> bool {
    crate::pretool::listing_reads::absent_listing_operand(value, context)
}

/// A shell glob operand whose every expansion is screened, and whose matched
/// directories are walked like a recursive search root. This is how a glob
/// into a sibling repository, such as `~/code/api/src/*.ts`, is proven.
fn proven_glob(value: &str, context: ReadContext<'_>) -> bool {
    value.contains(['*', '?', '[']) && tree::safe_glob_search_operand(value, context)
}

fn exact_exclusion(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_missing_root_beside_real_ones_is_proven_but_not_a_sensitive_one() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/grep-absent-roots")
            .join(std::process::id().to_string());
        let home = root.join("home");
        let repo = home.join("work/app");
        std::fs::create_dir_all(repo.join("src")).unwrap();
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::write(repo.join("src/index.ts"), "export const x = 1;\n").unwrap();
        let (home, repo) = (
            crate::runtime_read_paths::canonicalize_text(&home).unwrap(),
            crate::runtime_read_paths::canonicalize_text(&repo).unwrap(),
        );
        let context = crate::pretool::PathContext {
            home_dir: home.to_str(),
            cwd: repo.to_str(),
            ..Default::default()
        };
        let r = repo.display();
        let h = home.display();
        for (command, allowed) in [
            (format!("-rln x {r}/src {r}/lib"), true),
            (format!("-n x {r}/src/index.ts {r}/lib/index.ts"), true),
            ("-rn x src tests".to_owned(), true),
            (format!("-rln x {r}/src {h}/.ssh/missing"), false),
            (format!("-rln x {r}/src {r}/missing/.env"), false),
            (format!("-rln x {r}/src {r}/missing/id_rsa"), false),
            (format!("-n x {h}/.ssh/missing"), false),
        ] {
            let arguments: Vec<String> = command.split(' ').map(str::to_owned).collect();
            assert_eq!(
                super::safe_grep_arguments(&arguments, context),
                allowed,
                "{command}"
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_missing_operand_is_not_proven_beside_a_step_that_could_create_it() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/grep-absent-chains")
            .join(std::process::id().to_string());
        let home = root.join("home");
        let repo = home.join("work/app");
        std::fs::create_dir_all(repo.join("src")).unwrap();
        std::fs::write(repo.join("src/index.ts"), "export const x = 1;\n").unwrap();
        let (home, repo) = (
            crate::runtime_read_paths::canonicalize_text(&home).unwrap(),
            crate::runtime_read_paths::canonicalize_text(&repo).unwrap(),
        );
        let context = crate::pretool::PathContext {
            home_dir: home.to_str(),
            cwd: repo.to_str(),
            ..Default::default()
        };
        let r = repo.display();
        for (command, allowed) in [
            (format!("grep -rln x {r}/src {r}/cfg"), true),
            (format!("grep -rn x {r}/src {r}/cfg | head -5"), true),
            (format!("cd {r} && grep -rn x src cfg"), true),
            (
                format!("cat {r}/src/index.ts && grep -n x {r}/cfg/app.json"),
                true,
            ),
            (
                format!("ln -s {r}/src {r}/cfg && grep -rn . {r}/cfg/"),
                false,
            ),
            (
                format!("ln -s {r}/src {r}/cfg && grep -n x {r}/cfg/app.json"),
                false,
            ),
            (format!("mkdir -p {r}/cfg && grep -rn x {r}/cfg"), false),
            (format!("touch {r}/cfg && grep -n x {r}/cfg"), false),
            (format!("echo x > {r}/cfg; grep -n x {r}/cfg"), false),
            (format!("cat {r}/src/index.ts && grep -rn x {r}/cfg"), false),
        ] {
            let model = crate::parse_command(&crate::CommandModelRequestV1 {
                command: command.clone(),
                dialect: "posix".to_owned(),
                transport: "shell_string".to_owned(),
                extraction_provenance: "guard-shell".to_owned(),
            })
            .unwrap();
            // An output redirect leaves the model uncertain with no
            // segments, which no proof admits.
            let Some(segment) = model
                .segments
                .iter()
                .find(|segment| segment.executable.as_deref() == Some("grep"))
            else {
                assert!(!allowed, "{command}");
                continue;
            };
            assert_eq!(
                super::safe_grep_segment(&model, segment, context),
                allowed,
                "{command}"
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stdin_proof_cannot_open_files_or_recurse() {
        for (arguments, allowed) in [
            (vec!["-n", "-e", "fixture"], true),
            (vec!["-efixt"], true),
            (vec!["--regexp=fixture"], true),
            (vec!["-f", "one.txt"], false),
            (vec!["-nfone.txt"], false),
            (vec!["--file=one.txt"], false),
            (vec!["fixture", "one.txt"], false),
            (vec!["-r", "fixture"], false),
            (vec!["--directories=recurse", "fixture"], false),
            (vec!["-e", "fixture", "-f", "one.txt"], false),
            (vec!["--", "fixture", "one.txt"], false),
            (vec![], false),
        ] {
            let arguments: Vec<String> = arguments.into_iter().map(str::to_owned).collect();
            assert_eq!(
                super::safe_stdin_arguments(&arguments),
                allowed,
                "{arguments:?}"
            );
        }
    }
}
