//! The execution sink's peel, read from the command text.
//!
//! The sink used to lex this text a second time in Python, with its own
//! sibling-repository rule. That copy could not read a Windows owner SID, so
//! it peeled checkouts the classifier had refused and handed the sandbox a
//! core no receipt covered. The grammar lives here now, beside the
//! classifier's, and both read the same sibling-repository rule.
//!
//! It reads the raw text rather than the canonical parse because the sink
//! must answer for text the parse cannot model. `pytest -q | xargs rm` carries
//! no segments at all, and the sink's answer there is a refusal - run the
//! whole text in the sandbox - not silence. A grammar over the text gives that
//! answer for every shape, modelled or not.
use super::contained_wrapper;
use super::contained_wrapper::output_filters;
use super::contained_wrapper_plan::{ContainedOutput, ContainedWrapperCore};
use std::path::{Component, Path, PathBuf};

/// A lexed word (`false`) or operator (`true`).
type Token = (String, bool);

/// Characters that end a word and lex as an operator run.
const OPERATOR: &str = "();<>|&\n";
/// Characters the shell would expand outside quotes. The peel accepts only an
/// exact reading of the text, so any of them makes the lex inexact.
const UNQUOTED_EXPANSION: &str = "$`*?[{";
const DOUBLE_QUOTED_ESCAPES: &str = "$`\"\\";

/// Whether an unquoted `\` is a path separator rather than an escape, as the
/// classifier reads it (`preserve_unquoted_backslash`). The sink peels only
/// posix-dialect shell strings, so the host decides this alone. Reading it the
/// other way on Windows would peel a different command from the one the
/// classifier admitted: `cd C:\\repo && cargo test` would name `C:repo`.
const PRESERVE_UNQUOTED_BACKSLASH: bool = cfg!(windows);
/// Characters a surviving word may not contain: the core is handed to a
/// sandbox, not to a shell, so a redirection or list operator inside a word
/// would be passed through as text rather than obeyed.
const ARGUMENT_REJECT: &str = "<>|&;";
/// The quiet `cd` suffix the peel resolves itself instead of the shell.
const QUIET_SUFFIX: &str = "2>/dev/null";
/// The longest label a final `; echo "<label>$?"` may carry.
const STATUS_LABEL_LIMIT: usize = 32;

/// Package managers that run the rest in a directory named by a flag.
fn directory_flags(manager: &str) -> &'static [&'static str] {
    match manager {
        "bun" | "yarn" => &["--cwd"],
        "npm" => &["--prefix", "-C"],
        "pnpm" => &["--dir", "-C"],
        _ => &[],
    }
}

/// Flags whose value is a program, not a file: the interpreter reads that
/// text, so `;` or `|` inside its quotes is code, not an operator.
fn inline_program_flags(name: &str) -> &'static [&'static str] {
    match name {
        "node" | "nodejs" | "bun" => &["-e", "--eval"],
        "python" | "python3" => &["-c"],
        _ => &[],
    }
}

/// Peel `command` the way the sink runs it.
///
/// `Ok(None)` means nothing is wrapped and the sink runs the command as it
/// stands. `Err` means the shape is wrapped but unsupported, which the sink
/// answers by running the whole text in its sandbox.
pub(super) fn peel(
    command: &str,
    workspace: &str,
    cwd: Option<&str>,
    home_dir: Option<&str>,
    peels_relative_inside: bool,
) -> Result<Option<ContainedWrapperCore>, &'static str> {
    let mut characters: Vec<char> = command.chars().collect();
    let status = status_echo(&characters);
    if let Some((start, _)) = &status {
        characters.truncate(*start);
        while matches!(characters.last().copied(), Some(' ' | '\t')) {
            characters.pop();
        }
    }
    let quiet = quiet_cd(&characters);
    if let Some((kept, end)) = quiet {
        characters.drain(kept..end);
    }
    let rewritten_home = home_dir.is_some() && home_cd(&characters);
    if rewritten_home {
        // The cd target's leading `~` is the one expansion proved; lex it as `.`.
        let tilde = characters
            .iter()
            .position(|character| *character == '~')
            .ok_or("unsupported wrapper shape")?;
        characters[tilde] = '.';
    }
    let text: String = characters.iter().collect();
    let (mut tokens, exact) = lex(&text)?;
    let base = Path::new(cwd.unwrap_or(workspace));
    let mut directory = PathBuf::from(workspace);
    // The text `directory` was resolved from, which decides whether a `\\?\`
    // prefix on it is the caller's or one Windows generated.
    let mut spelled = PathBuf::from(workspace);
    let mut wrapped = status.is_some();
    let mut output: Option<ContainedOutput> = None;

    if tokens.first().map(word) == Some("cd") {
        if tokens.len() < 4 || tokens[1].1 || !matches!(operator(&tokens[2]), Some("&&" | ";")) {
            return Err("unsupported cd prefix");
        }
        let sequenced = operator(&tokens[2]) == Some(";");
        let target_text = tokens[1].0.clone();
        let target = match home_dir.filter(|_| rewritten_home) {
            // Only an unquoted leading `~` expands, so the rest of the word
            // spells the path from home. `~//x` is home/x: joining a path that
            // starts with a slash would drop home.
            Some(home) => Path::new(home).join(
                target_text
                    .chars()
                    .skip(2)
                    .collect::<String>()
                    .trim_start_matches('/'),
            ),
            None => PathBuf::from(&target_text),
        };
        if !exact {
            return Err("relative cd target");
        }
        let inside =
            std::fs::canonicalize(workspace).map_err(|_| "cd target outside the workspace")?;
        spelled = base.join(&target);
        directory =
            std::fs::canonicalize(&spelled).map_err(|_| "cd target outside the workspace")?;
        let within = directory.starts_with(&inside);
        let root = sibling_root(&directory, home_dir);
        // Only a host with no workspace sandbox peels an `&&`-joined relative
        // `cd` that stays inside the workspace; elsewhere that text stays
        // whole and the sandbox runs it, which is the stronger route.
        let peeled_inside = peels_relative_inside && !sequenced && quiet.is_none() && within;
        if !target.is_absolute()
            && !peeled_inside
            && (within || root.as_deref() != Some(directory.as_path()))
        {
            return Err("relative cd target");
        }
        if !directory.is_dir() || !(within || root.is_some()) {
            return Err("cd target outside the workspace");
        }
        // Only a cd into a sibling repository may end in `;` or carry
        // `2>/dev/null`: the directory is resolved here and nothing is peeled
        // when it is gone, so the core never falls back to the session
        // directory the way the shell would after a failed cd.
        if (sequenced || quiet.is_some()) && within {
            return Err("unsupported cd prefix");
        }
        let into_sibling_root = root.as_deref() == Some(directory.as_path()) && !within;
        tokens.drain(..3);
        wrapped = true;
        if into_sibling_root {
            // `cd <sibling root> && a && b` is re-authorized whole in that
            // root. A filter after `a && b` would apply to `b` alone, so none
            // is peeled there.
            if let Some(joined) = joined_list(&tokens) {
                return Ok(Some(ContainedWrapperCore {
                    core: joined,
                    directory: python_resolved(&spelled, directory),
                    output: status.map(|(_, label)| ContainedOutput {
                        status_label: Some(label),
                        ..passthrough()
                    }),
                }));
            }
        }
    } else if exact {
        if let Some((rewritten, resolved, joined)) = package_directory(&tokens, base) {
            let inside = std::fs::canonicalize(workspace)
                .map_err(|_| "package directory outside the workspace")?;
            if !(resolved.starts_with(&inside) || sibling_root(&resolved, home_dir).is_some()) {
                return Err("package directory outside the workspace");
            }
            tokens = rewritten;
            spelled = joined;
            directory = resolved;
            wrapped = true;
        }
    }

    if let Some(index) = tokens.iter().position(|token| operator(token) == Some("|")) {
        let stages = filter_chain(&tokens[index + 1..])?;
        tokens.truncate(index);
        let merge_stderr = tokens.last().map(operator) == Some(Some("2>&1"));
        if merge_stderr {
            tokens.pop();
        }
        let bounded = match stages.as_slice() {
            [stage] if stage.len() == 2 && matches!(stage[0].as_str(), "head" | "tail") => Some((
                if stage[0] == "head" { "head" } else { "tail" },
                stage[1].parse().unwrap_or(0),
            )),
            _ => None,
        };
        output = Some(match bounded {
            Some((kind, count)) => ContainedOutput {
                kind,
                count,
                merge_stderr,
                ..passthrough()
            },
            None => ContainedOutput {
                kind: "pipe",
                merge_stderr,
                stages,
                ..passthrough()
            },
        });
        wrapped = true;
    } else if tokens.last().map(operator) == Some(Some("2>&1")) {
        tokens.pop();
        output = Some(ContainedOutput {
            merge_stderr: true,
            ..passthrough()
        });
        wrapped = true;
    }
    if let Some((_, label)) = status {
        output = Some(ContainedOutput {
            status_label: Some(label),
            ..output.unwrap_or_else(passthrough)
        });
    }
    if !wrapped {
        return Ok(None);
    }
    let program = inline_program_index(&tokens);
    let rejected = tokens.iter().enumerate().any(|(index, (value, operator))| {
        *operator
            || (Some(index) != program
                && value
                    .chars()
                    .any(|character| ARGUMENT_REJECT.contains(character)))
    });
    if !exact || tokens.is_empty() || rejected {
        return Err("unsupported wrapper shape");
    }
    Ok(Some(ContainedWrapperCore {
        core: shlex_join(tokens.iter().map(|(value, _)| value.as_str())),
        directory: python_resolved(&spelled, directory),
        output,
    }))
}

/// The directory as Python's `Path.resolve` would spell it.
///
/// The sink compares this directory against its own `workspace.resolve()` and
/// runs the core in it, so the two must be spelled alike. On Windows
/// `canonicalize` keeps the `\\?\` prefix `GetFinalPathNameByHandle` adds and
/// `resolve` strips it, which would leave every peeled directory reading as
/// outside the workspace it is in. A prefix the caller spelled is left alone,
/// as `resolve` leaves it.
fn python_resolved(spelled: &Path, resolved: PathBuf) -> PathBuf {
    let _ = spelled;
    #[cfg(windows)]
    let resolved = PathBuf::from(
        crate::launch_identity_common::strip_generated_extended_prefix(
            &spelled.to_string_lossy(),
            resolved
                .into_os_string()
                .into_string()
                .unwrap_or_else(|path| path.to_string_lossy().into_owned()),
        ),
    );
    resolved
}

/// Output passed through untouched, which a merge, a chain or a status label
/// then describes.
fn passthrough() -> ContainedOutput {
    ContainedOutput {
        kind: "all",
        count: 0,
        merge_stderr: false,
        status_label: None,
        stages: Vec::new(),
    }
}

fn word(token: &Token) -> &str {
    if token.1 {
        ""
    } else {
        token.0.as_str()
    }
}

fn operator(token: &Token) -> Option<&str> {
    token.1.then_some(token.0.as_str())
}

/// The repository holding `directory`, as native authority finds it. An
/// absent home proves no root, as the Python peel's `home is None` did.
fn sibling_root(directory: &Path, home_dir: Option<&str>) -> Option<PathBuf> {
    contained_wrapper::sibling_project_root(directory, home_dir?)
}

/// Split like a POSIX shell into `(value, is_operator)` pairs, and report
/// whether the text read exactly: no expansion, glob, tilde or comment that
/// the shell would have rewritten before the words reached the program.
///
/// Quoted text is never an operator, so `'|'` or `'print(1)'` stay plain
/// words.
fn lex(command: &str) -> Result<(Vec<Token>, bool), &'static str> {
    let characters: Vec<char> = command.chars().collect();
    let mut tokens: Vec<Token> = Vec::new();
    let mut word: Option<String> = None;
    let mut exact = true;
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        if character == ' ' || character == '\t' {
            if let Some(value) = word.take() {
                tokens.push((value, false));
            }
            index += 1;
        } else if word.is_none() && merge_at(&characters, index) {
            tokens.push(("2>&1".to_owned(), true));
            index += 4;
        } else if OPERATOR.contains(character) {
            if let Some(value) = word.take() {
                tokens.push((value, false));
            }
            let mut end = index;
            while end < characters.len() && OPERATOR.contains(characters[end]) {
                end += 1;
            }
            tokens.push((characters[index..end].iter().collect(), true));
            index = end;
        } else if character == '\'' {
            let end = characters[index + 1..]
                .iter()
                .position(|character| *character == '\'')
                .map(|offset| index + 1 + offset)
                .ok_or("unterminated quote")?;
            word.get_or_insert_with(String::new)
                .extend(characters[index + 1..end].iter());
            index = end + 1;
        } else if character == '"' {
            let buffer = word.get_or_insert_with(String::new);
            index += 1;
            loop {
                let Some(mut quoted) = characters.get(index).copied() else {
                    return Err("unterminated quote");
                };
                if quoted == '"' {
                    index += 1;
                    break;
                }
                if quoted == '\\'
                    && characters
                        .get(index + 1)
                        .is_some_and(|next| DOUBLE_QUOTED_ESCAPES.contains(*next))
                {
                    index += 1;
                    quoted = characters[index];
                } else if quoted == '\\' && characters.get(index + 1) == Some(&'\n') {
                    return Err("line continuation");
                } else if quoted == '$' || quoted == '`' {
                    exact = false;
                }
                buffer.push(quoted);
                index += 1;
            }
        } else if character == '\\' {
            if matches!(characters.get(index + 1), None | Some(&'\n')) {
                return Err("unsupported escape");
            }
            if PRESERVE_UNQUOTED_BACKSLASH
                && !crate::command_tokens::backslash_escapes_operator(&characters, index)
            {
                word.get_or_insert_with(String::new).push(character);
                index += 1;
            } else {
                word.get_or_insert_with(String::new)
                    .push(characters[index + 1]);
                index += 2;
            }
        } else {
            if (character as u32) < 32
                || UNQUOTED_EXPANSION.contains(character)
                || (word.is_none() && (character == '~' || character == '#'))
            {
                exact = false;
            }
            word.get_or_insert_with(String::new).push(character);
            index += 1;
        }
    }
    if let Some(value) = word.take() {
        tokens.push((value, false));
    }
    Ok((tokens, exact))
}

/// `2>&1` as its own operator: the one redirection the sink applies itself.
fn merge_at(characters: &[char], index: usize) -> bool {
    characters.get(index..index + 4) == Some(&['2', '>', '&', '1'][..])
        && matches!(
            characters.get(index + 4).copied(),
            None | Some(' ' | '\t' | '|')
        )
}

/// A word as the shell would have to be given it back.
fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_owned();
    }
    if value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "_@%+=:,./-".contains(character))
    {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn shlex_join<'a>(values: impl Iterator<Item = &'a str>) -> String {
    values.map(shell_quote).collect::<Vec<_>>().join(" ")
}

/// The stages after a core's first `|`, or a refusal for any other shape.
fn filter_chain(tokens: &[Token]) -> Result<Vec<Vec<String>>, &'static str> {
    let mut stages: Vec<Vec<String>> = vec![Vec::new()];
    for token in tokens {
        match operator(token) {
            Some("|") => stages.push(Vec::new()),
            Some(_) => return Err("unsupported output filter"),
            None => stages.last_mut().expect("one stage").push(token.0.clone()),
        }
    }
    if stages.len() > output_filters::MAX_FILTERS {
        return Err("unsupported output filter");
    }
    let mut chain = Vec::with_capacity(stages.len());
    for stage in &stages {
        let (program, arguments) = match stage.split_first() {
            Some((program, arguments)) => (program.as_str(), arguments),
            None => ("", &[] as &[String]),
        };
        if matches!(program, "head" | "tail") {
            if let Some(count) = bounded_count(arguments) {
                chain.push(vec![program.to_owned(), count.to_string()]);
                continue;
            }
        }
        if output_filters::matcher_stage(program, arguments) {
            let mut argv = Vec::with_capacity(arguments.len() + 1);
            argv.push(program.to_owned());
            argv.extend(arguments.iter().cloned());
            chain.push(argv);
            continue;
        }
        return Err("unsupported output filter");
    }
    Ok(chain)
}

/// The line count of a `head`/`tail` stage: `-N` or `-n N`.
fn bounded_count(values: &[String]) -> Option<u32> {
    let digits = match values {
        [single] => single.strip_prefix('-')?,
        [flag, count] if flag == "-n" => count.as_str(),
        _ => return None,
    };
    if !output_filters::bounded_count(digits) {
        return None;
    }
    digits.parse().ok()
}

/// `bun --cwd <dir> build` as `bun build` in `<dir>`, as native authority
/// reads it.
///
/// One directory flag, before the verb or right after `run`. Whatever follows
/// the flag is carried over whole, so an implicit script run such as
/// `pnpm build` is read in `<dir>` the way `pnpm run build` already was. The
/// directory is joined to the physical working directory and normalized
/// lexically, as the package manager's `path.resolve` does, then resolved on
/// disk. Other spellings return `None` and keep the unwrapped path.
fn package_directory(tokens: &[Token], base: &Path) -> Option<(Vec<Token>, PathBuf, PathBuf)> {
    let manager = tokens.first().map(word)?;
    let flags = directory_flags(manager);
    if flags.is_empty() {
        return None;
    }
    let end = tokens
        .iter()
        .position(|token| token.1)
        .unwrap_or(tokens.len());
    let words: Vec<&str> = tokens[1..end]
        .iter()
        .map(|(value, _)| value.as_str())
        .collect();
    let options = match words.iter().position(|value| *value == "--") {
        Some(index) => &words[..index],
        None => &words[..],
    };
    if options
        .iter()
        .filter(|value| names_directory_flag(value, flags))
        .count()
        != 1
    {
        return None;
    }
    let index = usize::from(words.first() == Some(&"run"));
    let flag = words.get(index).copied().unwrap_or_default();
    let (value, consumed) = if flags.contains(&flag) && index + 1 < words.len() {
        (words[index + 1], 2)
    } else {
        match flag.split_once('=') {
            Some((name, value)) if flags.contains(&name) && name.starts_with("--") => (value, 1),
            _ => return None,
        }
    };
    let mut rest: Vec<&str> = words[..index].to_vec();
    rest.extend_from_slice(&words[index + consumed..]);
    if value.starts_with(['-', '~'])
        || value.contains("//")
        || !plain_word(value)
        || rest.is_empty()
    {
        return None;
    }
    // A flag naming a directory that is not there keeps the unwrapped path:
    // native authority reads that text unprojected too, and the package
    // manager is the one that reports the missing directory.
    let resolved = std::fs::canonicalize(base)
        .ok()
        .and_then(|root| std::fs::canonicalize(lexical(&root.join(value))).ok())
        .filter(|directory| directory.is_dir())?;
    let joined = lexical(&base.join(value));
    let mut rewritten = vec![tokens[0].clone()];
    rewritten.extend(rest.iter().map(|value| ((*value).to_owned(), false)));
    rewritten.extend_from_slice(&tokens[end..]);
    Some((rewritten, resolved, joined))
}

/// Any spelling of a directory flag: `--cwd`, `--cwd=x`, `-C`, `-Cx`.
fn names_directory_flag(value: &str, flags: &[&str]) -> bool {
    flags.iter().any(|flag| {
        let short = !flag.starts_with("--");
        value
            .strip_prefix(*flag)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('=') || short)
    })
}

/// A directory word the manager passes through unchanged.
fn plain_word(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "/._@+=:,-".contains(character))
}

/// `.` and `..` resolved lexically, as every package manager resolves them.
/// A `..` at the root stays at the root, which is where the shell leaves it.
fn lexical(path: &Path) -> PathBuf {
    let mut resolved = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => resolved.push(prefix.as_os_str()),
            Component::RootDir => resolved.push(std::path::MAIN_SEPARATOR_STR),
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(part) => resolved.push(part),
        }
    }
    resolved
}

/// `a && b && c` of plain words, rejoined, or `None` for any other shape.
fn joined_list(tokens: &[Token]) -> Option<String> {
    let mut segments: Vec<Vec<&str>> = vec![Vec::new()];
    for token in tokens {
        match operator(token) {
            Some("&&") => segments.push(Vec::new()),
            Some(_) => return None,
            None => {
                if token
                    .0
                    .chars()
                    .any(|character| ARGUMENT_REJECT.contains(character))
                {
                    return None;
                }
                segments.last_mut()?.push(token.0.as_str());
            }
        }
    }
    if segments.len() < 2 || segments.iter().any(|segment| segment.is_empty()) {
        return None;
    }
    Some(
        segments
            .iter()
            .map(|segment| shlex_join(segment.iter().copied()))
            .collect::<Vec<_>>()
            .join(" && "),
    )
}

/// Where a bare `node -e <program>` or `python3 -c <program>` holds its
/// program, else `None`.
///
/// That word is one argument the sandbox passes to the interpreter, never to
/// a shell, and the peeled core is re-authorized as quoted text.
fn inline_program_index(tokens: &[Token]) -> Option<usize> {
    if tokens.len() != 3 || tokens.iter().any(|token| token.1) {
        return None;
    }
    inline_program_flags(&tokens[0].0)
        .contains(&tokens[1].0.as_str())
        .then_some(2)
}

/// A final `; echo "<label>$?"`: where it starts, and the label it prints.
/// A label with spaces must be double-quoted.
fn status_echo(characters: &[char]) -> Option<(usize, String)> {
    (0..characters.len())
        .filter(|index| characters[*index] == ';')
        .find_map(|index| status_echo_at(characters, index).map(|label| (index, label)))
}

fn status_echo_at(characters: &[char], start: usize) -> Option<String> {
    let mut index = skip_blanks(characters, start + 1);
    index = literal(characters, index, "echo")?;
    index = require_blanks(characters, index)?;
    let quoted = characters.get(index) == Some(&'"');
    if quoted {
        index += 1;
    }
    let mut label = String::new();
    while label.len() < STATUS_LABEL_LIMIT
        && characters.get(index).copied().is_some_and(|character| {
            character.is_ascii_alphanumeric()
                || "_=:-".contains(character)
                || (quoted && character == ' ')
        })
    {
        label.push(characters[index]);
        index += 1;
    }
    index = literal(characters, index, "$?")?;
    if quoted {
        if characters.get(index) != Some(&'"') {
            return None;
        }
        index += 1;
    }
    (skip_blanks(characters, index) == characters.len()).then_some(label)
}

/// `cd <dir> 2>/dev/null; …` only silences a cd this peel resolves itself
/// first. The kept prefix ends at the first returned index, and the dropped
/// suffix at the second.
fn quiet_cd(characters: &[char]) -> Option<(usize, usize)> {
    let start = cd_word(characters)?;
    let mut index = start;
    while characters.get(index).copied().is_some_and(|character| {
        !matches!(
            character,
            ' ' | '\t' | ';' | '&' | '|' | '<' | '>' | '\'' | '"'
        )
    }) {
        index += 1;
    }
    if index == start {
        return None;
    }
    let kept = index;
    index = require_blanks(characters, index)?;
    index = literal(characters, index, QUIET_SUFFIX)?;
    let ahead = skip_blanks(characters, index);
    let sequenced = characters.get(ahead) == Some(&';')
        || (characters.get(ahead) == Some(&'&') && characters.get(ahead + 1) == Some(&'&'));
    sequenced.then_some((kept, index))
}

/// Whether the command opens with `cd ~/…` or `cd ~ …`.
fn home_cd(characters: &[char]) -> bool {
    let Some(index) = cd_word(characters) else {
        return false;
    };
    characters.get(index) == Some(&'~')
        && matches!(characters.get(index + 1).copied(), Some('/' | ' ' | '\t'))
}

/// The index just past a leading `cd` and the blanks after it.
fn cd_word(characters: &[char]) -> Option<usize> {
    let index = literal(characters, skip_blanks(characters, 0), "cd")?;
    require_blanks(characters, index)
}

/// The index just past `expected` at `index`, or `None` when it is not there.
fn literal(characters: &[char], index: usize, expected: &str) -> Option<usize> {
    let mut index = index;
    for character in expected.chars() {
        if characters.get(index) != Some(&character) {
            return None;
        }
        index += 1;
    }
    Some(index)
}

fn skip_blanks(characters: &[char], mut index: usize) -> usize {
    while matches!(characters.get(index).copied(), Some(' ' | '\t')) {
        index += 1;
    }
    index
}

fn require_blanks(characters: &[char], index: usize) -> Option<usize> {
    let end = skip_blanks(characters, index);
    (end > index).then_some(end)
}
