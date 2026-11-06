//! The lexical scan behind a `node <script>` launch identity: which modules a
//! source file names, and whether it can load code the names do not cover.
//!
//! The scan is not a parser. It refuses any construct it cannot read, so a
//! false refusal only keeps a launch once-only.

use std::sync::OnceLock;

use regex::Regex;

/// A module specifier and whether it loads while the script runs
/// (`import()` and `require()`) rather than before (a static `import`).
pub(super) struct Specifier {
    pub(super) name: String,
    pub(super) runtime: bool,
}

fn pattern(cell: &'static OnceLock<Regex>, source: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(source).expect("static pattern"))
}

/// A quoted specifier without escapes; `'` and `"` only, never a template.
const LITERAL: &str = r#"(?:'([^'\\\n]*)'|"([^"\\\n]*)")"#;

/// Constructs that evaluate strings, reach the loader or hide an identifier.
fn forbidden() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(
        &CELL,
        concat!(
            r#"\beval\b|\bFunction\s*\(|\bcreateRequire\b|\bgetBuiltinModule\b|\bWorker\s*\(|\barguments\b|\bimportScripts\b"#,
            r#"|\bprocess\s*\.\s*(?:binding|dlopen|mainModule)\b|\bmodule\s*\.\s*(?:require|register|constructor|paths)\b|\brequire\s*\.\s*(?:extensions|cache)\b"#,
            // Loader internals and process replacement, however they are reached.
            r#"|\b(?:dlopen|execve|_linkedBinding|mainModule|_load|_compile|_extensions|_resolveFilename|_nodeModulePaths|_initPaths|_preloadModules)\b"#,
            r#"|[.'"`]\s*binding\b|['"`]\s*(?:constructor|require|process|module|eval)\s*['"`]"#,
            r#"|\.\s*constructor\b|\[\s*['"`]constructor"#,
            // Keys built from strings: concatenation, templates and calls.
            r#"|\[[^\]\n]*['"`]\s*\+|\[[^\]\n]*\+\s*['"`]|[\w$)\]]\s*\[[^\]\n]*(?:\$\{|['"`][^\]\n]*\()"#,
            r#"|\bfromCharCode\b|\bglobalThis\b|\bglobal\s*[.\[]|\bReflect\b|\bWebAssembly\b|\\u(?:[0-9a-fA-F]{4}|\{)"#,
            // A comment between `from` and its specifier hides the specifier.
            r#"|\bfrom\s*/[/*]"#,
        ),
    )
}

fn loader_global() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"\b(?:process|module)\b")
}

fn process_specifier() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r#"['"`](?:node:)?process['"`]"#)
}

/// The `process` members a script may use: none loads code or replaces the
/// process.
fn process_member() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(
        &CELL,
        r"^process\s*\.\s*(?:argv0?|env|exit|exitCode|cwd|chdir|stdout|stderr|stdin|platform|arch|pid|ppid|versions?|release|hrtime|nextTick|on|once|off|emitWarning|uptime|memoryUsage|cpuUsage|resourceUsage|title|execPath|execArgv|umask)\b",
    )
}

fn module_member() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(
        &CELL,
        r"^module\s*(?:\.\s*exports\b|[!=]==?\s*require\s*\.\s*main\b)",
    )
}

/// The word in prose or a comment: same-line space, then a word.
fn prose() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"^(?:process|module)[ \t]+[A-Za-z]")
}

fn key_or_call() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"^(?:process|module)\s*(?::[^:]|\()")
}

/// Whether every `process` and `module` mention is a listed member, a
/// `require.main === module` check, `typeof`, prose, part of a specifier, an
/// object key or another object's property. Bracket, optional-chaining, comment-separated
/// and aliased access all reach the loader and fail.
/// What follows the global's own name, with the name and any space removed.
fn tail_after_name(rest: &str) -> &str {
    rest.trim_start_matches(|c: char| c.is_alphanumeric() || c == '_' || c == '$')
        .trim_start()
}

/// `process[key](…)`, `process(…)` or `process?.binding(…)`: the mention
/// reaches the real global whatever the text around it reads like, so the
/// context exemptions below must not apply to it.
fn calls_or_indexes(tail: &str) -> bool {
    let mut tail = tail;
    loop {
        if tail.starts_with(['[', '(', '?']) {
            return true;
        }
        // Step over a plain `.member` so `process.dlopen(…)` still counts, while
        // a specifier such as `./lib/process.js` does not.
        let Some(member) = tail.strip_prefix('.') else {
            return false;
        };
        let rest = member.trim_start_matches(|c: char| c.is_alphanumeric() || c == '_' || c == '$');
        if rest.len() == member.len() {
            return false;
        }
        tail = rest.trim_start();
    }
}

fn loader_globals_bound(source: &str) -> bool {
    // Imported `process` keeps its own name, so the member list still applies.
    let process_imports_named = process_specifier().find_iter(source).all(|found| {
        source[..found.start()]
            .split_whitespace()
            .rev()
            .take(3)
            .eq(["from", "process", "import"])
    });
    process_imports_named
        && loader_global().find_iter(source).all(|found| {
            let rest = &source[found.start()..];
            let before = source[..found.start()].trim_end();
            let preceding = source[..found.start()].chars().next_back();
            if process_member().is_match(rest) || module_member().is_match(rest) {
                return true;
            }
            // `typeof process[k](…)` and the other context exemptions below read
            // only what comes before the name; a call or computed member after it
            // runs all the same, so none of them may excuse one.
            let reached = calls_or_indexes(tail_after_name(rest));
            if !reached && (prose().is_match(rest) || before.ends_with("typeof")) {
                return true;
            }
            // An object key or method of that name, never the global itself.
            if key_or_call().is_match(rest) && (before.ends_with('{') || before.ends_with(',')) {
                return true;
            }
            if !reached
                && matches!(
                    before.get(before.len().saturating_sub(3)..),
                    Some("===" | "!==")
                )
            {
                return true;
            }
            // `node:process`, `./module.js`, `my-module` and `@scope/module`.
            if !reached && (before.ends_with("node:") || matches!(preceding, Some('/' | '-'))) {
                return true;
            }
            // `job.process(...)`, but never a function's `this` (the global
            // object in sloppy mode).
            match before.strip_suffix('.') {
                Some(object) => {
                    let object = object.trim_end().trim_end_matches('?');
                    !object.ends_with("this") && !object.ends_with(']') && !object.ends_with(')')
                }
                None => false,
            }
        })
}

/// File-writing APIs: with one in the graph, a module loaded at run time can
/// be rewritten before it loads.
fn writes_files() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(
        &CELL,
        r"\b(?:writeFile|appendFile|copyFile|createWriteStream|truncate|ftruncate|writev|unlink|rmdir)(?:Sync)?\b|\b(?:cpSync|rmSync)\b|\b(?:open|link|rename|symlink|cp|rm)(?:Sync)?\s*\(",
    )
}

pub(super) fn source_writes_files(source: &str) -> bool {
    writes_files().is_match(source)
}

fn from_prefix() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r#"\bfrom\s*['"`]"#)
}

fn from_literal() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, &format!(r"^from\s*{LITERAL}"))
}

fn import_word() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"\bimport\b")
}

fn import_literal() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, &format!(r"^import\s*{LITERAL}"))
}

fn import_call() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(
        &CELL,
        &format!(r"^import\s*\(\s*{LITERAL}\s*(?:,[^()]*)?\)"),
    )
}

/// `import.meta` and a static clause whose specifier the `from` rule reads.
fn import_other() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"^import(?:\s*\.\s*meta\b|\s+[\w$*{]|\s*[{*])")
}

fn require_word() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"\brequire\b")
}

fn require_call() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, &format!(r"^require\s*\(\s*{LITERAL}\s*\)"))
}

/// `require.resolve` and the `require.main === module` entrypoint check.
fn require_inert() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(
        &CELL,
        r"^require\s*\.\s*(?:resolve\b|main\s*(?:[!=]==?|[;)]|$))",
    )
}

fn literal_of(captures: &regex::Captures<'_>) -> String {
    captures
        .get(1)
        .or_else(|| captures.get(2))
        .map_or(String::new(), |found| found.as_str().to_owned())
}

/// Every module specifier `source` names, or `None` when it can load code by
/// a name the text does not spell out.
pub(super) fn module_specifiers(source: &str) -> Option<Vec<Specifier>> {
    if forbidden().is_match(source) || !loader_globals_bound(source) {
        return None;
    }
    let mut found = Vec::new();
    for start in from_prefix().find_iter(source).map(|m| m.start()) {
        let name = literal_of(&from_literal().captures(&source[start..])?);
        found.push(Specifier {
            name,
            runtime: false,
        });
    }
    for start in import_word().find_iter(source).map(|m| m.start()) {
        let rest = &source[start..];
        if let Some(captures) = import_literal().captures(rest) {
            found.push(Specifier {
                name: literal_of(&captures),
                runtime: false,
            });
        } else if let Some(captures) = import_call().captures(rest) {
            found.push(Specifier {
                name: literal_of(&captures),
                runtime: true,
            });
        } else if !import_other().is_match(rest) {
            return None;
        }
    }
    for start in require_word().find_iter(source).map(|m| m.start()) {
        let rest = &source[start..];
        if let Some(captures) = require_call().captures(rest) {
            found.push(Specifier {
                name: literal_of(&captures),
                runtime: true,
            });
        } else if !require_inert().is_match(rest) {
            return None;
        }
    }
    Some(found)
}
