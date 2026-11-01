//! What a script's code says about how it may be read and run, before Guard
//! runs it: whether it answers `--help` itself, which command-line frameworks
//! it builds on, whether it serves MCP, and the local modules it imports.
//!
//! Guard runs `script --help` only for a script whose own code shows that it
//! answers `--help`. A script that never looks for `--help` treats it as an
//! ordinary argument, or ignores it, and does its normal work instead, so its
//! commands are read from its source alone. Like the rest of the source read,
//! nothing here runs the script.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::daemon_lifecycle_text::py_strip;

/// Most local modules one read names. Python reads only the few that exist
/// beside the script.
const MAX_IMPORTS: usize = 32;
const IMPORT_CHARS: usize = 200;

/// How a script answers `--help`, from the strongest evidence its code holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum HelpHandler {
    /// Nothing in the code looks for `--help`: running it with `--help` may do
    /// the script's normal work.
    #[default]
    None,
    /// The script's own code looks for `--help` or `-h`. It answers at the top
    /// level, but a subcommand may run before the check, so only the top-level
    /// `--help` is asked for.
    Script,
    /// A framework that answers `--help` for every command before running any
    /// of them parses the arguments.
    Framework,
}

impl HelpHandler {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Script => "script",
            Self::Framework => "framework",
        }
    }
}

/// The facts one script's code holds.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Facts {
    pub(crate) help: HelpHandler,
    /// The code imports an MCP server library or answers `tools/list`, so
    /// launching it with its own arguments starts a server, not a command.
    pub(crate) mcp_server: bool,
    /// Local modules the script imports, as `./`-relative paths.
    pub(crate) imports: Vec<String>,
    /// Commander, yargs, cac or sade: `.command('name')` names a subcommand.
    pub(super) commander: bool,
    /// argparse: `add_parser("name")` names a subcommand.
    pub(super) argparse: bool,
    /// Click, Typer or Cyclopts: `@cli.command()` names a subcommand.
    pub(super) decorators: bool,
    /// argparse, optparse or Ruby's optparse is imported, so a parser
    /// constructor is the library's and not one the script defines itself.
    parser_library: bool,
    /// A shell `case ... in` has opened, so a `-h)` line is one of its arms.
    shell_case: bool,
}

/// Code that tests an argument for `-h` or `--help`, not code that merely
/// passes one to another program (`du -h`, `spawn('ls', ['-h'])`) or names it
/// in a message: a comparison, a lookup in the argument list, a membership
/// test, a `case`/`when` arm, or a shell test. A shell `case` arm is
/// [`SHELL_HELP_ARM`].
static ASKS_FOR_HELP: LazyLock<Regex> = LazyLock::new(|| {
    let flag = r#"["'](?:-h|--help)["']"#;
    let bare = r#"["']?\*?(?:-h|--help)\*?["']?"#;
    Regex::new(&format!(
        concat!(
            r"(?:===|!==|==|!=|\beq\b|\bne\b)\s*{flag}",
            r"|{flag}\s*(?:===|!==|==|!=|\beq\b|\bne\b)",
            r"|\.(?:includes|has|include\?|indexOf|index|count)\s*\(\s*{flag}",
            r"|{flag}\s+(?:not\s+)?in\b",
            r"|^(?:if|elif|elsif|unless|while)\b.*\bin\s*[(\[{{][^)\]}}]*{flag}",
            r"|^case\s[^:]*{flag}[^:]*:",
            r"|^when\s.*{flag}",
            r"|(?:\[\[?|\btest)\s[^\]]*\s(?:==?|!=)\s*{bare}(?:\s|\]|;|$)",
        ),
        flag = flag,
        bare = bare,
    ))
    .unwrap()
});

/// A shell `case` arm such as `-h)` or `-h|--help)`. Read only after a shell
/// `case ... in` opens, since a wrapped call's last line can look the same.
static SHELL_HELP_ARM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"^\(?\s*(?:[^\s()|]+\s*\|\s*)*["']?(?:-h|--help)["']?"#,
        r"\s*(?:\|\s*[^\s()|]+\s*)*\)",
    ))
    .unwrap()
});

static SHELL_CASE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^case\s.+\sin$").unwrap());

static JS_FRAMEWORK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?:\brequire\s*\(\s*|\bfrom\s*|\bimport\s*\(?\s*)["']"#,
        r#"(commander|yargs|meow|cac|sade|@oclif/core|clipanion|citty|caporal|vorpal)["'/]"#,
    ))
    .unwrap()
});

static PY_FRAMEWORK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?:import|from)\s+",
        r"(click|typer|docopt|fire|cleo|cyclopts|plac|rich_click|asyncclick|argparse|optparse)\b",
    ))
    .unwrap()
});

/// A parser made from a library that answers `--help` for it: Python's
/// argparse and optparse, and Ruby's OptionParser. Only a constructor call
/// counts; an import or a class of the same name makes no parser.
static HELP_PARSER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:ArgumentParser|OptionParser)\s*\(|\bOptionParser\s*\.\s*new\b").unwrap()
});

static DEFINITION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:class|def|function|async\s+def)\s").unwrap());

static NO_HELP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\badd_help(?:_option)?\s*=\s*False\b").unwrap());

static RUBY_OPTPARSE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\brequire\s+["']optparse["']"#).unwrap());

static OTHER_FRAMEWORK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\brequire\s+["'](?:optparse|thor|slop)["']|\bpod2usage\b|\bThor\b"#).unwrap()
});

/// An MCP server library, imported from JavaScript, Python or Ruby, or a
/// handler for the `tools/list` method every MCP server answers.
static MCP_SERVER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?:\brequire\s*\(\s*|\bfrom\s*|\bimport\s*\(?\s*)["'](?:@modelcontextprotocol/|fastmcp["'/]|mcp-framework["'/])"#,
        r"|^(?:import|from)\s+(?:mcp|fastmcp|modelcontextprotocol)\b",
        r#"|\brequire\s+["'](?:mcp|model_context_protocol|fast_mcp|fast-mcp)["'/]"#,
        r#"|["']tools/list["']"#,
    ))
    .unwrap()
});

static JS_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)["'](\./[^"'\s]+)["']"#).unwrap()
});

static RUBY_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\brequire_relative\s*\(?\s*["']([^"'\s]+)["']"#).unwrap());

static PY_FROM_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^from\s+([A-Za-z_][\w.]*)\s+import\b").unwrap());

static PY_IMPORT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^import\s+(.+)$").unwrap());

static PY_MODULE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([A-Za-z_][\w.]*)(?:\s+as\s+\w+)?$").unwrap());

/// The facts the code lines of a script hold. `lines` is the source's readable
/// text per line, `None` for a line of code, as the options read builds it.
pub(super) fn facts(raw: &[&str], lines: &[Option<String>]) -> Facts {
    let mut facts = Facts::default();
    let mut seen: HashSet<String> = HashSet::new();
    for (index, line) in raw.iter().enumerate() {
        if lines.get(index).is_some_and(Option::is_some) {
            continue;
        }
        let line = py_strip(line);
        if line.is_empty() {
            continue;
        }
        read_help(line, &raw[index..], &mut facts);
        facts.mcp_server |= MCP_SERVER.is_match(line);
        for import in imports(line) {
            if facts.imports.len() < MAX_IMPORTS && seen.insert(import.clone()) {
                facts.imports.push(import);
            }
        }
    }
    facts
}

fn read_help(line: &str, rest: &[&str], facts: &mut Facts) {
    facts.shell_case |= SHELL_CASE.is_match(line);
    let mut framework = false;
    if let Some(captures) = JS_FRAMEWORK.captures(line) {
        framework = true;
        facts.commander |= matches!(&captures[1], "commander" | "yargs" | "cac" | "sade");
    }
    if let Some(captures) = PY_FRAMEWORK.captures(line) {
        let name = &captures[1];
        facts.argparse |= name == "argparse";
        facts.parser_library |= matches!(name, "argparse" | "optparse");
        facts.decorators |= matches!(
            name,
            "click" | "typer" | "cyclopts" | "rich_click" | "asyncclick"
        );
        // Importing argparse or optparse answers nothing until a parser is made.
        framework |= !matches!(name, "argparse" | "optparse");
    }
    facts.parser_library |= RUBY_OPTPARSE.is_match(line);
    if facts.parser_library && HELP_PARSER.is_match(line) && !DEFINITION.is_match(line) {
        let call: String = rest
            .iter()
            .take(6)
            .map(|line| py_strip(line))
            .collect::<Vec<_>>()
            .join(" ");
        framework |= !NO_HELP.is_match(&call);
    }
    framework |= OTHER_FRAMEWORK.is_match(line);
    let handler = if framework {
        HelpHandler::Framework
    } else if ASKS_FOR_HELP.is_match(line) || (facts.shell_case && SHELL_HELP_ARM.is_match(line)) {
        HelpHandler::Script
    } else {
        HelpHandler::None
    };
    facts.help = facts.help.max(handler);
}

/// The local modules one line imports, as `./`-relative paths. A module that
/// leaves the script's folder (`../x`) or names a package is not local.
fn imports(line: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for captures in JS_IMPORT.captures_iter(line) {
        found.push(captures[1].to_owned());
    }
    for captures in RUBY_IMPORT.captures_iter(line) {
        let name = captures[1].trim_start_matches("./");
        let file = if name
            .rsplit('/')
            .next()
            .is_some_and(|last| last.contains('.'))
        {
            format!("./{name}")
        } else {
            format!("./{name}.rb")
        };
        found.push(file);
    }
    let python_module = |module: &str| format!("./{}.py", module.replace('.', "/"));
    if let Some(captures) = PY_FROM_IMPORT.captures(line) {
        found.push(python_module(&captures[1]));
    } else if let Some(captures) = PY_IMPORT.captures(line) {
        for part in captures[1].split(',') {
            if let Some(module) = PY_MODULE.captures(py_strip(part)) {
                found.push(python_module(&module[1]));
            }
        }
    }
    found.retain(|path| is_local_path(path));
    found
}

fn is_local_path(path: &str) -> bool {
    path.starts_with("./")
        && path.chars().count() <= IMPORT_CHARS
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && path.split('/').all(|part| part != "..")
}
