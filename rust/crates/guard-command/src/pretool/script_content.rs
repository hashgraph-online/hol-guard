//! What a script launched by an interpreter does, read from its source.
//!
//! The sandbox, not this scan, bounds what a contained script can do. The
//! scan predicts fit: a script that needs the network keeps its review instead
//! of failing inside a sandbox that withholds the network, and a script that
//! pairs a credential store with the network is blocked. It can only raise a
//! decision. An absent, unreadable, oversized or unrecognized script changes
//! nothing; a local module that cannot be read is left out of its graph.

use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

mod launch;
mod loopback;

use super::{read_paths, PathContext};
use crate::CanonicalCommandV1;
use guard_contracts::PreToolResultV1;
use launch::{Fed, Program, Stdin};
#[cfg_attr(not(unix), allow(unused_imports))]
pub(crate) use loopback::launch_loopback_ports;

const MAX_FILE_BYTES: usize = 256 * 1024;
const MAX_TOTAL_BYTES: usize = 1024 * 1024;
const MAX_FILES: usize = 32;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;

const NODE_EXTENSIONS: &[&str] = &["js", "mjs", "cjs", "jsx", "ts", "mts", "cts", "tsx"];

/// Node and Python options that take their value as the next argument.
const NODE_VALUE_OPTIONS: &[&str] = &[
    "-r",
    "--require",
    "--import",
    "--loader",
    "--experimental-loader",
    "-C",
    "--conditions",
    "--env-file",
    "--input-type",
    "--title",
    "--inspect-port",
];
const PYTHON_VALUE_OPTIONS: &[&str] = &["-W", "-X", "--check-hash-based-pycs"];

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::pretool) enum Language {
    Python,
    Node,
}

/// Network clients a script imports or calls.
static PYTHON_NETWORK: LazyLock<Regex> = LazyLock::new(|| {
    let clients = "socket|ssl|http|urllib|urllib3|requests|httpx|aiohttp|websocket|websockets|smtplib|ftplib|poplib|imaplib|telnetlib|xmlrpc|paramiko|asyncssh|pycurl|httplib2|boto3|botocore|googleapiclient|google\\.cloud|google\\.analytics|google\\.auth\\.transport|openai|anthropic|grpc|kubernetes|psycopg|psycopg2|pymysql|MySQLdb|redis|pymongo|slack_sdk|github|gql|stripe";
    // `from client import x`, or `client` anywhere in an `import a, b` list.
    Regex::new(&format!(
        r"(?m)^[ \t]*(?:from[ \t]+(?:{clients})\b|import[ \t]+(?:[\w.]+(?:[ \t]+as[ \t]+\w+)?[ \t]*,[ \t]*)*(?:{clients})\b)"
    ))
    .unwrap()
});
/// Stream and server calls that open a socket without importing a client.
static PYTHON_ASYNC_NETWORK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:open_connection|open_unix_connection|start_server|start_unix_server|create_connection|create_datagram_endpoint|create_server|create_unix_connection|create_unix_server)\b").unwrap()
});

fn python_network(code: &str) -> bool {
    PYTHON_NETWORK.is_match(code) || PYTHON_ASYNC_NETWORK.is_match(code)
}
static NODE_NETWORK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)["'](?:node:)?(?:https?|http2|net|tls|dgram|dns|undici|axios|node-fetch|got|ky|ws|superagent|request|socket\.io-client|ssh2|nodemailer|ftp|basic-ftp|pg|mysql2?|mongodb|ioredis|redis|openai|googleapis|google-auth-library|aws-sdk|octokit|stripe|@google-cloud/[^"']*|@google-analytics/[^"']*|@aws-sdk/[^"']*|@anthropic-ai/[^"']*|@octokit/[^"']*|@slack/[^"']*)(?:["']|/[^"']*["'])|\bfetch\s*\(|\bXMLHttpRequest\b|\bnew\s+WebSocket\b|\bEventSource\b|\bsendBeacon\b|\bBun\s*\.\s*connect\b|\bDeno\s*\.\s*connect\b"#,
    )
    .unwrap()
});

/// Credential stores that ordinary scripts reach through a client library,
/// never by naming the file: private keys, cloud credential files, browser
/// password and cookie databases, keychains and wallets. Configuration files
/// that legitimately carry a token (`.netrc`, `.npmrc`, kube config) are not
/// listed, so a script that authenticates with one is not blocked.
static CREDENTIAL_STORE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\bid_(?:rsa|dsa|ecdsa|ed25519)(?:[^.\w]|$)|\.aws/credentials|\.aws["']\s*[,/]\s*["']credentials|\.gnupg\b|private-keys-v1\.d|(?:default|profile [0-9]+)/(?:cookies|login data|web data)\b|cookies\.sqlite|logins\.json|key4\.db|keychains/|\.keychain(?:-db)?\b|wallet\.dat|\.ethereum/keystore|solana/id\.json|/etc/shadow\b"#,
    )
    .unwrap()
});

static NODE_RELATIVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)["'](\.{1,2}/[^"'\n]+)["']"#)
        .unwrap()
});
static PYTHON_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*(?:from[ \t]+(\.*)([\w.]*)[ \t]+import[ \t]+([\w, \t()*]+)|import[ \t]+([\w., \t]+))")
        .unwrap()
});

#[derive(Default)]
pub(super) struct Findings {
    /// Imports or calls a network client.
    pub(super) network: bool,
    /// Names a credential store by path.
    pub(super) credential_store: bool,
    /// For inline Node source or a Node script in the working directory whose
    /// only network use is loopback HTTP, the literal ports the workspace
    /// sandbox grants it.
    pub(super) loopback: Option<BTreeSet<u16>>,
    /// The program's source and the local modules read with it.
    pub(super) sources: Vec<String>,
}

/// What each script this command launches does, one entry per program whose
/// source could be read: a script file, inline source (`-c`, `-e`), or a
/// program fed on standard input from a heredoc, a local file redirect or a
/// `cat <file> |` pipe. A program fed to an interpreter inside a container
/// or pod (`kubectl exec … -- node -`) is read too, without its imports.
pub(super) fn assess(model: &CanonicalCommandV1, context: PathContext<'_>) -> Vec<Findings> {
    assess_programs(model, context, true)
}

/// The command's text and segments, in a verified path context. The command
/// model leaves a heredoc or an input redirect uncertain; the shell structure
/// parse reads both, so a program fed that way is read too.
fn structure(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> Option<(String, Vec<crate::CommandSegmentV1>)> {
    if !read_paths::verified_path_context(context.home_dir, context.cwd) {
        return None;
    }
    if model.confidence == "exact" {
        return Some((model.normalized_text.clone(), model.segments.clone()));
    }
    let structured = crate::critical_floor_context::parse_floor_command(
        &model.normalized_text,
        context.cwd.map(Path::new),
        context.home_dir.map(Path::new),
    );
    (structured.confidence == "exact" && structured.wrapper_chain.is_empty())
        .then_some((structured.normalized_text, structured.segments))
}

/// The sources of the program, when the command is one interpreter launch,
/// with no wrapper or environment prefix, whose inline source or program fed
/// on standard input this scan read. The interpreter then runs only that
/// program, as it would run a script file.
pub(crate) fn sole_program_sources(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> Option<Vec<String>> {
    let sole = model.wrapper_chain.is_empty()
        && !model.path_overridden
        && structure(model, context).is_some_and(|(_, segments)| {
            matches!(segments.as_slice(), [segment]
                if segment.wrapper_chain.is_empty()
                    && segment.environment_names.is_empty()
                    && !segment.path_overridden)
        });
    if !sole {
        return None;
    }
    match <[Findings; 1]>::try_from(assess_programs(model, context, false)) {
        Ok([only]) => Some(only.sources),
        Err(_) => None,
    }
}

/// The text of every file the command sources, when each one resolves to a
/// readable local file.
///
/// Sourcing runs a file's words in the shell that reads it, so the file names
/// the programs the command can run, exactly as a script file names the ones
/// an interpreter runs. `None` means the command sources something this scan
/// did not read, so it keeps the owners it had: a file that was never read
/// must not buy a bounded owner set it has not earned. A command whose words
/// name sourcing but whose segments hold no `source` builtin reads the same
/// way, because the word belongs to something this scan has not modelled.
pub(crate) fn sourced_program_sources(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> Option<Vec<String>> {
    let (_, segments) = structure(model, context)?;
    let mut sources = Vec::new();
    let mut sourcing = false;
    for (index, segment) in segments.iter().enumerate() {
        if !sources_a_file(segment) {
            continue;
        }
        sourcing = true;
        // The shape of the segment decides whether the file is knowable at
        // all: a bare name the shell searches on `PATH`, a target an
        // expansion or a glob builds, and a wrapper or environment prefix
        // each leave the file unknown, and an unknown file is unread.
        let target = sourced_file(segment)?;
        // An earlier directory change moves a relative path out of reach.
        let moved = segments[..index].iter().any(|prior| {
            prior.executable.as_deref().is_some_and(|value| {
                matches!(super::executable_basename(value), "cd" | "pushd" | "popd")
            })
        });
        if moved && !Path::new(target).is_absolute() {
            return None;
        }
        sources.push(read_text(&resolve(target, context)?)?);
    }
    sourcing.then_some(sources)
}

/// Whether the segment runs the shell's `source` builtin, whatever file it
/// names. A path-qualified `./source` is an ordinary external program whose
/// behaviour this scan does not know, not the builtin.
fn sources_a_file(segment: &crate::CommandSegmentV1) -> bool {
    segment
        .executable
        .as_deref()
        .is_some_and(|value| value == "." || value == "source")
}

/// The file a `source FILE` or `. FILE` segment runs, when the shell reads it
/// from a path it was given rather than searching `PATH`.
fn sourced_file(segment: &crate::CommandSegmentV1) -> Option<&str> {
    if !sources_a_file(segment) {
        return None;
    }
    if !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
        || segment.path_overridden
    {
        return None;
    }
    let target = segment.arguments.first()?;
    // A name without a separator is searched for on `PATH`, so the file the
    // shell runs is not the one this relative path names. An expansion or a
    // glob leaves the target unknown either way.
    (target.contains('/')
        && !target.starts_with('-')
        && !target.contains(['$', '*', '?', '[', '`']))
    .then_some(target.as_str())
}

/// `assess`, leaving out script files when `scripts` is false.
fn assess_programs(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
    scripts: bool,
) -> Vec<Findings> {
    let mut findings = Vec::new();
    let Some((text, segments)) = structure(model, context) else {
        return findings;
    };
    let segments = segments.as_slice();
    let stdin = Stdin::new(&text);
    for (index, segment) in segments.iter().enumerate() {
        let Some((language, program, remote)) = launch::launched_program(segment) else {
            continue;
        };
        // An earlier directory change moves a relative path out of reach.
        let moved = segments[..index].iter().any(|prior| {
            prior.executable.as_deref().is_some_and(|value| {
                matches!(super::executable_basename(value), "cd" | "pushd" | "popd")
            })
        });
        let reachable = |path: &str| !moved || Path::new(path).is_absolute();
        // Imports resolve against the working directory for inline source,
        // and inside the container for a remote program, so they are not read.
        let imports_from = || {
            (!moved && !remote)
                .then(|| context.cwd.and_then(|cwd| std::fs::canonicalize(cwd).ok()))
                .flatten()
        };
        let inline = matches!(program, Program::Inline(_)) && !remote;
        let script_file = matches!(program, Program::Script(_));
        let entry = match program {
            Program::Script(script) if scripts && !remote && reachable(script) => {
                let Some(path) = resolve(script, context) else {
                    continue;
                };
                Entry::File(path)
            }
            Program::Script(_) => continue,
            Program::Inline(source) => Entry::Text {
                source: source.to_owned(),
                directory: imports_from(),
            },
            Program::Stdin => match stdin.source(segments, index) {
                Some(Fed::Text(source)) => Entry::Text {
                    source,
                    directory: imports_from(),
                },
                Some(Fed::File(file)) if reachable(&file) => {
                    let Some(path) = resolve(&file, context) else {
                        continue;
                    };
                    if remote {
                        let Some(source) = read_text(&path) else {
                            continue;
                        };
                        Entry::Text {
                            source,
                            directory: None,
                        }
                    } else {
                        Entry::File(path)
                    }
                }
                _ => continue,
            },
        };
        // A script file the sandbox runs from the workspace may earn the
        // loopback grant too; one fed on standard input does not.
        let workspace_script = match &entry {
            Entry::File(path) => {
                script_file
                    && loopback::in_working_directory(path, context)
                    && !loopback::may_rewrite(segments, index)
            }
            Entry::Text { .. } => false,
        };
        let Some((sources, complete)) = read_graph(language, entry) else {
            continue;
        };
        let mut found = Findings::default();
        for source in &sources {
            let code = code_lines(language, source);
            found.network |= match language {
                Language::Python => python_network(&code),
                Language::Node => NODE_NETWORK.is_match(&code),
            };
            found.credential_store |= CREDENTIAL_STORE.is_match(&code);
        }
        if (inline || workspace_script) && complete && language == Language::Node {
            found.loopback = loopback::program_ports(&sources, context.home_dir);
        }
        found.sources = sources;
        findings.push(found);
    }
    findings
}

/// Whether one launched program both reads a credential store and uses the
/// network. Two programs that each do one of them are not paired.
pub(super) fn exfiltrates(model: &CanonicalCommandV1, context: PathContext<'_>) -> bool {
    assess(model, context)
        .iter()
        .any(|found| found.network && found.credential_store)
}

/// Whether the script at `path` stands alone and does neither of the things
/// the sandbox cannot serve: it imports no local module (a sibling outside the
/// workspace would be unreadable there), uses no network client, and names no
/// credential store. An unreadable, oversized or non-UTF-8 script is not clean.
pub(in crate::pretool) fn standalone_clean(language: Language, path: &Path) -> bool {
    let Some((sources, _)) = read_graph(language, Entry::File(path.to_path_buf())) else {
        return false;
    };
    let [source] = sources.as_slice() else {
        return false;
    };
    let code = code_lines(language, source);
    let network = match language {
        Language::Python => python_network(&code),
        Language::Node => NODE_NETWORK.is_match(&code),
    };
    !network && !CREDENTIAL_STORE.is_match(&code)
}

/// Whether a program this command launches uses the network.
pub(super) fn uses_network(model: &CanonicalCommandV1, context: PathContext<'_>) -> bool {
    assess(model, context).iter().any(|found| found.network)
}

/// Whether a program the POSIX shell text `command` launches uses the
/// network, for a caller that judges a projection of the text.
pub(super) fn text_uses_network(command: &str, context: PathContext<'_>) -> bool {
    crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .is_ok_and(|model| uses_network(&model, context))
}

/// Whether inline source or a program fed on standard input uses the
/// network. A test script that imports a client usually stubs it, so script
/// files are left to their own route.
pub(super) fn inline_uses_network(
    model: &CanonicalCommandV1,
    command_text: Option<&str>,
    context: PathContext<'_>,
) -> bool {
    let inline = |model: &CanonicalCommandV1| {
        assess_programs(model, context, false)
            .iter()
            .any(|found| found.network)
    };
    inline(model) || sent_model(model, command_text).is_some_and(|sent| inline(&sent))
}

/// The model of the text the agent sent, when `model` is a projection of it,
/// such as one with an input redirect removed, which loses the program that
/// redirect feeds.
fn sent_model(
    model: &CanonicalCommandV1,
    command_text: Option<&str>,
) -> Option<CanonicalCommandV1> {
    let text = command_text?.trim();
    if text == model.normalized_text {
        return None;
    }
    crate::parse_command(&crate::CommandModelRequestV1 {
        command: text.to_owned(),
        dialect: model.dialect.clone(),
        transport: model.transport.clone(),
        extraction_provenance: model.extraction_provenance.clone(),
    })
    .ok()
}

/// Keeps the review of a command whose program uses the network: the sandbox
/// withholds it, so the program would only fail there. Node source, inline or
/// a script in the working directory, that only serves and fetches on literal
/// loopback ports is the exception: the sandbox grants it exactly those ports.
pub(super) fn keeps_network_review(
    result: &mut PreToolResultV1,
    model: &CanonicalCommandV1,
    command_text: Option<&str>,
    context: PathContext<'_>,
) -> bool {
    let withheld = |model: &CanonicalCommandV1| {
        assess(model, context)
            .iter()
            .any(|found| found.network && found.loopback.is_none())
    };
    if !withheld(model) && !sent_model(model, command_text).is_some_and(|sent| withheld(&sent)) {
        return false;
    }
    result.reason = concat!(
        "HOL Guard needs your review because this script uses the network, ",
        "which Guard's sandbox withholds."
    )
    .into();
    true
}

pub(in crate::pretool) fn launched_script(
    segment: &crate::CommandSegmentV1,
) -> Option<(Language, &str)> {
    let name = super::executable_basename(segment.executable.as_deref()?);
    let name = name.strip_suffix(".exe").unwrap_or(name);
    let arguments = segment.arguments.as_slice();
    let python = name.strip_prefix("python").is_some_and(|version| {
        version
            .split('.')
            .all(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
    });
    if python {
        return first_operand(arguments, PYTHON_VALUE_OPTIONS, &["-c", "-m", "-"])
            .map(|script| (Language::Python, script));
    }
    let arguments = match (name, arguments) {
        ("bun" | "deno", [run, rest @ ..]) if run == "run" => rest,
        ("node" | "nodejs" | "bun" | "tsx" | "deno", rest) => rest,
        _ => return None,
    };
    let script = first_operand(
        arguments,
        NODE_VALUE_OPTIONS,
        &["-e", "--eval", "-p", "--print", "-"],
    )?;
    NODE_EXTENSIONS
        .contains(&extension(Path::new(script)).as_str())
        .then_some((Language::Node, script))
}

/// The first argument that is not an option, unless an option that runs
/// other code (inline source, a module, standard input) comes first.
fn first_operand<'a>(
    arguments: &'a [String],
    value_options: &[&str],
    stops: &[&str],
) -> Option<&'a str> {
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        if stops.contains(&argument.as_str()) {
            return None;
        }
        if argument == "--" {
            return rest.next().map(String::as_str);
        }
        if value_options.contains(&argument.as_str()) {
            rest.next()?;
            continue;
        }
        if !argument.starts_with('-') {
            return Some(argument);
        }
    }
    None
}

fn resolve(script: &str, context: PathContext<'_>) -> Option<PathBuf> {
    if !read_paths::bounded_file_read_target(script, context.home_dir, context.cwd) {
        return None;
    }
    let path = guard_secure_fs::resolve_candidate(
        script,
        context.cwd.map(Path::new),
        Path::new(context.home_dir.unwrap_or_default()),
    )
    .ok()?;
    std::fs::canonicalize(path)
        .ok()
        .filter(|path| path.is_file())
}

enum Entry {
    File(PathBuf),
    /// Source with no file of its own; local imports resolve from
    /// `directory`, or are not read without one.
    Text {
        source: String,
        directory: Option<PathBuf>,
    },
}

/// The program's source and that of the local modules it imports, breadth
/// first, within the file and byte bounds, or `None` when the program itself
/// cannot be read. A module that cannot be read, or would pass the byte
/// bound, is left out so what the rest of the graph does still counts.
/// Packages and the standard library are not read. The flag says whether
/// every local import found was read.
fn read_graph(language: Language, entry: Entry) -> Option<(Vec<String>, bool)> {
    let (root, mut seen, first) = match entry {
        Entry::File(path) => {
            let root = path.parent()?.to_path_buf();
            let source = read_text(&path)?;
            (
                Some(root.clone()),
                BTreeSet::from([path]),
                (source, Some(root)),
            )
        }
        Entry::Text { source, directory } => {
            if source.len() > MAX_FILE_BYTES {
                return None;
            }
            (directory.clone(), BTreeSet::new(), (source, directory))
        }
    };
    let mut queue = VecDeque::new();
    let mut sources = Vec::new();
    let mut total = 0usize;
    let mut complete = true;
    let mut next = Some(first);
    while let Some((source, directory)) = next.take() {
        total += source.len();
        if let (Some(root), Some(directory)) = (root.as_deref(), directory.as_deref()) {
            let (imports, imports_complete) = match language {
                Language::Node => node_imports(&source, directory),
                // Statements after a `;` import too.
                Language::Python => (
                    python_imports(&code_lines(language, &source), root, directory),
                    true,
                ),
            };
            // A relative import that does not resolve is code this scan never
            // read. Leaving `complete` set would still grant that program the
            // loopback ports named in the file it did read.
            if !imports_complete {
                complete = false;
            }
            for import in imports {
                if seen.len() >= MAX_FILES {
                    complete = false;
                    break;
                }
                if seen.insert(import.clone()) {
                    queue.push_back(import);
                }
            }
        } else if language == Language::Node && NODE_RELATIVE.is_match(&source) {
            // `cd sub && node -e "require('./x.js')"` has no directory left to
            // resolve that import against. The imported file is unread.
            complete = false;
        }
        sources.push(source);
        while let Some(path) = queue.pop_front() {
            let source = read_text(&path).filter(|source| total + source.len() <= MAX_TOTAL_BYTES);
            if let (Some(source), Some(directory)) = (source, path.parent()) {
                next = Some((source, Some(directory.to_path_buf())));
                break;
            }
            complete = false;
        }
    }
    Some((sources, complete))
}

fn read_text(path: &Path) -> Option<String> {
    guard_secure_fs::read_bounded(path, MAX_FILE_BYTES)
        .ok()
        .and_then(|read| String::from_utf8(read.bytes).ok())
}

/// Local files a Node source imports, and whether every relative specifier
/// resolved to a file. One that does not is left unread, so the graph is not
/// complete.
fn node_imports(source: &str, directory: &Path) -> (Vec<PathBuf>, bool) {
    let mut complete = true;
    let mut imports = Vec::new();
    for capture in NODE_RELATIVE.captures_iter(source) {
        match node_module(&directory.join(&capture[1]))
            .and_then(|path| std::fs::canonicalize(path).ok())
        {
            Some(path) => imports.push(path),
            None => complete = false,
        }
    }
    (imports, complete)
}

/// The file Node loads for a relative specifier: the path itself, the path
/// with an extension, or for a directory its `package.json` `main` and then
/// its `index` file.
fn node_module(base: &Path) -> Option<PathBuf> {
    let mut candidates = with_extension(base);
    if base.is_dir() {
        if let Some(main) = package_main(base) {
            let main = base.join(main);
            candidates.extend(with_extension(&main));
            candidates.extend(index_files(&main));
        }
        candidates.extend(index_files(base));
    }
    candidates.into_iter().find(|candidate| {
        candidate.is_file() && NODE_EXTENSIONS.contains(&extension(candidate).as_str())
    })
}

fn with_extension(path: &Path) -> Vec<PathBuf> {
    std::iter::once(path.to_path_buf())
        .chain(
            NODE_EXTENSIONS
                .iter()
                .map(|extension| PathBuf::from(format!("{}.{extension}", path.display()))),
        )
        .collect()
}

fn index_files(directory: &Path) -> Vec<PathBuf> {
    NODE_EXTENSIONS
        .iter()
        .map(|extension| directory.join(format!("index.{extension}")))
        .collect()
}

/// A local package directory's `main` entry.
fn package_main(directory: &Path) -> Option<String> {
    let read =
        guard_secure_fs::read_bounded(&directory.join("package.json"), MAX_MANIFEST_BYTES).ok()?;
    let manifest: serde_json::Value = serde_json::from_slice(&read.bytes).ok()?;
    manifest.get("main")?.as_str().map(str::to_owned)
}

/// The local modules a Python source imports. An absolute name resolves from
/// the launched script's directory (`sys.path[0]`), a relative one from the
/// importing module's package, one parent up for each dot past the first.
fn python_imports(source: &str, root: &Path, directory: &Path) -> Vec<PathBuf> {
    let listed = |names: &str| -> Vec<String> {
        names
            .split(',')
            .filter_map(|name| {
                name.trim_matches(['(', ')', ' ', '\t'])
                    .split_whitespace()
                    .next()
            })
            .map(str::to_owned)
            .collect()
    };
    let mut modules: Vec<(usize, String)> = Vec::new();
    for capture in PYTHON_IMPORT.captures_iter(source) {
        if let Some(names) = capture.get(4) {
            modules.extend(listed(names.as_str()).into_iter().map(|name| (0, name)));
            continue;
        }
        let dots = capture.get(1).map_or(0, |value| value.as_str().len());
        let module = capture.get(2).map_or("", |value| value.as_str());
        let names = listed(capture.get(3).map_or("", |value| value.as_str()));
        if module.is_empty() {
            // `from . import a, b` imports sibling modules by name.
            modules.extend(names.into_iter().map(|name| (dots, name)));
        } else {
            // `from pkg import a` can import the submodule `pkg.a`, which an
            // empty `pkg/__init__.py` does not name.
            modules.extend(
                names
                    .into_iter()
                    .map(|name| (dots, format!("{module}.{name}"))),
            );
            modules.push((dots, module.to_owned()));
        }
    }
    modules
        .into_iter()
        .filter(|(_, module)| {
            !module.is_empty()
                && module.split('.').all(|part| {
                    !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                })
        })
        .filter_map(|(dots, module)| {
            let base = match dots {
                0 => root,
                _ => directory.ancestors().nth(dots - 1)?,
            };
            let relative = module.replace('.', "/");
            [
                base.join(format!("{relative}.py")),
                base.join(&relative).join("__init__.py"),
            ]
            .into_iter()
            .find(|candidate| candidate.is_file())
        })
        .filter_map(|path| std::fs::canonicalize(path).ok())
        .collect()
}

/// The source without its comments, so a path named in a note is not read
/// as one the script opens. Only whole-line comments, block comments that
/// open a line and comments after whitespace are dropped; a comment marker
/// inside a string can drop the rest of that line, which only lowers what
/// the scan finds.
fn code_lines(language: Language, source: &str) -> String {
    let marker = match language {
        Language::Python => "#",
        Language::Node => "//",
    };
    let mut code = String::with_capacity(source.len());
    let mut in_block = false;
    for line in source.lines() {
        let trimmed = line.trim_start();
        if language == Language::Node && (in_block || trimmed.starts_with("/*")) {
            in_block = !trimmed.contains("*/");
            if in_block || trimmed.trim_end().ends_with("*/") {
                continue;
            }
        }
        if trimmed.starts_with(marker) {
            continue;
        }
        let end = line
            .match_indices(marker)
            .find(|(at, _)| line[..*at].ends_with([' ', '\t']))
            .map_or(line.len(), |(at, _)| at);
        // `python -c 'import os; import socket'` puts statements on one line.
        match language {
            Language::Python => code.push_str(&split_statements(&line[..end])),
            Language::Node => code.push_str(&line[..end]),
        }
        code.push('\n');
    }
    code
}

/// A Python line with each `;` outside a string literal starting a new line.
/// A line whose strings this cannot follow, with a triple quote, an f-string
/// field or a string left open, splits at every `;`, which only finds more.
fn split_statements(line: &str) -> String {
    let everywhere = || line.replace(';', "\n");
    if line.contains("\"\"\"") || line.contains("'''") || line.contains('{') {
        return everywhere();
    }
    let mut split = String::with_capacity(line.len());
    let (mut quote, mut escaped) = (None, false);
    for character in line.chars() {
        match quote {
            Some(_) if escaped => escaped = false,
            Some(_) if character == '\\' => escaped = true,
            Some(open) if character == open => quote = None,
            Some(_) => {}
            None if matches!(character, '\'' | '"') => quote = Some(character),
            None if character == ';' => {
                split.push('\n');
                continue;
            }
            None => {}
        }
        split.push(character);
    }
    if quote.is_some() {
        return everywhere();
    }
    split
}

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}
