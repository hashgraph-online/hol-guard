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

use super::{read_paths, PathContext};
use crate::CanonicalCommandV1;
use guard_contracts::PreToolResultV1;

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
enum Language {
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
}

/// What each script this command launches does, one entry per script whose
/// source could be read.
pub(super) fn assess(model: &CanonicalCommandV1, context: PathContext<'_>) -> Vec<Findings> {
    let mut findings = Vec::new();
    if model.confidence != "exact"
        || !read_paths::verified_path_context(context.home_dir, context.cwd)
    {
        return findings;
    }
    for (index, segment) in model.segments.iter().enumerate() {
        let Some((language, script)) = launched_script(segment) else {
            continue;
        };
        // An earlier directory change moves a relative script out of reach.
        let moved = model.segments[..index].iter().any(|prior| {
            prior.executable.as_deref().is_some_and(|value| {
                matches!(super::executable_basename(value), "cd" | "pushd" | "popd")
            })
        });
        if moved && !Path::new(script).is_absolute() {
            continue;
        }
        let Some(path) = resolve(script, context) else {
            continue;
        };
        let Some(sources) = read_graph(language, path) else {
            continue;
        };
        let mut found = Findings::default();
        for source in sources {
            let code = code_lines(language, &source);
            found.network |= match language {
                Language::Python => PYTHON_NETWORK.is_match(&code),
                Language::Node => NODE_NETWORK.is_match(&code),
            };
            found.credential_store |= CREDENTIAL_STORE.is_match(&code);
        }
        findings.push(found);
    }
    findings
}

/// Whether one launched script both reads a credential store and uses the
/// network. Two scripts that each do one of them are not paired.
pub(super) fn exfiltrates(model: &CanonicalCommandV1, context: PathContext<'_>) -> bool {
    assess(model, context)
        .iter()
        .any(|found| found.network && found.credential_store)
}

/// Keeps the review of a command whose script uses the network: the sandbox
/// withholds it, so the script would only fail there.
pub(super) fn keeps_network_review(
    result: &mut PreToolResultV1,
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> bool {
    if !assess(model, context).iter().any(|found| found.network) {
        return false;
    }
    result.reason = concat!(
        "HOL Guard needs your review because this script uses the network, ",
        "which Guard's sandbox withholds."
    )
    .into();
    true
}

fn launched_script(segment: &crate::CommandSegmentV1) -> Option<(Language, &str)> {
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

/// The script's source and that of the local modules it imports, breadth
/// first, within the file and byte bounds, or `None` when the script itself
/// cannot be read. A module that cannot be read, or would pass the byte
/// bound, is left out so what the rest of the graph does still counts.
/// Packages and the standard library are not read.
fn read_graph(language: Language, entry: PathBuf) -> Option<Vec<String>> {
    let root = entry.parent()?.to_path_buf();
    let mut seen = BTreeSet::from([entry.clone()]);
    let mut queue = VecDeque::from([entry.clone()]);
    let mut sources = Vec::new();
    let mut total = 0usize;
    while let Some(path) = queue.pop_front() {
        let source = guard_secure_fs::read_bounded(&path, MAX_FILE_BYTES)
            .ok()
            .filter(|read| total + read.bytes.len() <= MAX_TOTAL_BYTES)
            .and_then(|read| String::from_utf8(read.bytes).ok());
        let (Some(source), Some(directory)) = (source, path.parent()) else {
            if path == entry {
                return None;
            }
            continue;
        };
        total += source.len();
        let directory = directory.to_path_buf();
        let imports = match language {
            Language::Node => node_imports(&source, &directory),
            Language::Python => python_imports(&source, &root, &directory),
        };
        for import in imports {
            if seen.len() >= MAX_FILES {
                break;
            }
            if seen.insert(import.clone()) {
                queue.push_back(import);
            }
        }
        sources.push(source);
    }
    Some(sources)
}

fn node_imports(source: &str, directory: &Path) -> Vec<PathBuf> {
    NODE_RELATIVE
        .captures_iter(source)
        .filter_map(|capture| node_module(&directory.join(&capture[1])))
        .filter_map(|path| std::fs::canonicalize(path).ok())
        .collect()
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
        code.push_str(&line[..end]);
        code.push('\n');
    }
    code
}

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}
