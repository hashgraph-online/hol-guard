//! Finds the project files a typed prompt is about, before CIGAR ranks them.
//!
//! This runs on every opted-in prompt, so it is bounded in files, bytes and
//! time, never follows a link, and never starts a program in the project
//! (a repository's own config can run code, so no `git` either). It only
//! proposes paths: each one is read again through the CIGAR source screen,
//! which refuses secrets, keys and credential files on its own.
use crate::context_assistance_prompt_ignore::{extend, ignored, root_chain};
use guard_secure_fs::{credential_directory_path, credential_named_path};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

/// Files offered to CIGAR for one prompt.
pub(crate) const MAX_CANDIDATES: usize = 24;
const MAX_VISITED: usize = 6_000;
const MAX_SCANNED_BYTES: u64 = 12 * 1024 * 1024;
/// Big enough for a project's main module, such as a CLI library's core file;
/// the scanned-bytes cap still bounds the walk.
const MAX_FILE_BYTES: u64 = 262_144;
const MAX_DEPTH: usize = 10;
const MAX_TERMS: usize = 12;
const MAX_PHRASES: usize = 4;
/// Files the prompt names, such as `CHANGES.rst`, each standing for at most
/// `MAX_NAMED_MATCHES` files with that name.
const MAX_NAMED: usize = 4;
const MAX_NAMED_MATCHES: usize = 2;
/// How far past an opening quote to look for its closing one, so a prompt
/// full of unmatched quotes is still scanned in one pass.
const MAX_PHRASE_SPAN: usize = 120;
const WALK_BUDGET: Duration = Duration::from_millis(350);

const SKIPPED_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "dist",
    "build",
    "out",
    "vendor",
    "coverage",
    "__pycache__",
    "venv",
    "env",
    "site-packages",
    "bower_components",
    "Pods",
    "DerivedData",
];
const TEST_DIRS: &[&str] = &["test", "tests", "__tests__", "spec", "e2e"];
const TEST_WORDS: &[&str] = &["test", "tests", "spec", "e2e", "testing"];
const TEXT_EXTENSIONS: &[&str] = &[
    "adoc", "astro", "c", "cc", "cjs", "clj", "cpp", "cs", "css", "dart", "erl", "ex", "exs", "go",
    "gradle", "graphql", "h", "hpp", "html", "java", "js", "json", "jsx", "kt", "kts", "less",
    "lua", "m", "md", "mdx", "mjs", "mm", "nix", "php", "proto", "py", "r", "rb", "rs", "rst",
    "sass", "scala", "scss", "sh", "sql", "svelte", "swift", "toml", "ts", "tsx", "txt", "vue",
    "xml", "yaml", "yml", "zig",
];
const SKIPPED_FILES: &[&str] = &[
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Cargo.lock",
    "poetry.lock",
    "Gemfile.lock",
    "composer.lock",
    "go.sum",
    "uv.lock",
];
const STOP_WORDS: &[&str] = &[
    "about", "add", "also", "and", "any", "are", "build", "but", "can", "change", "could",
    "create", "does", "fix", "for", "from", "get", "have", "help", "how", "into", "its", "just",
    "let", "like", "make", "need", "new", "not", "now", "our", "please", "put", "should", "some",
    "that", "the", "them", "then", "there", "this", "update", "use", "want", "what", "when",
    "where", "which", "why", "will", "with", "would", "you", "your",
];

/// The folder a hook's working directory belongs to: the nearest enclosing
/// repository, or the folder itself. Never the home folder, a drive root,
/// or anything inside Guard's own home.
pub(crate) fn project_root(cwd: &Path, home: &Path, guard_home: &Path) -> Option<PathBuf> {
    let cwd = plain(fs::canonicalize(cwd).ok()?);
    let home = fs::canonicalize(home)
        .map(plain)
        .unwrap_or_else(|_| home.into());
    let guard_home = fs::canonicalize(guard_home)
        .map(plain)
        .unwrap_or_else(|_| guard_home.into());
    let mut root = cwd.clone();
    for dir in cwd.ancestors().take(16) {
        if dir == home || dir.parent().is_none() {
            break;
        }
        if fs::symlink_metadata(dir.join(".git")).is_ok() {
            root = dir.to_path_buf();
            break;
        }
    }
    let refused = root == home
        || home.starts_with(&root)
        || root.starts_with(&guard_home)
        || root.components().count() < 3
        || credential_directory_path(&root);
    (!refused).then_some(root)
}

/// Lowercase words from the prompt worth looking for in paths and code.
/// Words written like code come first, so a long prompt keeps the names it
/// is about (`case_sensitive`, `IntRange`) over the plain words around them.
pub(crate) fn terms(prompt: &str) -> Vec<String> {
    let mut code: Vec<String> = Vec::new();
    let mut plain: Vec<String> = Vec::new();
    for (word, shaped) in words(prompt) {
        let joined = word.replace(['-', '_'], "").to_lowercase();
        for part in std::iter::once(joined).chain(
            word.split(['-', '_'])
                .filter(|_| word.contains(['-', '_']))
                .map(str::to_lowercase),
        ) {
            let term = singular(&part);
            if term.chars().count() >= 3
                && !STOP_WORDS.contains(&term.as_str())
                && !term.chars().all(|c| c.is_ascii_digit())
            {
                if shaped {
                    code.push(term);
                } else {
                    plain.push(term);
                }
            }
        }
    }
    let mut found: Vec<String> = Vec::new();
    for term in code.into_iter().chain(plain) {
        if found.len() >= MAX_TERMS {
            break;
        }
        if !found.contains(&term) {
            found.push(term);
        }
    }
    // A request for tests counts even when it comes late in a long prompt.
    if !asks_for_tests(&found) && prompt_mentions_tests(prompt) {
        found.truncate(MAX_TERMS - 1);
        found.push("test".into());
    }
    found
}

/// The prompt's words, each marked when it is written like code: inside
/// backticks, dotted (`click.Choice`), snake_case or camelCase. A file name
/// gives its name without the extension.
fn words(prompt: &str) -> Vec<(String, bool)> {
    let mut found = Vec::new();
    for (span, ticked) in spans(prompt) {
        for token in tokens(span) {
            let token = token.trim_matches(['.', '-', '/']);
            let token = file_name(token).map_or(token, |(stem, _)| stem);
            let shaped = ticked || token.contains(['.', '_']) || camel(token);
            for piece in token.split(['.', '/']).filter(|piece| !piece.is_empty()) {
                found.push((piece.to_owned(), shaped));
            }
        }
    }
    found
}

/// The prompt's text between backticks and outside them, each marked when it
/// was backticked. A backticked command line (`pytest -x tests`) says how to
/// run something, not what the request is about, so it is left out.
fn spans(prompt: &str) -> impl Iterator<Item = (&str, bool)> {
    let parts: Vec<&str> = prompt.split('`').collect();
    let last = parts.len() - 1;
    parts
        .into_iter()
        .enumerate()
        .map(move |(index, span)| (span, index % 2 == 1 && index < last))
        .filter(|(span, ticked)| !(*ticked && span.trim().contains(char::is_whitespace)))
}

fn tokens(span: &str) -> impl Iterator<Item = &str> {
    span.split(|c: char| !(c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | '/')))
}

fn camel(word: &str) -> bool {
    word.chars()
        .zip(word.chars().skip(1))
        .any(|(a, b)| a.is_lowercase() && b.is_uppercase())
}

/// `(stem, extension)` when `token` is a file name this search reads.
fn file_name(token: &str) -> Option<(&str, &str)> {
    let (stem, extension) = token.rsplit_once('.')?;
    let base = stem.rsplit('/').next().unwrap_or(stem);
    (!base.is_empty() && wanted_file(token.rsplit('/').next().unwrap_or(token)))
        .then_some((stem, extension))
}

/// Files the prompt names, as typed (`CHANGES.rst`, `src/app/cli.py`).
pub(crate) fn named(prompt: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for token in spans(prompt).flat_map(|(span, _)| tokens(span)) {
        if found.len() >= MAX_NAMED {
            break;
        }
        let name = token.trim_matches(['.', '/']);
        if !token.contains("..") && file_name(name).is_some() && !found.iter().any(|n| n == name) {
            found.push(name.to_owned());
        }
    }
    found
}

/// Which of the prompt's `named` files `relative` is, if any: the same path,
/// or the same file name when the prompt gave no folder.
fn named_as(relative: &str, named: &[String]) -> Option<usize> {
    let name = relative.rsplit('/').next().unwrap_or(relative);
    named.iter().take(MAX_NAMED).position(|wanted| {
        if wanted.contains('/') {
            relative.eq_ignore_ascii_case(wanted)
                || relative
                    .to_lowercase()
                    .ends_with(&format!("/{}", wanted.to_lowercase()))
        } else {
            name.eq_ignore_ascii_case(wanted)
        }
    })
}

/// True when the search terms ask about tests.
pub(crate) fn asks_for_tests(terms: &[String]) -> bool {
    terms.iter().any(|term| TEST_WORDS.contains(&term.as_str()))
}

fn prompt_mentions_tests(prompt: &str) -> bool {
    prompt
        .split(|c: char| !c.is_alphanumeric())
        .any(|word| TEST_WORDS.contains(&singular(&word.to_lowercase()).as_str()))
}

/// Text the prompt quotes, such as a label to change, lowercased. A quote
/// opens only at the start of a word, so an apostrophe inside one ("dialog's")
/// never pairs with a later quote.
pub(crate) fn phrases(prompt: &str) -> Vec<String> {
    let chars: Vec<char> = prompt.chars().collect();
    let mut found: Vec<String> = Vec::new();
    let mut at = 0;
    while at < chars.len() && found.len() < MAX_PHRASES {
        if at > 0 && chars[at - 1].is_alphanumeric() {
            at += 1;
            continue;
        }
        let close = match chars[at] {
            '"' => '"',
            '\u{201c}' => '\u{201d}',
            '`' => '`',
            '\'' => '\'',
            _ => {
                at += 1;
                continue;
            }
        };
        let end = chars[at + 1..]
            .iter()
            .take(MAX_PHRASE_SPAN)
            .enumerate()
            .position(|(offset, &c)| {
                let next = chars.get(at + offset + 2);
                (c == close || (close == '\u{201d}' && c == '"'))
                    && (close != '\'' || next.is_none_or(|n| !n.is_alphanumeric()))
            });
        let Some(end) = end else {
            at += 1;
            continue;
        };
        let phrase: String = chars[at + 1..at + 1 + end].iter().collect();
        let phrase = phrase.trim().to_lowercase();
        if (3..=80).contains(&phrase.chars().count()) && !found.contains(&phrase) {
            found.push(phrase);
        }
        at += end + 2;
    }
    found
}

fn singular(word: &str) -> String {
    if word.len() > 4 && word.ends_with("ies") {
        return format!("{}y", &word[..word.len() - 3]);
    }
    if word.len() > 4 && word.ends_with('s') && !word.ends_with("ss") {
        return word[..word.len() - 1].into();
    }
    word.into()
}

/// What one file matched, kept until the walk ends because a word's weight
/// depends on how many files contain it.
struct Seen {
    relative: String,
    modified: SystemTime,
    in_path: Vec<bool>,
    hits: Vec<u8>,
    quoted: Vec<bool>,
    named: Option<usize>,
}

struct Scored {
    relative: String,
    score: f64,
    modified: SystemTime,
    named: Option<usize>,
}

/// Project files the prompt names, then the ones that mention its words or
/// quoted phrases, best first. An empty result means nothing in the project
/// matched, so no context is added. The walk stops after `budget` or its own
/// time limit, whichever comes first.
pub(crate) fn candidates(
    root: &Path,
    terms: &[String],
    phrases: &[String],
    named: &[String],
    budget: Duration,
) -> Vec<String> {
    let budget = budget.min(WALK_BUDGET);
    if terms.is_empty() && phrases.is_empty() && named.is_empty() {
        return Vec::new();
    }
    let started = Instant::now();
    let Ok(rules) = root_chain(root) else {
        return Vec::new();
    };
    let mut stack = vec![(root.to_path_buf(), String::new(), 0_usize, rules)];
    let mut visited = 0_usize;
    let mut scanned = 0_u64;
    let mut files = 0_usize;
    let mut seen = Vec::new();
    while let Some((dir, prefix, depth, rules)) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited > MAX_VISITED || started.elapsed() >= budget {
                return ranked(scores(seen, files, terms.len(), phrases.len()), terms);
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            // `file_type` never follows a link, so a linked folder or file is skipped.
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if name.starts_with('.') {
                continue;
            }
            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if ignored(&rules, &relative, kind.is_dir()) {
                continue;
            }
            if kind.is_dir() {
                if depth < MAX_DEPTH
                    && !SKIPPED_DIRS.contains(&name.as_str())
                    && !credential_directory_path(Path::new(&relative))
                {
                    // A folder whose own ignore file cannot be read stays out.
                    let path = entry.path();
                    if let Ok(inner) = extend(rules.clone(), &path.join(".gitignore"), &relative) {
                        stack.push((path, relative, depth + 1, inner));
                    }
                }
                continue;
            }
            if !kind.is_file() || !wanted_file(&name) || credential_named_path(Path::new(&relative))
            {
                continue;
            }
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.len() == 0 || metadata.len() > MAX_FILE_BYTES {
                continue;
            }
            files += 1;
            let in_path = in_path(&relative, terms);
            let mut text = None;
            if scanned + metadata.len() <= MAX_SCANNED_BYTES {
                scanned += metadata.len();
                text = guard_secure_fs::read_bounded(&entry.path(), MAX_FILE_BYTES as usize)
                    .ok()
                    .and_then(|read| String::from_utf8(read.bytes).ok())
                    .map(|text| text.to_lowercase());
            }
            let text = text.unwrap_or_default();
            let hits: Vec<u8> = terms
                .iter()
                .map(|term| text.matches(term.as_str()).take(8).count() as u8)
                .collect();
            let quoted: Vec<bool> = phrases.iter().map(|p| text.contains(p.as_str())).collect();
            let named = named_as(&relative, named);
            if in_path.contains(&true)
                || hits.iter().any(|&n| n > 0)
                || quoted.contains(&true)
                || named.is_some()
            {
                seen.push(Seen {
                    relative,
                    modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                    in_path,
                    hits,
                    quoted,
                    named,
                });
            }
        }
    }
    ranked(scores(seen, files, terms.len(), phrases.len()), terms)
}

/// A word counts for more the fewer files contain it, so a name like
/// "confirm" outweighs "button", which half a project says. A word in the
/// file's path counts twice; repeats inside the file add a little, capped.
/// Quoted text the file contains, such as the label being changed, counts
/// most of all, again more the rarer it is.
fn scores(seen: Vec<Seen>, files: usize, terms: usize, phrases: usize) -> Vec<Scored> {
    let rarity = |containing: usize| {
        if containing == 0 {
            0.0
        } else {
            (1.0 + files as f64 / containing as f64).ln()
        }
    };
    let term_weights: Vec<f64> = (0..terms)
        .map(|i| {
            rarity(
                seen.iter()
                    .filter(|s| s.in_path[i] || s.hits[i] > 0)
                    .count(),
            )
        })
        .collect();
    let phrase_weights: Vec<f64> = (0..phrases)
        .map(|i| 2.0 * rarity(seen.iter().filter(|s| s.quoted[i]).count()))
        .collect();
    seen.into_iter()
        .map(|file| {
            let mut score = 0.0;
            for (i, weight) in term_weights.iter().enumerate() {
                if file.in_path[i] {
                    score += 2.0 * weight;
                }
                if file.hits[i] > 0 {
                    score += weight * (1.0 + f64::from(file.hits[i]) / 8.0);
                }
            }
            for (i, weight) in phrase_weights.iter().enumerate() {
                if file.quoted[i] {
                    score += weight;
                }
            }
            Scored {
                relative: file.relative,
                score,
                modified: file.modified,
                named: file.named,
            }
        })
        .collect()
}

/// Files the prompt names first, in its order and the shortest path first
/// when a name matches several; then the rest, best first. Test files stay
/// out when a source file matched and the prompt did not ask about tests,
/// since a test that quotes the same words would otherwise crowd out the
/// file the request is about.
fn ranked(scored: Vec<Scored>, terms: &[String]) -> Vec<String> {
    let (mut pinned, mut scored): (Vec<Scored>, Vec<Scored>) =
        scored.into_iter().partition(|item| item.named.is_some());
    pinned.sort_by(|a, b| {
        a.named
            .cmp(&b.named)
            .then(
                a.relative
                    .matches('/')
                    .count()
                    .cmp(&b.relative.matches('/').count()),
            )
            .then(a.relative.cmp(&b.relative))
    });
    let mut per_name = [0_usize; MAX_NAMED];
    pinned.retain(|item| {
        let count = &mut per_name[item.named.unwrap_or_default()];
        *count += 1;
        *count <= MAX_NAMED_MATCHES
    });
    if !asks_for_tests(terms) && scored.iter().any(|item| !test_file(&item.relative)) {
        scored.retain(|item| !test_file(&item.relative));
    }
    scored.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then(b.modified.cmp(&a.modified))
            .then(a.relative.cmp(&b.relative))
    });
    pinned
        .into_iter()
        .chain(scored)
        .take(MAX_CANDIDATES)
        .map(|item| item.relative)
        .collect()
}

/// A test or spec file by its usual name or folder in common languages.
pub(crate) fn test_file(relative: &str) -> bool {
    let lower = relative.to_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    let stem = name.rsplit_once('.').map_or(name, |(stem, _)| stem);
    lower.split('/').any(|part| TEST_DIRS.contains(&part))
        || name.contains(".test.")
        || name.contains(".spec.")
        || stem.starts_with("test_")
        || stem.ends_with("_test")
        || stem.ends_with("_tests")
        || stem.ends_with("_spec")
        || stem == "test"
        || stem == "tests"
}

fn wanted_file(name: &str) -> bool {
    if SKIPPED_FILES.contains(&name) || name.ends_with(".min.js") || name.ends_with(".min.css") {
        return false;
    }
    Path::new(name)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| TEXT_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
}

fn in_path(relative: &str, terms: &[String]) -> Vec<bool> {
    let lower = relative.to_lowercase().replace(['-', '_'], "");
    terms
        .iter()
        .map(|term| lower.contains(term.as_str()))
        .collect()
}

/// The path without Windows' `\\?\` prefix, as grants spell it.
pub(crate) fn plain(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        let text = path.as_os_str().to_string_lossy();
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{rest}").into();
        }
        if let Some(rest) = text.strip_prefix(r"\\?\") {
            return rest.into();
        }
    }
    path
}

#[cfg(test)]
#[path = "context_assistance_prompt_files_tests.rs"]
mod tests;
