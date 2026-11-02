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
const MAX_FILE_BYTES: u64 = 65_536;
const MAX_DEPTH: usize = 10;
const MAX_TERMS: usize = 12;
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
    "astro", "c", "cc", "cjs", "clj", "cpp", "cs", "css", "dart", "erl", "ex", "exs", "go",
    "gradle", "graphql", "h", "hpp", "html", "java", "js", "json", "jsx", "kt", "kts", "less",
    "lua", "m", "md", "mdx", "mjs", "mm", "nix", "php", "proto", "py", "r", "rb", "rs", "sass",
    "scala", "scss", "sh", "sql", "svelte", "swift", "toml", "ts", "tsx", "txt", "vue", "xml",
    "yaml", "yml", "zig",
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
pub(crate) fn terms(prompt: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for word in prompt.split(|c: char| !(c.is_alphanumeric() || c == '-' || c == '_')) {
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
                && !found.contains(&term)
            {
                found.push(term);
            }
        }
        if found.len() >= MAX_TERMS {
            break;
        }
    }
    found.truncate(MAX_TERMS);
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

struct Scored {
    relative: String,
    score: u32,
    modified: SystemTime,
}

/// Project files that mention the prompt's words, best first. An empty
/// result means nothing in the project matched, so no context is added. The
/// walk stops after `budget` or its own time limit, whichever comes first.
pub(crate) fn candidates(root: &Path, terms: &[String], budget: Duration) -> Vec<String> {
    let budget = budget.min(WALK_BUDGET);
    if terms.is_empty() {
        return Vec::new();
    }
    let started = Instant::now();
    let Ok(rules) = root_chain(root) else {
        return Vec::new();
    };
    let mut stack = vec![(root.to_path_buf(), String::new(), 0_usize, rules)];
    let mut visited = 0_usize;
    let mut scanned = 0_u64;
    let mut scored = Vec::new();
    while let Some((dir, prefix, depth, rules)) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited > MAX_VISITED || started.elapsed() >= budget {
                return ranked(scored, terms);
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
            let path_score = path_score(&relative, terms);
            let mut score = path_score * 6;
            if scanned + metadata.len() <= MAX_SCANNED_BYTES {
                scanned += metadata.len();
                score += guard_secure_fs::read_bounded(&entry.path(), MAX_FILE_BYTES as usize)
                    .ok()
                    .map_or(0, |read| content_score(&read.bytes, terms));
            }
            if score > 0 {
                scored.push(Scored {
                    relative,
                    score,
                    modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                });
            }
        }
    }
    ranked(scored, terms)
}

/// Best first. Test files stay out when a source file matched and the prompt
/// did not ask about tests, since a test that quotes the same words would
/// otherwise crowd out the file the request is about.
fn ranked(mut scored: Vec<Scored>, terms: &[String]) -> Vec<String> {
    let asks_for_tests = terms.iter().any(|term| TEST_WORDS.contains(&term.as_str()));
    if !asks_for_tests && scored.iter().any(|item| !test_file(&item.relative)) {
        scored.retain(|item| !test_file(&item.relative));
    }
    scored.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then(b.modified.cmp(&a.modified))
            .then(a.relative.cmp(&b.relative))
    });
    scored
        .into_iter()
        .take(MAX_CANDIDATES)
        .map(|item| item.relative)
        .collect()
}

/// A test or spec file by its usual name or folder in common languages.
fn test_file(relative: &str) -> bool {
    let lower = relative.to_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    let stem = name.split('.').next().unwrap_or(name);
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

fn path_score(relative: &str, terms: &[String]) -> u32 {
    let lower = relative.to_lowercase().replace(['-', '_'], "");
    terms
        .iter()
        .filter(|term| lower.contains(term.as_str()))
        .count() as u32
}

/// Distinct words found count most; repeats add a little, capped.
fn content_score(bytes: &[u8], terms: &[String]) -> u32 {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return 0;
    };
    let lower = text.to_lowercase();
    let mut score = 0;
    for term in terms {
        let hits = lower.matches(term.as_str()).count().min(8) as u32;
        if hits > 0 {
            score += 3 + hits / 2;
        }
    }
    score
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
