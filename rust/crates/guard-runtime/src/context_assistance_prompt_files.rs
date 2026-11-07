//! Finds the project files a typed prompt is about, before CIGAR ranks them.
//!
//! This runs on every opted-in prompt, so it is bounded in files, bytes and
//! time, never follows a link, and never starts a program in the project
//! (a repository's own config can run code, so no `git` either). It only
//! proposes paths: each one is read again through the CIGAR source screen,
//! which refuses secrets, keys and credential files on its own.
use crate::context_assistance_engine::prose;
use crate::context_assistance_prompt_ignore::{extend, ignored, root_chain};
#[cfg(test)]
pub(crate) use crate::context_assistance_prompt_words::terms;
use crate::context_assistance_prompt_words::MAX_NAMED;
pub(crate) use crate::context_assistance_prompt_words::{asks_for_tests, named, phrases};
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
/// Files kept per name the prompt gives.
const MAX_NAMED_MATCHES: usize = 2;
/// Test files kept aside for the map's list of where a new test goes.
const MAX_KEPT_TESTS: usize = 6;
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

/// What one file matched, kept until the walk ends because a word's weight
/// depends on how many files contain it.
struct Seen {
    relative: String,
    modified: SystemTime,
    in_path: Vec<bool>,
    hits: Vec<u8>,
    /// For each term, whether this is a code file holding it as a whole word.
    whole: Vec<bool>,
    quoted: Vec<bool>,
    named: Option<usize>,
}

struct Scored {
    relative: String,
    score: f64,
    modified: SystemTime,
    named: Option<usize>,
}

/// What the walk found: the matched files, best first; the best test files,
/// kept apart from them;
/// how many files it checked; how many of those hold each term and each
/// quoted phrase; and how many code files hold each term as a whole word.
#[derive(Debug, Default)]
pub(crate) struct Walk {
    pub(crate) files: Vec<String>,
    pub(crate) tests: Vec<String>,
    pub(crate) checked: usize,
    pub(crate) holding: Vec<usize>,
    pub(crate) quoting: Vec<usize>,
    pub(crate) words: Vec<usize>,
}

/// Project files the prompt names, then the ones that mention its words or
/// quoted phrases, best first. An empty result means nothing in the project
/// matched, so no context is added. The walk stops after `budget` or its own
/// time limit, whichever comes first.
#[cfg(test)]
pub(crate) fn candidates(
    root: &Path,
    terms: &[String],
    phrases: &[String],
    named: &[String],
    budget: Duration,
) -> Vec<String> {
    walk(root, terms, phrases, named, budget).files
}

/// The walk behind `candidates`, with what it counted on the way.
pub(crate) fn walk(
    root: &Path,
    terms: &[String],
    phrases: &[String],
    named: &[String],
    budget: Duration,
) -> Walk {
    let budget = budget.min(WALK_BUDGET);
    if terms.is_empty() && phrases.is_empty() && named.is_empty() {
        return Walk::default();
    }
    let started = Instant::now();
    let Ok(rules) = root_chain(root) else {
        return Walk::default();
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
        // Test folders go deepest in the stack, so source is read first when
        // the walk runs out of time.
        let mut inside = Vec::new();
        for entry in entries.flatten() {
            visited += 1;
            if visited > MAX_VISITED || started.elapsed() >= budget {
                return finish(seen, files, terms, phrases.len());
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
                        let tests = TEST_DIRS.contains(&name.as_str());
                        inside.push((tests, (path, relative, depth + 1, inner)));
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
            let code = !prose(Path::new(&name));
            let whole: Vec<bool> = (terms.iter().zip(&hits))
                .map(|(term, &n)| code && n > 0 && whole_word(&text, term))
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
                    whole,
                    quoted,
                    named,
                });
            }
        }
        inside.sort_by_key(|(tests, _)| !tests);
        stack.extend(inside.into_iter().map(|(_, dir)| dir));
    }
    finish(seen, files, terms, phrases.len())
}

fn finish(seen: Vec<Seen>, checked: usize, terms: &[String], phrases: usize) -> Walk {
    let holding = (0..terms.len())
        .map(|i| {
            seen.iter()
                .filter(|s| s.in_path[i] || s.hits[i] > 0)
                .count()
        })
        .collect();
    let words = (0..terms.len())
        .map(|i| seen.iter().filter(|s| s.whole[i]).count())
        .collect();
    let quoting = (0..phrases)
        .map(|i| seen.iter().filter(|s| s.quoted[i]).count())
        .collect();
    let (files, tests) = ranked(scores(seen, checked, terms.len(), phrases));
    Walk {
        files,
        tests,
        checked,
        holding,
        quoting,
        words,
    }
}

/// Whether `text` holds `term` with no letter, digit or `_` on either side,
/// so `enum` is not found in `enumerate` nor `completion` in
/// `shell_completion`.
fn whole_word(text: &str, term: &str) -> bool {
    let part = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    text.match_indices(term).any(|(at, _)| {
        !part(text[..at].chars().next_back()) && !part(text[at + term.len()..].chars().next())
    })
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

/// Which of the prompt's `named` files `relative` is, if any. A name with a
/// folder claims its own path first, so `cli.py` cannot take the place of
/// `packages/z/cli.py`; a bare name matches that file name in any folder. A
/// name that ends with the whole relative path is the same file written out
/// in full, as a traceback prints `/home/me/project/src/app/cli.py`.
fn named_as(relative: &str, named: &[String]) -> Option<usize> {
    let name = relative.rsplit('/').next().unwrap_or(relative);
    let lower = relative.to_lowercase();
    let named = &named[..named.len().min(MAX_NAMED)];
    named
        .iter()
        .position(|wanted| {
            let wanted = wanted.to_lowercase();
            wanted.contains('/')
                && (lower == wanted
                    || lower.ends_with(&format!("/{wanted}"))
                    || wanted.ends_with(&format!("/{lower}")))
        })
        .or_else(|| {
            named
                .iter()
                .position(|wanted| !wanted.contains('/') && name.eq_ignore_ascii_case(wanted))
        })
}

/// Files the prompt names first, in its order and the shortest path first
/// when a name matches several; then the rest, best first. Test files stay
/// out when a source file matched and the prompt did not ask about tests,
/// since a test that quotes the same words would otherwise crowd out the
/// file the request is about.
fn ranked(scored: Vec<Scored>) -> (Vec<String>, Vec<String>) {
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
    // Tests are kept aside even when the prompt asks for them, so source
    // files fill the candidates and the map still finds where new tests go.
    let mut tests = Vec::new();
    if scored.iter().any(|item| !test_file(&item.relative)) {
        (tests, scored) = scored
            .into_iter()
            .partition(|item| test_file(&item.relative));
    }
    let best_first = |a: &Scored, b: &Scored| {
        b.score
            .total_cmp(&a.score)
            .then(b.modified.cmp(&a.modified))
            .then(a.relative.cmp(&b.relative))
    };
    scored.sort_by(best_first);
    tests.sort_by(best_first);
    let files = pinned
        .into_iter()
        .chain(scored)
        .take(MAX_CANDIDATES)
        .map(|item| item.relative)
        .collect();
    let tests = tests
        .into_iter()
        .take(MAX_KEPT_TESTS)
        .map(|item| item.relative)
        .collect();
    (files, tests)
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

pub(crate) fn wanted_file(name: &str) -> bool {
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
