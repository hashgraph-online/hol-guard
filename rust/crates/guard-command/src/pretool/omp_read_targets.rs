//! Oh My Pi `read` target proofs: bounded line selectors and names-only
//! directory listings. Kept apart from the shared command/file proofs.

use super::{
    bounded_structured_file_read_target, expand_home_read_path,
    resolved_path_allowed_for_operation, verified_path_context,
};

/// OMP's `read` tool accepts a bounded source selector after a literal-path
/// probe. Keep that host-specific syntax out of shared command/file proofs.
pub(in crate::pretool) fn bounded_omp_file_read_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    if let Some(base) = super::omp_json_query::json_query_base(value) {
        // The host queries the file only when it exists; a missing one falls
        // back to a workspace suffix match, which this proof does not model.
        return value.trim() == value
            && !base.split(['/', '\\']).any(|part| part == "..")
            && bounded_existing_file_read_target(base, home_dir, cwd);
    }
    if let Some(parts) = omp_read_list(value, home_dir, cwd) {
        return parts
            .iter()
            .all(|part| bounded_omp_list_part_read_target(part, home_dir, cwd));
    }
    bounded_omp_list_part_read_target(value, home_dir, cwd)
}

fn bounded_omp_list_part_read_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    match bounded_selector_path(value, home_dir, cwd) {
        BoundedSelectorPath::Base(base)
        | BoundedSelectorPath::RawFile(base)
        | BoundedSelectorPath::RawWindow(base) => {
            return bounded_existing_file_read_target(&base, home_dir, cwd);
        }
        BoundedSelectorPath::Unsupported => return false,
        BoundedSelectorPath::NotSelector => {}
    }
    bounded_structured_file_read_target(value, home_dir, cwd)
}

const MAX_OMP_READ_LIST_PARTS: usize = 16;

/// The parts of OMP's documented `;` read list (`a.ts:1-20; b.ts`). OMP fans
/// the list out only when neither the whole input nor its selector base
/// exists, then reads each trimmed, non-empty part on its own. Braces,
/// escapes, quotes and URLs change how OMP splits or routes the input, so
/// those stay on the single-path proofs.
fn omp_read_list(value: &str, home_dir: Option<&str>, cwd: Option<&str>) -> Option<Vec<String>> {
    if !value.contains(';')
        || value.trim() != value
        || value.len() > 4096
        || value.contains(['{', '}', '\\', '"', '\''])
        || value.contains("://")
        || value.chars().any(|c| c.is_control() || c == '\u{feff}')
        || !verified_path_context(home_dir, cwd)
    {
        return None;
    }
    let literal_missing = |path: &str| {
        let Some(candidate) = verified_selector_candidate(path, home_dir, cwd) else {
            return false;
        };
        matches!(
            std::fs::symlink_metadata(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        )
    };
    if !literal_missing(value) || selector_bases(value).any(|base| !literal_missing(base)) {
        return None;
    }
    let parts: Vec<String> = value
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect();
    (!parts.is_empty() && parts.len() <= MAX_OMP_READ_LIST_PARTS).then_some(parts)
}

/// Paths the host could read in place of `value` by peeling a trailing read
/// selector. It peels a `:tail` only when the tail fits its selector grammar
/// (line windows, `raw`, `conflicts`, `img`), and at most twice, for
/// `:1-5:raw`. Every such tail is made of letters, digits and `.+,-`, so a
/// tail that holds the rest of a list, like `1-5; b.json`, is never peeled.
fn selector_bases(value: &str) -> impl Iterator<Item = &str> {
    let mut rest = value;
    std::iter::from_fn(move || {
        let (base, tail) = rest.rsplit_once(':')?;
        let peelable = !tail.is_empty()
            && tail.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b',' | b'-')
            });
        rest = base;
        peelable.then_some(base)
    })
    .take(2)
}

/// Whether `value` is OMP's `path:N-M` (or `path:raw`) form for an existing
/// bounded file. `read` and `grep` both narrow to that file's lines, so the
/// form reads no more than the bare file would. A bare path is not a match.
pub(in crate::pretool) fn bounded_omp_file_selector_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    match bounded_selector_path(value, home_dir, cwd) {
        BoundedSelectorPath::Base(base) | BoundedSelectorPath::RawFile(base) => {
            bounded_existing_file_read_target(&base, home_dir, cwd)
        }
        BoundedSelectorPath::RawWindow(_)
        | BoundedSelectorPath::Unsupported
        | BoundedSelectorPath::NotSelector => false,
    }
}

pub(in crate::pretool) fn bounded_omp_selector_requires_review(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    matches!(
        bounded_selector_path(value, home_dir, cwd),
        BoundedSelectorPath::Unsupported
    )
}

/// Prove the exact read-only directory target used by OMP's native tree
/// listing. This is deliberately separate from the file-read proof: a
/// directory allow only authorizes bounded entry names, never file contents.
pub(in crate::pretool) fn bounded_omp_directory_read_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    match bounded_selector_path(value, home_dir, cwd) {
        BoundedSelectorPath::Base(base) => {
            return bounded_omp_directory_read_target_without_selector(&base, home_dir, cwd);
        }
        BoundedSelectorPath::RawFile(_)
        | BoundedSelectorPath::RawWindow(_)
        | BoundedSelectorPath::Unsupported => return false,
        BoundedSelectorPath::NotSelector => {}
    }
    bounded_omp_directory_read_target_without_selector(value, home_dir, cwd)
}

#[path = "directory_read_tools.rs"]
mod tools;
pub(in crate::pretool) use tools::bounded_directory_read_tool_target;

fn bounded_omp_directory_read_target_without_selector(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    if value.trim() != value || !verified_path_context(home_dir, cwd) {
        return false;
    }
    let path = value.strip_prefix(r"\\?\").unwrap_or(value);
    if path.is_empty() || path.len() > 4096 {
        return false;
    }
    if path.split(['/', '\\']).any(|part| part == "..") {
        // A climb is proved only to the root of a linked worktree of the
        // session's repository beside the checkout (see `sibling`).
        return cwd
            .and_then(|cwd| {
                super::super::directory_targets::sibling::linked_root(
                    path,
                    std::path::Path::new(cwd),
                )
            })
            .is_some_and(|root| {
                resolved_path_allowed_for_operation(&root, home_dir, cwd, false, true)
            });
    }
    if path.contains([
        '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '[', ']', '{', '}',
    ]) {
        return false;
    }
    if path.starts_with('~') && expand_home_read_path(path, home_dir).is_none() {
        return false;
    }
    let Some(candidate) = verified_selector_candidate(path, home_dir, cwd) else {
        return false;
    };
    if !candidate.is_absolute() || guard_secure_fs::contains_symlink_component(&candidate) {
        return false;
    }
    let Ok(canonical) = std::fs::canonicalize(&candidate) else {
        return false;
    };
    canonical.is_dir()
        && resolved_path_allowed_for_operation(&canonical, home_dir, cwd, false, true)
}

enum BoundedSelectorPath {
    NotSelector,
    Unsupported,
    Base(String),
    /// Bare `:raw` returns the same file's bytes without line formatting, so
    /// it carries the plain file-read proof but never a directory listing.
    RawFile(String),
    /// `:N-M:raw` or `:raw:N-M`: a line window of one file without line
    /// formatting. Only `read` takes this compound; OMP's `grep` rejects it.
    RawWindow(String),
}

/// OMP peels a selector only after proving that the complete input is not a
/// literal filesystem path. The native proof accepts OMP's line windows
/// (`line_selector`), a bare file `:raw`, and the two-chunk compound of one
/// line window plus `raw` in either order, each of which reads no more than
/// the bare path. Other compounds, time selectors and binary views remain on
/// the normal review path.
fn bounded_selector_path(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> BoundedSelectorPath {
    if value.trim() != value || !verified_path_context(home_dir, cwd) {
        return BoundedSelectorPath::NotSelector;
    }
    let path = value.strip_prefix(r"\\?\").unwrap_or(value);
    let Some((base, selector)) = path.rsplit_once(':') else {
        return BoundedSelectorPath::NotSelector;
    };
    // This parser is reached only by the OMP-specific bounded read helpers;
    // keep the host's non-range selector names here without widening generic reads.
    let selector_like = selector.eq_ignore_ascii_case("raw")
        || selector.eq_ignore_ascii_case("conflicts")
        || selector.eq_ignore_ascii_case("img")
        || selector.bytes().any(|byte| byte.is_ascii_digit());

    let expanded = expand_home_read_path(path, home_dir).unwrap_or_else(|| path.to_owned());
    let expanded_path = std::path::Path::new(&expanded);
    let candidate = if expanded_path.is_absolute() {
        expanded_path.to_path_buf()
    } else {
        let Some(root) = cwd
            .and_then(|root| {
                expand_home_read_path(root, home_dir).or_else(|| Some(root.to_owned()))
            })
            .filter(|root| std::path::Path::new(root).is_absolute())
        else {
            return BoundedSelectorPath::NotSelector;
        };
        std::path::Path::new(&root).join(expanded_path)
    };
    // A literal path wins even when it is a symlink or otherwise fails the
    // native proof; never reinterpret it as a selector in that case.
    match std::fs::symlink_metadata(&candidate) {
        Ok(_) => return BoundedSelectorPath::NotSelector,
        Err(error)
            if error.kind() != std::io::ErrorKind::NotFound
                && !windows_stream_spelling(&candidate) =>
        {
            return BoundedSelectorPath::NotSelector;
        }
        Err(_) => {}
    }

    if base.is_empty() || base.contains("://") || path.split(['/', '\\']).any(|part| part == "..") {
        return if selector_like {
            BoundedSelectorPath::Unsupported
        } else {
            BoundedSelectorPath::NotSelector
        };
    }
    // A colon left in the final component makes a compound selector. OMP
    // peels exactly one line window plus `raw`, in either order; a `raw`
    // compound of any other shape stays on the review path.
    let compound = base
        .rsplit(['/', '\\'])
        .next()
        .is_some_and(|name| name.contains(':'));
    if let Some(file) = compound.then(|| raw_window_path(base, selector)).flatten() {
        return BoundedSelectorPath::RawWindow(file);
    }
    if selector.eq_ignore_ascii_case("raw") && !compound {
        return BoundedSelectorPath::RawFile(base.to_owned());
    }
    if !line_selector(selector) {
        return if selector_like {
            BoundedSelectorPath::Unsupported
        } else {
            BoundedSelectorPath::NotSelector
        };
    }
    BoundedSelectorPath::Base(base.to_owned())
}

/// Windows file names cannot hold `:`; one there names an NTFS data stream
/// (`main.rs:raw:raw` is stream `raw` of type `raw`), and an invalid stream
/// spelling fails with an error other than `NotFound`. Such a name is no
/// literal file, so it is judged as the OMP selector it spells.
fn windows_stream_spelling(candidate: &std::path::Path) -> bool {
    cfg!(windows)
        && candidate
            .file_name()
            .is_some_and(|name| name.to_string_lossy().contains(':'))
}

/// The file behind OMP's `path:N-M:raw` or `path:raw:N-M`. The window must
/// be a range list or a lone `-N` tail, as OMP requires before peeling both
/// chunks, and the remaining name must hold no further selector.
fn raw_window_path(base: &str, selector: &str) -> Option<String> {
    let (path, inner) = base.rsplit_once(':')?;
    let window = if selector.eq_ignore_ascii_case("raw") {
        inner
    } else if inner.eq_ignore_ascii_case("raw") {
        selector
    } else {
        return None;
    };
    let tail = window.starts_with('-');
    let range_list = !window.split(',').any(|part| part.starts_with('-'));
    let file = path.rsplit(['/', '\\']).next().unwrap_or(path);
    (line_selector(window)
        && (range_list || (tail && !window.contains(',')))
        && !file.is_empty()
        && !file.contains(':'))
    .then(|| path.to_owned())
}

/// OMP's line windows: `N`, `N-`, `N-M`, `N+K` and `-N`, alone or joined by
/// commas. Each picks lines of the same file or entries of the same directory,
/// so it reads no more than the bare path would.
fn line_selector(selector: &str) -> bool {
    selector.len() <= 256
        && selector.split(',').count() <= 32
        && selector.split(',').all(line_window)
}

fn line_window(window: &str) -> bool {
    if let Some(count) = window.strip_prefix('-') {
        return line_number(count).is_some();
    }
    if let Some((start, count)) = window.split_once('+') {
        return line_number(start).is_some() && line_number(count).is_some();
    }
    match window.split_once('-') {
        Some((start, "")) => line_number(start).is_some(),
        Some((start, end)) => line_number(start)
            .zip(line_number(end))
            .is_some_and(|(start, end)| start <= end),
        None => line_number(window).is_some(),
    }
}

/// A positive decimal line number, digits only.
fn line_number(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>().ok().filter(|number| *number > 0)
}

fn bounded_existing_file_read_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let Some(candidate) = verified_selector_candidate(value, home_dir, cwd) else {
        return false;
    };
    if guard_secure_fs::contains_symlink_component(&candidate) {
        return false;
    }
    let Ok(canonical) = std::fs::canonicalize(&candidate) else {
        return false;
    };
    canonical.is_file()
        && super::resolved_read_target_allowed(&candidate, &canonical, home_dir, cwd)
}

/// Resolve selector targets through the verified context roots first. macOS
/// exposes `/tmp` as a symlink to `/private/tmp`; that trusted system alias
/// must not make an ordinary OMP selector look like an untrusted path. Any
/// symlink remaining below the canonical home/cwd roots is still rejected.
fn verified_selector_candidate(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> Option<std::path::PathBuf> {
    let expanded = expand_home_read_path(value, home_dir).unwrap_or_else(|| value.to_owned());
    let expanded_path = std::path::Path::new(&expanded);
    if expanded_path.is_absolute() {
        // The same fixed alias mapping `verified_cwd_target` accepts.
        let aliased =
            super::super::directory_targets::tmp_alias::private_tmp_spelling(expanded_path);
        for root in [home_dir, cwd].into_iter().flatten() {
            let root = expand_home_read_path(root, home_dir).or_else(|| Some(root.to_owned()))?;
            let root_path = std::path::Path::new(&root);
            let canonical_root = std::fs::canonicalize(root_path).ok()?;
            let Ok(relative) = expanded_path.strip_prefix(root_path) else {
                let Some(relative) = aliased
                    .as_deref()
                    .and_then(|mapped| mapped.strip_prefix(&canonical_root).ok())
                else {
                    continue;
                };
                return Some(canonical_root.join(relative));
            };
            return Some(canonical_root.join(relative));
        }
        // Location alone is not a denial reason for OMP's names-only listing.
        // Callers still canonicalize this path and apply every sensitive-root,
        // credential, foreign-home, and hidden-component check below. A
        // sibling project below the `/tmp` alias keeps those checks on its
        // `/private/tmp` spelling, so only links below the alias still count.
        return Some(aliased.unwrap_or_else(|| expanded_path.to_path_buf()));
    }
    let root = cwd
        .and_then(|root| expand_home_read_path(root, home_dir).or_else(|| Some(root.to_owned())))
        .filter(|root| std::path::Path::new(root).is_absolute())?;
    Some(std::fs::canonicalize(root).ok()?.join(expanded_path))
}

/// Whether a structured read names a path that does not exist. The read is
/// stopped either way; this only lets Guard say why, so the agent can correct
/// the path instead of waiting on an approval. OMP's `path:selector` form
/// counts as missing only when the selector base is missing too.
pub(in crate::pretool) fn missing_read_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    selectors: bool,
) -> bool {
    let missing = |value: &str| missing_literal_path(value, home_dir, cwd);
    if let Some(parts) = selectors
        .then(|| omp_read_list(value, home_dir, cwd))
        .flatten()
    {
        // A list names each part; only a missing part is a wrong path.
        return parts
            .iter()
            .any(|part| missing_read_target(part, home_dir, cwd, true));
    }
    if !missing(value) {
        return false;
    }
    !selectors
        || value
            .rsplit_once(':')
            .is_none_or(|(base, _)| base.is_empty() || missing(base))
}

fn missing_literal_path(value: &str, home_dir: Option<&str>, cwd: Option<&str>) -> bool {
    if value.is_empty()
        || value.trim() != value
        || value.len() > 4096
        || value.chars().any(char::is_control)
        || value.contains(['$', '`', '*', '?', '[', ']', '{', '}'])
        || value.contains("://")
        || !verified_path_context(home_dir, cwd)
    {
        return false;
    }
    let expanded = if value.starts_with('~') {
        let Some(expanded) = expand_home_read_path(value, home_dir) else {
            return false;
        };
        expanded
    } else {
        value.to_owned()
    };
    let path = std::path::Path::new(&expanded);
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        let Some(root) = cwd.and_then(|root| {
            expand_home_read_path(root, home_dir).or_else(|| Some(root.to_owned()))
        }) else {
            return false;
        };
        std::path::Path::new(&root).join(path)
    };
    matches!(
        std::fs::symlink_metadata(&candidate),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}
