//! Bounded OMP read-selector grammar (`:N-M`) and its resolution helpers.
//! Kept out of the shared command/file proofs: a selector is peeled only after
//! the complete input fails to resolve as a literal filesystem path, and only
//! through the verified context roots.

use super::screens::{resolved_path_allowed_for_operation, verified_path_context};
use super::*;

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
        BoundedSelectorPath::Unsupported => return false,
        BoundedSelectorPath::NotSelector => {}
    }
    bounded_omp_directory_read_target_without_selector(value, home_dir, cwd)
}

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
        return false;
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

pub(super) enum BoundedSelectorPath {
    NotSelector,
    Unsupported,
    Base(String),
}

/// OMP peels a selector only after proving that the complete input is not a
/// literal filesystem path. Keep the native proof narrower than OMP: one
/// positive bounded range (`:N-M`) only. Tails, open-ended ranges, compound
/// selectors, and comma lists remain on the normal review path.
pub(super) fn bounded_selector_path(
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
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
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
    let Some((start, end)) = selector.split_once('-') else {
        return if selector_like {
            BoundedSelectorPath::Unsupported
        } else {
            BoundedSelectorPath::NotSelector
        };
    };
    if start.is_empty()
        || end.is_empty()
        || !start.bytes().all(|byte| byte.is_ascii_digit())
        || !end.bytes().all(|byte| byte.is_ascii_digit())
    {
        return if selector_like {
            BoundedSelectorPath::Unsupported
        } else {
            BoundedSelectorPath::NotSelector
        };
    }
    let Ok(start) = start.parse::<u64>() else {
        return BoundedSelectorPath::Unsupported;
    };
    let Ok(end) = end.parse::<u64>() else {
        return BoundedSelectorPath::Unsupported;
    };
    if start == 0 || end == 0 || end < start {
        return BoundedSelectorPath::Unsupported;
    }
    BoundedSelectorPath::Base(base.to_owned())
}

pub(super) fn bounded_existing_file_read_target(
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
    let Ok(canonical) = std::fs::canonicalize(candidate) else {
        return false;
    };
    canonical.is_file()
        && resolved_path_allowed_for_operation(&canonical, home_dir, cwd, false, true)
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
        for root in [home_dir, cwd].into_iter().flatten() {
            let root = expand_home_read_path(root, home_dir).or_else(|| Some(root.to_owned()))?;
            let root_path = std::path::Path::new(&root);
            let canonical_root = std::fs::canonicalize(root_path).ok()?;
            let Ok(relative) = expanded_path.strip_prefix(root_path) else {
                let tmp_alias = std::path::Path::new("/tmp");
                let Ok(tmp_relative) = expanded_path.strip_prefix(tmp_alias) else {
                    continue;
                };
                let canonical_tmp = std::fs::canonicalize(tmp_alias).ok()?;
                let mapped = canonical_tmp.join(tmp_relative);
                let Ok(relative) = mapped.strip_prefix(&canonical_root) else {
                    continue;
                };
                return Some(canonical_root.join(relative));
            };
            return Some(canonical_root.join(relative));
        }
        // Location alone is not a denial reason for OMP's names-only listing.
        // Callers still canonicalize this path and apply every sensitive-root,
        // credential, foreign-home, and hidden-component check below.
        return Some(expanded_path.to_path_buf());
    }
    let root = cwd
        .and_then(|root| expand_home_read_path(root, home_dir).or_else(|| Some(root.to_owned())))
        .filter(|root| std::path::Path::new(root).is_absolute())?;
    Some(std::fs::canonicalize(root).ok()?.join(expanded_path))
}
