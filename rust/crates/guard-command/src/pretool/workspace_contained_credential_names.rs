//! A read of a file named like a credential store stays at review.
//!
//! The workspace sandbox withholds a fixed set of credential paths (`.env`,
//! `*.key`, `.npmrc` and the like). Guard's read review also holds files
//! whose names say they carry a token or a secret, such as
//! `brand-github-token.txt` or `secrets/prod.yaml`. Those are not on the
//! sandbox's list, so routing the review into the sandbox would let the
//! contained run open the file the review was holding.
use crate::CanonicalCommandV1;
use std::path::Path;

/// Whether any operand of the command names an existing file or folder whose
/// name marks it as a credential store. Only operands that exist under the
/// working directory count, so a search pattern such as `token` does not.
pub(super) fn names_credential_path(model: &CanonicalCommandV1, cwd: &Path) -> bool {
    model.segments.iter().any(|segment| {
        segment.arguments.iter().any(|argument| {
            let value = argument
                .strip_prefix('-')
                .and_then(|flag| flag.split_once('=').map(|(_, value)| value))
                .unwrap_or(argument);
            credential_operand(value, cwd)
        })
    })
}

fn credential_operand(value: &str, cwd: &Path) -> bool {
    if value.is_empty() || value.starts_with('-') {
        return false;
    }
    let path = Path::new(value);
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    let Ok(real) = std::fs::canonicalize(&resolved) else {
        return false;
    };
    let root = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    // The name screen reads the path below the workspace, so a credential
    // word in a parent directory's name does not count, and a tracked,
    // secret-free document named for a feature is read like any other file,
    // exactly as the read review treats it.
    let named = |candidate: &Path| guard_secure_fs::credential_named_path(candidate);
    (named(resolved.strip_prefix(cwd).unwrap_or(&resolved))
        || named(real.strip_prefix(&root).unwrap_or(&real)))
        && !crate::pretool::search_scope_tracked::names::tracked_document(&real, cwd.to_str())
}
