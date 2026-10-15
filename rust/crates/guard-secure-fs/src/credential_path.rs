//! Paths whose names mark credential data: the file's own name, or a
//! directory that stores credentials.

use super::{is_source_code_extension, sensitive_external_filename, EXTERNAL_SENSITIVE_PARTS};
use std::path::Path;

pub fn credential_named_path(path: &Path) -> bool {
    let normalized = path.to_string_lossy().replace('\\', "/");
    let Some(last) = normalized.rsplit('/').find(|part| !part.is_empty()) else {
        return false;
    };
    let last = Path::new(last);
    let extension = last
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    // Keep bounded source-code inspection (and its compiled bytecode);
    // credential data directories still retain review even when their final
    // filename has no credential marker.
    if is_source_code_extension(extension) || matches!(extension, "pyc" | "pyo") {
        return false;
    }
    let mut parts = normalized.split('/').filter(|part| !part.is_empty());
    parts
        .next_back()
        .is_some_and(|name| sensitive_external_filename(Path::new(name)))
        || parts.any(credential_directory)
}

/// A directory named for credentials: a marker on its own (`secrets`,
/// `.auth`, `token`), or a compound naming stored secrets with a plural
/// marker (`prod-secrets`, `aws_credentials`, `api-tokens`). A compound with
/// a singular or generic marker, such as `secret-egress` or `auth-service`,
/// names a feature rather than a store, and so do design tokens
/// (`design-tokens`), which hold styles rather than credentials.
fn credential_directory(part: &str) -> bool {
    let lower = part.to_ascii_lowercase();
    let bare = lower.trim_start_matches('.');
    let stem = |name: &str| {
        Path::new(name)
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
    };
    let exact = [
        Some(lower.clone()),
        Some(bare.to_owned()),
        stem(&lower),
        stem(bare),
    ];
    if exact
        .iter()
        .flatten()
        .any(|name| EXTERNAL_SENSITIVE_PARTS.contains(&name.as_str()))
    {
        return true;
    }
    let words = bare.replace(['-', '.'], "_");
    let words: Vec<&str> = words.split('_').collect();
    words.iter().any(|word| match *word {
        "secrets" | "credentials" => true,
        "tokens" => !words.contains(&"design"),
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::credential_named_path;
    use std::path::Path;

    #[test]
    fn credential_stores_keep_review_while_feature_directories_do_not() {
        for path in [
            "secrets/prod.yaml",
            "config/prod-secrets/db.json",
            "deploy/aws_credentials/config",
            "playwright/.auth/user.json",
            ".env.d/local.conf",
            "fixtures/github-token.txt",
            "keys/service_credentials.json",
            "config/api-tokens/github.json",
            "auth/oauth_tokens/session.json",
            "home/kubeconfig.yaml",
            "deploy/prod-kubeconfig.yml",
        ] {
            assert!(credential_named_path(Path::new(path)), "{path}");
        }
        for path in [
            "seeds/hermes/mcp/secret-egress/server.json",
            "services/auth-service/config.json",
            "design-tokens/colors.json",
            "packages/ui/design_tokens/spacing.json",
            "guard/__pycache__/oauth_token_claims.cpython-312.pyc",
            "guard/runtime/command_tokens.py",
            "docs/notes.md",
        ] {
            assert!(!credential_named_path(Path::new(path)), "{path}");
        }
    }
}
