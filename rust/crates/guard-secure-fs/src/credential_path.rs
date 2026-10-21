//! Paths whose names mark credential data: the file's own name, or a
//! directory that stores credentials.

use super::{
    is_source_code_extension, sensitive_external_filename, win32_name, EXTERNAL_SENSITIVE_PARTS,
};
use std::path::Path;

pub fn credential_named_path(path: &Path) -> bool {
    let normalized = path.to_string_lossy().replace('\\', "/");
    let Some(last) = normalized
        .rsplit('/')
        .map(win32_name)
        .find(|part| !part.is_empty())
    else {
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
    // A migration script is named for the table or column it defines:
    // `0296_blog_preview_token.sql` adds a token column,
    // `0060_programmable-secrets-policy-schema.sql` creates the tables a
    // secrets feature stores rows in. That is a description of the code, the
    // way a source file's name is, not a mark on stored credentials.
    //
    // Only the migration shape is read that way. A database dump carries the
    // rows themselves and is named for what it holds, so
    // `prod_credentials_dump.sql` and `oauth_tokens_export.sql` keep the
    // review their names earn. The directory screen below applies either
    // way, so a script written into a credential store keeps its review too.
    let schema_script = extension.eq_ignore_ascii_case("sql")
        && last
            .file_stem()
            .and_then(|stem| stem.to_str())
            .is_some_and(migration_script_stem);
    let mut parts = normalized
        .split('/')
        .map(win32_name)
        .filter(|part| !part.is_empty());
    let name = parts.next_back();
    (!schema_script && name.is_some_and(|name| sensitive_external_filename(Path::new(name))))
        || parts.any(credential_directory)
}

/// Whether a `.sql` file is named the way a migration is.
///
/// A migration carries the sequence it runs in, either as a leading number
/// (`0296_blog_preview_token`, `20260307051222_add_tokens`) or as the fixed
/// name a tool generates (`migration`, `schema`), and a project that spells
/// it out says so in the name (`programmable-secrets-policy-schema`). A dump
/// has none of that: it is named for the rows it holds, which is exactly
/// what the filename screen reads.
fn migration_script_stem(stem: &str) -> bool {
    let lower = stem.to_ascii_lowercase();
    let digits = lower
        .split(|character: char| !character.is_ascii_digit())
        .next()
        .unwrap_or_default()
        .len();
    // `0296_…`, `20260307051222_…`; a two-digit prefix would catch a dump
    // that happens to start with a year.
    if digits >= 3 && digits < lower.len() {
        return true;
    }
    lower
        .split(['-', '_', '.'])
        .any(|word| DEFINITION_WORDS.contains(&word) || MIGRATION_WORDS.contains(&word))
}

/// Whether any directory on the way to `path` stores credentials, whatever
/// the path's last component is called.
///
/// [`credential_named_path`] answers for one file and stands aside as soon as
/// that file is source code, so `secrets/service.ts` clears it. A rule that
/// takes a path as a walk root, or as the repository a later screen measures
/// its descendants against, needs the other half of the question: a store on
/// the way down keeps its review even where the name at the end does not look
/// like a credential's.
pub fn credential_directory_path(path: &Path) -> bool {
    path.to_string_lossy()
        .replace('\\', "/")
        .split('/')
        .map(win32_name)
        .filter(|part| !part.is_empty())
        .any(credential_directory)
}

/// A directory named for credentials: a marker on its own (`secrets`,
/// `.auth`, `token`), or a compound naming stored secrets with a plural
/// marker (`prod-secrets`, `aws_credentials`, `api-tokens`). A compound with
/// a singular or generic marker, such as `secret-egress` or `auth-service`,
/// names a feature rather than a store, and so do design tokens
/// (`design-tokens`), which hold styles rather than credentials, and
/// compounds that end on a schema or policy
/// (`programmable-secrets-policy-schema`).
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
    let marker = |word: &str| match word {
        "secrets" | "credentials" => true,
        "tokens" => !words.contains(&"design"),
        _ => false,
    };
    // A compound that ends on a schema or policy belongs to a feature about
    // credentials rather than to a store of them:
    // `programmable-secrets-policy-schema` holds the definition of where
    // secrets will live, not the secrets.
    //
    // The word has to be the last one, and the marker it clears has to be
    // the last marker, or a store reads as its own definition:
    // `prod-secrets-schema-credentials` and `secrets-schema-api-tokens` both
    // end on a store marker. Migration directories are not cleared at all —
    // `secrets-migration` and `credentials_migrations` are where an export
    // from one vault waits for its import into the next.
    let Some(at) = words.iter().rposition(|word| marker(word)) else {
        return false;
    };
    at + 1 == words.len()
        || !words
            .last()
            .is_some_and(|word| DEFINITION_WORDS.contains(word))
}

/// Words that name a definition of a store rather than the store.
const DEFINITION_WORDS: [&str; 6] = ["policies", "policy", "schema", "schemas", "spec", "specs"];

/// Words that name the script that moves a store, which describes a file but
/// never clears a directory: a migrations directory is where exported rows
/// sit.
const MIGRATION_WORDS: [&str; 2] = ["migration", "migrations"];

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
            // A dump written into a store is still the store's content.
            "secrets/dump.sql",
            "config/prod-secrets/schema.sql",
            // A dump is named for the rows it holds, wherever it is written.
            "backups/prod_credentials_dump.sql",
            "backups/vault_secrets.sql",
            "backups/oauth_tokens_export.sql",
            // A migrations directory is where exported rows wait.
            "ops/secrets-migration/export.json",
            "ops/credentials_migrations/prod.yaml",
            "ops/vault-secrets-migration/export.json",
            // The compound still ends on a store marker.
            "ops/prod-secrets-schema-credentials/export.json",
            "ops/secrets-schema-api-tokens/export.json",
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
            // Migration scripts named for the column or feature they define.
            "db/0296_blog_preview_token.sql",
            "db/0362_guard_controls_assistant_service_credential.sql",
            "db/0060_programmable-secrets-policy-schema.sql",
            "prisma/migrations/20260307051222_programmable-secrets-policy-schema/migration.sql",
            "prisma/migrations/20260307051222_programmable-secrets-policy-schema/snapshot.json",
            "db/schema.sql",
            "db/migration.sql",
        ] {
            assert!(!credential_named_path(Path::new(path)), "{path}");
        }
    }
}
