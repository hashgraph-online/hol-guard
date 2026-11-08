//! Per-entry screens for what a recursive walk may print.
//!
//! The walk judges each descendant by its name and metadata alone: it never
//! opens a file to decide. A hidden entry must be on a short benign list,
//! because recursion would otherwise reach `.env`, `.ssh` or `.git`. A
//! credential-named file is refused unless it is source code or test data
//! below a test-data directory inside the walk.
use std::path::Path;

/// Hidden names that carry no credentials and are common in source trees.
/// Hidden names that hold project metadata, never credentials. Descendants of
/// the listed directories still clear every per-entry screen.
const BENIGN_HIDDEN_NAMES: &[&str] = &[
    ".ds_store",
    ".well-known",
    ".gitignore",
    ".gitkeep",
    ".keep",
    ".gitattributes",
    ".nvmrc",
    ".node-version",
    ".python-version",
    ".editorconfig",
    ".prettierrc",
    ".prettierignore",
    ".eslintignore",
    ".dockerignore",
    ".github",
    ".vscode",
    ".husky",
    ".changeset",
];

/// Key and certificate containers whose names carry no credential word.
pub(in crate::pretool) const SECRET_EXTENSIONS: &[&str] = &[
    "pem", "p12", "pfx", "jks", "keystore", "asc", "gpg", "kdbx", "ppk",
];

pub(in crate::pretool::search) fn hidden_allowed(name: &str) -> bool {
    BENIGN_HIDDEN_NAMES.contains(&name.to_ascii_lowercase().as_str())
}

/// `node_modules/.bin` holds a package manager's executable shims. The name is
/// hidden, but the directory is part of every install, and what it holds is
/// links into packages this walk screens entry by entry. Refusing it on the
/// name alone sends every recursive search of an installed checkout to review.
fn package_store_bin(path: &Path, name: &str) -> bool {
    name == ".bin"
        && path
            .parent()
            .and_then(|parent| parent.file_name())
            .and_then(|parent| parent.to_str())
            .is_some_and(|parent| parent == "node_modules")
}

pub(in crate::pretool::search) fn descendant_allowed(
    path: &Path,
    root: &Path,
    is_file: bool,
) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if (name.starts_with('.') && !hidden_allowed(name) && !package_store_bin(path, name))
        || guard_secure_fs::sensitive_path_family(path).is_some()
    {
        return false;
    }
    if !is_file {
        return true;
    }
    let relative = path.strip_prefix(root).unwrap_or(path);
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    !SECRET_EXTENSIONS.contains(&extension.as_str())
        && (!guard_secure_fs::credential_named_path(relative)
            || synthetic_fixture(root, relative)
            || crate::pretool::search_scope_tracked::names::committed_document(path))
}

/// Directories that hold a project's test data.
const FIXTURE_DIRECTORIES: &[&str] = &[
    "testdata",
    "test-data",
    "test_data",
    "fixtures",
    "fixture",
    "__fixtures__",
    "tests",
    "test",
    "__tests__",
];

/// Test trees name their vectors for what they exercise
/// (`testdata/secrets_cli/vectors.json`, `tests/fixtures/tokens.json`), so a
/// credential name at or below a test-data directory inside the walk marks
/// data a test reads, not a store. A test directory inside a credential
/// directory (`secrets/tests/prod.json`), or a walk rooted in one, is still a
/// store. Key containers, hidden names and the sensitive families (`.env`,
/// `*.key`, `.npmrc`) are refused before this is asked.
fn synthetic_fixture(root: &Path, relative: &Path) -> bool {
    let Some(parent) = relative.parent() else {
        return false;
    };
    let mut above = root.to_path_buf();
    for part in parent.components() {
        let std::path::Component::Normal(name) = part else {
            return false;
        };
        if name
            .to_str()
            .is_some_and(|name| FIXTURE_DIRECTORIES.contains(&name.to_ascii_lowercase().as_str()))
        {
            // Every directory above the test directory is checked as a
            // directory, below a neutral entry name.
            return !guard_secure_fs::credential_named_path(&above.join("entry"));
        }
        above.push(name);
    }
    false
}
