//! Workspace-protection proofs that the recorded vectors cannot express:
//! dependency-tree credentials, the generic package names that must stay
//! ordinary code, committed exclusion without reading, and the hard bounds.

use std::fs;
use std::path::Path;

use super::snapshot::{complete_workspace_snapshot, reject_external_node_modules};
use super::vector_support::Workspace;

const PROTECTED_REVIEW: &str = "protected workspace content requires Guard review";

/// Withdraw read access so a snapshot that opened the file would surface an I/O
/// error instead of the protected verdict. Unix clears every mode bit; Windows
/// has no equivalent, so the read-only attribute is the closest marker there.
fn deny_reads(path: &Path) {
    let mut permissions = fs::metadata(path).expect("metadata").permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o000);
    }
    #[cfg(not(unix))]
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions).expect("deny reads");
}

/// Restore read and write access so the workspace root can be removed on drop.
fn restore_reads(path: &Path) {
    let mut permissions = fs::metadata(path).expect("metadata").permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o600);
    }
    #[cfg(not(unix))]
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions).expect("restore reads");
}

/// Whether withdrawn read access really makes a read fail here. An unprivileged
/// Unix process cannot open mode 000; root reads straight through it, and the
/// Windows read-only attribute does not block reads at all.
fn read_trap_is_armed() -> bool {
    #[cfg(unix)]
    {
        !nix::unistd::geteuid().is_root()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn write(path: &Path, content: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("parent dirs");
    fs::write(path, content).expect("write");
}

fn paths(workspace: &Path, exclude_protected: bool) -> Vec<String> {
    let (_digest, inputs) =
        complete_workspace_snapshot(workspace, exclude_protected).expect("snapshot");
    inputs.into_iter().map(|item| item.snapshot_path).collect()
}

/// Credentials inside a dependency tree stay protected even though the package
/// directories around them are deliberately exempt from the generic words.
#[test]
fn dependency_tree_credentials_require_review() {
    for relative in [
        "node_modules/pkg/clientSecret.json",
        "node_modules/pkg/apiToken.json",
        "node_modules/pkg/serviceAccount.json",
        "node_modules/pkg/privateKey.json",
        "node_modules/pkg/.env",
        "node_modules/pkg/api-key.txt",
        "node_modules/@scope/pkg/runtime/clientSecret.json",
        "node_modules/outer/node_modules/inner/apiToken.json",
        "node_modules/clientSecret.json",
    ] {
        let workspace = Workspace::new();
        write(&workspace.path.join("package.json"), "{}\n");
        write(&workspace.path.join(relative), "MUST_NOT_CROSS=synthetic\n");

        assert_eq!(
            complete_workspace_snapshot(&workspace.path, false).unwrap_err(),
            PROTECTED_REVIEW,
            "{relative}"
        );
        assert_eq!(
            paths(&workspace.path, true),
            vec!["package.json".to_owned()],
            "{relative}"
        );
    }
}

/// A package named for a protected word is still ordinary code; excluding it
/// would break the dependency closure a contained run needs.
#[test]
fn generic_package_names_stay_in_the_snapshot() {
    for relative in [
        "node_modules/js-tokens/index.js",
        "node_modules/@secret-scope/js-tokens/index.js",
        "node_modules/outer/node_modules/js-tokens/index.js",
        "node_modules/token-parser/tokens.js",
    ] {
        let workspace = Workspace::new();
        write(&workspace.path.join(relative), "export const value = 1;\n");

        assert_eq!(paths(&workspace.path, true), vec![relative.to_owned()]);
        assert_eq!(paths(&workspace.path, false), vec![relative.to_owned()]);
    }
}

/// Presence alone decides review, so an unreadable credential still produces
/// the protected verdict instead of a read failure.
///
/// Withdrawn read access makes a stray read fail only for an unprivileged Unix
/// process. Root reads straight through mode 000, and the Windows read-only
/// attribute never blocks reads, so there the verdicts below still hold but the
/// file proves nothing about whether it was opened; the trap is checked to be
/// armed wherever it can be.
#[test]
fn protected_presence_is_decided_without_reading_the_file() {
    let trap_armed = read_trap_is_armed();
    for relative in [
        ".env.example",
        ".git-credentials",
        "terraform.tfvars",
        "wallet.key",
        "tls/client.key",
        "nested/.docker/config.json",
        "nested/.kube/config",
        "nested/service-account.json",
        "runtime/APIToken.json",
        "runtime/apiToken.json",
        "runtime/clientSecret.json",
        "runtime/privateKey.json",
        "runtime/serviceAccount.json",
        "runtime/token.txt",
        "runtime/id_dsa",
        "runtime/id_ecdsa",
        "runtime/id_ed25519",
        "runtime/id_rsa",
    ] {
        let workspace = Workspace::new();
        write(&workspace.path.join("package.json"), "{}\n");
        let protected = workspace.path.join(relative);
        write(&protected, "must-not-read\n");
        deny_reads(&protected);
        assert!(
            !trap_armed || fs::read(&protected).is_err(),
            "{relative}: withdrawn read access must make a read of the credential fail"
        );

        assert_eq!(
            complete_workspace_snapshot(&workspace.path, false).unwrap_err(),
            PROTECTED_REVIEW,
            "{relative}"
        );
        assert_eq!(
            paths(&workspace.path, true),
            vec!["package.json".to_owned()],
            "{relative}"
        );

        restore_reads(&protected);
    }
}

/// The exclusion is committed to the identity: adding or removing a protected
/// file moves the digest, while editing its contents cannot.
#[test]
fn protected_presence_changes_the_snapshot_identity() {
    let workspace = Workspace::new();
    write(&workspace.path.join("src/unit.test.ts"), "test('unit');\n");
    let before = complete_workspace_snapshot(&workspace.path, true)
        .expect("before")
        .0;

    let protected = workspace.path.join(".env");
    write(&protected, "FAKE_TEST_SECRET=one\n");
    let with_protected = complete_workspace_snapshot(&workspace.path, true)
        .expect("with")
        .0;
    assert_ne!(with_protected, before);

    write(&protected, "FAKE_TEST_SECRET=two\n");
    assert_eq!(
        complete_workspace_snapshot(&workspace.path, true)
            .expect("edited")
            .0,
        with_protected
    );

    fs::remove_file(&protected).expect("remove");
    assert_eq!(
        complete_workspace_snapshot(&workspace.path, true)
            .expect("after")
            .0,
        before
    );
}

/// Guard state is skipped rather than captured, but its presence still moves
/// the identity so a run cannot silently inherit a different checkout.
#[test]
fn skipped_state_presence_changes_the_snapshot_identity() {
    let workspace = Workspace::new();
    write(
        &workspace.path.join("src/example.ts"),
        "export const a = 1;\n",
    );
    let before = complete_workspace_snapshot(&workspace.path, false)
        .expect("before")
        .0;

    write(
        &workspace.path.join(".git/HEAD"),
        "ref: refs/heads/release\n",
    );

    assert_ne!(
        complete_workspace_snapshot(&workspace.path, false)
            .expect("after")
            .0,
        before
    );
}

/// Dependencies resolved from an ancestor are outside the captured identity,
/// so the request cannot be contained against them.
#[test]
fn external_node_modules_require_review() {
    let workspace = Workspace::new();
    let nested = workspace.path.join("packages/app");
    fs::create_dir_all(&nested).expect("nested");
    write(
        &workspace.path.join("node_modules/ambient/index.js"),
        "module.exports = 1;\n",
    );

    assert_eq!(
        reject_external_node_modules(&nested).unwrap_err(),
        "external Node dependencies require Guard review"
    );
    assert!(reject_external_node_modules(&workspace.path).is_ok());
}

/// The file bound is a hard refusal, not a truncation: an oversized workspace
/// must not snapshot as a smaller successful identity.
#[test]
fn the_file_budget_refuses_an_oversized_workspace() {
    let workspace = Workspace::new();
    let directory = workspace.path.join("many");
    fs::create_dir_all(&directory).expect("many");
    for index in 0..=20_000u32 {
        fs::write(directory.join(format!("{index}.txt")), b"x").expect("write");
    }

    assert_eq!(
        complete_workspace_snapshot(&workspace.path, false).unwrap_err(),
        "workspace snapshot exceeds containment identity budget"
    );
}
