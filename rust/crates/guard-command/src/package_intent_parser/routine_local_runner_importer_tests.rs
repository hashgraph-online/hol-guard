//! What the `importers` block of a `pnpm-lock.yaml` answers for: one
//! lockfile serves a whole monorepo, so the block is the only thing in it
//! that speaks for the workspace the run is in.

use super::*;

#[test]
fn a_monorepo_lockfile_answers_for_this_workspace_only() {
    let dir = workspace();
    let root = dir.path();

    // One `pnpm-lock.yaml` serves every workspace in a monorepo, so its
    // `packages` block lists both releases of the runner the tree resolved.
    // The `importers` block is what says which one this workspace runs.
    let value = only_lockfile(
        root,
        "pnpm-lock.yaml",
        &format!(
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    devDependencies:\n      eslint:\n        specifier: {DECLARED_VERSION}\n        version: {INSTALLED_VERSION}\n\n  packages/api:\n    devDependencies:\n      eslint:\n        specifier: ^8.0.0\n        version: 8.57.0\n\npackages:\n\n  eslint@8.57.0:\n    resolution: {{integrity: sha512-x}}\n\n  eslint@{INSTALLED_VERSION}:\n    resolution: {{integrity: sha512-y}}\n"
        ),
    );
    assert!(routine_local_runner(&value));

    // The other workspace's release answers for that workspace, not this
    // one, so the installed copy stays unaccounted for.
    write(
        &root.join("pnpm-lock.yaml"),
        &format!(
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    devDependencies:\n      eslint:\n        specifier: ^8.0.0\n        version: 8.57.0\n\npackages:\n\n  eslint@8.57.0:\n    resolution: {{integrity: sha512-x}}\n\n  eslint@{INSTALLED_VERSION}:\n    resolution: {{integrity: sha512-y}}\n"
        ),
    );
    assert!(!routine_local_runner(&value));

    // An importer that links the runner from elsewhere in the tree names no
    // release, and the block is the only thing that speaks for this
    // workspace, so nothing is left to answer for the installed copy.
    write(
        &root.join("pnpm-lock.yaml"),
        &format!(
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    devDependencies:\n      eslint:\n        specifier: workspace:*\n        version: link:../tools/eslint\n\npackages:\n\n  eslint@8.57.0:\n    resolution: {{integrity: sha512-x}}\n\n  eslint@{INSTALLED_VERSION}:\n    resolution: {{integrity: sha512-y}}\n"
        ),
    );
    assert!(!routine_local_runner(&value));
}

#[test]
fn a_monorepo_lockfile_still_refuses_a_patched_runner() {
    let dir = workspace();
    let root = dir.path();

    // Narrowing to this workspace's importer reads the `packages` block
    // first, so everything that block refuses still refuses the whole file.
    let value = only_lockfile(
        root,
        "pnpm-lock.yaml",
        &format!(
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    devDependencies:\n      eslint:\n        specifier: {DECLARED_VERSION}\n        version: {INSTALLED_VERSION}\n\npatchedDependencies:\n\n  eslint:\n    hash: abc\n    path: patches/eslint.patch\n\npackages:\n\n  eslint@8.57.0:\n    resolution: {{integrity: sha512-x}}\n\n  eslint@{INSTALLED_VERSION}:\n    resolution: {{integrity: sha512-y}}\n"
        ),
    );
    assert!(!routine_local_runner(&value));
}

#[test]
fn a_nested_workspace_is_named_by_its_path_under_the_lockfile() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    let nested = root.join("packages/app");

    write(
        &nested.join("package.json"),
        &format!(r#"{{"devDependencies": {{"eslint": "{DECLARED_VERSION}"}}}}"#),
    );
    write(
        &nested.join("node_modules/eslint/package.json"),
        &format!(r#"{{"name": "eslint", "version": "{INSTALLED_VERSION}"}}"#),
    );
    write(
        &nested.join("node_modules/eslint/bin/eslint.js"),
        "#!/usr/bin/env node\n",
    );

    // pnpm keeps one lockfile at the monorepo root and names every workspace
    // below it by the path between them, so the run is read through the key
    // its own directory spells.
    let lockfile = root.join("pnpm-lock.yaml");
    write(
        &lockfile,
        &format!(
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    devDependencies:\n      eslint:\n        specifier: ^8.0.0\n        version: 8.57.0\n\n  packages/app:\n    devDependencies:\n      eslint:\n        specifier: {DECLARED_VERSION}\n        version: {INSTALLED_VERSION}\n\npackages:\n\n  eslint@8.57.0:\n    resolution: {{integrity: sha512-x}}\n\n  eslint@{INSTALLED_VERSION}:\n    resolution: {{integrity: sha512-y}}\n"
        ),
    );
    let mut value = intent(&nested);
    value.local_executions[0].lockfiles = vec![evidence(&lockfile)];

    assert!(routine_local_runner(&value));
}

#[test]
fn an_importer_pinning_a_release_the_file_never_served_answers_for_nothing() {
    let dir = workspace();
    let root = dir.path();

    // The block says this workspace resolved a release the `packages` block
    // never carries, which leaves the file contradicting itself. The one
    // release it does carry belongs to some other workspace, so it must not
    // be handed over as this workspace's pin.
    let value = only_lockfile(
        root,
        "pnpm-lock.yaml",
        &format!(
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    devDependencies:\n      eslint:\n        specifier: ^10.0.0\n        version: 10.0.0\n\npackages:\n\n  eslint@{INSTALLED_VERSION}:\n    resolution: {{integrity: sha512-x}}\n"
        ),
    );
    assert!(!routine_local_runner(&value));
}

#[test]
fn an_importers_block_that_never_names_this_workspace_answers_for_nothing() {
    let dir = workspace();
    let root = dir.path();

    // Every release in the file belongs to a workspace the block names, and
    // this one is not among them, so the single release it carries says
    // nothing about the copy installed here.
    let value = only_lockfile(
        root,
        "pnpm-lock.yaml",
        &format!(
            "lockfileVersion: '9.0'\n\nimporters:\n\n  packages/api:\n    devDependencies:\n      eslint:\n        specifier: {DECLARED_VERSION}\n        version: {INSTALLED_VERSION}\n\npackages:\n\n  eslint@{INSTALLED_VERSION}:\n    resolution: {{integrity: sha512-x}}\n"
        ),
    );
    assert!(!routine_local_runner(&value));
}
