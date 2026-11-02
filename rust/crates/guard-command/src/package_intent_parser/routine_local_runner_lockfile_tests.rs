//! The lockfile and manifest evidence behind the routine-runner verdict:
//! what the installed package has to say about itself, and what a lock
//! entry has to pin before it answers for the installed version.

use super::*;

#[test]
fn the_installed_manifest_must_identify_itself() {
    let dir = workspace();
    let root = dir.path();

    write(
        &root.join("node_modules/eslint/package.json"),
        r#"{"name": "eslint-fork", "version": "9.1.0"}"#,
    );
    assert!(!routine_local_runner(&intent(root)));

    write(
        &root.join("node_modules/eslint/package.json"),
        r#"{"name": "eslint"}"#,
    );
    assert!(!routine_local_runner(&intent(root)));
}

#[test]
fn every_lockfile_must_agree_with_the_installed_version() {
    let dir = workspace();
    let root = dir.path();

    write(
        &root.join("package-lock.json"),
        r#"{"packages": {"node_modules/eslint": {"version": "9.0.0"}}}"#,
    );
    assert!(!routine_local_runner(&intent(root)));

    // Two lockfiles that disagree leave no single locked version.
    write(
        &root.join("package-lock.json"),
        &format!(
            r#"{{"packages": {{"node_modules/eslint": {{"version": "{INSTALLED_VERSION}"}}}}}}"#
        ),
    );
    write(
        &root.join("npm-shrinkwrap.json"),
        r#"{"packages": {"node_modules/eslint": {"version": "9.0.0"}}}"#,
    );
    let mut two = intent(root);
    two.local_executions[0]
        .lockfiles
        .push(evidence(&root.join("npm-shrinkwrap.json")));
    assert!(!routine_local_runner(&two));

    // A lockfile that names nothing at all leaves the version unlocked.
    write(&root.join("package-lock.json"), r#"{"packages": {}}"#);
    assert!(!routine_local_runner(&intent(root)));

    // A lockfile Guard cannot read fails closed even when another agrees.
    write(&root.join("package-lock.json"), "{ not json");
    assert!(!routine_local_runner(&intent(root)));
}

#[test]
fn a_bun_lockfile_is_read_as_jsonc() {
    let dir = workspace();
    let root = dir.path();
    fs::remove_file(root.join("package-lock.json")).unwrap();
    write(
        &root.join("bun.lock"),
        &format!(
            "{{\n  // bun writes comments into its text lockfile\n  \"packages\": {{\n    \"eslint\": [\"eslint@{INSTALLED_VERSION}\", {{}}, \"sha512-x\"]\n  }}\n}}\n"
        ),
    );

    let mut value = intent(root);
    value.local_executions[0].lockfiles = vec![evidence(&root.join("bun.lock"))];
    assert!(routine_local_runner(&value));

    write(
        &root.join("bun.lock"),
        "{\n  \"packages\": {\n    \"eslint\": [\"eslint@9.0.0\", {}, \"sha512-x\"]\n  }\n}\n",
    );
    assert!(!routine_local_runner(&value));
}

#[test]
fn the_installed_version_must_satisfy_the_declared_specifier() {
    let dir = workspace();
    let root = dir.path();
    write(
        &root.join("package.json"),
        r#"{"devDependencies": {"eslint": "~9.0.0"}}"#,
    );
    write(
        &root.join("node_modules/eslint/package.json"),
        &format!(r#"{{"name": "eslint", "version": "{INSTALLED_VERSION}"}}"#),
    );

    let mut value = intent(root);
    value.local_executions[0].declared_version = Some("~9.0.0".to_owned());
    assert!(!routine_local_runner(&value));
}

#[test]
fn a_lockfile_that_omits_the_runner_binds_nothing() {
    let dir = workspace();
    let root = dir.path();

    // The second lockfile parses and names other packages, but never this
    // runner. The first one must not answer for it.
    write(
        &root.join("npm-shrinkwrap.json"),
        r#"{"packages": {"node_modules/other": {"version": "1.0.0"}}}"#,
    );
    let mut value = intent(root);
    value.local_executions[0]
        .lockfiles
        .push(evidence(&root.join("npm-shrinkwrap.json")));
    assert!(!routine_local_runner(&value));
}

#[test]
fn a_lock_entry_outside_the_registry_proves_nothing() {
    let dir = workspace();
    let root = dir.path();

    // A linked workspace package is whatever that directory holds today.
    write(
        &root.join("package-lock.json"),
        &format!(
            r#"{{"packages": {{"node_modules/eslint": {{"version": "{INSTALLED_VERSION}", "link": true}}}}}}"#
        ),
    );
    assert!(!routine_local_runner(&intent(root)));

    // So is a checkout resolved from a git remote.
    write(
        &root.join("package-lock.json"),
        &format!(
            r#"{{"packages": {{"node_modules/eslint": {{"version": "{INSTALLED_VERSION}", "resolved": "git+ssh://git@example.test/eslint.git#abc"}}}}}}"#
        ),
    );
    assert!(!routine_local_runner(&intent(root)));

    // A registry tarball is the shape the declared pin actually describes.
    write(
        &root.join("package-lock.json"),
        &format!(
            r#"{{"packages": {{"node_modules/eslint": {{"version": "{INSTALLED_VERSION}", "resolved": "https://registry.example.test/eslint.tgz"}}}}}}"#
        ),
    );
    assert!(routine_local_runner(&intent(root)));
}

#[test]
fn a_bun_entry_naming_a_checkout_is_not_a_release() {
    let dir = workspace();
    let root = dir.path();
    fs::remove_file(root.join("package-lock.json")).unwrap();
    write(
        &root.join("bun.lock"),
        "{\"packages\": {\"eslint\": [\"eslint@github:example/eslint#abc\", {}, \"\"]}}",
    );

    let mut value = intent(root);
    value.local_executions[0].lockfiles = vec![evidence(&root.join("bun.lock"))];
    assert!(!routine_local_runner(&value));
}

/// Replace the workspace's only lockfile with `name`, holding `body`.
fn only_lockfile(root: &Path, name: &str, body: &str) -> PackageIntent {
    fs::remove_file(root.join("package-lock.json")).unwrap();
    write(&root.join(name), body);
    let mut value = intent(root);
    value.local_executions[0].lockfiles = vec![evidence(&root.join(name))];
    value
}

#[test]
fn a_pnpm_lockfile_pins_the_installed_version() {
    let dir = workspace();
    let root = dir.path();

    // pnpm 9 keys its `packages` block by `name@version`, and carries the
    // peers the package was resolved against in parentheses.
    let value = only_lockfile(
        root,
        "pnpm-lock.yaml",
        &format!(
            "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      eslint:\n        specifier: ^9.0.0\n        version: {INSTALLED_VERSION}\n\npackages:\n\n  eslint@{INSTALLED_VERSION}(jiti@2.0.0):\n    resolution: {{integrity: sha512-x}}\n\nsnapshots:\n\n  eslint@9.0.0: {{}}\n"
        ),
    );
    assert!(routine_local_runner(&value));

    // Only the `packages` block pins a release. The `snapshots` block above
    // names the same packages again and must not answer for them.
    write(
        &root.join("pnpm-lock.yaml"),
        &format!("packages:\n\n  eslint@9.0.0:\n    resolution: {{integrity: sha512-x}}\n\nsnapshots:\n\n  eslint@{INSTALLED_VERSION}: {{}}\n"),
    );
    assert!(!routine_local_runner(&value));
}

#[test]
fn the_older_pnpm_key_spellings_still_pin_a_version() {
    let dir = workspace();
    let root = dir.path();

    // Lockfile 6 wrote a leading slash before the `name@version` key.
    let value = only_lockfile(
        root,
        "pnpm-lock.yaml",
        &format!("packages:\n\n  /eslint@{INSTALLED_VERSION}:\n    resolution: {{integrity: sha512-x}}\n"),
    );
    assert!(routine_local_runner(&value));

    // Lockfile 5 separated the name and the version with a slash instead.
    write(
        &root.join("pnpm-lock.yaml"),
        &format!("packages:\n\n  /eslint/{INSTALLED_VERSION}:\n    resolution: {{integrity: sha512-x}}\n"),
    );
    assert!(routine_local_runner(&value));
}

#[test]
fn a_pnpm_lockfile_that_never_names_the_runner_binds_nothing() {
    let dir = workspace();
    let root = dir.path();

    // A package whose name merely starts with the runner's is a different
    // package, and the importer entry above pins nothing on its own.
    let value = only_lockfile(
        root,
        "pnpm-lock.yaml",
        &format!("importers:\n  .:\n    dependencies:\n      eslint:\n        version: {INSTALLED_VERSION}\n\npackages:\n\n  eslint-plugin-demo@1.0.0:\n    resolution: {{integrity: sha512-x}}\n"),
    );
    assert!(!routine_local_runner(&value));
}

#[test]
fn a_pnpm_entry_naming_a_source_is_not_a_release() {
    let dir = workspace();
    let root = dir.path();

    // pnpm writes the source into the key, so a directory dependency says
    // nothing about what the declared range would have installed.
    let value = only_lockfile(
        root,
        "pnpm-lock.yaml",
        "packages:\n\n  eslint@file:../eslint:\n    resolution: {directory: ../eslint, type: directory}\n",
    );
    assert!(!routine_local_runner(&value));
}

#[test]
fn a_yarn_classic_lockfile_pins_the_installed_version() {
    let dir = workspace();
    let root = dir.path();

    let value = only_lockfile(
        root,
        "yarn.lock",
        &format!(
            "# THIS IS AN AUTOGENERATED FILE.\n\neslint@^9.0.0:\n  version \"{INSTALLED_VERSION}\"\n  resolved \"https://registry.yarnpkg.com/eslint/-/eslint-{INSTALLED_VERSION}.tgz#abc\"\n  integrity sha512-x\n"
        ),
    );
    assert!(routine_local_runner(&value));

    write(
        &root.join("yarn.lock"),
        "eslint@^9.0.0:\n  version \"9.0.0\"\n  resolved \"https://registry.yarnpkg.com/eslint/-/eslint-9.0.0.tgz#abc\"\n",
    );
    assert!(!routine_local_runner(&value));
}

#[test]
fn a_yarn_berry_lockfile_pins_the_installed_version() {
    let dir = workspace();
    let root = dir.path();

    // Berry quotes its headers, writes YAML scalars and names the source on
    // a `resolution` line instead of a registry URL.
    let value = only_lockfile(
        root,
        "yarn.lock",
        &format!(
            "__metadata:\n  version: 8\n  cacheKey: 10\n\n\"eslint@npm:^9.0.0\":\n  version: {INSTALLED_VERSION}\n  resolution: \"eslint@npm:{INSTALLED_VERSION}\"\n  checksum: 10/abc\n  languageName: node\n  linkType: hard\n"
        ),
    );
    assert!(routine_local_runner(&value));
}

#[test]
fn a_yarn_entry_outside_the_registry_proves_nothing() {
    let dir = workspace();
    let root = dir.path();

    // Yarn 1 resolves a checkout without a registry URL.
    let value = only_lockfile(
        root,
        "yarn.lock",
        &format!(
            "eslint@^9.0.0:\n  version \"{INSTALLED_VERSION}\"\n  resolved \"file:../eslint\"\n"
        ),
    );
    assert!(!routine_local_runner(&value));

    // Berry names a patched copy in the resolution it records.
    write(
        &root.join("yarn.lock"),
        &format!(
            "\"eslint@npm:^9.0.0\":\n  version: {INSTALLED_VERSION}\n  resolution: \"eslint@patch:eslint@npm%3A{INSTALLED_VERSION}#./.yarn/patch.diff\"\n"
        ),
    );
    assert!(!routine_local_runner(&value));

    // A block that never names a version pins nothing either.
    write(
        &root.join("yarn.lock"),
        "eslint@^9.0.0:\n  resolved \"https://registry.yarnpkg.com/eslint/-/eslint-9.1.0.tgz#abc\"\n",
    );
    assert!(!routine_local_runner(&value));
}

#[test]
fn a_yarn_lockfile_that_never_names_the_runner_binds_nothing() {
    let dir = workspace();
    let root = dir.path();

    let value = only_lockfile(
        root,
        "yarn.lock",
        &format!(
            "eslint-plugin-demo@^1.0.0:\n  version \"{INSTALLED_VERSION}\"\n  resolved \"https://registry.yarnpkg.com/eslint-plugin-demo/-/eslint-plugin-demo-{INSTALLED_VERSION}.tgz#abc\"\n"
        ),
    );
    assert!(!routine_local_runner(&value));
}

#[test]
fn a_binary_bun_lockfile_gives_no_verdict() {
    let dir = workspace();
    let root = dir.path();

    // `bun.lockb` is Bun's binary format. Nothing in it can be read, so the
    // workspace holding one keeps its review.
    let value = only_lockfile(root, "bun.lockb", "#!/usr/bin/env bun\nnot a lockfile\n");
    assert!(!routine_local_runner(&value));
}

#[test]
fn a_patched_pnpm_entry_is_not_the_release_it_names() {
    let dir = workspace();
    let root = dir.path();

    // A patch rewrites the package's files after the registry served them,
    // so the version in the key no longer describes what is installed.
    let value = only_lockfile(
        root,
        "pnpm-lock.yaml",
        &format!(
            "packages:\n\n  eslint@{INSTALLED_VERSION}(patch_hash=abc123):\n    resolution: {{integrity: sha512-x}}\n"
        ),
    );
    assert!(!routine_local_runner(&value));
}

#[test]
fn a_lockfile_9_patch_is_read_from_the_patched_dependencies_block() {
    let dir = workspace();
    let root = dir.path();

    // Lockfile 9 splits the package metadata from the resolved graph, and it
    // is the `snapshots` key that carries `patch_hash=`. The `packages` key
    // is spelled like any other release, so the patch is only visible in the
    // top-level block that every lockfile version writes.
    let value = only_lockfile(
        root,
        "pnpm-lock.yaml",
        &format!(
            "lockfileVersion: '9.0'\n\npatchedDependencies:\n  eslint@{INSTALLED_VERSION}:\n    hash: abc123\n    path: patches/eslint.patch\n\npackages:\n\n  eslint@{INSTALLED_VERSION}:\n    resolution: {{integrity: sha512-x}}\n\nsnapshots:\n\n  eslint@{INSTALLED_VERSION}(patch_hash=abc123): {{}}\n"
        ),
    );
    assert!(!routine_local_runner(&value));
}

#[test]
fn a_patched_dependency_block_naming_another_package_still_pins() {
    let dir = workspace();
    let root = dir.path();

    // Patching something else says nothing about the runner, and the block's
    // own body lines must not be read as patch keys either.
    let value = only_lockfile(
        root,
        "pnpm-lock.yaml",
        &format!(
            "lockfileVersion: '9.0'\n\npatchedDependencies:\n  eslint-plugin-demo@1.0.0:\n    hash: abc123\n    path: patches/demo.patch\n\npackages:\n\n  eslint@{INSTALLED_VERSION}:\n    resolution: {{integrity: sha512-x}}\n"
        ),
    );
    assert!(routine_local_runner(&value));
}

#[test]
fn a_pnpm_entry_resolved_from_a_checkout_is_not_a_release() {
    let dir = workspace();
    let root = dir.path();

    // Lockfile 5 wrote a plain `name/version` key for a git dependency and
    // left the remote to the entry body, so the key alone proves nothing.
    let value = only_lockfile(
        root,
        "pnpm-lock.yaml",
        &format!(
            "packages:\n\n  /eslint/{INSTALLED_VERSION}:\n    resolution: {{type: git, repo: git@example.test:demo/eslint.git, commit: abc}}\n"
        ),
    );
    assert!(!routine_local_runner(&value));
}

#[test]
fn a_pnpm_entry_that_never_resolves_pins_nothing() {
    let dir = workspace();
    let root = dir.path();

    // A truncated lockfile holds the key but never says what it resolved to.
    let value = only_lockfile(
        root,
        "pnpm-lock.yaml",
        &format!("packages:\n\n  eslint@{INSTALLED_VERSION}:\n"),
    );
    assert!(!routine_local_runner(&value));
}

#[test]
fn a_yarn_classic_header_naming_a_tarball_proves_nothing() {
    let dir = workspace();
    let root = dir.path();

    // Yarn 1 keeps the requested source in the header and still writes a
    // `resolved` URL for it, so only the header says this is not a release.
    let value = only_lockfile(
        root,
        "yarn.lock",
        &format!(
            "eslint@https://example.test/eslint.tgz:\n  version \"{INSTALLED_VERSION}\"\n  resolved \"https://example.test/eslint.tgz#abc\"\n"
        ),
    );
    assert!(!routine_local_runner(&value));
}

#[test]
fn a_yarn_berry_patch_block_fails_the_whole_lockfile() {
    let dir = workspace();
    let root = dir.path();

    // Berry keeps the npm block the patch was taken from. Skipping the patch
    // block would leave that one answering for a copy nobody installed.
    let value = only_lockfile(
        root,
        "yarn.lock",
        &format!(
            "\"eslint@npm:^9.0.0\":\n  version: {INSTALLED_VERSION}\n  resolution: \"eslint@npm:{INSTALLED_VERSION}\"\n\n\"eslint@patch:eslint@npm%3A{INSTALLED_VERSION}#./.yarn/patch.diff\":\n  version: {INSTALLED_VERSION}\n  resolution: \"eslint@patch:eslint@npm%3A{INSTALLED_VERSION}#./.yarn/patch.diff\"\n"
        ),
    );
    assert!(!routine_local_runner(&value));
}

#[test]
fn a_yarn_line_that_opens_no_block_fails_the_whole_lockfile() {
    let dir = workspace();
    let root = dir.path();

    // A column-zero line that is not a header is a file Guard cannot read,
    // whatever the blocks before it said.
    let value = only_lockfile(
        root,
        "yarn.lock",
        &format!(
            "eslint@^9.0.0:\n  version \"{INSTALLED_VERSION}\"\n  resolved \"https://registry.yarnpkg.com/eslint/-/eslint-{INSTALLED_VERSION}.tgz#abc\"\n\nnot a header\n"
        ),
    );
    assert!(!routine_local_runner(&value));
}

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
    // release, so the `packages` block is left to answer on its own.
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
