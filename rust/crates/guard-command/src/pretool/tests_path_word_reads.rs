use super::*;

fn request(command: &str) -> CommandModelRequestV1 {
    CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    }
}

fn allowed(command: &str) -> bool {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .unwrap();
    let root = root.to_str().unwrap();
    evaluate_pre_tool_with_context(&request(command), Some(root), Some(root))
        .is_ok_and(|decision| decision.minimum_action == "allow")
}

#[test]
fn rewriting_a_path_word_needs_no_review() {
    for command in [
        "dirname /a/b/c",
        "dirname .",
        "dirname -z /a/b/c",
        "dirname -- -weird/path",
        "basename /a/b/c.txt",
        "basename /a/b/c.txt .txt",
        "basename -s .txt /a/b/c.txt",
        "basename -a /a/b /c/d",
        "basename --suffix=.rs src/main.rs",
    ] {
        assert!(allowed(command), "{command}");
    }
}

#[test]
fn resolving_a_path_word_needs_no_review_inside_the_workspace() {
    for command in [
        "realpath Cargo.toml",
        "realpath .",
        "realpath -q src",
        "readlink -f Cargo.toml",
        "readlink -f src",
    ] {
        assert!(allowed(command), "{command}");
    }
}

/// `cat` already prints the `ENOENT` error for an absolute path with nothing
/// at it, and a resolver that reports where the path would be reports less
/// than the reader that would print its bytes. The two answer the same way.
#[test]
fn resolving_an_absent_absolute_path_reads_no_more_than_printing_it() {
    for command in [
        "realpath /nonexistent-guard-sample/notes.txt",
        "realpath -q /nonexistent-guard-sample/nested/notes.txt",
        "readlink -f /nonexistent-guard-sample/notes.txt",
        // The reader that prints the bytes already passes, so the resolver
        // that prints only the path cannot need more.
        "cat /nonexistent-guard-sample/notes.txt",
    ] {
        assert!(allowed(command), "{command}");
    }
}

#[test]
fn an_unproven_path_word_still_takes_review() {
    for command in [
        // An option this proof never screened.
        "dirname --relative-to=/ /a/b",
        "dirname -X /a/b",
        "basename -X /a/b",
        "realpath --relative-to=/tmp Cargo.toml",
        "realpath --relative-base=/ Cargo.toml",
        "readlink --badoption Cargo.toml",
        // The shell runs the substitution before the rewrite ever happens.
        "basename \"$(touch marker.txt)\"",
        "dirname \"$(touch marker.txt)\"",
        "basename -s \"$(touch marker.txt)\" src/main.rs",
        "basename --suffix=\"$(touch marker.txt)\" src/main.rs",
        "basename -- \"`touch marker.txt`\"",
        // No operand to rewrite.
        "dirname",
        "basename",
        "realpath",
        // A resolved operand outside the proven read scope.
        "realpath /nonexistent-guard-fixture/secret.key",
        "readlink -f /nonexistent-guard-fixture/secret.key",
    ] {
        assert!(!allowed(command), "{command}");
    }
}

/// A checkout beside the session with one dependency installed through a
/// content store, the way pnpm and Bun install one.
fn package_tree_checkout() -> tempfile::TempDir {
    // Not the private temporary directory: a path below it has its own
    // screens, and the directory it hands out is itself hidden.
    let base = std::env::current_exe()
        .expect("executable")
        .ancestors()
        .nth(3)
        .expect("target directory")
        .join("package-tree-fixtures");
    std::fs::create_dir_all(&base).expect("base");
    let home = tempfile::Builder::new()
        .prefix("home")
        .tempdir_in(&base)
        .expect("home");
    let root = home.path().join("other-project");
    let store = root.join("node_modules/.pnpm/codegen-kit@2.1.0/node_modules/codegen-kit/bin");
    std::fs::create_dir_all(&store).expect("store");
    std::fs::write(store.join("codegen-kit.js"), "#!/usr/bin/env node\n").expect("launcher");
    std::os::unix::fs::symlink(
        ".pnpm/codegen-kit@2.1.0/node_modules/codegen-kit",
        root.join("node_modules/codegen-kit"),
    )
    .expect("entry");
    std::fs::create_dir_all(root.join("node_modules/.bin")).expect("shims");
    std::os::unix::fs::symlink(
        "../codegen-kit/bin/codegen-kit.js",
        root.join("node_modules/.bin/codegen-kit"),
    )
    .expect("shim");
    // A hidden directory of the user's own, beside the package tree.
    std::fs::create_dir_all(root.join(".config/tool")).expect("config");
    std::fs::write(root.join(".config/tool/settings"), "theme = dark\n").expect("settings");
    home
}

fn allowed_in(home: &std::path::Path, command: &str) -> bool {
    let home = home.canonicalize().expect("home");
    let workspace = home.join("session-workspace");
    std::fs::create_dir_all(&workspace).ok();
    evaluate_pre_tool_with_context(&request(command), home.to_str(), workspace.to_str())
        .is_ok_and(|decision| decision.minimum_action == "allow")
}

#[test]
fn resolving_a_package_manager_shim_needs_no_review() {
    let home = package_tree_checkout();
    let root = home
        .path()
        .canonicalize()
        .expect("home")
        .join("other-project");
    let root = root.display();
    for command in [
        format!("realpath {root}/node_modules/.bin/codegen-kit"),
        format!("realpath -q {root}/node_modules/.bin/codegen-kit"),
        format!("readlink -f {root}/node_modules/.bin/codegen-kit"),
        format!("realpath {root}/node_modules/codegen-kit/bin/codegen-kit.js"),
    ] {
        assert!(allowed_in(home.path(), &command), "{command}");
    }
}

#[test]
fn another_hidden_directory_beside_the_package_tree_keeps_its_review() {
    let home = package_tree_checkout();
    let root = home
        .path()
        .canonicalize()
        .expect("home")
        .join("other-project");
    let root = root.display();
    for command in [
        // `.config` is the user's own, not a directory a package manager wrote.
        format!("realpath {root}/.config/tool/settings"),
        format!("readlink -f {root}/.config/tool/settings"),
    ] {
        assert!(!allowed_in(home.path(), &command), "{command}");
    }
}

#[test]
fn a_hidden_component_outside_a_package_tree_is_not_admitted() {
    use super::path_word_reads::package_tree_path;
    for path in [
        "/w/node_modules/.bin/tsc",
        "/w/node_modules/.pnpm/tsc@1.0.0/node_modules/typescript/bin/tsc",
        "/w/packages/web/node_modules/.store/x/node_modules/x/index.js",
    ] {
        assert!(package_tree_path(std::path::Path::new(path)), "{path}");
    }
    for path in [
        // `.bin` only counts directly below `node_modules`.
        "/w/.bin/tsc",
        "/w/tools/.bin/tsc",
        // A package manager does not write `.cache` or `.ssh` there.
        "/w/node_modules/.cache/tsc",
        "/w/node_modules/.ssh/id_ed25519",
        // A hidden directory above the tree is the user's own.
        "/w/.config/node_modules/.bin/tsc",
        // No package tree at all.
        "/w/src/main.rs",
    ] {
        assert!(!package_tree_path(std::path::Path::new(path)), "{path}");
    }
}
