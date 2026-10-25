#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

struct FixtureDirectory(std::path::PathBuf);

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn recursive_search_exclusions_prove_only_unread_descendants() {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/recursive-file-search")
        .join(format!("exclusions-{}-{nonce}", std::process::id()));
    let _fixture = FixtureDirectory(root.clone());
    std::fs::create_dir_all(root.join("tests/fixtures/tls")).unwrap();
    std::fs::create_dir_all(root.join("mixed")).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    // Match the real project's scale without touching production credentials.
    for index in 0..5_025 {
        std::fs::write(root.join(format!("tests/case-{index}.test.ts")), "ordinary").unwrap();
    }
    std::fs::write(
        root.join("tests/fixtures/tls/test-root-ca.key"),
        "synthetic key",
    )
    .unwrap();
    std::fs::write(root.join("mixed/one.ts"), "ordinary").unwrap();
    std::fs::write(root.join("mixed/private.key"), "synthetic key").unwrap();
    std::os::unix::fs::symlink(root.join("mixed/private.key"), root.join("mixed/alias.ts"))
        .unwrap();
    for harness in ["omp", "zcode"] {
        for (command, expected) in [
            ("grep -rn ordinary tests/", false),
            ("grep -rn --exclude-dir=fixtures ordinary tests/", true),
            ("grep -rn --exclude-dir fixtures ordinary tests/", true),
            ("grep -rn ordinary tests/ --exclude-dir=fixtures", false),
            ("grep -rn --exclude-dir=fixture ordinary tests/", false),
            ("grep -rn --exclude=fixtures ordinary tests/", false),
            ("grep -rn --exclude=test-root-ca.key ordinary tests/", true),
            ("grep -rn --exclude test-root-ca.key ordinary tests/", true),
            (
                "grep -rn --exclude=test-root-ca.key ordinary tests/fixtures/tls/test-root-ca.key",
                false,
            ),
            (
                "grep -rn --exclude-dir=fixtures ordinary tests/fixtures/",
                false,
            ),
            (
                "grep -rn --exclude-dir=fixtures ordinary tests/ mixed/",
                false,
            ),
            // Both names are excluded, and `-r` does not read through the
            // link, so nothing grep would open is left unproven.
            (
                "grep -rn --exclude=private.key --exclude=alias.ts ordinary mixed/",
                true,
            ),
            ("grep -rn --exclude='*.key' ordinary tests/", false),
            (
                "grep -rn --exclude-dir=fixtures ordinary tests/ --exclude",
                false,
            ),
            ("grep -rn --exclude-dir= fixtures ordinary tests/", false),
            (
                "grep -rn --exclude= test-root-ca.key ordinary tests/",
                false,
            ),
            (
                "grep -rn --exclude=test-root-ca.key --include=test-root-ca.key ordinary tests/",
                false,
            ),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"toolName":"Bash", "toolInput":{"command":command}}),
                None,
                None,
                root.to_str(),
                root.to_str(),
            );
            assert_eq!(
                result.minimum_action == "allow",
                expected,
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn recursive_search_checks_every_reachable_path() {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/recursive-file-search")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    let _fixture = FixtureDirectory(root.clone());
    std::fs::create_dir_all(root.join("src")).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::write(root.join("src/one.ts"), "ordinary source").unwrap();
    std::fs::write(root.join("src/two.ts"), "ordinary source").unwrap();
    std::fs::create_dir_all(root.join("__tests__/nested")).unwrap();
    std::fs::write(
        root.join("__tests__/nested/canary.test.ts"),
        "ordinary source",
    )
    .unwrap();
    std::fs::create_dir_all(root.join("unsafe-tests")).unwrap();
    std::fs::write(root.join("unsafe-tests/.env"), "ordinary synthetic secret").unwrap();
    std::fs::write(root.join(".env"), "ordinary synthetic secret").unwrap();
    std::os::unix::fs::symlink(root.join(".env"), root.join("src/alias.ts")).unwrap();
    std::os::unix::fs::symlink(root.join("__tests__"), root.join("test-alias")).unwrap();
    for harness in ["omp", "zcode"] {
        for cwd in ["~", "~/__tests__"] {
            let command = if cwd == "~" {
                "grep -rn ordinary __tests__/"
            } else {
                "grep -rn ordinary nested/"
            };
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"toolName":"Bash", "toolInput":{"command":command}}),
                None,
                None,
                root.to_str(),
                Some(cwd),
            );
            assert_eq!(result.minimum_action, "allow", "{harness}: {cwd}");
        }
        for (command, expected) in [
            ("grep -rn ordinary src/one.ts src/two.ts".to_owned(), true),
            (
                format!(
                    "grep -rn ordinary {}/src/one.ts {}/src/two.ts",
                    root.display(),
                    root.display()
                ),
                true,
            ),
            ("grep -Rn ordinary src/one.ts".to_owned(), true),
            ("grep --recursive -n ordinary src/one.ts".to_owned(), true),
            (
                "grep --directories=recurse ordinary src/one.ts".to_owned(),
                true,
            ),
            // `src/alias.ts` links to the `.env`, but `-r` lists it without
            // opening it, so the walk is proven by what grep actually reads.
            ("grep -rn ordinary src".to_owned(), true),
            // BSD grep's `-S` turns the same walk into one that reads through
            // every link it meets, so the `.env` behind `src/alias.ts` is back
            // in what the search would open and the walk needs it proven.
            ("grep -rSn ordinary src".to_owned(), false),
            ("grep -rOn ordinary src".to_owned(), false),
            ("grep -rn ordinary __tests__/".to_owned(), true),
            (
                "grep -rn --exclude='*.md' ordinary __tests__/".to_owned(),
                true,
            ),
            (
                format!("grep -rn ordinary {}/__tests__/", root.display()),
                true,
            ),
            ("grep -Rn ordinary __tests__/".to_owned(), true),
            ("grep --recursive ordinary __tests__/".to_owned(), true),
            ("grep -rn ordinary unsafe-tests/".to_owned(), false),
            (
                format!("rg -n ordinary {}/__tests__/", root.display()),
                true,
            ),
            // rg skips the hidden `.env`, exactly as for the relative spelling.
            (
                format!("rg -n ordinary {}/unsafe-tests/", root.display()),
                true,
            ),
            ("rg -n ordinary unsafe-tests/".to_owned(), true),
            ("grep -Rn ordinary test-alias/".to_owned(), false),
            ("grep -rn ordinary __tests__/ src/".to_owned(), true),
            ("grep -rn -e ordinary __tests__/".to_owned(), true),
            ("grep -rn -- ordinary __tests__/".to_owned(), true),
            ("grep -rn ordinary .".to_owned(), false),
            ("grep -rn ordinary".to_owned(), false),
            ("grep -rn ordinary src/missing.ts".to_owned(), false),
            ("grep -rn ordinary src/alias.ts".to_owned(), false),
            ("grep -rn ordinary src/one.ts .env".to_owned(), false),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"toolName":"Bash", "toolInput":{"command":command}}),
                None,
                None,
                root.to_str(),
                root.to_str(),
            );
            assert_eq!(
                result.minimum_action == "allow",
                expected,
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn recursive_search_reads_feature_directories_but_not_credential_stores() {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/recursive-file-search")
        .join(format!("features-{}-{nonce}", std::process::id()));
    let _fixture = FixtureDirectory(root.clone());
    for (path, text) in [
        ("scripts/seeds/mcp/secret-egress/server.json", "{}"),
        (
            "scripts/guard/__pycache__/oauth_token_claims.cpython-312.pyc",
            "x",
        ),
        ("scripts/guard/oauth_token_claims.py", "ordinary"),
        ("scripts/docker-lab/.dockerignore", "ordinary"),
        ("deploy/prod-secrets/db.json", "{}"),
        ("deploy/run.sh", "ordinary"),
    ] {
        let file = root.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, text).unwrap();
    }
    let root = std::fs::canonicalize(root).unwrap();
    for harness in ["omp", "zcode", "claude-code"] {
        for (command, expected) in [
            ("grep -rln ordinary scripts", true),
            ("grep -rn ordinary scripts/seeds", true),
            ("grep -rn ordinary deploy", false),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"toolName":"Bash", "toolInput":{"command":command}}),
                None,
                None,
                root.to_str(),
                root.to_str(),
            );
            assert_eq!(
                result.minimum_action == "allow",
                expected,
                "{harness}: {command}: {}",
                result.reason_code
            );
        }
    }
}

#[test]
fn recursive_search_source_globs_are_not_mistaken_for_env_files() {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/recursive-file-search")
        .join(format!("source-globs-{}-{nonce}", std::process::id()));
    let _fixture = FixtureDirectory(root.clone());
    for (path, text) in [
        ("tests/deploy.test.ts", "ordinary"),
        ("tests/helpers.ts", "ordinary"),
        ("configured/app.test.ts", "ordinary"),
        ("configured/.env", "TOKEN=ordinary"),
    ] {
        let file = root.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, text).unwrap();
    }
    let root = std::fs::canonicalize(root).unwrap();
    for harness in ["omp", "zcode", "claude-code"] {
        for (command, expected) in [
            ("grep -rl --include=*.test.ts ordinary tests", true),
            ("grep -r --include=\"*.test.ts\" -l ordinary tests", true),
            ("grep -rl --include=*.spec.tsx ordinary tests", true),
            ("grep -rl --include=*.ts ordinary tests", true),
            ("grep -rl --include=.env.* ordinary tests", false),
            ("grep -rl --include=*.env.* ordinary tests", false),
            ("grep -rl --include=.env*.ts ordinary tests", false),
            ("grep -rl --include=.e*.ts ordinary tests", false),
            ("grep -rl --include=?env.*.ts ordinary tests", false),
            ("grep -rl --include=[.]env*.ts ordinary tests", false),
            // The walk still refuses a tree that holds a credential file.
            ("grep -rl --include=*.test.ts ordinary configured", false),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"toolName":"Bash", "toolInput":{"command":command}}),
                None,
                None,
                root.to_str(),
                root.to_str(),
            );
            assert_eq!(
                result.minimum_action == "allow",
                expected,
                "{harness}: {command}: {}",
                result.reason_code
            );
        }
    }
}

/// `grep -r` lists a link without reading through it, and `-R` reads through
/// every link it finds. A package store is the ordinary case: every install
/// writes `node_modules/.bin` full of shims pointing back into the packages.
#[test]
fn a_package_store_is_walked_for_what_the_search_actually_reads() {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/recursive-file-search")
        .join(format!("package-store-{}-{nonce}", std::process::id()));
    let _fixture = FixtureDirectory(root.clone());
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("node_modules/.bin")).unwrap();
    std::fs::create_dir_all(root.join("node_modules/vitest/bin")).unwrap();
    let outside = root.with_file_name(format!("outside-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&outside).unwrap();
    let _outside_fixture = FixtureDirectory(outside.clone());
    let outside = std::fs::canonicalize(outside).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::write(root.join("src/index.ts"), "ordinary").unwrap();
    std::fs::write(root.join("node_modules/vitest/package.json"), "{}").unwrap();
    std::fs::write(root.join("node_modules/vitest/bin/vitest.js"), "ordinary").unwrap();
    std::os::unix::fs::symlink(
        root.join("node_modules/vitest/bin/vitest.js"),
        root.join("node_modules/.bin/vitest"),
    )
    .unwrap();
    // A link out of the tree to something the walk has never screened. `-r`
    // never opens it; `-R` would.
    std::fs::write(outside.join("id_rsa"), "synthetic key").unwrap();
    std::os::unix::fs::symlink(outside.join("id_rsa"), root.join("src/alias.ts")).unwrap();
    for harness in ["omp", "zcode"] {
        for (command, expected) in [
            ("grep -rln ordinary .", true),
            ("grep -rln ordinary node_modules/", true),
            ("grep -rln ordinary src/", true),
            ("grep -Rln ordinary .", false),
            ("grep -Rln ordinary src/", false),
            // A glob operand is walked the same way, so it cannot stand in as
            // proof for a search that reads through every link it finds.
            ("grep -Rln ordinary src/*", false),
            ("grep -rln ordinary node_modules/*", true),
            ("grep --dereference-recursive -ln ordinary src/", false),
            // The link is the operand, so every recursive tool follows it and
            // the target still needs proof of its own.
            ("grep -rln ordinary src/alias.ts", false),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"toolName":"Bash", "toolInput":{"command":command}}),
                None,
                None,
                root.to_str(),
                root.to_str(),
            );
            assert_eq!(
                result.minimum_action == "allow",
                expected,
                "{harness}: {command}"
            );
        }
    }
}

/// A pipe in the tree is not a link: a search can be told to read it in place,
/// and what it hands back is not something the walk could have proven.
#[test]
fn a_recursive_search_over_a_pipe_still_asks() {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/recursive-file-search")
        .join(format!("pipe-{}-{nonce}", std::process::id()));
    let _fixture = FixtureDirectory(root.clone());
    std::fs::create_dir_all(root.join("src")).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::write(root.join("src/index.ts"), "ordinary").unwrap();
    let status = std::process::Command::new("mkfifo")
        .arg(root.join("src/stream"))
        .status()
        .unwrap();
    assert!(status.success());
    for harness in ["omp", "zcode"] {
        for (command, expected) in [
            ("grep -rln ordinary src/", false),
            ("grep -rln --devices=read ordinary src/", false),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"toolName":"Bash", "toolInput":{"command":command}}),
                None,
                None,
                root.to_str(),
                root.to_str(),
            );
            assert_eq!(
                result.minimum_action == "allow",
                expected,
                "{harness}: {command}"
            );
        }
    }
}
