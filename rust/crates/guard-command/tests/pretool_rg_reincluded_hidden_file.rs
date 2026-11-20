#![cfg(unix)]
//! A hidden fixture file an ignore rule re-includes holds a recursive `rg`
//! only when `rg` would refuse to search that file by name.
//!
//! A repository that commits `tests/fixtures/kit/.mcp.json` re-includes it
//! with `!tests/fixtures/kit/.mcp.json`. `rg PATTERN tests/fixtures/kit/.mcp.json`
//! already proceeds, so `rg PATTERN tests`, which reads the same file through
//! the re-include, proceeds too. A re-included `.env`, `.envrc`, hidden
//! directory or link keeps the review.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// A repository with a root `.env`, a source tree and the hidden fixture
/// `tests/fixtures/kit/.mcp.json`, plus the `.gitignore` and extra files
/// given. The root stays below the target directory: `$TMPDIR` on macOS
/// resolves under `/private/var`, which the sensitive-root screen rejects.
fn repository(gitignore: &str, files: &[(&str, &str)]) -> (PathBuf, PathBuf) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-rg-reincluded-hidden-file")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    let repository = home.join("app");
    std::fs::create_dir_all(repository.join(".git/info")).unwrap();
    write(repository.join(".env"), "KEY=synthetic\n");
    write(repository.join("src/download.test.ts"), "export {};\n");
    write(repository.join("tests/unit/a.test.ts"), "export {};\n");
    write(
        repository.join("tests/fixtures/kit/.mcp.json"),
        "{\"mcpServers\": {}}\n",
    );
    write(repository.join(".gitignore"), gitignore);
    for (file, text) in files {
        write(repository.join(file), text);
    }
    let home = std::fs::canonicalize(home).unwrap();
    let repository = home.join("app");
    (home, repository)
}

fn action(home: &Path, cwd: &Path, command: &str) -> String {
    evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    )
    .minimum_action
}

/// Searches that read whatever an ignore rule puts back within their reach.
const TREE_SEARCHES: [&str; 3] = ["rg -l download tests", "rg -n download .", "rg download"];

/// The same work with a `-g` inclusion, which reads only what it selects.
const GLOB_SEARCH: &str = "rg -l 'download|href' tests src --glob '*.test.ts' | head -80";

const SEARCHES: [&str; 4] = [
    TREE_SEARCHES[0],
    TREE_SEARCHES[1],
    TREE_SEARCHES[2],
    GLOB_SEARCH,
];

#[test]
fn a_reincluded_fixture_file_rg_searches_by_name_proceeds() {
    for gitignore in [
        "node_modules/\n!tests/fixtures/kit/.mcp.json\n",
        "node_modules/\n!/tests/fixtures/kit/.mcp.json\n",
        "node_modules/\n!.mcp.json\n",
    ] {
        let (home, repository) = repository(gitignore, &[]);
        assert_eq!(
            action(
                &home,
                &repository,
                "rg -n download tests/fixtures/kit/.mcp.json"
            ),
            "allow",
            "{gitignore:?}: the file by name"
        );
        for command in SEARCHES {
            assert_eq!(
                action(&home, &repository, command),
                "allow",
                "{gitignore:?}: {command}"
            );
        }
    }
}

/// A `.gitignore`, the extra files it needs, whether the fixture is replaced
/// with a link to the root `.env`, and what the `-g` narrowed search answers
/// there (`None` where the case does not reach the fixture directory).
type Case = (
    &'static str,
    &'static [(&'static str, &'static str)],
    bool,
    Option<&'static str>,
);

#[test]
fn a_reincluded_secret_directory_or_link_keeps_review() {
    let link = |repository: &Path| {
        let kit = repository.join("tests/fixtures/kit");
        std::fs::remove_file(kit.join(".mcp.json")).unwrap();
        std::os::unix::fs::symlink(repository.join(".env"), kit.join(".mcp.json")).unwrap();
    };
    let cases: [Case; 4] = [
        ("!.env\n", &[], false, None),
        (
            "!tests/fixtures/kit/.envrc\n",
            &[("tests/fixtures/kit/.envrc", "export KEY=synthetic\n")],
            false,
            // `*.test.ts` cannot select `.envrc`, so the narrowed search
            // never reads what the re-include brought back.
            Some("allow"),
        ),
        (
            "!tests/fixtures/kit/.settings\n",
            &[("tests/fixtures/kit/.settings/config.json", "{}\n")],
            false,
            // A re-included directory is what the glob would have to skip,
            // and an inclusion glob never prunes one: `rg` walks into it and
            // the rule answers for whatever the walk finds there.
            Some("review"),
        ),
        (
            "!tests/fixtures/kit/.mcp.json\n",
            &[],
            true,
            // The link's own name is what the glob is read against, and
            // `*.test.ts` does not select it.
            Some("allow"),
        ),
    ];
    for (gitignore, files, linked, narrowed) in cases {
        let (home, repository) = repository(gitignore, files);
        if linked {
            link(&repository);
        }
        for command in TREE_SEARCHES {
            if gitignore == "!.env\n" && command.contains("tests") {
                continue;
            }
            let seen = action(&home, &repository, command);
            assert_ne!(seen, "allow", "{gitignore:?}: {command}");
        }
        if let Some(expected) = narrowed {
            assert_eq!(
                action(&home, &repository, GLOB_SEARCH),
                expected,
                "{gitignore:?}: {GLOB_SEARCH}"
            );
        }
    }
}

#[test]
fn a_search_after_cd_is_answered_for_its_own_directory() {
    let (home, repository) = repository("node_modules/\n!tests/fixtures/kit/.mcp.json\n", &[]);
    let tests = repository.join("tests");
    let first = format!("rg -l download {}", tests.display());
    let moved = format!("cd src && rg -l download {}", tests.display());
    assert_eq!(action(&home, &repository, &first), "allow", "{first}");
    let alone = action(&home, &repository, &moved);
    assert_ne!(alone, "allow", "{moved}");
    // The first search must not answer for the second, which runs from `src`
    // where the fixture is not below the working directory.
    let chained = format!("{first}; {moved}");
    assert_eq!(action(&home, &repository, &chained), alone, "{chained}");
}
