//! `rg` skips hidden files unless something selects them again: a `!` rule
//! in an ignore file it honors, a file type whose globs name dotfiles, or an
//! extra ignore file. A Bash `rg` search stays unproved when any of these can
//! bring a hidden secret such as `.env` into reach.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    home: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// A home holding one repository per name, each with a root `.env` and
/// the ignore files given for it.
fn fixture(repositories: &[(&str, &[(&str, &str)])]) -> Fixture {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    fixture_in(&base, repositories)
}

fn fixture_in(base: &Path, repositories: &[(&str, &[(&str, &str)])]) -> Fixture {
    let root = base.join("pretool-rg-hidden-whitelist").join(format!(
        "home-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    for (name, files) in repositories {
        let repository = home.join(name);
        std::fs::create_dir_all(repository.join(".git/info")).unwrap();
        write(repository.join("src/main.rs"), "fn main() {}\n");
        write(repository.join(".env"), "KEY=synthetic\n");
        for (file, text) in *files {
            write(repository.join(file), text);
        }
    }
    Fixture { root, home }
}

fn action(fixture: &Fixture, cwd: &str, command: &str) -> String {
    evaluate(fixture, cwd, command).minimum_action
}

fn evaluate(fixture: &Fixture, cwd: &str, command: &str) -> guard_contracts::PreToolResultV1 {
    let cwd = fixture.home.join(cwd);
    evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        None,
        None,
        fixture.home.to_str(),
        cwd.to_str(),
    )
}

fn assert_actions(fixture: &Fixture, cwd: &str, commands: &[&str], expected: &str) {
    for command in commands {
        assert_eq!(action(fixture, cwd, command), expected, "{cwd}: {command}");
    }
}

#[test]
fn an_ignore_file_that_re_includes_a_hidden_secret_keeps_rg_reviewed() {
    let fixture = fixture(&[
        ("dot-ignore", &[(".ignore", "!.env\n")]),
        ("gitignore", &[(".gitignore", "*.log\n!.env\n")]),
        (
            "nested",
            &[
                ("src/.rgignore", "!.env\n"),
                ("src/.env", "KEY=synthetic\n"),
            ],
        ),
        (
            "template",
            &[
                (".gitignore", ".env*\n!.env.example\n"),
                (".env.example", "KEY=\n"),
            ],
        ),
        ("wildcard", &[(".gitignore", "!.*\n")]),
        ("excluded", &[(".git/info/exclude", "!.env\n")]),
        // `rg` enters an ignored directory again when another rule
        // re-includes it, and then honors the ignore files inside.
        (
            "reentered",
            &[
                (".gitignore", "build\n!build\n"),
                ("build/.ignore", "!.env\n"),
            ],
        ),
    ]);
    for cwd in [
        "dot-ignore",
        "gitignore",
        "nested",
        "wildcard",
        "excluded",
        "template",
    ] {
        assert_actions(&fixture, cwd, &["rg -n foo", "rg foo ."], "review");
    }
    assert_actions(&fixture, "reentered", &["rg -n foo"], "review");
    // The review names the narrower search Guard can prove.
    let result = evaluate(&fixture, "template", "rg -n foo");
    assert!(
        result.reason.contains("Name the directories to search"),
        "{}",
        result.reason
    );
    let other = evaluate(&fixture, "template", "rg -n foo | sh");
    assert!(
        !other.reason.contains("Name the directories"),
        "{}",
        other.reason
    );
    // A root below the re-including file still honors it, when a hidden
    // file it names is there.
    assert_actions(&fixture, "nested", &["rg -n foo src"], "review");
    write(fixture.home.join("dot-ignore/src/.env"), "KEY=synthetic\n");
    assert_actions(&fixture, "dot-ignore", &["rg -n foo src"], "review");
    // A root beside the ignore file is out of its reach.
    let sibling = fixture.home.join("nested/docs/guide.md");
    write(sibling, "guide\n");
    assert_actions(&fixture, "nested", &["rg -n foo docs"], "allow");
    // Listing names reads no contents.
    assert_actions(&fixture, "dot-ignore", &["rg --files"], "allow");
}

#[test]
fn benign_negations_and_pruned_directories_keep_rg_allowed() {
    let fixture = fixture(&[
        (
            "benign",
            &[
                (
                    ".gitignore",
                    ".env\n/target\nnode_modules/\nrust/target\n!.gitkeep\n!*.rs\n!/docs/\n",
                ),
                ("logs/.gitkeep", ""),
                // `rg` never enters these, so their rules do not apply.
                ("target/.ignore", "!.env\n"),
                ("web/node_modules/pkg/.ignore", "!.env\n"),
                ("rust/target/.ignore", "!.env\n"),
                ("rust/src/lib.rs", "pub fn f() {}\n"),
            ],
        ),
        // A rule that would re-include a template that is not there.
        ("absent", &[(".gitignore", ".env*\n!.env.example\n")]),
        ("plain", &[]),
    ]);
    assert_actions(
        &fixture,
        "benign",
        &["rg -n foo", "rg foo .", "rg -n foo src", "rg -n foo rust"],
        "allow",
    );
    assert_actions(&fixture, "absent", &["rg -n foo"], "allow");
    assert_actions(
        &fixture,
        "plain",
        &["rg -n foo", "rg -n foo -t rust"],
        "allow",
    );
}

#[test]
fn rg_file_types_that_name_dotfiles_stay_reviewed() {
    let fixture = fixture(&[("plain", &[])]);
    assert_actions(
        &fixture,
        "plain",
        &[
            "rg -n foo -t rust",
            "rg -n foo --type rust",
            "rg -n foo -tpy",
            "rg -n foo --type=ts",
            "rg -n foo -T sh",
        ],
        "allow",
    );
    assert_actions(
        &fixture,
        "plain",
        &[
            "rg -n foo -t sh",
            "rg -n foo -tsh",
            "rg -n foo --type sh",
            "rg -n foo --type=ruby",
            "rg -n foo -t all",
            "rg -n foo --type-add 'x:include:sh' -t x",
            "rg -n foo --type-add 'rust:include:sh' -t rust",
            "rg -n foo --ignore-file other.ignore",
            "rg -n foo --ignore-file=other.ignore",
        ],
        "review",
    );
}

#[test]
fn a_wildcard_negation_that_matches_a_hidden_directory_keeps_rg_reviewed() {
    // `!.c[a]rgo` re-includes the whole `.cargo` directory, credentials and
    // all, just as `!.cargo` would.
    let fixture = fixture(&[
        (
            "bracket",
            &[
                (".gitignore", "!.c[a]rgo\n"),
                (".cargo/credentials.toml", "token = \"synthetic\"\n"),
            ],
        ),
        (
            "question",
            &[
                (".ignore", "!.confi?/\n"),
                (".config/app.toml", "token = 1\n"),
            ],
        ),
        // The same wildcard with nothing hidden to match stays allowed.
        ("unmatched", &[(".gitignore", "!.c[a]rgo\n")]),
    ]);
    assert_actions(&fixture, "bracket", &["rg -n foo"], "review");
    assert_actions(&fixture, "question", &["rg -n foo"], "review");
    std::fs::remove_file(fixture.home.join("unmatched/.env")).unwrap();
    assert_actions(&fixture, "unmatched", &["rg -n foo"], "allow");
}

#[test]
fn a_gitignore_outside_any_repository_is_not_honored() {
    // The checkout's own `target` directory sits inside a repository.
    let fixture = fixture_in(&std::env::temp_dir(), &[]);
    let plain = fixture.home.join("notes");
    write(plain.join(".gitignore"), "!.env\n");
    write(plain.join(".env"), "KEY=synthetic\n");
    write(plain.join("todo.md"), "todo\n");
    assert_actions(&fixture, "notes", &["rg -n foo"], "allow");
    // A repository below it honors its own `.gitignore` all the way down.
    let nested = plain.join("app");
    std::fs::create_dir_all(nested.join(".git")).unwrap();
    write(nested.join("src/.gitignore"), "!.env\n");
    write(nested.join("src/.env"), "KEY=synthetic\n");
    assert_actions(&fixture, "notes", &["rg -n foo"], "review");
}

#[test]
fn a_pattern_file_search_checks_the_roots_after_it() {
    let fixture = fixture(&[(
        "nested",
        &[
            ("src/.rgignore", "!.env\n"),
            ("src/.env", "KEY=synthetic\n"),
            ("patterns.txt", "KEY\n"),
            ("docs/guide.md", "guide\n"),
        ],
    )]);
    // The root after the pattern file is what `rg` searches, so a root
    // beside the re-including file stays allowed.
    assert_actions(
        &fixture,
        "nested",
        &[
            "rg -f patterns.txt docs",
            "rg --file patterns.txt docs",
            "rg -fpatterns.txt docs",
            "rg docs -f patterns.txt",
        ],
        "allow",
    );
    assert_actions(
        &fixture,
        "nested",
        &[
            "rg -f patterns.txt src",
            "rg --file patterns.txt src",
            "rg -fpatterns.txt src",
        ],
        "review",
    );
}

#[test]
fn a_path_rule_above_the_search_root_does_not_prune() {
    let fixture = fixture(&[(
        "subdir",
        &[
            (".gitignore", "rust/target\n"),
            ("rust/target/.ignore", "!.env\n"),
            ("rust/target/.env", "KEY=synthetic\n"),
            ("rust/src/lib.rs", "pub fn f() {}\n"),
        ],
    )]);
    // `rg` before 15 skips slash rules from parent ignore files, so a
    // search from `rust` enters `target` and reads its `.env`.
    assert_actions(&fixture, "subdir/rust", &["rg -n foo"], "review");
    assert_actions(&fixture, "subdir/rust", &["rg -n foo src"], "allow");
}

#[test]
fn a_nested_repository_exclude_file_is_honored() {
    let fixture = fixture(&[(
        "outer",
        &[
            ("vendor/lib/.git/info/exclude", "!.env\n"),
            ("vendor/lib/.env", "KEY=synthetic\n"),
            ("vendor/lib/src/lib.rs", "pub fn f() {}\n"),
        ],
    )]);
    // `rg` reads the nested clone's own `info/exclude`, which is local and
    // never committed.
    assert_actions(
        &fixture,
        "outer",
        &["rg -n foo", "rg -n foo vendor"],
        "review",
    );
    assert_actions(&fixture, "outer", &["rg -n foo src"], "allow");
}

#[test]
fn a_pipe_into_rg_reads_the_previous_step_rather_than_the_tree() {
    let fixture = fixture(&[(
        "template",
        &[
            (".gitignore", ".env*\n!.env.example\n"),
            (".env.example", "KEY=\n"),
        ],
    )]);
    // An ignore rule answers for what a walk would re-include. After a pipe
    // and without a path operand `rg` reads the previous step's output, so
    // there is no walk for the rule to reach.
    assert_actions(
        &fixture,
        "template",
        &[
            "cat src/main.rs | rg -n foo",
            "cat src/main.rs | rg foo",
            "cat src/main.rs | rg -n \"(/Users/|hostname)\"",
        ],
        "allow",
    );
    // A path operand is still a walk, wherever the segment sits.
    assert_actions(
        &fixture,
        "template",
        &["cat src/main.rs | rg -n foo .", "rg -n foo"],
        "review",
    );
}

#[test]
fn inclusion_globs_that_cannot_reach_a_re_included_secret_keep_rg_allowed() {
    let fixture = fixture(&[(
        "template",
        &[
            (".gitignore", ".env*\n!.env.example\n"),
            (".env.example", "KEY=\n"),
        ],
    )]);
    // The negation re-includes a hidden file, so a whole-tree search is
    // unproved however narrow its pattern.
    assert_actions(&fixture, "template", &["rg -n foo"], "review");
    // A `-g` inclusion is a whitelist: with one of them `rg` reads only what
    // it selects, and `src/**` cannot select the re-included template.
    assert_actions(
        &fixture,
        "template",
        &[
            "rg -n foo --glob 'src/**'",
            "rg -n foo -g 'src/**'",
            "rg -l foo --glob 'src/**'",
            "rg --files-with-matches foo --glob 'src/**'",
        ],
        "allow",
    );
    // An inclusion that does reach the re-included file proves nothing, and
    // neither does one whose case folding the scope filter cannot model.
    assert_actions(
        &fixture,
        "template",
        &[
            "rg -n foo --glob '**'",
            "rg -n foo --glob '.env*'",
            "rg -n foo --iglob 'src/**'",
            "rg -n foo --glob 'src/**' --iglob '.ENV*'",
        ],
        "review",
    );
    // An exclusion only takes files away, so it narrows nothing on its own.
    assert_actions(
        &fixture,
        "template",
        &["rg -n foo --glob '!.env.example'"],
        "review",
    );
}

#[test]
fn ambiguous_rg_globs_cannot_hide_reincluded_secret_names() {
    let fixture = fixture(&[(
        "template",
        &[
            (".gitignore", ".env*\n!.env.test.ts\n"),
            (".env.test.ts", "KEY=SYNTHETIC_MARKER_ONLY\n"),
        ],
    )]);
    // Across ripgrep versions a comment-shaped inclusion may not be
    // installed, and whitespace can be normalized before glob matching.
    // Neither spelling may justify screening away the hidden filename.
    assert_actions(
        &fixture,
        "template",
        &[
            "rg -n KEY --glob '#comment'",
            "rg -n KEY --glob '*.ts '",
            // The first -- is consumed as an option value, not the
            // end of options; the following --iglob is case-blind.
            "rg -n KEY --context-separator -- --iglob '*.TS'",
        ],
        "review",
    );
    assert_actions(
        &fixture,
        "template",
        &[
            "rg -n KEY --glob '*.rs'",
            "rg -n KEY --context-separator -- --glob '*.rs'",
        ],
        "allow",
    );
}

#[test]
fn a_path_glob_with_explicit_rg_root_cannot_hide_reincluded_secrets() {
    let fixture = fixture(&[(
        "explicit-root",
        &[
            ("src/.gitignore", "!.env.test.ts\n"),
            ("src/.env.test.ts", "KEY=SYNTHETIC_MARKER_ONLY\n"),
            ("src/app.ts", "const KEY = 1;\n"),
        ],
    )]);
    // Ripgrep matches 'src/*.ts' against paths from the cwd, even when
    // 'src' is the explicit search operand. The hidden filename is reached.
    assert_actions(
        &fixture,
        "explicit-root",
        &[
            "rg -n KEY src --glob 'src/*.ts'",
            "rg -n KEY --glob 'src/*.ts'",
        ],
        "review",
    );
    // A basename-only inclusion can be matched from either root safely.
    assert_actions(
        &fixture,
        "explicit-root",
        &["rg -n KEY src --glob '*.rs'"],
        "allow",
    );
    // An unrelated path-shaped glob is still safely narrow from the cwd.
    assert_actions(
        &fixture,
        "explicit-root",
        &["rg -n KEY --glob 'docs/**'"],
        "allow",
    );
}

#[test]
fn broad_rg_globs_must_not_reopen_gitignored_secrets() {
    let fixture = fixture(&[("ignored", &[(".gitignore", ".env*\n")])]);
    assert_actions(
        &fixture,
        "ignored",
        &["rg -n route -g '**'", "rg -n route --glob '**'"],
        "review",
    );
    assert_actions(&fixture, "ignored", &["rg -n route -g 'src/**'"], "allow");
}
