#![cfg(unix)]
//! A recursive content search over a repository root that holds a `.env.bak`
//! or a `.dev.vars` beside the code. The search prints only the lines that
//! match its pattern, so a plain word the sensitive files do not contain adds
//! nothing from them and the search proceeds. A pattern one of them could
//! match, a pattern Guard cannot read as plain text, and files that are never
//! read (keys, credential stores, links) keep the review.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::PreToolResultV1;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    repo: PathBuf,
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

fn fixture(name: &str) -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-grep-pattern-clearance")
        .join(format!("{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let repo = home.join("work/app");
    write(repo.join("src/index.ts"), "export const handler = 1;\n");
    write(repo.join("README.md"), "# Synthetic app\n");
    write(
        repo.join("workers/api/src/index.ts"),
        "export default {};\n",
    );
    write(
        repo.join("workers/api/.dev.vars"),
        "API_TOKEN=placeholder\n",
    );
    write(
        repo.join(".env.bak"),
        "SESSION_SECRET=placeholder\nCOOKIE_NAME=synthetic\n",
    );
    let root = std::fs::canonicalize(&root).unwrap();
    Fixture {
        home: root.join("home"),
        repo: root.join("home/work/app"),
        root,
    }
}

fn run(fixture: &Fixture, harness: &str, tool: &str, input: Value) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": tool, "tool_input": input}),
        None,
        None,
        fixture.home.to_str(),
        fixture.repo.to_str(),
    )
}

fn omp_grep(fixture: &Fixture, input: Value) -> PreToolResultV1 {
    run(fixture, "omp", "grep", input)
}

fn shell(fixture: &Fixture, command: &str) -> PreToolResultV1 {
    run(fixture, "omp", "bash", json!({ "command": command }))
}

fn allowed(result: &PreToolResultV1) -> bool {
    result.minimum_action == "allow"
}

#[test]
fn omp_grep_over_the_repository_root_proceeds_when_the_pattern_cannot_match_a_sensitive_file() {
    let f = fixture("omp-root");
    for input in [
        json!({"pattern": "handler"}),
        json!({"pattern": "handler", "path": "."}),
        json!({"pattern": "some_cookie_name"}),
        json!({"pattern": "handler|helper"}),
        json!({"pattern": "handler", "path": "workers"}),
        json!({"pattern": "handler", "gitignore": false}),
    ] {
        let result = omp_grep(&f, input.clone());
        assert!(allowed(&result), "{input}: {}", result.reason);
    }
}

#[test]
fn omp_grep_keeps_its_review_when_a_sensitive_file_could_print() {
    let f = fixture("omp-held");
    for input in [
        // The pattern occurs in a sensitive file, in any letter case.
        json!({"pattern": "COOKIE_NAME"}),
        json!({"pattern": "cookie_name"}),
        json!({"pattern": "session_secret", "gitignore": false}),
        json!({"pattern": "handler|session_secret"}),
        // A pattern that is not plain text is never read as a clearance.
        json!({"pattern": "hand.*er"}),
        json!({"pattern": "^handler"}),
        json!({"pattern": "[h]andler"}),
        json!({"pattern": "(handler)"}),
    ] {
        let result = omp_grep(&f, input.clone());
        assert!(!allowed(&result), "{input}");
        assert_eq!(result.reason_code, "native_file_read_review", "{input}");
    }
}

#[test]
fn the_omp_review_names_the_sensitive_file_and_never_a_cleared_one() {
    let f = fixture("omp-note");
    let held = omp_grep(&f, json!({"pattern": "cookie_name"}));
    assert!(!allowed(&held));
    assert!(
        held.reason
            .contains("The search would reach `.env.bak`, which Guard treats as sensitive."),
        "{}",
        held.reason
    );
    // `.env.bak` is the only file this pattern could print from; the cleared
    // `.dev.vars` is not named, and no content is shown.
    assert!(!held.reason.contains(".dev.vars"), "{}", held.reason);
    assert!(!held.reason.contains("placeholder"), "{}", held.reason);
    assert!(!held.reason.contains("synthetic"), "{}", held.reason);
}

#[test]
fn key_material_stores_credential_names_and_links_are_never_cleared() {
    // Oh My Pi's `grep` does not hold a certificate or key container by its
    // extension, so `omp` is false for those: the shell walk holds them.
    for (name, relative, text, omp) in [
        ("key", "certs/server.pem", "synthetic\n", false),
        ("store", ".ssh/config", "synthetic\n", true),
        ("aws", ".aws/credentials", "synthetic\n", true),
        ("credential", "credentials.json", "{}\n", true),
        ("secrets", "secrets/db.json", "{}\n", true),
        ("password", "password.txt", "synthetic\n", true),
    ] {
        let f = fixture(&format!("never-{name}"));
        write(f.repo.join(relative), text);
        if omp {
            let result = omp_grep(&f, json!({"pattern": "handler"}));
            assert!(!allowed(&result), "{relative}");
        }
        let result = shell(&f, "grep -rn handler .");
        assert!(!allowed(&result), "{relative}");
    }
    let f = fixture("never-link");
    write(f.home.join("outside.txt"), "synthetic\n");
    std::os::unix::fs::symlink(f.home.join("outside.txt"), f.repo.join(".env.link")).unwrap();
    assert!(!allowed(&omp_grep(&f, json!({"pattern": "handler"}))));
    assert!(!allowed(&shell(&f, "grep -rn handler .")));
}

#[test]
fn a_large_or_binary_sensitive_file_is_never_cleared() {
    let f = fixture("unreadable");
    std::fs::write(f.repo.join(".env.big"), vec![b'x'; 300 * 1024]).unwrap();
    assert!(!allowed(&omp_grep(&f, json!({"pattern": "handler"}))));
    assert!(!allowed(&shell(&f, "grep -rn handler .")));
    std::fs::remove_file(f.repo.join(".env.big")).unwrap();
    std::fs::write(f.repo.join(".env.nul"), b"X=1\0\n").unwrap();
    assert!(!allowed(&omp_grep(&f, json!({"pattern": "handler"}))));
    assert!(!allowed(&shell(&f, "grep -rn handler .")));
}

#[test]
fn a_sensitive_file_with_bytes_past_ascii_is_never_cleared() {
    // A C locale reads `.` as one byte and a UTF-8 locale as one character,
    // so a pattern like `caf.x` can match a Latin-1 or UTF-8 line the check
    // would otherwise call clear.
    for (name, bytes) in [
        ("latin1", b"PASS=caf\xE9x\n".to_vec()),
        ("utf8", "PASS=caf\u{e9}x\n".as_bytes().to_vec()),
    ] {
        let f = fixture(&format!("non-ascii-{name}"));
        std::fs::write(f.repo.join(".env.local"), bytes).unwrap();
        assert!(
            !allowed(&omp_grep(&f, json!({"pattern": "caf.x"}))),
            "{name}"
        );
        assert!(!allowed(&shell(&f, "grep -rn caf.x .")), "{name}");
        assert!(!allowed(&shell(&f, "grep -rn handler .")), "{name}");
    }
}

#[test]
fn bash_grep_over_the_repository_root_proceeds_when_the_pattern_cannot_match() {
    let f = fixture("bash-root");
    for command in [
        "grep -rn handler .",
        "grep -rln some_cookie_name .",
        "grep -rln \"some_cookie_name\" . | head -5",
        "grep -rni HANDLER .",
        "grep -rn -e handler .",
        "grep -rn \"handler|helper\" workers",
    ] {
        let result = shell(&f, command);
        assert!(allowed(&result), "{command}: {}", result.reason);
    }
}

#[test]
fn bash_grep_keeps_its_review_when_a_sensitive_file_could_print() {
    let f = fixture("bash-held");
    for command in [
        "grep -rn cookie_name .",
        "grep -rln COOKIE_NAME .",
        "grep -rln \"cookie.*name\" .",
        "grep -rln \"cookie.name\" .",
        "grep -rn api_token workers",
        "grep -rn \"handler|cookie_name\" .",
        "grep -rn -ehandler .",
        "grep -rn -e handler -e foo .",
        "grep -rnv handler .",
        "grep -rnL handler .",
        "grep -rn --invert-match handler .",
        "grep -rn '^handler' .",
        "grep -rn -f patterns.txt .",
        // A count prints every file it reads, so a match-free sensitive file
        // would still be named in the output.
        "grep -rc handler .",
        "grep -rnc handler .",
        "grep -r --count handler .",
        "grep -rcn handler workers",
    ] {
        let result = shell(&f, command);
        assert!(!allowed(&result), "{command}");
    }
}

#[test]
fn an_excluded_sensitive_file_needs_no_clearance() {
    let f = fixture("bash-exclude");
    for command in [
        "grep -rn --exclude=.env.bak --exclude=.dev.vars cookie_name .",
        "grep -rn --exclude-dir=workers --exclude=.env.bak cookie_name .",
    ] {
        let result = shell(&f, command);
        assert!(allowed(&result), "{command}: {}", result.reason);
    }
    // Excluding one of two sensitive files leaves the other under review.
    let result = shell(&f, "grep -rn --exclude=.env.bak api_token .");
    assert!(!allowed(&result));
}

#[test]
fn the_bash_review_for_a_recursive_search_names_the_file_in_the_omp_grep_words() {
    let f = fixture("bash-note");
    let result = shell(&f, "grep -rln \"cookie.*name\" .");
    assert!(!allowed(&result));
    // A containment posture can replace the review with a sandbox request;
    // the reason text is the review's whenever it stays a review.
    if result.minimum_action == "review" {
        assert!(
            result
                .reason
                .contains("the search would reach `.env.bak`, which Guard treats as sensitive."),
            "{}",
            result.reason
        );
        assert!(
            result.reason.contains("--exclude=<file>") && result.reason.contains("--exclude-dir="),
            "{}",
            result.reason
        );
        assert!(!result.reason.contains("placeholder"), "{}", result.reason);
    }
}

#[test]
fn a_search_named_by_the_absolute_path_of_the_repository_follows_the_same_rule() {
    let f = fixture("absolute");
    let repo = f.repo.display();
    for (command, expected) in [
        (format!("grep -rln \"some_cookie_name\" {repo}/"), true),
        (format!("grep -rln some_cookie_name {repo}"), true),
        (format!("grep -rn handler {repo}/workers/"), true),
        (format!("grep -rn cookie_name {repo}"), false),
        (format!("grep -rln \"cookie.*name\" {repo}/"), false),
        (format!("grep -rn api_token {repo}/workers/"), false),
    ] {
        let result = shell(&f, &command);
        assert_eq!(allowed(&result), expected, "{command}: {}", result.reason);
    }
}

#[test]
fn find_fanout_over_the_absolute_repository_path_proceeds() {
    let f = fixture("find-absolute");
    let repo = f.repo.display();
    for command in [
        format!("find {repo}/workers -type f -name \"*.ts\" -exec grep -l \"handler\" {{}} \\;"),
        format!("find {repo}/workers -type f -name \"*.ts\" -exec grep -l handler {{}} +"),
        format!("find {repo}/src -type f -name \"*.ts\" -print0 | xargs -0 grep -l handler"),
    ] {
        let result = shell(&f, &command);
        assert!(allowed(&result), "{command}: {}", result.reason);
    }
    // A search that is not limited to regular files could read through a link.
    let result = shell(
        &f,
        &format!("find {repo}/workers -name \"*.ts\" -exec grep -l handler {{}} \\;"),
    );
    assert!(!allowed(&result));
}

#[test]
fn a_hidden_folder_the_clearance_admits_is_searched_file_by_file() {
    let f = fixture("hidden-folder");
    write(
        f.repo.join(".cache/notes.txt"),
        "retry window is 30 seconds\n",
    );
    write(
        f.repo.join(".cache/nested/state.log"),
        "<source name=\"synthetic-match\"/>\n",
    );
    // A pattern none of those files hold proceeds, whatever they are named.
    assert!(allowed(&omp_grep(&f, json!({"pattern": "handler"}))));
    assert!(allowed(&shell(&f, "grep -rn handler .")));
    // The Oh My Pi walk never refused a hidden folder by its name, only a file
    // named as sensitive, so that tool searches `.cache` as it always has. The
    // shell walk refuses the folder by name, and a pattern an ordinary-named
    // file inside it holds keeps the review: the folder was admitted on the
    // strength of each file's content.
    for pattern in ["retry", "synthetic-match"] {
        let result = shell(&f, &format!("grep -rn {pattern} ."));
        assert!(!allowed(&result), "{pattern}");
    }
    let result = shell(&f, "grep -rn retry .");
    assert!(
        result.reason.contains("`.cache/notes.txt`"),
        "{}",
        result.reason
    );
    // A file the check cannot read as plain text inside the folder is never cleared.
    write(f.repo.join(".cache/blob.bin"), "caf\u{e9} handler\n");
    assert!(!allowed(&shell(&f, "grep -rn other .")));
}

#[test]
fn a_fan_out_that_prunes_a_vendored_tree_proceeds() {
    let f = fixture("find-prune");
    for command in [
        "find . -name node_modules -prune -o -type f -name \"*.ts\" -exec grep -l handler {} +",
        "find . -type d -name node_modules -prune -o -type f -name \"*.ts\" -exec cat {} +",
        "find . \\( -name node_modules -o -name dist \\) -prune -o -type f -name \"*.ts\" -exec cat {} +",
        "find . -name node_modules -prune -o -name .git -prune -o -type f -name \"*.ts\" -exec cat {} +",
        // A negated test only takes names away from a bounded walk.
        "find . -type f -name \"*.ts\" ! -name \"*.min.ts\" -exec cat {} +",
        "find . -name node_modules -prune -o -type f -name \"*.ts\" -print0 | xargs -0 grep -l handler",
    ] {
        let result = shell(&f, command);
        assert!(allowed(&result), "{command}: {}", result.reason);
    }
}

#[test]
fn a_fan_out_keeps_its_review_when_pruning_cannot_bound_what_the_child_reads() {
    let f = fixture("find-prune-held");
    for command in [
        // An unparenthesized `-o` makes the whole expression a disjunction, so
        // the extension pattern bounds only one of its branches.
        "find . -name \".env.bak\" -o -type f -name \"*.ts\" -exec cat {} +",
        // The pruned branch is the only one carrying a name, so the printing
        // branch hands the child every regular file.
        "find . -name node_modules -prune -o -type f -exec cat {} +",
        // `-prune` outside the `-prune -o` idiom leaves the walk unread.
        "find . -name node_modules -prune -type f -name \"*.ts\" -exec cat {} +",
        // The extension pattern is negated, so it names what is left out.
        "find . -type f ! -name \"*.ts\" -exec cat {} +",
        // Without `-type f` the walk can still reach a link.
        "find . -name node_modules -prune -o -name \"*.ts\" -exec cat {} +",
    ] {
        let result = shell(&f, command);
        assert!(!allowed(&result), "{command}: {}", result.reason);
    }
}
