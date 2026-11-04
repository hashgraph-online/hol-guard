//! Claude Code's plugin record, its marketplace checkouts, a checkout's
//! commit and HOL's integrity ledger, as `plugin install` and `plugin verify`
//! read them.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{json, Value};

const SCANNED: &str = "0123456789abcdef0123456789abcdef01234567";
const OTHER: &str = "fedcba9876543210fedcba9876543210fedcba98";

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn folder() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "guard-plugin-kit-claude-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("folder");
    root
}

fn call(request: Value) -> Value {
    let response = guard_plugin_kit::run_request(request.to_string().as_bytes());
    assert_eq!(response["ok"], true, "{response}");
    response["result"].clone()
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("parent");
    fs::write(path, text).expect("write");
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

fn state(home: &Path, plugin_id: &str, marketplace: &str) -> Value {
    call(
        json!({"command": "claude", "home": path_str(home), "plugin_id": plugin_id, "marketplace": marketplace}),
    )
}

fn git_head(root: &Path) -> Value {
    call(json!({"command": "git_head", "root": path_str(root)}))["commit"].clone()
}

#[test]
fn a_missing_record_reads_as_nothing_installed() {
    let home = folder();
    let result = state(&home, "toolgate@acme", "acme");
    assert_eq!(result["record"], "read");
    assert_eq!(result["user_plugins"], json!([]));
    assert_eq!(result["entry"], Value::Null);
    assert_eq!(result["marketplace"], Value::Null);
}

#[test]
fn an_unreadable_record_is_never_read_as_empty() {
    let home = folder();
    for text in ["{not json", "[]", r#"{"plugins": []}"#] {
        write(&home.join("plugins/installed_plugins.json"), text);
        let result = state(&home, "toolgate@acme", "acme");
        assert_eq!(result["record"], "unreadable", "{text}");
        assert_eq!(result["user_plugins"], Value::Null);
    }
    fs::write(
        home.join("plugins/installed_plugins.json"),
        b"{\"plugins\": {\"\xff\": []}}",
    )
    .expect("write");
    assert_eq!(
        state(&home, "toolgate@acme", "acme")["record"],
        "unreadable"
    );
}

#[test]
fn the_user_entry_and_scopes_come_from_the_record() {
    let home = folder();
    let record = json!({"version": 2, "plugins": {
        "toolgate@acme": [
            {"scope": "project", "gitCommitSha": OTHER},
            {"scope": "user", "gitCommitSha": SCANNED, "version": "1.2.0", "sourceCommand": 7},
        ],
        "other@acme": [{"scope": "local"}],
        "broken@acme": ["user"],
    }});
    write(
        &home.join("plugins/installed_plugins.json"),
        &record.to_string(),
    );
    let result = state(&home, "toolgate@acme", "acme");
    assert_eq!(result["user_plugins"], json!(["toolgate@acme"]));
    assert_eq!(result["plugins"], json!(["other@acme", "toolgate@acme"]));
    assert_eq!(
        result["entry"],
        json!({"commit": SCANNED, "version": "1.2.0", "source_command": null})
    );
    assert_eq!(state(&home, "other@acme", "acme")["entry"], Value::Null);
}

#[test]
fn a_marketplace_source_is_its_github_repository() {
    let home = folder();
    let cases = [
        (
            json!({"source": "github", "repo": "Acme/ToolGate"}),
            "acme/toolgate",
        ),
        (
            json!({"source": "git", "url": "https://github.com/Acme/ToolGate.git"}),
            "acme/toolgate",
        ),
        (
            json!({"source": "git", "url": "https://github.com/acme/toolgate/"}),
            "acme/toolgate",
        ),
        (
            json!({"source": "git", "url": "https://github.com/acme/.git"}),
            "acme/.git",
        ),
        (
            json!({"source": "git", "url": "https://github.com/acme/toolgate/tree"}),
            "",
        ),
        (
            json!({"source": "git", "url": "https://gitlab.com/acme/toolgate"}),
            "",
        ),
        (
            json!({"source": "git", "url": "https://github.com/acme"}),
            "",
        ),
        (json!("acme/toolgate"), ""),
    ];
    for (source, expected) in cases {
        write(
            &home.join("plugins/known_marketplaces.json"),
            &json!({"acme": {"source": source}}).to_string(),
        );
        assert_eq!(
            state(&home, "toolgate@acme", "acme")["marketplace"]["source"],
            expected,
            "{source}"
        );
    }
    assert_eq!(
        state(&home, "toolgate@acme", "other")["marketplace"],
        Value::Null
    );
}

#[test]
fn a_checkout_gives_its_head_and_declared_command() {
    let home = folder();
    let checkout = folder();
    write(&checkout.join(".git/HEAD"), &format!("{SCANNED}\n"));
    write(
        &checkout.join(".claude-plugin/marketplace.json"),
        &json!({"plugins": [
            {"name": "toolgate", "source": "./plugins/toolgate"},
            {"name": "toolgate", "source": {"source": "command", "command": "node setup.js"}},
        ]})
        .to_string(),
    );
    write(
        &home.join("plugins/known_marketplaces.json"),
        &json!({"acme": {"source": {"repo": "acme/toolgate"}, "installLocation": path_str(&checkout)}}).to_string(),
    );
    let market = state(&home, "toolgate@acme", "acme")["marketplace"].clone();
    assert_eq!(market["head"], SCANNED);
    assert_eq!(market["command"], "node setup.js");
    assert_eq!(
        state(&home, "other@acme", "acme")["marketplace"]["command"],
        Value::Null
    );
    write(
        &home.join("plugins/known_marketplaces.json"),
        &json!({"acme": {"source": {"repo": "acme/toolgate"}, "installLocation": "relative/checkout"}}).to_string(),
    );
    let market = state(&home, "toolgate@acme", "acme")["marketplace"].clone();
    assert_eq!(market["head"], Value::Null);
    assert_eq!(market["command"], Value::Null);
}

#[test]
fn git_head_follows_symbolic_packed_and_linked_refs() {
    let root = folder();
    let git = root.join("repo/.git");
    write(&git.join("HEAD"), "ref: refs/heads/main\n");
    write(
        &git.join("packed-refs"),
        &format!("# pack-refs\r\n{SCANNED} refs/heads/main\r\n"),
    );
    assert_eq!(git_head(&root.join("repo")), SCANNED);
    write(&git.join("refs/heads/main"), &format!("{OTHER}\n"));
    assert_eq!(git_head(&root.join("repo")), OTHER);
    write(&git.join("refs/heads/main"), "not a commit\n");
    assert_eq!(git_head(&root.join("repo")), Value::Null);
    write(&root.join("linked/.git"), "gitdir: ../repo/.git\n");
    write(&git.join("refs/heads/main"), &format!("{SCANNED}\n"));
    assert_eq!(git_head(&root.join("linked")), SCANNED);
    // `git worktree add`: the worktree's own folder holds `HEAD` and names
    // the shared folder its branch refs live in.
    write(
        &root.join("added/.git"),
        "gitdir: ../repo/.git/worktrees/added\n",
    );
    write(
        &git.join("worktrees/added/HEAD"),
        "ref: refs/heads/feature\n",
    );
    write(&git.join("worktrees/added/commondir"), "../..\n");
    assert_eq!(git_head(&root.join("added")), Value::Null);
    write(&git.join("refs/heads/feature"), &format!("{OTHER}\n"));
    assert_eq!(git_head(&root.join("added")), OTHER);
    fs::remove_file(git.join("refs/heads/feature")).expect("remove");
    write(
        &git.join("packed-refs"),
        &format!("{SCANNED} refs/heads/main\n{OTHER} refs/heads/feature\n"),
    );
    assert_eq!(git_head(&root.join("added")), OTHER);
    write(&git.join("HEAD"), "ref: refs/../../../etc/passwd\n");
    assert_eq!(git_head(&root.join("repo")), Value::Null);
    assert_eq!(git_head(&root.join("missing")), Value::Null);
    fs::write(git.join("HEAD"), b"ref: refs/heads/\xff\n").expect("write");
    assert_eq!(git_head(&root.join("repo")), Value::Null);
    assert_eq!(
        call(json!({"command": "git_head", "root": "repo"}))["commit"],
        Value::Null
    );
}

#[test]
fn a_relative_claude_home_is_refused() {
    let response = guard_plugin_kit::run_request(
        json!({"command": "claude", "home": "claude"})
            .to_string()
            .as_bytes(),
    );
    assert_eq!(
        response,
        json!({"ok": false, "error": "plugin_kit_claude_home_invalid"})
    );
}

fn record(commit: &str, version: &str, channel: &str) -> Value {
    json!({"channel": channel, "kind": "git_commit", "version": version, "commitSha": commit})
}

fn ledger(records: Value, events: Value) -> Value {
    json!({"schema": "hol.plugin-integrity-ledger.v1", "slug": "acme/toolgate", "records": records, "events": events})
}

fn integrity(version: Option<&str>, commit: Option<&str>, ledger: Value) -> Value {
    call(json!({
        "command": "integrity",
        "slug": "acme/toolgate",
        "spec_slug": "Acme/ToolGate-Canonical",
        "installed": {"version": version, "commit": commit},
        "ledger": ledger,
    }))
}

#[test]
fn the_installed_commit_is_held_against_its_version() {
    let records = json!([
        record(SCANNED, "1.2.0", "hol_catalog"),
        record(SCANNED, "1.2.0", "github"),
        record(SCANNED, "1.2.0", "github"),
        record(OTHER, "1.1.0", "hol_catalog"),
        {"channel": "npm", "kind": "npm_tarball", "version": "1.2.0", "commitSha": OTHER},
    ]);
    let events = json!([
        {"kind": "republished", "version": "1.2.0", "sentence": "Republished."},
        {"kind": "differs", "sentence": "Any version."},
        {"kind": "differs", "version": "1.1.0", "sentence": "Old version."},
        {"kind": "renamed", "version": "1.2.0", "sentence": "Packaging."},
    ]);
    let result = integrity(
        Some("1.2.0"),
        Some(SCANNED),
        ledger(records.clone(), events),
    );
    assert_eq!(result["status"], "matches");
    assert_eq!(
        result["recorded"],
        json!([{"commit": SCANNED, "channels": ["hol_catalog", "github"]}])
    );
    assert_eq!(
        result["events"],
        json!([
            {"kind": "republished", "version": "1.2.0", "sentence": "Republished."},
            {"kind": "differs", "version": null, "sentence": "Any version."},
        ])
    );
    let status = |version: Option<&str>, commit: Option<&str>| {
        integrity(version, commit, ledger(records.clone(), json!([])))["status"].clone()
    };
    assert_eq!(status(Some("1.1.0"), Some(SCANNED)), "differs");
    assert_eq!(status(Some("2.0.0"), Some(SCANNED)), "not_recorded");
    assert_eq!(status(None, Some(SCANNED)), "no_version");
    assert_eq!(status(Some("1.2.0"), None), "no_commit");
}

#[test]
fn a_malformed_or_foreign_ledger_is_refused() {
    let shapes = [
        json!([]),
        json!({"schema": "other", "slug": "acme/toolgate", "records": [], "events": []}),
        ledger(json!({}), json!([])),
        ledger(json!([{"kind": "git_commit", "channel": 1}]), json!([])),
        ledger(
            json!([{"kind": "git_commit", "channel": "x", "commitSha": 7}]),
            json!([]),
        ),
        ledger(json!([]), json!([{"kind": "differs"}])),
        ledger(
            json!([]),
            json!([{"kind": "differs", "sentence": "s", "channels": [1]}]),
        ),
    ];
    for shape in shapes {
        assert_eq!(
            integrity(Some("1.2.0"), Some(SCANNED), shape.clone()),
            json!({"refused": "shape"}),
            "{shape}"
        );
    }
    let mut foreign = ledger(json!([]), json!([]));
    foreign["slug"] = json!("evil/toolgate");
    assert_eq!(
        integrity(Some("1.2.0"), Some(SCANNED), foreign.clone()),
        json!({"refused": "listing"})
    );
    foreign["slug"] = json!("ACME/toolgate-canonical");
    assert_eq!(
        integrity(Some("1.2.0"), Some(SCANNED), foreign)["status"],
        "not_recorded"
    );
}
