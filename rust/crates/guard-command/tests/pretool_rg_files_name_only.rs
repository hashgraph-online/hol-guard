#![cfg(unix)]

//! `rg --files` over a tree that holds a hidden entry.
//!
//! `--files` prints the paths `rg` would search and opens none of them, and
//! without `--hidden` it never descends into a hidden file or directory. The
//! roots it names are therefore proven as a listing is, stepping over hidden
//! descendants the way `rg` does. Every visible entry keeps the screens a
//! reading walk applies, and a content search of the same root still has to
//! answer for the hidden entries it would open.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::PreToolResultV1;
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

fn fixture() -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-rg-files-name-only")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    let app = home.join("portal");
    std::fs::create_dir_all(app.join(".git")).unwrap();
    write(app.join("src/main.ts"), "export const main = 1;\n");

    // A scratch directory an agent wrote into: ordinary sources beside the
    // hidden entries a running service and an initialised repository leave.
    let scratch = home.join("scratch");
    write(scratch.join("notes.txt"), "first draft\n");
    write(
        scratch.join("preserved/src/catalog.ts"),
        "export const c = [];\n",
    );
    write(
        scratch.join("preserved/tests/catalog.test.ts"),
        "export const t = 1;\n",
    );
    write(scratch.join(".s.PGSQL.5432.lock"), "4242\n");
    write(scratch.join("pg-run/.s.PGSQL.5432.lock"), "4242\n");
    std::fs::create_dir_all(scratch.join("checkout/.git")).unwrap();
    write(scratch.join("checkout/run.py"), "print('run')\n");

    // Visible names a listing must keep asking about, hidden entries or not.
    write(home.join("store/credentials.json"), "{}\n");
    write(home.join("keys/server.pem"), "-----BEGIN-----\n");
    Fixture { root, home }
}

fn check(f: &Fixture, command: &str, want_allow: bool) {
    let cwd = f.home.join("portal");
    let result: PreToolResultV1 = evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        None,
        None,
        f.home.to_str(),
        cwd.to_str(),
    );
    assert_eq!(
        result.minimum_action,
        if want_allow { "allow" } else { "review" },
        "{command}: {} {}",
        result.minimum_action,
        result.reason_code
    );
}

#[test]
fn a_names_only_listing_steps_over_the_hidden_entries_it_skips() {
    let f = fixture();
    for command in [
        "rg --files ~/scratch",
        "rg --files ~/scratch/pg-run",
        "rg --files -g '*.ts' ~/scratch",
        // `--files` is as often spelled after its operands as before them.
        "rg ~/scratch --files",
        "rg --files ~/scratch ~/scratch/preserved",
    ] {
        check(&f, command, true);
    }
}

#[test]
fn a_listing_that_could_name_or_read_more_keeps_its_review() {
    let f = fixture();
    for command in [
        // `--hidden` is what makes the skipped entries reachable again.
        "rg --files --hidden ~/scratch",
        // An ignore file could re-include a hidden entry the default skips.
        "rg --files --no-ignore ~/scratch",
        // A content search opens what it walks, hidden entries included.
        "rg -n draft ~/scratch",
        // Visible names a listing would print are screened as they always are.
        "rg --files ~/store",
        "rg --files ~/keys",
        // The same root, with the flag after it: a listing proves its roots
        // wherever `--files` is spelled.
        "rg ~/store --files",
        // A parent component leaves the tree these screens walked.
        "rg --files ../scratch",
    ] {
        check(&f, command, false);
    }
}

/// An inclusion glob and an ignore-file negation each bring back a hidden
/// entry `rg` would otherwise skip, so neither listing is a walk that steps
/// over it.
#[test]
fn a_listing_that_re_includes_a_hidden_entry_keeps_its_review() {
    let f = fixture();
    write(f.home.join("vault/notes.txt"), "plain\n");
    write(f.home.join("vault/.ssh/id_ed25519"), "key\n");
    write(f.home.join("ledger/notes.txt"), "plain\n");
    write(f.home.join("ledger/.aws/credentials"), "[default]\n");
    write(f.home.join("ledger/.ignore"), "!.aws/\n");
    check(&f, "rg --files ~/vault", true);
    // A glob that names both the hidden directory and the key in it walks
    // into `.ssh` and prints the key, past the hidden filter.
    for command in [
        "rg --files -g '{.ssh,id_ed25519}' ~/vault",
        "rg --files --glob='{.ssh,id_ed25519}' ~/vault",
        // `--` here is the separator's value, so the `-g` after it still
        // selects the hidden entry.
        "rg --files --context-separator -- -g '{.ssh,id_ed25519}' ~/vault",
        "rg --files ~/ledger",
    ] {
        check(&f, command, false);
    }
}
