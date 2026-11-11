use super::*;

fn run(request: Value) -> Value {
    let bytes = serde_json::to_vec(&request).unwrap();
    serde_json::from_slice(&run_command(bytes.as_slice()).unwrap()).unwrap()
}

fn report_of(dry_run: bool, results: Value) -> Value {
    run(json!({"schema": SCHEMA, "op": "report", "dry_run": dry_run, "results": results}))
}

fn only_step(dry_run: bool, result: Value) -> Value {
    report_of(dry_run, json!([result]))["steps"][0].clone()
}

#[test]
fn a_healthy_run_reports_nothing_to_repair() {
    let report = report_of(
        false,
        json!([
            {"step": "daemon", "runtime_status": "healthy"},
            {"step": "command_queue", "repaired_count": 0},
        ]),
    );
    assert_eq!(report["schema"], "guard.repair.v1");
    assert_eq!(report["status"], "healthy");
    assert_eq!(report["steps"][0]["title"], "Guard daemon");
    assert_eq!(report["steps"][0]["runtime_status"], "healthy");
    assert_eq!(
        report["summary"],
        "Guard repair\n  [ok] Guard daemon: Daemon is healthy.\n  [ok] Command queue: Command queue is healthy.\nNothing needed repair."
    );
}

#[test]
fn a_restarted_daemon_is_a_repair() {
    let report = report_of(
        false,
        json!([{"step": "daemon", "runtime_status": "restarted"}]),
    );
    assert_eq!(report["status"], "repaired");
    assert_eq!(report["steps"][0]["status"], "changed");
    assert!(report["summary"]
        .as_str()
        .unwrap()
        .ends_with("Restart any open coding-agent sessions that were blocked."));
}

#[test]
fn a_dry_run_plans_and_says_so() {
    let report = report_of(
        true,
        json!([
            {"step": "daemon", "probe": "unhealthy"},
            {"step": "command_queue"},
        ]),
    );
    assert_eq!(report["status"], "needs_repair");
    assert_eq!(report["steps"][1]["status"], "skipped");
    let summary = report["summary"].as_str().unwrap();
    assert!(summary.starts_with("Guard repair (dry run, nothing changed)\n  [would fix]"));
    assert!(summary.ends_with("Run `hol-guard repair` to apply these fixes."));
}

#[test]
fn an_error_is_cut_and_ends_partial() {
    let long = "x".repeat(400);
    let report = report_of(
        false,
        json!([{"step": "command_queue", "error_type": "OSError", "error_message": long}]),
    );
    let step = &report["steps"][0];
    assert_eq!(step["status"], "error");
    assert_eq!(
        step["error"].as_str().unwrap().len(),
        "OSError: ".len() + 160
    );
    assert_eq!(report["status"], "partial");
    assert!(report["summary"]
        .as_str()
        .unwrap()
        .ends_with("if it persists, run `hol-guard doctor --json`."));
}

#[test]
fn native_runtime_reports_what_the_prune_found() {
    let unavailable = only_step(false, json!({"step": "native_runtime", "detail": null}));
    assert_eq!(unavailable["status"], "skipped");
    assert_eq!(unavailable["outcome"], "unavailable");
    let offered = only_step(
        false,
        json!({"step": "native_runtime", "detail": null, "offered": true}),
    );
    assert_eq!(offered["status"], "error");
    let pruned = only_step(
        true,
        json!({"step": "native_runtime", "detail": {"outcome": "pruned", "stale_dirs": 2, "dead_sockets": 1}}),
    );
    assert_eq!(pruned["status"], "planned");
    assert_eq!(
        pruned["summary"],
        "Would remove 2 stale runtime folder(s) and 1 dead socket(s)."
    );
    assert_eq!(pruned["stale_dirs"], 2);
}

#[test]
fn a_collapse_turns_a_clean_runtime_step_into_a_change() {
    let collapse = json!({"collapsed": 1, "outcome": "collapsed"});
    let step = only_step(
        false,
        json!({"step": "native_runtime",
               "detail": {"outcome": "pruned", "stale_dirs": 0, "dead_sockets": 0},
               "durable_runtimes": collapse}),
    );
    assert_eq!(step["status"], "changed");
    assert_eq!(
        step["summary"],
        "Shared one file among 1 older durable runtime copy."
    );
    assert_eq!(step["durable_runtimes"]["collapsed"], 1);
    let errored = only_step(
        false,
        json!({"step": "native_runtime", "error_type": "OSError", "error_message": "",
               "durable_runtimes": {"collapsed": 3}}),
    );
    assert_eq!(errored["status"], "error");
    assert_eq!(errored["durable_runtimes"]["collapsed"], 3);
}

#[test]
fn an_install_only_a_reinstall_fixes_needs_attention() {
    let step = only_step(
        false,
        json!({"step": "native_install", "report": {
            "outcome": "needs_reinstall", "candidates": 1, "action": null, "summary": "Reinstall."}}),
    );
    assert_eq!(step["status"], "skipped");
    assert_eq!(step["needs_attention"], json!(["native runtime"]));
    assert!(step.get("action").is_none());
    let report = report_of(
        false,
        json!([{"step": "native_install", "report": {
            "outcome": "refused", "candidates": 1, "action": "chmod", "summary": "Refused."}}]),
    );
    assert_eq!(report["status"], "partial");
    assert!(report["summary"].as_str().unwrap().contains(
        "No step failed, and another `hol-guard repair` run reaches the same answer.\nThese still need attention: Native runtime install."
    ));
    let restored = only_step(
        false,
        json!({"step": "native_install", "report": {
            "outcome": "restored", "candidates": 1, "action": "chmod", "summary": "Restored."}}),
    );
    assert_eq!(restored["status"], "changed");
    assert_eq!(restored["action"], "chmod");
}

#[test]
fn onefile_leaks_report_reclaimed_folders_and_budget() {
    let step = only_step(
        false,
        json!({"step": "onefile_leaks", "result": {
            "reclaimed_count": 3, "reclaimed_bytes": 5 * 1024 * 1024 + 7, "unmarked_count": 4,
            "unmarked_scan": "complete", "budget_exhausted": true, "error_count": 0}}),
    );
    assert_eq!(step["status"], "changed");
    assert_eq!(
        step["summary"],
        "Reclaimed 3 leaked folder(s), about 5 MB. Run repair again to continue."
    );
    assert_eq!(step["unmarked_remaining"], 4);
    let report = report_of(
        false,
        json!([{"step": "onefile_leaks", "result": {
            "reclaimed_count": 0, "reclaimed_bytes": 0, "unmarked_count": 9,
            "unmarked_scan": "complete", "budget_exhausted": true, "error_count": 0}}]),
    );
    assert_eq!(report["status"], "healthy");
    let unavailable = only_step(
        false,
        json!({"step": "onefile_leaks", "result": {
            "reclaimed_count": 0, "reclaimed_bytes": 0, "unmarked_count": 0,
            "unmarked_scan": "unavailable", "budget_exhausted": false, "error_count": 0}}),
    );
    assert_eq!(unavailable["status"], "skipped");
    let not_owner = only_step(false, json!({"step": "onefile_leaks", "not_owner": true}));
    assert_eq!(not_owner["status"], "skipped");
}

#[test]
fn hooks_report_reinstalls_failures_and_what_stays_broken() {
    let broken = json!([{"harness": "codex", "setup_status": "broken"},
                        {"harness": "cursor", "setup_status": "partial"}]);
    let planned = only_step(true, json!({"step": "hooks", "broken": broken}));
    assert_eq!(
        planned["summary"],
        "Would reinstall hooks for: codex, cursor."
    );
    let changed = only_step(
        false,
        json!({"step": "hooks", "broken": broken, "repaired": ["codex", "cursor"],
               "failed": [], "still_broken": ["cursor"]}),
    );
    assert_eq!(changed["status"], "changed");
    assert_eq!(
        changed["summary"],
        "Reinstalled hooks for: codex. Still needs attention: cursor."
    );
    assert_eq!(changed["repaired"], json!(["codex"]));
    let stuck = only_step(
        false,
        json!({"step": "hooks", "broken": broken, "repaired": ["cursor"],
               "failed": [], "still_broken": ["cursor"]}),
    );
    assert_eq!(stuck["status"], "skipped");
    let failed = only_step(
        false,
        json!({"step": "hooks", "broken": broken, "repaired": ["codex"], "still_broken": [],
               "failed": [{"harness": "cursor", "error_type": "OSError", "error_message": "denied"}]}),
    );
    assert_eq!(failed["status"], "error");
    assert_eq!(failed["summary"], "Reinstalled 1 app(s); 1 failed: cursor.");
    assert_eq!(
        failed["failed"],
        json!([{"harness": "cursor", "error": "OSError: denied"}])
    );
    let intact = only_step(false, json!({"step": "hooks", "broken": []}));
    assert_eq!(intact["status"], "ok");
}

#[test]
fn package_shims_and_the_queue_report_their_work() {
    let shims = only_step(
        false,
        json!({"step": "package_shims", "managers": ["npm", "pnpm"], "restart_shell_required": true}),
    );
    assert_eq!(shims["summary"], "Regenerated shims for: npm, pnpm.");
    assert_eq!(shims["restart_shell_required"], true);
    let none = only_step(false, json!({"step": "package_shims", "managers": []}));
    assert_eq!(none["status"], "ok");
    let queue = only_step(false, json!({"step": "command_queue", "repaired_count": 2}));
    assert_eq!(queue["summary"], "Cleared 2 stuck queue item(s).");
}

#[test]
fn an_unknown_step_or_op_is_refused() {
    let bytes = serde_json::to_vec(&json!({"schema": SCHEMA, "op": "report", "dry_run": false,
        "results": [{"step": "other"}]}))
    .unwrap();
    assert_eq!(run_command(bytes.as_slice()).unwrap_err(), INVALID);
    let bytes = serde_json::to_vec(&json!({"schema": SCHEMA, "op": "other"})).unwrap();
    assert_eq!(run_command(bytes.as_slice()).unwrap_err(), INVALID);
}

#[test]
fn reconcile_collects_every_error() {
    let answer = run(json!({
        "schema": SCHEMA, "op": "reconcile",
        "launcher_errors": ["codex:denied"],
        "repaired_harnesses": ["codex"], "failed_harnesses": ["grok"],
        "cursor_rebind": {"rebound": true, "reason": "cursor_hook_script_unreadable"},
        "package": {
            "initial": {"manifest_state": "corrupt", "installed_managers": ["npm", "pnpm"]},
            "repaired": ["npm"],
            "verified": {"manager_details": [
                {"manager": "npm", "integrity": "ok", "path_active": true},
                {"manager": "pnpm", "integrity": "mismatch", "path_active": false},
                {"manager": "yarn", "integrity": "mismatch"}
            ]}
        }
    }));
    assert_eq!(answer["repaired_harnesses"], json!(["codex", "cursor"]));
    assert_eq!(answer["failed_harnesses"], json!(["grok"]));
    assert_eq!(answer["repaired_package_managers"], json!(["npm"]));
    assert_eq!(
        answer["errors"],
        json!([
            "launcher:codex:denied",
            "cursor:rebind:failed",
            "package:manifest:corrupt",
            "package:pnpm:integrity",
            "package:pnpm:path_inactive"
        ])
    );
}

#[test]
fn reconcile_reports_missing_status_and_failures() {
    let missing = run(json!({
        "schema": SCHEMA, "op": "reconcile",
        "package": {"initial": {"manifest_state": "valid", "installed_managers": ["npm"]},
                    "repaired": [], "verified": {}}
    }));
    assert_eq!(missing["errors"], json!(["package:npm:status_missing"]));
    let failed = run(json!({
        "schema": SCHEMA, "op": "reconcile",
        "package": {"failed": true}
    }));
    assert_eq!(failed["errors"], json!(["package:reconciliation_failed"]));
    let failed_after_read = run(json!({
        "schema": SCHEMA, "op": "reconcile",
        "package": {"initial": {"manifest_state": "corrupt", "installed_managers": ["npm"]}, "failed": true}
    }));
    assert_eq!(
        failed_after_read["errors"],
        json!(["package:manifest:corrupt", "package:reconciliation_failed"])
    );
    let absent = run(json!({
        "schema": SCHEMA, "op": "reconcile",
        "package": {"initial": {"manifest_state": "absent", "installed_managers": []}}
    }));
    assert_eq!(absent["errors"], json!([]));
}
