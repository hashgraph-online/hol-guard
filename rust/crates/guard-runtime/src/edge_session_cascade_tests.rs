use std::time::{Duration, Instant};

use super::{
    call_digest, let_through, stopped, Kind, Observed, Stop, Tracker, FANOUT_PRIORS, FANOUT_WINDOW,
    LOOP_PRIORS, LOOP_WINDOW,
};

fn base() -> guard_contracts::PreToolResultV1 {
    guard_command::pretool::evaluate_pre_tool_envelope(
        "claude-code",
        "PreToolUse",
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "cwd": "/tmp",
            "tool_input": {"command": "ls"}
        }),
    )
}

fn digest(tool: &str, input: serde_json::Value) -> ([u8; 32], Kind) {
    call_digest(&serde_json::json!({"tool_name": tool, "tool_input": input})).unwrap()
}

fn bash(command: &str) -> ([u8; 32], Kind) {
    digest("Bash", serde_json::json!({"command": command}))
}

fn spawn(prompt: &str) -> ([u8; 32], Kind) {
    digest(
        "Agent",
        serde_json::json!({"description": "part", "prompt": prompt, "subagent_type": "general-purpose"}),
    )
}

fn call(
    tracker: &mut Tracker,
    session: &str,
    (digest, kind): ([u8; 32], Kind),
    allowed: bool,
    now: Instant,
) -> Option<Stop> {
    tracker.observe(
        &Observed {
            session,
            request: None,
            digest,
            kind,
            allowed,
        },
        now,
    )
}

#[test]
fn the_sixth_identical_call_in_a_row_is_stopped_once() {
    let mut tracker = Tracker::default();
    let start = Instant::now();
    for step in 0..LOOP_PRIORS {
        let at = start + Duration::from_secs(step as u64);
        assert_eq!(call(&mut tracker, "s", bash("npm test"), true, at), None);
    }
    let at = start + Duration::from_secs(LOOP_PRIORS as u64);
    assert_eq!(
        call(&mut tracker, "s", bash("npm test"), true, at),
        Some(Stop::Loop)
    );
    // The stop ends the streak: trying again runs.
    assert_eq!(
        call(
            &mut tracker,
            "s",
            bash("npm test"),
            true,
            at + Duration::from_secs(1)
        ),
        None
    );
}

#[test]
fn any_other_call_between_repeats_breaks_the_streak() {
    let mut tracker = Tracker::default();
    let start = Instant::now();
    for step in 0..20u64 {
        let at = start + Duration::from_secs(step);
        assert_eq!(call(&mut tracker, "s", bash("cargo test"), true, at), None);
        let edit = digest(
            "Edit",
            serde_json::json!({"file_path": "src/lib.rs", "old_string": format!("a{step}"), "new_string": "b"}),
        );
        assert_eq!(call(&mut tracker, "s", edit, true, at), None);
    }
}

#[test]
fn different_commands_never_stop() {
    let mut tracker = Tracker::default();
    let now = Instant::now();
    for command in [
        "ls",
        "git status",
        "npm test",
        "cat README.md",
        "git diff",
        "npm run build",
        "ls -la",
    ] {
        assert_eq!(call(&mut tracker, "s", bash(command), true, now), None);
    }
}

#[test]
fn slow_repeats_and_other_sessions_do_not_count() {
    let mut tracker = Tracker::default();
    let start = Instant::now();
    for step in 0..10u64 {
        let at = start + LOOP_WINDOW * (step as u32) + Duration::from_secs(step);
        assert_eq!(call(&mut tracker, "s", bash("make"), true, at), None);
    }
    for step in 0..10u64 {
        let session = format!("session-{step}");
        assert_eq!(
            call(&mut tracker, &session, bash("make"), true, start),
            None
        );
    }
}

#[test]
fn reviewed_calls_are_never_counted_or_stopped() {
    let mut tracker = Tracker::default();
    let now = Instant::now();
    for _ in 0..(LOOP_PRIORS * 3) {
        assert_eq!(
            call(&mut tracker, "s", bash("rm -rf build"), false, now),
            None
        );
    }
    // A reviewed call between allowed repeats breaks the streak too.
    for _ in 0..LOOP_PRIORS - 1 {
        assert_eq!(call(&mut tracker, "s", bash("npm test"), true, now), None);
    }
    assert_eq!(call(&mut tracker, "s", bash("npm test"), false, now), None);
    assert_eq!(call(&mut tracker, "s", bash("npm test"), true, now), None);
}

#[test]
fn a_redelivered_request_is_counted_once() {
    let mut tracker = Tracker::default();
    let now = Instant::now();
    let (digest, kind) = bash("npm test");
    for _ in 0..(LOOP_PRIORS * 3) {
        let observed = Observed {
            session: "s",
            request: Some("same-request"),
            digest,
            kind,
            allowed: true,
        };
        assert_eq!(tracker.observe(&observed, now), None);
    }
}

#[test]
fn a_user_prompt_starts_the_counts_again() {
    let mut tracker = Tracker::default();
    let now = Instant::now();
    for _ in 0..LOOP_PRIORS {
        call(&mut tracker, "s", bash("npm test"), true, now);
    }
    tracker.prompt("s");
    assert_eq!(call(&mut tracker, "s", bash("npm test"), true, now), None);
}

#[test]
fn the_ninth_subagent_in_a_minute_is_stopped_once() {
    let mut tracker = Tracker::default();
    let start = Instant::now();
    for step in 0..FANOUT_PRIORS {
        let at = start + Duration::from_secs(step as u64);
        assert_eq!(
            call(&mut tracker, "s", spawn(&format!("part {step}")), true, at),
            None
        );
    }
    let at = start + Duration::from_secs(FANOUT_PRIORS as u64);
    assert_eq!(
        call(&mut tracker, "s", spawn("one more"), true, at),
        Some(Stop::Fanout)
    );
    assert_eq!(call(&mut tracker, "s", spawn("one more"), true, at), None);
}

#[test]
fn a_few_subagents_or_a_slow_trickle_run() {
    let mut tracker = Tracker::default();
    let start = Instant::now();
    for step in 0..4u64 {
        assert_eq!(
            call(&mut tracker, "a", spawn(&format!("p{step}")), true, start),
            None
        );
    }
    for step in 0..30u64 {
        let at = start + FANOUT_WINDOW / 4 * (step as u32);
        assert_eq!(
            call(&mut tracker, "b", spawn(&format!("p{step}")), true, at),
            None
        );
    }
}

#[test]
fn only_let_through_results_are_counted() {
    let result = |minimum: &str, decision: &str| guard_contracts::PreToolResultV1 {
        minimum_action: minimum.into(),
        decision: decision.into(),
        ..base()
    };
    assert!(let_through(&result("allow", "allow")));
    assert!(let_through(&result("warn", "allow")));
    assert!(let_through(&result("sandbox-required", "allow")));
    assert!(let_through(&result("sandbox-required", "deny")));
    assert!(!let_through(&result("review", "deny")));
    assert!(!let_through(&result("require-reapproval", "deny")));
    assert!(!let_through(&result("block", "deny")));
    assert!(!let_through(&result("allow", "deny")));
}

#[test]
fn a_stop_is_a_block_that_names_its_reason() {
    let loop_stop = stopped(base(), &Stop::Loop);
    assert_eq!(loop_stop.minimum_action, "block");
    assert_eq!(loop_stop.decision, "deny");
    assert_eq!(
        loop_stop.reason_code,
        "native_session_repeated_call_stopped"
    );
    let fanout = stopped(base(), &Stop::Fanout);
    assert_eq!(fanout.reason_code, "native_session_subagent_fanout_stopped");
}

#[test]
fn only_a_shell_command_loops_into_a_stop() {
    let mut tracker = Tracker::default();
    let now = Instant::now();
    for tool in ["Read", "wait", "Grep"] {
        for _ in 0..(LOOP_PRIORS * 3) {
            let call_input = digest(tool, serde_json::json!({"path": "README.md"}));
            assert_eq!(
                call(&mut tracker, "s", call_input, true, now),
                None,
                "{tool}"
            );
        }
    }
    for tool in ["Bash", "bash", "PowerShell"] {
        assert_eq!(
            digest(tool, serde_json::json!({"command": "ls"})).1,
            Kind::Shell
        );
    }
    for tool in ["Agent", "Task", "task"] {
        assert_eq!(
            digest(tool, serde_json::json!({"prompt": "x"})).1,
            Kind::Subagent
        );
    }
}
