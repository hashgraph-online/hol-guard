use super::{
    ensure_argv, gate_line, hands_off, kickable, startup, warms_up, Gate, Kick, LaneKick,
    DAEMON_REFUSED, DAEMON_UNREACHABLE,
};
use crate::mcp_relay_args::parse;
use std::cell::Cell;
use std::time::{Duration, Instant};

/// Answers each kick with `answer` and counts them.
struct FakeKick {
    answer: Kick,
    kicks: usize,
}

impl LaneKick for FakeKick {
    fn kick(&mut self, _deadline: Instant) -> Kick {
        self.kicks += 1;
        self.answer
    }
}

fn kick(answer: Kick) -> FakeKick {
    FakeKick { answer, kicks: 0 }
}

/// Not ready (with `code`) for the first `misses` probes, then ready.
fn probes(
    misses: usize,
    code: &'static str,
) -> (Cell<usize>, impl Fn(&Cell<usize>) -> Result<(), String>) {
    let probe = move |count: &Cell<usize>| {
        count.set(count.get() + 1);
        if count.get() > misses {
            Ok(())
        } else {
            Err(code.to_owned())
        }
    };
    (Cell::new(0), probe)
}

const BUDGET: Duration = Duration::from_millis(400);

#[test]
fn a_ready_lane_relays_without_asking_the_daemon() {
    let (count, probe) = probes(0, "direct_lane_unbound");
    let mut fake = kick(Kick::Requested);
    let gate = startup(&mut |_| probe(&count), &mut fake, BUDGET);
    assert!(matches!(gate, Gate::Relay { kicked: false, .. }));
    assert_eq!((count.get(), fake.kicks), (1, 0));
}

#[test]
fn an_unbound_lane_relays_once_the_daemon_binds_it() {
    let (count, probe) = probes(3, "direct_lane_unbound");
    let mut fake = kick(Kick::Requested);
    let gate = startup(&mut |_| probe(&count), &mut fake, BUDGET);
    assert!(matches!(gate, Gate::Relay { kicked: true, .. }));
    assert_eq!((count.get(), fake.kicks), (4, 1));
}

#[test]
fn a_lane_still_unbound_at_the_deadline_is_not_ready_with_its_code() {
    let (count, probe) = probes(usize::MAX, "direct_lane_ack_missing");
    let mut fake = kick(Kick::Requested);
    let started = Instant::now();
    let gate = startup(
        &mut |_| probe(&count),
        &mut fake,
        Duration::from_millis(150),
    );
    assert_eq!(gate, Gate::NotReady("direct_lane_ack_missing".to_owned()));
    assert!(started.elapsed() >= Duration::from_millis(150));
    assert_eq!(fake.kicks, 1);
}

#[test]
fn a_down_or_refusing_daemon_is_not_ready_at_once() {
    for (answer, code) in [
        (Kick::DaemonUnreachable, DAEMON_UNREACHABLE),
        (Kick::Refused, DAEMON_REFUSED),
    ] {
        let (count, probe) = probes(usize::MAX, "direct_lane_unbound");
        let mut fake = kick(answer);
        let gate = startup(&mut |_| probe(&count), &mut fake, BUDGET);
        assert_eq!(gate, Gate::NotReady(code.to_owned()));
        assert_eq!((count.get(), fake.kicks), (1, 1));
    }
}

#[test]
fn a_skipped_kick_keeps_probing_until_the_deadline() {
    let (count, probe) = probes(3, "direct_lane_unbound");
    let mut fake = kick(Kick::Skipped);
    let gate = startup(&mut |_| probe(&count), &mut fake, BUDGET);
    assert!(matches!(gate, Gate::Relay { kicked: false, .. }));
    assert_eq!((count.get(), fake.kicks), (4, 1));
    let (count, probe) = probes(usize::MAX, "direct_lane_unbound");
    let mut fake = kick(Kick::Skipped);
    let gate = startup(
        &mut |_| probe(&count),
        &mut fake,
        Duration::from_millis(150),
    );
    assert_eq!(gate, Gate::NotReady("direct_lane_unbound".to_owned()));
    assert!(!hands_off("direct_lane_unbound"));
}

#[test]
fn a_reason_the_daemon_cannot_clear_is_not_ready_without_a_kick() {
    for code in [
        "mcp_relay_facts_unavailable",
        "mcp_relay_reply_invalid",
        "mcp_relay_runtime_superseded",
        "mcp_relay_evidence_undrained",
        "direct_lane_unsupported",
    ] {
        let (count, probe) = probes(usize::MAX, code);
        let mut fake = kick(Kick::Requested);
        let gate = startup(&mut |_| probe(&count), &mut fake, BUDGET);
        assert_eq!(gate, Gate::NotReady(code.to_owned()));
        assert_eq!(fake.kicks, 0);
    }
}

#[test]
fn only_lane_defers_the_daemon_can_clear_are_kickable() {
    for code in [
        "direct_lane_unbound",
        "direct_lane_ack_missing",
        "direct_lane_ack_mismatch",
        "direct_lane_ack_expired",
        "direct_lane_workspace_unknown",
        "direct_lane_snapshot_unavailable",
        "direct_lane_input_changed",
        "mcp_relay_harness_unbound",
        "mcp_relay_view_missing",
        "mcp_relay_resident_unreachable",
    ] {
        assert!(kickable(code), "{code}");
    }
    for code in [
        "direct_lane_unsupported",
        "mcp_relay_policy_need",
        "mcp_relay_reply_invalid",
        "mcp_relay_binding_incomplete",
    ] {
        assert!(!kickable(code), "{code}");
    }
}

#[test]
fn the_gate_line_has_a_fixed_shape() {
    let ready = Gate::Relay {
        kicked: true,
        elapsed: Duration::from_millis(42),
    };
    assert_eq!(
        gate_line(&ready),
        "hol-guard mcp-relay: lane ready: kicked 42 ms\n"
    );
    assert_eq!(
        gate_line(&Gate::NotReady("direct_lane_unbound".to_owned())),
        "hol-guard mcp-relay: lane not ready: direct_lane_unbound\n"
    );
    assert_eq!(
        gate_line(&Gate::NotReady(
            "mcp_relay_session_server_proxy_tools".to_owned()
        )),
        "hol-guard mcp-relay: python proxy: mcp_relay_session_server_proxy_tools\n"
    );
}

#[test]
fn only_a_lane_the_daemon_has_not_prepared_yet_keeps_the_session_native() {
    for code in [
        DAEMON_UNREACHABLE,
        "direct_lane_unbound",
        "direct_lane_snapshot_unavailable",
        "direct_lane_ack_missing",
        "direct_lane_ack_mismatch",
        "direct_lane_ack_expired",
        "direct_lane_workspace_unknown",
        "direct_lane_input_changed",
        "mcp_relay_harness_unbound",
        "mcp_relay_view_missing",
        "mcp_relay_resident_unreachable",
        "mcp_relay_session_server_unknown",
    ] {
        assert!(warms_up(code) && !hands_off(code), "{code}");
    }
    // Every other reason `mcp_relay_ready`, the probe or the gate can name
    // runs the session as the Python proxy, as before the lane warmed up.
    for code in [
        DAEMON_REFUSED,
        "direct_lane_unsupported",
        "mcp_relay_runtime_superseded",
        "mcp_relay_workspace_invalid",
        "mcp_relay_evidence_undrained",
        "mcp_relay_binding_incomplete",
        "mcp_relay_view_invalid",
        "mcp_relay_layers_unavailable",
        "mcp_relay_session_review_mode",
        "mcp_relay_session_redaction_unbound",
        "mcp_relay_store_unreadable",
        "mcp_relay_saved_remote_policy",
        "mcp_relay_saved_policy_unverifiable",
        "mcp_relay_session_server_proxy_tools",
        "mcp_relay_facts_unavailable",
        "mcp_relay_request_unsendable",
        "mcp_relay_reply_invalid",
    ] {
        assert!(hands_off(code), "{code}");
    }
    assert!(
        hands_off("mcp_relay_a_code_added_later"),
        "an unknown code hands off"
    );
}

#[test]
fn the_ensure_command_reuses_the_proxy_interpreter_and_guard_home() {
    let argv: Vec<String> = [
        "/opt/py/bin/python3",
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "codex-mcp-proxy",
        "--guard-home",
        "/g",
        "--home",
        "/h",
        "--server-name",
        "demo",
        "--config-path",
        "/c/config.toml",
        "--command",
        "/bin/cat",
    ]
    .map(str::to_owned)
    .to_vec();
    let args = parse(&argv).unwrap();
    assert_eq!(
        ensure_argv(&args, &argv).unwrap(),
        [
            "/opt/py/bin/python3",
            "-m",
            "codex_plugin_scanner.cli",
            "guard",
            "daemon",
            "ensure",
            "--guard-home",
            "/g",
            "--home",
            "/h",
        ]
    );
}
