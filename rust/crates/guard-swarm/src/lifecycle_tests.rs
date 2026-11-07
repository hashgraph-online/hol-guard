//! Disposable CLI doubles exercise the actual stdin, JSONL, child ownership,
//! action and shutdown paths without authenticating or calling a model.
use crate::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

const START: &str = "printf '%s\\n' '{\"type\":\"thread.started\",\"thread_id\":\"session-1\"}'\n";
const FINISH: &str = "printf '%s\\n' '{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"Finished fixture task\"}}' '{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":12,\"output_tokens\":3}}'\n";

fn fixture(body: &str) -> (tempfile::TempDir, Service, Launch) {
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("fixture-cli");
    fs::write(&executable, format!("#!/bin/sh\nprintf '%s\\n' \"$@\" >> args.txt\ncat >> prompts.txt\n{START}{body}\n{FINISH}")).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let mut service = Service::default();
    service.test_executable = Some(executable);
    let request = Launch {
        request_id: "launch-1".into(),
        epoch: service.snapshot().unwrap().epoch,
        harness: "codex".into(),
        workspace: directory.path().to_string_lossy().into(),
        task: "review $(touch escaped)\n--dangerously-bypass-approvals".into(),
        model: None,
    };
    (directory, service, request)
}

fn wait(service: &Service, id: &str, until: impl Fn(&Agent) -> bool) -> Agent {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let agent = service
            .registry
            .lock()
            .unwrap()
            .runs
            .get(id)
            .unwrap()
            .agent
            .clone();
        if until(&agent) {
            return agent;
        }
        assert!(
            Instant::now() < deadline,
            "agent did not reach expected state: {:?}",
            agent.state
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn action(request: &Launch, agent: &Agent, id: &str, kind: &str, text: Option<&str>) -> Action {
    Action {
        request_id: id.into(),
        epoch: request.epoch.clone(),
        run_id: agent.id.clone(),
        expected_revision: agent.revision,
        action: kind.into(),
        text: text.map(str::to_owned),
    }
}

#[test]
fn launch_and_resume_use_literal_stdin_and_idempotent_requests() {
    let (dir, service, request) = fixture("");
    let first = service.launch(request.clone()).unwrap();
    let ready = wait(&service, &first.id, |a| {
        a.state == AgentState::AwaitingInput
    });
    assert!(!service.has_active_runs());
    assert!(ready.controls.message && !ready.controls.interrupt);
    assert_eq!(ready.input_tokens, 12);
    assert_eq!(service.launch(request.clone()).unwrap().id, first.id);
    assert_eq!(
        fs::read_to_string(dir.path().join("prompts.txt")).unwrap(),
        request.task
    );
    assert!(!dir.path().join("escaped").exists());
    let follow = action(&request, &ready, "follow-1", "message", Some("next task"));
    service.action(follow.clone()).unwrap();
    service.action(follow).unwrap();
    let next = wait(&service, &first.id, |a| {
        a.state == AgentState::AwaitingInput && a.input_tokens == 24
    });
    assert_eq!(next.output_tokens, 6);
    assert_eq!(
        fs::read_to_string(dir.path().join("prompts.txt")).unwrap(),
        format!("{}next task", request.task)
    );
    assert!(fs::read_to_string(dir.path().join("args.txt"))
        .unwrap()
        .contains("exec\nresume\nsession-1\n--json\n-"));
    assert!(service
        .events(&first.id)
        .unwrap()
        .iter()
        .any(|e| e.text == "Finished fixture task"));
}

#[test]
fn stale_foreign_conflicting_and_observed_actions_cannot_launch_or_signal() {
    let (_dir, service, request) = fixture("");
    let run = service.launch(request.clone()).unwrap();
    let ready = wait(&service, &run.id, |a| a.state == AgentState::AwaitingInput);
    let mut conflict = request.clone();
    conflict.task = "a different task".into();
    assert_eq!(
        service.launch(conflict).unwrap_err(),
        "swarm_request_conflict"
    );
    let mut foreign = request.clone();
    foreign.epoch = "old-resident".into();
    assert_eq!(service.launch(foreign).unwrap_err(), "swarm_stale");
    let stale = action(&request, &run, "stale", "stop", None);
    assert_eq!(service.action(stale).unwrap_err(), "swarm_stale");
    let mut observed = action(&request, &ready, "observed", "stop", None);
    observed.run_id = "process-1-123".into();
    assert_eq!(service.action(observed).unwrap_err(), "swarm_unknown_run");
    assert_eq!(service.registry.lock().unwrap().runs.len(), 1);
}

#[test]
fn busy_instructions_queue_and_stop_clears_the_queue_and_reaps_child() {
    let (dir, service, request) = fixture("sleep 60 &\nprintf '%s' \"$!\" > child.txt\nwait");
    let run = service.launch(request.clone()).unwrap();
    let running = wait(&service, &run.id, |a| a.state == AgentState::Running);
    assert!(service.has_active_runs());
    let deadline = Instant::now() + Duration::from_secs(3);
    let child: u32 = loop {
        if let Ok(Some(pid)) =
            fs::read_to_string(dir.path().join("child.txt")).map(|text| text.parse::<u32>().ok())
        {
            break pid;
        }
        assert!(Instant::now() < deadline, "fixture child did not start");
        std::thread::sleep(Duration::from_millis(20));
    };
    let queued = service
        .action(action(
            &request,
            &running,
            "queue-1",
            "message",
            Some("must not run"),
        ))
        .unwrap();
    assert_eq!(queued.queued, 1);
    let stop = service
        .action(action(&request, &queued, "stop-1", "stop", None))
        .unwrap();
    assert_eq!(stop.state, AgentState::Stopping);
    let stopped = wait(&service, &run.id, |a| a.state == AgentState::Stopped);
    assert!(!service.has_active_runs());
    assert_eq!(stopped.queued, 0);
    assert!(!stopped.controls.message);
    assert!(stopped.pid.is_none());
    let mut processes = sysinfo::System::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let pid = sysinfo::Pid::from_u32(child);
        processes.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
        if processes.process(pid).is_none_or(|p| {
            matches!(
                p.status(),
                sysinfo::ProcessStatus::Zombie | sysinfo::ProcessStatus::Dead
            )
        }) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "owned descendant is still running"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(running.pid.unwrap() as i32),
            None
        ),
        Err(nix::errno::Errno::ESRCH)
    );
    assert!(!fs::read_to_string(dir.path().join("prompts.txt"))
        .unwrap_or_default()
        .contains("must not run"));
}

#[test]
fn interrupt_preserves_followup_but_shutdown_never_leaves_the_owned_root() {
    let (_dir, service, request) = fixture("sleep 60");
    let run = service.launch(request.clone()).unwrap();
    let running = wait(&service, &run.id, |a| a.state == AgentState::Running);
    wait(&service, &run.id, |_| service.events(&run.id).is_ok());
    // Wait for the session ID, rather than presuming spawn means initialized.
    let deadline = Instant::now() + Duration::from_secs(3);
    while service.registry.lock().unwrap().runs[&run.id]
        .session
        .is_none()
    {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
    }
    service
        .action(action(&request, &running, "interrupt-1", "interrupt", None))
        .unwrap();
    let interrupted = wait(&service, &run.id, |a| a.state == AgentState::Interrupted);
    assert!(interrupted.controls.message);
    service
        .action(action(
            &request,
            &interrupted,
            "follow-2",
            "message",
            Some("resume"),
        ))
        .unwrap();
    let resumed = wait(&service, &run.id, |a| a.state == AgentState::Running);
    drop(service);
    assert_eq!(
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(resumed.pid.unwrap() as i32),
            None
        ),
        Err(nix::errno::Errno::ESRCH)
    );
}

#[test]
fn history_is_private_summary_and_restores_no_control_or_work() {
    let (_dir, service, request) = fixture("");
    let run = service.launch(request.clone()).unwrap();
    wait(&service, &run.id, |a| a.state == AgentState::AwaitingInput);
    let history = service.history().unwrap();
    let bytes = serde_json::to_string(&history).unwrap();
    assert!(!bytes.contains(&request.task));
    assert!(!bytes.contains("session-1"));
    let recovered = Service::default();
    recovered.restore_history(history).unwrap();
    let state = recovered.snapshot().unwrap();
    let old = state.agents.iter().find(|a| a.id == run.id).unwrap();
    assert_eq!(old.state, AgentState::Interrupted);
    assert!(!old.controls.message && !old.controls.stop && old.pid.is_none());
    assert_eq!(recovered.launch(request).unwrap_err(), "swarm_stale");
}

#[test]
fn oversized_output_fails_the_turn_and_does_not_grow_event_memory() {
    let (_dir, service, request) = fixture("dd if=/dev/zero bs=262145 count=1 2>/dev/null");
    let run = service.launch(request).unwrap();
    wait(&service, &run.id, |a| a.state == AgentState::Failed);
    assert!(service
        .events(&run.id)
        .unwrap()
        .iter()
        .any(|e| e.text.contains("bounded activity")));
    let mut registry = service.registry.lock().unwrap();
    let run = registry.runs.get_mut(&run.id).unwrap();
    for _ in 0..1000 {
        run.event("test", "bounded");
    }
    assert_eq!(run.events.len(), MAX_EVENTS);
    run.event("message", "🦀".repeat(4096));
    assert!(run.events.back().unwrap().text.len() <= 4096);
    assert!(run.events.back().unwrap().text.ends_with('…'));
}

#[test]
fn claude_structured_results_resume_the_exact_session_and_report_denials() {
    let body = r#"printf '%s\n' '{"type":"system","subtype":"init","session_id":"claude-session"}' '{"type":"assistant","message":{"content":[{"type":"text","text":"Read the project"},{"type":"thinking","thinking":"not public"}]}}' '{"type":"result","is_error":false,"session_id":"claude-session","permission_denials":[{"tool_name":"Bash"}],"usage":{"input_tokens":15,"output_tokens":4}}'"#;
    let (dir, service, mut request) = fixture(body);
    request.harness = "claude-code".into();
    let run = service.launch(request.clone()).unwrap();
    let ready = wait(&service, &run.id, |a| {
        a.state == AgentState::NeedsAttention && a.pid.is_none()
    });
    assert!(ready.controls.message);
    assert_eq!(ready.input_tokens, 15);
    assert!(!service
        .events(&run.id)
        .unwrap()
        .iter()
        .any(|e| e.text.contains("not public")));
    service
        .action(action(
            &request,
            &ready,
            "claude-follow",
            "message",
            Some("continue"),
        ))
        .unwrap();
    wait(&service, &run.id, |a| a.input_tokens == 30);
    assert!(fs::read_to_string(dir.path().join("args.txt"))
        .unwrap()
        .contains("--resume\nclaude-session"));
}
