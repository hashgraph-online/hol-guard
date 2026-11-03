use super::*;
use crate::{BundleApproval, ContextDocument, Limits, RuntimeSelection};
use std::collections::BTreeSet;
use std::sync::atomic::AtomicUsize;

#[test]
#[ignore = "requires the explicitly approved installed CIGAR 0.14.1 candidate"]
fn installed_actor_serializes_graphs_bounds_queue_and_cancels_without_blocking_status() {
    let actor = Arc::new(RuntimeActor::start(installed_runtime(), 0_usize).unwrap());
    exercise_queue(&actor);
    assert!(actor.close_and_wait(Duration::from_millis(500)));
}

fn installed_runtime() -> VerifiedRuntime {
    let selection: RuntimeSelection = serde_json::from_slice(
        &std::fs::read(
            std::env::var_os("GUARD_CIGAR_TEST_SELECTION").expect("explicit candidate selection"),
        )
        .unwrap(),
    )
    .unwrap();
    let approval: BundleApproval = serde_json::from_slice(
        &std::fs::read(
            std::env::var_os("GUARD_CIGAR_TEST_APPROVAL").expect("explicit candidate approval"),
        )
        .unwrap(),
    )
    .unwrap();
    VerifiedRuntime::start(selection, &approval).unwrap()
}

#[test]
#[ignore = "requires the explicitly approved installed CIGAR 0.14.1 candidate"]
fn installed_short_deadline_abandons_queued_work_and_closes_dispatched_uncertainty() {
    let actor = Arc::new(RuntimeActor::start(installed_runtime(), 0_usize).unwrap());
    let activity = actor.activity();
    let (entered, observed) = mpsc::sync_channel(1);
    let (release, held) = mpsc::sync_channel(1);
    let running = Arc::clone(&actor);
    let first = std::thread::spawn(move || {
        running.call(move |_, count| {
            entered.send(()).unwrap();
            held.recv_timeout(Duration::from_secs(2)).unwrap();
            *count += 1;
            Ok(())
        })
    });
    observed.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(
        actor.call_until(Instant::now() + Duration::from_millis(20), |_, count| {
            *count += 100;
            Ok(())
        }),
        Err(RuntimeError::DeadlineExceeded)
    );
    assert!(
        activity.is_active(),
        "known queued abandonment cannot poison the runtime"
    );
    release.send(()).unwrap();
    first.join().unwrap().unwrap();
    assert_eq!(actor.call(|_, count| Ok(*count)), Ok(1));
    assert_eq!(
        actor.call_until(Instant::now() + Duration::from_millis(10), |_, count| {
            *count += 1;
            std::thread::sleep(Duration::from_millis(50));
            Ok(())
        }),
        Err(RuntimeError::DeadlineExceeded)
    );
    assert!(
        !activity.is_active(),
        "an already dispatched job has unknown outcome"
    );
    assert!(actor.close_and_wait(Duration::from_millis(500)));
}

fn exercise_queue(actor: &Arc<RuntimeActor<usize>>) {
    let brief = actor
        .call(|runtime, count| {
            *count += 1;
            let workspace = runtime.open_workspace("actor-workspace", &Limits::default())?;
            runtime.replace_source(
                &workspace,
                "guard:policy",
                vec![ContextDocument {
                    id: "native-fact".into(),
                    text: "Both approval choices remain available.".into(),
                    start_line: 1,
                }],
            )?;
            let view = runtime.create_view(
                &workspace,
                "actor-view",
                BTreeSet::from(["guard:policy".into()]),
                "9007199254740993",
            )?;
            let context =
                runtime.compile_context(&view, "approval choices", vec!["native-fact".into()])?;
            runtime.explain_context(&context)?;
            Ok(context.brief().clone())
        })
        .unwrap();
    assert_eq!(brief.policy_revision, "9007199254740993");
    assert!(!brief.citations.is_empty());
    assert_eq!(actor.call(|_, count| Ok(*count)), Ok(1));

    let started = Arc::new(AtomicBool::new(false));
    let running = Arc::clone(&started);
    let cancel = Arc::clone(&actor.cancel);
    let first_actor = Arc::clone(actor);
    let first = std::thread::spawn(move || {
        first_actor.call(move |_, _| {
            running.store(true, Ordering::Release);
            let deadline = Instant::now() + Duration::from_secs(3);
            while !cancel.load(Ordering::Acquire) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(())
        })
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while !started.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    }
    let began = Instant::now();
    assert!(actor.status().active);
    assert!(began.elapsed() < Duration::from_millis(20));
    let performed = Arc::new(AtomicUsize::new(0));
    let mut requests = Vec::new();
    for _ in 0..8 {
        let actor = Arc::clone(actor);
        let performed = Arc::clone(&performed);
        requests.push(std::thread::spawn(move || {
            actor.call(move |_, _| {
                performed.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
        }));
    }
    // At least one refusal proves the finite queue while the running job is held.
    let deadline = Instant::now() + Duration::from_secs(1);
    while !requests.iter().any(JoinHandle::is_finished) {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    }
    actor.cancel();
    assert!(!actor.status().active);
    assert_eq!(first.join().unwrap(), Err(RuntimeError::Cancelled));
    let results: Vec<_> = requests
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert!(results.contains(&Err(RuntimeError::Busy)));
    assert!(results.iter().all(|r| matches!(
        r,
        Err(RuntimeError::Busy | RuntimeError::Cancelled | RuntimeError::RuntimeClosed)
    )));
    assert_eq!(performed.load(Ordering::Relaxed), 0);
    assert_eq!(actor.call(|_, _| Ok(())), Err(RuntimeError::RuntimeClosed));
    println!(
        "GUARD_CIGAR_ACTOR_VERIFICATION={}",
        serde_json::json!({
            "schema":"guard-cigar-actor-verification.v1", "status":"passed", "real_sdk":true,
            "queue_capacity":QUEUE_CAPACITY, "queued_mutations_after_cancel":0,
            "cited_graph":true, "exact_revision":brief.policy_revision, "final_active":false,
        })
    );
}

#[test]
#[ignore = "requires the explicitly approved installed CIGAR 0.14.1 candidate"]
fn cleanup_acknowledgement_requires_dropping_private_state_after_process_close() {
    struct PrivateState {
        entered: mpsc::SyncSender<()>,
        release: Receiver<()>,
        dropped: Arc<AtomicBool>,
    }
    impl Drop for PrivateState {
        fn drop(&mut self) {
            let _ = self.entered.try_send(());
            let _ = self.release.recv_timeout(Duration::from_secs(5));
            self.dropped.store(true, Ordering::Release);
        }
    }
    let (entered, observed) = mpsc::sync_channel(1);
    let (release, held) = mpsc::sync_channel(1);
    let dropped = Arc::new(AtomicBool::new(false));
    let actor = RuntimeActor::start(
        installed_runtime(),
        PrivateState {
            entered,
            release: held,
            dropped: Arc::clone(&dropped),
        },
    )
    .unwrap();
    assert!(!actor.close_and_wait(Duration::from_millis(10)));
    observed.recv_timeout(Duration::from_secs(3)).unwrap();
    assert!(!actor.status().active);
    assert!(!actor.cleanup_finished());
    assert!(!dropped.load(Ordering::Acquire));
    release.send(()).unwrap();
    assert!(actor.close_and_wait(Duration::from_millis(500)));
    assert!(actor.cleanup_finished());
    assert!(dropped.load(Ordering::Acquire));
}
