use std::time::{Duration, Instant};

use super::{call_digest, Observed, Stop, Tracker, LOOP_PRIORS};

fn make(tracker: &mut Tracker, now: Instant) -> Option<Stop> {
    let (digest, kind) = call_digest(&serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {"command": "make"}
    }))
    .unwrap();
    tracker.observe(
        &Observed {
            session: "s",
            request: None,
            digest,
            kind,
            allowed: true,
        },
        now,
    )
}

#[test]
fn a_loop_at_a_model_pace_is_stopped() {
    // A live model takes five to fifteen seconds per call, so six identical
    // calls in a row span about a minute.
    let mut tracker = Tracker::default();
    let start = Instant::now();
    for step in 0..LOOP_PRIORS {
        let at = start + Duration::from_secs(12 * step as u64);
        assert_eq!(make(&mut tracker, at), None);
    }
    let sixth = start + Duration::from_secs(12 * LOOP_PRIORS as u64 + 15);
    assert_eq!(make(&mut tracker, sixth), Some(Stop::Loop));
}
