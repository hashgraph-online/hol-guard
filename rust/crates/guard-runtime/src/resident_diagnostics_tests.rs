use super::*;

fn phase_line(text: &str) -> PhaseLine {
    let mut bytes = [0u8; PHASE_LINE_BYTES];
    bytes[..text.len()].copy_from_slice(text.as_bytes());
    PhaseLine {
        bytes,
        length: text.len(),
    }
}

#[test]
fn phase_batch_takes_the_queued_lines_in_order() {
    let (sender, receiver) = mpsc::sync_channel(MANAGED_PHASE_QUEUE_LINES);
    for index in 1..4 {
        sender.send(phase_line(&format!("line-{index}\n"))).unwrap();
    }
    let batch = next_batch(phase_line("line-0\n"), &receiver);
    assert_eq!(batch, b"line-0\nline-1\nline-2\nline-3\n");
    assert!(receiver.try_recv().is_err());
}

#[test]
fn phase_batch_stops_at_the_batch_bound_and_leaves_the_rest_queued() {
    let (sender, receiver) = mpsc::sync_channel(MANAGED_PHASE_QUEUE_LINES);
    let full = "x".repeat(PHASE_LINE_BYTES - 1) + "\n";
    for _ in 0..MANAGED_PHASE_QUEUE_LINES {
        sender.send(phase_line(&full)).unwrap();
    }
    let batch = next_batch(phase_line(&full), &receiver);
    assert!(batch.len() <= PHASE_BATCH_BYTES);
    assert!(batch.len() + PHASE_LINE_BYTES > PHASE_BATCH_BYTES);
    assert_eq!(batch.len() % PHASE_LINE_BYTES, 0);
    let taken = batch.len() / PHASE_LINE_BYTES;
    assert_eq!(
        receiver.try_iter().count(),
        MANAGED_PHASE_QUEUE_LINES + 1 - taken
    );
}
