use super::*;
use std::cell::Cell;
use std::collections::VecDeque;

struct Chunks<'a> {
    remaining_ms: &'a Cell<u64>,
    reads: usize,
    steps: VecDeque<(Vec<u8>, u64)>,
}

impl Read for Chunks<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.reads += 1;
        let (chunk, remaining) = self.steps.pop_front().expect("unexpected read");
        assert!(chunk.len() <= buffer.len());
        buffer[..chunk.len()].copy_from_slice(&chunk);
        self.remaining_ms.set(remaining);
        Ok(chunk.len())
    }
}

fn budget(remaining: &Cell<u64>) -> Result<()> {
    if remaining.get() < 10 {
        Err(Failure::timeout())
    } else {
        Ok(())
    }
}

#[test]
fn complete_body_keeps_frozen_python_final_eof_budget_check() {
    let clock = Cell::new(100);
    let mut input = Chunks {
        remaining_ms: &clock,
        reads: 0,
        steps: VecDeque::from([(b"{}".to_vec(), 5)]),
    };
    let result = read_body(&mut input, 2, "daemon hook", |_| budget(&clock));
    assert_eq!(result.unwrap_err().value["kind"], "timeout");
    assert_eq!(input.reads, 1, "complete chunk was actually consumed");
}

#[test]
fn zero_length_body_keeps_frozen_python_first_budget_check() {
    let clock = Cell::new(5);
    let mut input = Chunks {
        remaining_ms: &clock,
        reads: 0,
        steps: VecDeque::new(),
    };
    assert_eq!(
        read_body(&mut input, 0, "daemon hook", |_| budget(&clock))
            .unwrap_err()
            .value["kind"],
        "timeout"
    );
    assert_eq!(input.reads, 0);
    clock.set(100);
    assert!(read_body(&mut input, 0, "daemon hook", |_| budget(&clock))
        .unwrap()
        .is_empty());
}

#[test]
fn early_eof_does_not_add_a_terminal_budget_gate() {
    let clock = Cell::new(100);
    let mut input = Chunks {
        remaining_ms: &clock,
        reads: 0,
        steps: VecDeque::from([(b"{}".to_vec(), 50), (Vec::new(), 5)]),
    };
    assert_eq!(
        read_body(&mut input, 20, "daemon hook", |_| budget(&clock)).unwrap(),
        b"{}"
    );
    assert_eq!(input.reads, 2);
}

#[test]
fn complete_body_with_remaining_budget_keeps_exact_bytes() {
    let clock = Cell::new(100);
    let mut input = Chunks {
        remaining_ms: &clock,
        reads: 0,
        steps: VecDeque::from([(b"{}".to_vec(), 50)]),
    };
    assert_eq!(
        read_body(&mut input, 2, "daemon hook", |_| budget(&clock)).unwrap(),
        b"{}"
    );
    assert_eq!(input.reads, 1);
}

struct PartialWriter<'a> {
    remaining_ms: &'a Cell<u64>,
    accepted: Vec<u8>,
    delay_ms: u64,
}

impl Write for PartialWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let count = bytes.len().min(2);
        self.accepted.extend_from_slice(&bytes[..count]);
        self.remaining_ms
            .set(self.remaining_ms.get().saturating_sub(self.delay_ms));
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn partial_progress_cannot_reset_the_absolute_write_budget() {
    let clock = Cell::new(100);
    let mut stream = PartialWriter {
        remaining_ms: &clock,
        accepted: Vec::new(),
        delay_ms: 50,
    };
    let mut timeouts = Vec::new();
    let result = write_with_budget(&mut stream, b"abcdef", |_| {
        timeouts.push(clock.get());
        budget(&clock)
    });
    assert_eq!(result.unwrap_err().value["kind"], "timeout");
    assert_eq!(
        stream.accepted, b"abcd",
        "no write may begin after the budget expires"
    );
    assert_eq!(timeouts, [100, 50, 0]);
}

#[test]
fn partial_writes_complete_exact_request_within_original_budget() {
    let clock = Cell::new(100);
    let mut stream = PartialWriter {
        remaining_ms: &clock,
        accepted: Vec::new(),
        delay_ms: 20,
    };
    let mut timeouts = Vec::new();
    write_with_budget(&mut stream, b"abcdef", |_| {
        timeouts.push(clock.get());
        budget(&clock)
    })
    .unwrap();
    assert_eq!(stream.accepted, b"abcdef");
    assert_eq!(timeouts, [100, 80, 60]);
}
