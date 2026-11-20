//! Batch handoff keeps order, admission failures and unfinished durable work visible.

use super::*;

struct BatchJournal {
    journal: Arc<RecordingJournal>,
    appended: Mutex<Vec<Vec<String>>>,
    settled: Mutex<Vec<Vec<String>>>,
    refuse_second: bool,
    rewrite_gate: Option<Arc<Gate>>,
}

impl BatchJournal {
    fn new(refuse_second: bool, rewrite_gate: Option<Arc<Gate>>) -> Arc<Self> {
        Arc::new(Self {
            journal: RecordingJournal::new(),
            appended: Mutex::new(Vec::new()),
            settled: Mutex::new(Vec::new()),
            refuse_second,
            rewrite_gate,
        })
    }
}

impl EvidenceJournalApi for Arc<BatchJournal> {
    fn append_journal(&self, path: &Path, record: &EvidenceRecord) -> Result<(), io::Error> {
        self.journal.append_journal(path, record)
    }

    fn append_journal_batch(
        &self,
        path: &Path,
        records: &[&EvidenceRecord],
    ) -> Vec<Result<(), io::Error>> {
        self.appended
            .lock()
            .unwrap()
            .push(records.iter().map(|r| r.record_id()).collect());
        records
            .iter()
            .enumerate()
            .map(|(index, record)| {
                if self.refuse_second && index == 1 {
                    Err(io::Error::other("injected append refusal"))
                } else {
                    self.journal.append_journal(path, record)
                }
            })
            .collect()
    }

    fn rewrite_journal(&self, path: &Path, id: &str, max_bytes: usize) -> Result<u64, io::Error> {
        if let Some(gate) = &self.rewrite_gate {
            gate.enter();
        }
        self.journal.rewrite_journal(path, id, max_bytes)
    }

    fn rewrite_journal_batch(
        &self,
        path: &Path,
        ids: &[String],
        max_bytes: usize,
    ) -> Result<u64, io::Error> {
        self.settled.lock().unwrap().push(ids.to_vec());
        if let Some(gate) = &self.rewrite_gate {
            gate.enter();
        }
        ids.iter().try_fold(0, |invalid, id| {
            self.journal
                .rewrite_journal(path, id, max_bytes)
                .map(|n| invalid + n)
        })
    }

    fn recover_journal_records(
        &self,
        path: &Path,
        max_bytes: usize,
    ) -> Result<(Vec<Map<String, Value>>, u64), io::Error> {
        self.journal.recover_journal_records(path, max_bytes)
    }

    fn now_utc_iso(&self) -> String {
        self.journal.now_utc_iso()
    }
}

fn writer(store: Arc<StubStore>, journal: Arc<BatchJournal>) -> Arc<RuntimeHookEvidenceWriter> {
    let mut deps = deps_with_journal(Arc::clone(&journal.journal));
    deps.journal = Box::new(journal);
    Arc::new(
        RuntimeHookEvidenceWriter::new(
            store,
            deps,
            64,
            1 << 20,
            8,
            0.0,
            Some(queue_home().join("batch.jsonl")),
        )
        .unwrap(),
    )
}

#[test]
fn queued_records_append_and_settle_once_per_bounded_batch_in_order() {
    let gate = Gate::new();
    let journal = BatchJournal::new(false, None);
    let writer = writer(
        StubStore::gated(queue_home(), Arc::clone(&gate)),
        Arc::clone(&journal),
    );
    assert!(writer.submit_native_decision_receipt(&receipt("first")));
    gate.wait_for_entry();
    for index in 0..8 {
        assert!(writer.submit_native_decision_receipt(&receipt(&format!("queued-{index}"))));
    }
    gate.release();
    assert!(writer.stop(DRAIN_BUDGET_SECONDS));
    let expected = vec![
        vec!["first".to_owned()],
        (0..8).map(|i| format!("queued-{i}")).collect(),
    ];
    assert_eq!(*journal.appended.lock().unwrap(), expected);
    assert_eq!(*journal.settled.lock().unwrap(), expected);
    assert_eq!(writer.stats().receipt_processed, 9);
    assert_eq!(writer.stats().receipt_dropped, 0);
    assert!(journal.journal.records().is_empty());
}

#[test]
fn a_partial_append_refusal_cannot_reach_the_store_or_drop_other_records() {
    let gate = Gate::new();
    let journal = BatchJournal::new(true, None);
    let writer = writer(
        StubStore::gated(queue_home(), Arc::clone(&gate)),
        Arc::clone(&journal),
    );
    assert!(writer.submit_native_decision_receipt(&receipt("first")));
    gate.wait_for_entry();
    for index in 0..3 {
        assert!(writer.submit_native_decision_receipt(&receipt(&format!("queued-{index}"))));
    }
    gate.release();
    assert!(writer.stop(DRAIN_BUDGET_SECONDS));
    let stats = writer.stats();
    assert_eq!(stats.receipt_accepted, 4);
    assert_eq!(stats.receipt_processed, 3);
    assert_eq!(stats.receipt_dropped, 1);
    assert_eq!(stats.receipt_failures, 1);
    assert!(stats.degraded);
    assert_eq!(journal.settled.lock().unwrap()[1], ["queued-0", "queued-2"]);
    assert!(journal.journal.records().is_empty());
}

#[test]
fn blocked_journal_settlement_does_not_hold_the_queue_mutex() {
    let gate = Gate::new();
    let journal = BatchJournal::new(false, Some(Arc::clone(&gate)));
    let writer = writer(StubStore::new(queue_home(), false), journal);
    assert!(writer.submit_native_decision_receipt(&receipt("first")));
    gate.wait_for_entry();
    let (send, receive) = std::sync::mpsc::channel();
    let reader = {
        let writer = Arc::clone(&writer);
        thread::spawn(move || {
            send.send(writer.stats()).unwrap();
        })
    };
    let observed = receive.recv_timeout(Duration::from_secs(1));
    // Release before asserting so a regression never strands the worker.
    gate.release();
    reader.join().unwrap();
    assert!(writer.stop(DRAIN_BUDGET_SECONDS));
    assert_eq!(
        observed
            .expect("stats should not wait for journal I/O")
            .receipt_processed,
        1
    );
}

#[test]
fn an_expired_stop_journals_every_queued_batch_for_the_next_writer() {
    let gate = Gate::new();
    let journal = BatchJournal::new(false, None);
    let writer = writer(
        StubStore::gated(queue_home(), Arc::clone(&gate)),
        Arc::clone(&journal),
    );
    assert!(writer.submit_native_decision_receipt(&receipt("first")));
    gate.wait_for_entry();
    for index in 0..24 {
        assert!(writer.submit_native_decision_receipt(&receipt(&format!("queued-{index}"))));
    }
    assert!(!writer.stop(0.0));
    gate.release();
    assert!(writer.stop(0.0));
    let stats = writer.stats();
    assert_eq!(stats.receipt_accepted, 25);
    assert_eq!(stats.receipt_processed, 1);
    assert_eq!(stats.receipt_dropped, 0);
    assert_eq!(stats.receipt_durable_pending, 24);
    let retained = journal.journal.records();
    assert_eq!(
        retained.iter().map(journaled_record_id).collect::<Vec<_>>(),
        (0..24).map(|i| format!("queued-{i}")).collect::<Vec<_>>()
    );
    let recovered = queue_writer(
        StubStore::new(queue_home(), false),
        Arc::clone(&journal.journal),
        64,
    );
    assert!(recovered.stop(DRAIN_BUDGET_SECONDS));
    assert_eq!(recovered.stats().receipt_processed, 24);
    assert!(journal.journal.records().is_empty());
}
