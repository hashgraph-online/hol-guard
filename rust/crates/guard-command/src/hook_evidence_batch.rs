//! Keep journal I/O outside the queue mutex and amortize it over bounded batches.

use super::*;

impl EvidenceWorker {
    pub(super) fn journal_batch(&self, batch: &[EvidenceRecord]) -> Vec<bool> {
        let pending = {
            let mut state = self.lock_state();
            state.in_flight = true;
            batch
                .iter()
                .enumerate()
                .filter(|(_, record)| !state.durable.contains_key(&record.record_id()))
                .collect::<Vec<_>>()
        };
        let records = pending
            .iter()
            .map(|(_, record)| *record)
            .collect::<Vec<_>>();
        let mut outcomes = self
            .deps
            .journal
            .append_journal_batch(&self.journal_path, &records)
            .into_iter();
        let mut ready = vec![true; batch.len()];
        let mut state = self.lock_state();
        for (index, record) in pending {
            // A seam contract violation cannot let an unjournaled record
            // reach the store. Every pending record needs its own result.
            if outcomes.next().is_some_and(|result| result.is_ok()) {
                state.durable.insert(record.record_id(), record.clone());
            } else {
                ready[index] = false;
                state.dropped += 1;
                state.failures += 1;
                if record.is_receipt() {
                    state.receipt_dropped += 1;
                    state.receipt_failures += 1;
                }
                state.degraded = true;
            }
        }
        ready
    }

    pub(super) fn settle_journal_batch(&self, settled: &[String]) {
        if settled.is_empty() {
            return;
        }
        // Completed store writes remain replayable until this single atomic
        // rewrite succeeds. Existing store identities dedupe any replay.
        let failures = self
            .deps
            .journal
            .rewrite_journal_batch(&self.journal_path, settled, self.max_bytes)
            .unwrap_or(1);
        if failures > 0 {
            let mut state = self.lock_state();
            state.failures += failures;
            state.degraded = true;
        }
    }
}
