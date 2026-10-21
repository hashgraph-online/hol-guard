//! Bounded metadata work, reserved from the existing evaluation pool budget.
use super::{handle_pending_request, spawn_workers, write_overload, PendingRequest};
use crate::policy_store::PolicySnapshotStore;
use crate::resident_diagnostics::{self, Phase, Status};
use serde::Deserialize;
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;

pub(super) const WORKERS: usize = 1;

pub(super) fn capacity() -> usize {
    crate::evaluation_queue_capacity() / 4
}

pub(super) fn start(
    policy_store: Option<Arc<PolicySnapshotStore>>,
) -> (SyncSender<PendingRequest>, Vec<JoinHandle<()>>) {
    let (sender, receiver) = sync_channel(capacity());
    let workers = spawn_workers(WORKERS, receiver, move |pending| {
        handle_pending_request(pending, policy_store.clone(), None);
    });
    (sender, workers)
}

/// A scheduling hint only. The authenticated frame digest and complete strict
/// operation/authority validation still run before any operation is evaluated.
pub(super) fn is_request(bytes: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct Route {
        operation: String,
    }
    serde_json::from_slice::<Route>(bytes).is_ok_and(|route| {
        matches!(
            route.operation.as_str(),
            "catalog_read"
                | "catalog_read_v2"
                | "catalog_prepare_v1"
                | "catalog_read_prepared_v1"
                | "cloud_catalog"
                | "discovery_placement_project"
        )
    })
}

pub(super) fn enqueue(sender: &SyncSender<PendingRequest>, pending: PendingRequest) {
    match sender.try_send(pending) {
        Ok(()) => {}
        Err(TrySendError::Full(mut pending)) => write_overload(&mut pending),
        Err(TrySendError::Disconnected(pending)) => {
            resident_diagnostics::finish_since(
                Phase::ResidentDispatchWait,
                Status::Error,
                pending.accepted_at,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_metadata_independently_of_field_order_without_accepting_ambiguous_tags() {
        for operation in [
            "catalog_read",
            "catalog_read_v2",
            "catalog_prepare_v1",
            "catalog_read_prepared_v1",
            "cloud_catalog",
            "discovery_placement_project",
        ] {
            let bytes = serde_json::to_vec(&serde_json::json!({
                "request": {"data": "bounded opaque data"}, "operation": operation,
            }))
            .unwrap();
            assert!(is_request(&bytes));
        }
        for bytes in [
            br#"{"operation":"hook_review","request":{}}"#.as_slice(),
            br#"{"operation":"catalog_read","operation":"hook_review"}"#,
            br#"{"request":{"operation":"catalog_read"}}"#,
            br#"{"operation":"catalog_read""#,
        ] {
            assert!(!is_request(bytes));
        }
    }
}
