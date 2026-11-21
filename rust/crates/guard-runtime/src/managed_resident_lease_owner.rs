#![forbid(unsafe_code)]

use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use super::LeaseIdentity;

pub(super) fn deadline_for_timeout(timeout: Duration) -> Result<Instant, String> {
    if timeout.is_zero() {
        return Err("native_client_deadline_exceeded".to_owned());
    }
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| "native_client_deadline_exceeded".to_owned())
}

struct Heartbeat {
    stop: Sender<()>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Heartbeat {
    fn start(interval: Duration, mut renew: impl FnMut() -> bool + Send + 'static) -> Self {
        let (stop, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            while matches!(
                receiver.recv_timeout(interval),
                Err(RecvTimeoutError::Timeout)
            ) {
                if !renew() {
                    break;
                }
            }
        });
        Self {
            stop,
            worker: Some(worker),
        }
    }

    fn stop_and_join(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub(in crate::managed_resident) struct ClientLease {
    directory: PathBuf,
    pub(super) path: PathBuf,
    private_root: PathBuf,
    identity: LeaseIdentity,
    heartbeat: Heartbeat,
    deadline: Option<Instant>,
}

impl ClientLease {
    pub(super) fn new(
        directory: PathBuf,
        path: PathBuf,
        private_root: PathBuf,
        identity: LeaseIdentity,
        contents: String,
    ) -> Self {
        let heartbeat_directory = directory.clone();
        let heartbeat_path = path.clone();
        let heartbeat_private_root = private_root.clone();
        let heartbeat = Heartbeat::start(super::LEASE_HEARTBEAT, move || {
            if let Ok(Some(directory_lock)) =
                super::acquire_directory_lock(&heartbeat_directory, &heartbeat_private_root)
            {
                let Ok(mut file) = crate::resident_state::private_file(
                    &heartbeat_path,
                    false,
                    &heartbeat_private_root,
                ) else {
                    return false;
                };
                // Preserve renewal/expiry serialization and flush outside the lock.
                let wrote = file.write_all(contents.as_bytes());
                drop(directory_lock);
                if wrote.and_then(|()| file.sync_all()).is_err() {
                    return false;
                }
            }
            true
        });
        Self {
            directory,
            path,
            private_root,
            identity,
            heartbeat,
            deadline: None,
        }
    }

    pub(super) fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    fn cleanup_lock(&self) -> Option<super::LeaseDirectoryLock> {
        let now = Instant::now();
        match self.deadline {
            // An expired one-shot can still remove its own lease if the lock
            // is immediately available. Busy leases remain fail-closed until
            // the existing identity/liveness reclamation path handles them.
            Some(deadline) if deadline <= now => {
                super::acquire_directory_lock(&self.directory, &self.private_root)
                    .ok()
                    .flatten()
            }
            Some(deadline) => super::acquire_directory_lock_until(
                &self.directory,
                &self.private_root,
                deadline.min(now + super::LEASE_CLEANUP_RETRY_BUDGET),
            )
            .ok(),
            None => super::acquire_directory_lock_with_retry(
                &self.directory,
                &self.private_root,
                super::LEASE_CLEANUP_RETRY_BUDGET,
            )
            .ok(),
        }
    }
}

impl Drop for ClientLease {
    fn drop(&mut self) {
        // Wake an idle heartbeat before joining; teardown still waits for an
        // in-flight renewal and identity-checked cleanup to finish.
        self.heartbeat.stop_and_join();
        if let Some(_lock) = self.cleanup_lock() {
            let _ = self.identity.remove_if_same(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    #[test]
    fn stopping_idle_heartbeat_wakes_worker_without_waiting_for_refresh() {
        let renewals = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&renewals);
        let mut heartbeat = Heartbeat::start(Duration::from_secs(5), move || {
            count.fetch_add(1, Ordering::SeqCst);
            true
        });
        let started = Instant::now();
        heartbeat.stop_and_join();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(renewals.load(Ordering::SeqCst), 0);
        assert!(heartbeat.worker.is_none());
    }
}
