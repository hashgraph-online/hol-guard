//! Deadline-bound writes hold their own file handle through late completion.
//!
//! A timed-out worker can only write the original unlinked inode; it cannot
//! reuse a caller's descriptor or follow a replaced blob path.

use super::restricted_archive::RestrictedDownloadError;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::time::Instant;

static ACTIVE_WRITES: AtomicUsize = AtomicUsize::new(0);
const MAX_ACTIVE_WRITES: usize = 4;

struct WriteAdmission;
impl WriteAdmission {
    fn acquire() -> Option<Self> {
        ACTIVE_WRITES
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                (count < MAX_ACTIVE_WRITES).then_some(count + 1)
            })
            .ok()
            .map(|_| Self)
    }
}
impl Drop for WriteAdmission {
    fn drop(&mut self) {
        ACTIVE_WRITES.fetch_sub(1, Ordering::SeqCst);
    }
}

enum Message {
    Chunk(Vec<u8>, SyncSender<std::io::Result<()>>),
    Finish,
}

pub(super) struct BlobWriter {
    sender: Option<SyncSender<Message>>,
    completion: Receiver<()>,
}

impl BlobWriter {
    pub(super) fn start(file: &File, path: &Path) -> Result<Self, RestrictedDownloadError> {
        Self::start_with(file, path.to_owned(), || {})
    }

    fn start_with(
        file: &File,
        _path: PathBuf,
        mut before_write: impl FnMut() + Send + 'static,
    ) -> Result<Self, RestrictedDownloadError> {
        let mut owned = file.try_clone().map_err(|_| failure())?;
        let slot = WriteAdmission::acquire().ok_or_else(timeout)?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let (finished, completion) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("guard-archive-write".into())
            .spawn(move || {
                let mut retained = false;
                while let Ok(message) = receiver.recv() {
                    match message {
                        Message::Chunk(bytes, reply) => {
                            before_write();
                            let result = owned.write_all(&bytes);
                            let failed = result.is_err();
                            if reply.send(result).is_err() || failed {
                                break;
                            }
                        }
                        Message::Finish => {
                            retained = true;
                            break;
                        }
                    }
                }
                drop(owned);
                #[cfg(windows)]
                if !retained {
                    if let Ok(metadata) = std::fs::metadata(&_path) {
                        let mut permissions = metadata.permissions();
                        permissions.set_readonly(false);
                        let _ = std::fs::set_permissions(&_path, permissions);
                    }
                    let _ = std::fs::remove_file(&_path);
                    // Only an empty private spool can be removed; never recurse.
                    if let Some(parent) = _path.parent() {
                        if parent.file_name().is_some_and(|name| {
                            name.to_string_lossy().starts_with("hol-guard-acquisition-")
                        }) {
                            let _ = std::fs::remove_dir(parent);
                        }
                    }
                }
                #[cfg(not(windows))]
                let _ = retained;
                drop(slot);
                let _ = finished.send(());
            })
            .map_err(|_| failure())?;
        Ok(Self {
            sender: Some(sender),
            completion,
        })
    }

    pub(super) fn write(
        &self,
        chunk: &[u8],
        deadline: Instant,
    ) -> Result<(), RestrictedDownloadError> {
        if Instant::now() >= deadline {
            return Err(timeout());
        }
        let (reply, response) = mpsc::sync_channel(1);
        self.sender
            .as_ref()
            .ok_or_else(failure)?
            .try_send(Message::Chunk(chunk.to_vec(), reply))
            .map_err(|_| failure())?;
        match response.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => Err(failure()),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(timeout()),
        }
    }

    pub(super) fn finish(&mut self, deadline: Instant) -> Result<(), RestrictedDownloadError> {
        self.sender
            .take()
            .ok_or_else(failure)?
            .try_send(Message::Finish)
            .map_err(|_| failure())?;
        self.completion
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| timeout())
    }
}

fn timeout() -> RestrictedDownloadError {
    RestrictedDownloadError::new(
        "external_archive_download_timeout",
        "External archive download exceeded Guard's time limit.",
    )
}
fn failure() -> RestrictedDownloadError {
    RestrictedDownloadError::new(
        "external_archive_connection_failed",
        "External archive temporary blob could not be written completely.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn late_write_stays_on_unlinked_inode_and_keeps_admission() {
        let _test_lock = crate::restricted_archive::ARCHIVE_TEST_LOCK.lock().unwrap();
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!("guard-late-write-{}", hex::encode(nonce)));
        let mut file = File::create_new(&path).unwrap();
        let (release, wait) = mpsc::channel();
        let writer = BlobWriter::start_with(&file, path.clone(), move || {
            wait.recv().unwrap();
        })
        .unwrap();
        let error = writer
            .write(
                b"late archive bytes",
                Instant::now() + Duration::from_millis(20),
            )
            .unwrap_err();
        assert_eq!(error.code, "external_archive_download_timeout");
        assert_eq!(ACTIVE_WRITES.load(Ordering::SeqCst), 1);
        drop(file);
        // Windows does not unlink an open file; a sibling file still proves
        // that the late worker never opens another pathname/descriptor.
        #[cfg(unix)]
        std::fs::remove_file(&path).unwrap();
        let protected = path.with_extension("protected");
        file = File::create_new(&protected).unwrap();
        file.write_all(b"protected database bytes").unwrap();
        release.send(()).unwrap();
        writer
            .completion
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            std::fs::read(&protected).unwrap(),
            b"protected database bytes"
        );
        drop(file);
        std::fs::remove_file(protected).unwrap();
        assert!(!path.exists());
    }
}
