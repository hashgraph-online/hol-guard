//! Select only the three fixed diagnostic effects for post-close process
//! image sampling. A proc-fd name is a cheap filter, never a path to open.

use crate::staging_effect_events::{CloseWriteEvent, EffectWriter};
use crate::staging_file_handle::sample_file_handle;
use crate::staging_writer_process::observe_writer_image;
use crate::{hex, open_root_owned_public_directory, StagingRole};
use gauntlet_contracts::MAX_EFFECT_WRITER_IMAGES;
use rustix::fs::{fstat, openat2, FileType, Mode, OFlags, ResolveFlags};
use serde_json::{json, Value};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::sync::mpsc::{sync_channel, SyncSender};
use std::thread::JoinHandle;

const SURFACES: [(&str, &str); 3] = [
    (
        "provider-remote",
        "tasks/remote/private-provider-control.txt",
    ),
    ("provider-home", "tasks/home/private-provider-control.txt"),
    ("contained-output", "tasks/checkout/native-contained.txt"),
];

pub(crate) struct WriterImageCapture {
    run_id: String,
    role: StagingRole,
    sender: Option<SyncSender<PendingImage>>,
    worker: Option<JoinHandle<Vec<Value>>>,
    queued: usize,
    overflowed: bool,
}

struct PendingImage {
    sequence: usize,
    surface: &'static str,
    pid: u32,
    start_ticks: Option<u64>,
    source: Result<(EffectWriter, OwnedFd), &'static str>,
}

impl PendingImage {
    fn sample(self) -> Value {
        let result = self.source.and_then(|(writer, pidfd)| {
            observe_writer_image(&writer, &pidfd).map_err(|_| "process-sample-unavailable")
        });
        let (sample, reason) = match result {
            Ok(sample) => (sample, Value::Null),
            Err(reason) => (Value::Null, json!(reason)),
        };
        json!({"event_sequence":self.sequence,"surface":self.surface,
            "writer_pid":self.pid,"writer_start_ticks":self.start_ticks,
            "sample":sample,"unavailable_reason":reason})
    }
}

impl WriterImageCapture {
    pub(crate) fn new(run_id: &str, role: StagingRole) -> Result<Self, String> {
        if !hex(run_id, 16) {
            return Err("writer image capture requires an exact run ID".to_owned());
        }
        let (sender, receiver) = sync_channel::<PendingImage>(MAX_EFFECT_WRITER_IMAGES);
        let worker = std::thread::Builder::new()
            .name("gauntlet-writer-images".to_owned())
            .spawn(move || receiver.into_iter().map(PendingImage::sample).collect())
            .map_err(|error| format!("writer image collector unavailable: {error}"))?;
        Ok(Self {
            run_id: run_id.to_owned(),
            role,
            sender: Some(sender),
            worker: Some(worker),
            queued: 0,
            overflowed: false,
        })
    }

    pub(crate) fn record(
        &mut self,
        sequence: usize,
        event: &CloseWriteEvent,
        file: &OwnedFd,
        pidfd: Option<&OwnedFd>,
    ) {
        let Some(surface) = self.match_target(event, file) else {
            return;
        };
        let source = match (pidfd, event.writer.as_ref()) {
            (None, _) => Err("pidfd-unavailable"),
            (Some(_), None) => Err("writer-unavailable"),
            (Some(pidfd), Some(writer)) => {
                if !product_service(&self.run_id, &writer.cgroup) {
                    Err("outside-product-service")
                } else {
                    rustix::io::fcntl_dupfd_cloexec(pidfd, 0)
                        .map(|held| (writer.clone(), held))
                        .map_err(|_| "process-sample-unavailable")
                }
            }
        };
        self.enqueue(PendingImage {
            sequence,
            surface,
            pid: event.reported_pid,
            start_ticks: event.writer.as_ref().map(|writer| writer.start_ticks),
            source,
        });
    }

    fn enqueue(&mut self, image: PendingImage) {
        // Hashing an executable can outlive a short-lived probe. Keep it off
        // the fanotify thread, which must promptly sample all writer tuples.
        // At most 64 duplicated pidfds can be owned by the queue and worker.
        if self.queued >= MAX_EFFECT_WRITER_IMAGES
            || self
                .sender
                .as_ref()
                .is_none_or(|sender| sender.try_send(image).is_err())
        {
            // The caller closes the rest of the batch before refusing it.
            self.overflowed = true;
        } else {
            self.queued += 1;
        }
    }

    fn match_target(&self, event: &CloseWriteEvent, file: &OwnedFd) -> Option<&'static str> {
        let hint = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()?;
        let basename = hint.file_name()?.to_str()?;
        if !matches!(
            basename,
            "private-provider-control.txt" | "native-contained.txt"
        ) {
            return None;
        }
        let event_handle = event.file_handle.as_ref()?;
        let path = format!("/home/hx-{}/{}", self.run_id, self.role.as_str());
        let root = open_root_owned_public_directory(Path::new(&path)).ok()?;
        let root_stat = fstat(&root).ok()?;
        if root_stat.st_mode & 0o7777 != 0o700 {
            return None;
        }
        for (surface, relative) in SURFACES {
            if !relative.ends_with(basename) {
                continue;
            }
            let Ok(held) = openat2(
                &root,
                relative,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            ) else {
                continue;
            };
            let stat = fstat(&held).ok()?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || stat.st_nlink != 1
                || stat.st_dev != event.device
                || stat.st_ino != event.inode
                || sample_file_handle(&held).as_ref() != Ok(event_handle)
            {
                continue;
            }
            let visible_root = open_root_owned_public_directory(Path::new(&path)).ok()?;
            let visible_stat = fstat(&visible_root).ok()?;
            if visible_stat.st_dev != root_stat.st_dev || visible_stat.st_ino != root_stat.st_ino {
                return None;
            }
            let visible = openat2(
                &visible_root,
                relative,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .ok()?;
            let final_stat = fstat(&visible).ok()?;
            if final_stat.st_dev == stat.st_dev
                && final_stat.st_ino == stat.st_ino
                && sample_file_handle(&visible).as_ref() == Ok(event_handle)
            {
                return Some(surface);
            }
        }
        None
    }

    pub(crate) fn check_bound(&self) -> Result<(), String> {
        if self.overflowed {
            Err("effect writer image bound exceeded".to_owned())
        } else {
            Ok(())
        }
    }

    pub(crate) fn finish(mut self) -> Result<Vec<Value>, String> {
        self.check_bound()?;
        self.sender.take();
        let images = self
            .worker
            .take()
            .ok_or("writer image collector missing")?
            .join()
            .map_err(|_| "writer image collector panicked")?;
        if images.len() != self.queued {
            return Err("writer image collector lost a queued sample".to_owned());
        }
        Ok(images)
    }
}

impl Drop for WriterImageCapture {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn product_service(run_id: &str, cgroup: &str) -> bool {
    cgroup
        .strip_prefix(&format!("/holgauntletrust{run_id}.slice/hol-product-cell-"))
        .and_then(|unit| unit.strip_suffix(".service"))
        .is_some_and(|unit| hex(unit, 32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_run_service_cannot_select_another_run_or_descendant() {
        let run = "0123456789abcdef";
        let group = format!(
            "/holgauntletrust{run}.slice/hol-product-cell-{}.service",
            "a".repeat(32)
        );
        assert!(product_service(run, &group));
        assert!(!product_service("fedcba9876543210", &group));
        assert!(!product_service(run, &format!("{group}/child")));
        assert!(WriterImageCapture::new("../outside", StagingRole::Success).is_err());
    }

    #[test]
    fn asynchronous_images_drain_in_order_and_never_silently_truncate() {
        let pending = |sequence| PendingImage {
            sequence,
            surface: "contained-output",
            pid: 42,
            start_ticks: None,
            source: Err("writer-unavailable"),
        };
        for overflow in [false, true] {
            let mut capture =
                WriterImageCapture::new("0123456789abcdef", StagingRole::Success).unwrap();
            for sequence in 1..=MAX_EFFECT_WRITER_IMAGES {
                capture.enqueue(pending(sequence));
            }
            if overflow {
                capture.enqueue(pending(MAX_EFFECT_WRITER_IMAGES + 1));
                assert!(capture.check_bound().is_err());
                assert!(capture.finish().is_err());
            } else {
                let images = capture.finish().unwrap();
                assert_eq!(images.len(), MAX_EFFECT_WRITER_IMAGES);
                for (i, image) in images.iter().enumerate() {
                    assert_eq!(image["event_sequence"], i + 1);
                    assert_eq!(image["unavailable_reason"], "writer-unavailable");
                    assert!(image["sample"].is_null());
                }
            }
        }
    }
}
