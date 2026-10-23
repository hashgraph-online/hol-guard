//! Root-owned, bounded Linux close-write capture for later staging effect
//! attribution. A pidfd and an inode are kernel observations, not proof that
//! a Guard decision caused an effect. No caller uses this for admission yet.

use crate::linux_process::{parse_proc_stat, valid_cgroup};
use crate::staging_file_handle::sample_file_handle;
use crate::staging_writer_capture::WriterImageCapture;
use crate::StagingRole;
use gauntlet_contracts::{EffectFileHandle, MAX_EFFECT_WRITER_IMAGES};
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fs::{fstat, FileType};
use rustix::io::{read, Errno};
use rustix::process::geteuid;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

// A known-writer row with a handle consumes at most fifteen JSON nodes. Keep
// the capture below the contracts parser's 500,000-node ceiling.
pub const MAX_EFFECT_EVENTS: usize = 32_768;
const _: () = assert!(
    MAX_EFFECT_EVENTS * 15 + MAX_EFFECT_WRITER_IMAGES * 32 + 64 <= gauntlet_contracts::MAX_NODES
);
const READ_BYTES: usize = 64 * 1024;
const MAX_PROC_BYTES: u64 = 4096;
const METADATA_BYTES: usize = 24;
const PIDFD_INFO_BYTES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectWriter {
    pub pid: u32,
    pub start_ticks: u64,
    pub cgroup: String,
}

#[derive(Debug)]
pub struct CloseWriteEvent {
    pub device: u64,
    pub inode: u64,
    pub owner: u32,
    pub file_handle: Option<EffectFileHandle>,
    pub reported_pid: u32,
    pub pidfd_available: bool,
    pub writer: Option<EffectWriter>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelatedFileEffect {
    pub device: u64,
    pub inode: u64,
    pub close_writes: usize,
    pub writers: Vec<EffectWriter>,
    pub cgroup: String,
}

pub struct StagingEffectEvents {
    group: OwnedFd,
    filesystem_device: u64,
    events: Vec<CloseWriteEvent>,
    writer_images: Option<WriterImageCapture>,
    poisoned: bool,
}

pub struct FinishedStagingEffectEvents {
    filesystem_device: u64,
    events: Vec<CloseWriteEvent>,
    writer_images: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EventHeader {
    file_fd: i32,
    pidfd: i32,
    pid: u32,
}

fn u16_ne(raw: &[u8]) -> Option<u16> {
    Some(u16::from_ne_bytes(raw.try_into().ok()?))
}

fn u32_ne(raw: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(raw.try_into().ok()?))
}

fn i32_ne(raw: &[u8]) -> Option<i32> {
    Some(i32::from_ne_bytes(raw.try_into().ok()?))
}

fn u64_ne(raw: &[u8]) -> Option<u64> {
    Some(u64::from_ne_bytes(raw.try_into().ok()?))
}

fn parse_event(raw: &[u8]) -> Result<(usize, EventHeader), String> {
    if raw.len() < METADATA_BYTES {
        return Err("truncated fanotify metadata".to_owned());
    }
    let length = u32_ne(&raw[0..4]).ok_or("invalid fanotify length")? as usize;
    let metadata_len = u16_ne(&raw[6..8]).ok_or("invalid fanotify metadata length")? as usize;
    let mask = u64_ne(&raw[8..16]).ok_or("invalid fanotify mask")?;
    if mask & libc::FAN_Q_OVERFLOW != 0 {
        return Err("fanotify event queue overflow; effect attribution unknown".to_owned());
    }
    if raw[4] != libc::FANOTIFY_METADATA_VERSION
        || raw[5] != 0
        || metadata_len != METADATA_BYTES
        || length != METADATA_BYTES + PIDFD_INFO_BYTES
        || length > raw.len()
        || mask != libc::FAN_CLOSE_WRITE
        || raw[24] != libc::FAN_EVENT_INFO_TYPE_PIDFD
        || raw[25] != 0
        || u16_ne(&raw[26..28]) != Some(PIDFD_INFO_BYTES as u16)
    {
        return Err("unexpected fanotify event shape".to_owned());
    }
    let file_fd = i32_ne(&raw[16..20]).ok_or("invalid fanotify file fd")?;
    let pid = i32_ne(&raw[20..24]).ok_or("invalid fanotify pid")?;
    let pidfd = i32_ne(&raw[28..32]).ok_or("invalid fanotify pidfd")?;
    if file_fd < 0 || pid <= 0 || pidfd < 0 && pidfd != libc::FAN_NOPIDFD {
        return Err("fanotify file or process descriptor unavailable".to_owned());
    }
    Ok((
        length,
        EventHeader {
            file_fd,
            pidfd,
            pid: pid as u32,
        },
    ))
}

fn read_proc(pid: u32, name: &str) -> Option<Vec<u8>> {
    let path = format!("/proc/{pid}/{name}");
    let mut raw = Vec::new();
    File::open(path)
        .ok()?
        .take(MAX_PROC_BYTES + 1)
        .read_to_end(&mut raw)
        .ok()?;
    (raw.len() as u64 <= MAX_PROC_BYTES).then_some(raw)
}

fn pidfd_alive(pidfd: &OwnedFd) -> bool {
    let mut row = [PollFd::new(pidfd, PollFlags::IN)];
    poll(
        &mut row,
        Some(&Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    ) == Ok(0)
}

fn sample_writer(pid: u32, pidfd: &OwnedFd) -> Option<EffectWriter> {
    if !pidfd_alive(pidfd) {
        return None;
    }
    let stat_before = parse_proc_stat(&read_proc(pid, "stat")?, pid)?;
    let cgroup_before = read_proc(pid, "cgroup")?;
    let stat_after = parse_proc_stat(&read_proc(pid, "stat")?, pid)?;
    let cgroup_after = read_proc(pid, "cgroup")?;
    let cgroup = std::str::from_utf8(&cgroup_after)
        .ok()?
        .strip_prefix("0::")?
        .strip_suffix('\n')?;
    if stat_before.start_ticks != stat_after.start_ticks
        || !matches!(stat_after.state, 'R' | 'S' | 'D')
        || cgroup_before != cgroup_after
        || !valid_cgroup(cgroup)
        || !pidfd_alive(pidfd)
    {
        return None;
    }
    Some(EffectWriter {
        pid,
        start_ticks: stat_after.start_ticks,
        cgroup: cgroup.to_owned(),
    })
}

impl StagingEffectEvents {
    /// Watch the filesystem containing an outside-selected Root-owned
    /// directory. The caller must later match the captured inode to an exact
    /// descriptor-opened effect path; this API never trusts a pathname from
    /// an event or claims a Guard verdict.
    pub fn start(directory: &Path) -> Result<Self, String> {
        if geteuid().as_raw() != 0 || !directory.is_absolute() {
            return Err("Linux Root and an absolute watch directory required".to_owned());
        }
        let held = crate::open_root_owned_public_directory(directory)
            .map_err(|error| error.to_string())?;
        let before = fstat(&held).map_err(|error| error.to_string())?;
        if FileType::from_raw_mode(before.st_mode) != FileType::Directory || before.st_uid != 0 {
            return Err("unsafe fanotify watch directory".to_owned());
        }
        // SAFETY: libc receives fixed flags and returns a new descriptor.
        let raw = unsafe {
            libc::fanotify_init(
                libc::FAN_CLOEXEC | libc::FAN_NONBLOCK | libc::FAN_REPORT_PIDFD,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u32,
            )
        };
        if raw < 0 {
            return Err(format!(
                "fanotify_init failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: successful fanotify_init returns a new owned descriptor.
        let group = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: both descriptors remain live. Relative "." makes the mark
        // target the held directory even if the visible pathname changes.
        let marked = unsafe {
            libc::fanotify_mark(
                group.as_raw_fd(),
                libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
                libc::FAN_CLOSE_WRITE,
                held.as_raw_fd(),
                c".".as_ptr(),
            )
        };
        if marked != 0 {
            return Err(format!(
                "fanotify_mark failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let after = fstat(&held).map_err(|error| error.to_string())?;
        if before.st_dev != after.st_dev || before.st_ino != after.st_ino {
            return Err("fanotify watch directory changed".to_owned());
        }
        Ok(Self {
            group,
            filesystem_device: before.st_dev,
            events: Vec::new(),
            writer_images: None,
            poisoned: false,
        })
    }

    /// Opt in to bounded post-event images for this outside-selected run's
    /// three fixed effect paths. The original start API retains v2 evidence.
    pub fn start_for_run(
        directory: &Path,
        run_id: &str,
        role: StagingRole,
    ) -> Result<Self, String> {
        let capture = WriterImageCapture::new(run_id, role)?;
        let mut monitor = Self::start(directory)?;
        monitor.writer_images = Some(capture);
        Ok(monitor)
    }

    pub fn drain(&mut self) -> Result<usize, String> {
        if self.poisoned {
            return Err("fanotify capture already uncertain".to_owned());
        }
        let result = self.drain_inner();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn drain_inner(&mut self) -> Result<usize, String> {
        let before = self.events.len();
        let mut buffer = [0u8; READ_BYTES];
        loop {
            let count = match read(&self.group, &mut buffer) {
                Ok(0) => return Err("fanotify event stream ended".to_owned()),
                Ok(count) => count,
                Err(Errno::AGAIN) => break,
                Err(error) => return Err(format!("fanotify read failed: {error}")),
            };
            let mut position = 0;
            while position < count {
                if self.events.len() >= MAX_EFFECT_EVENTS {
                    return Err("fanotify event bound exceeded".to_owned());
                }
                let (length, header) = parse_event(&buffer[position..count])?;
                position += length;
                // SAFETY: the kernel supplied each nonnegative event fd once
                // in this read; these wrappers close it on every exit path.
                let file = unsafe { OwnedFd::from_raw_fd(header.file_fd) };
                let pidfd =
                    (header.pidfd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(header.pidfd) });
                let metadata = fstat(&file).map_err(|error| error.to_string())?;
                if metadata.st_dev != self.filesystem_device {
                    return Err("fanotify event outside marked filesystem".to_owned());
                }
                let event = CloseWriteEvent {
                    device: metadata.st_dev,
                    inode: metadata.st_ino,
                    owner: metadata.st_uid,
                    // The handle preserves object identity after this event
                    // descriptor closes, including across inode reuse. A
                    // missing handle is explicit and cannot match in v2.
                    file_handle: sample_file_handle(&file).ok(),
                    reported_pid: header.pid,
                    pidfd_available: pidfd.is_some(),
                    // Keep the kernel pidfd open through both /proc samples.
                    // The immutable PID/start/cgroup tuple is then retained,
                    // while descriptors are promptly released.
                    writer: pidfd.as_ref().and_then(|fd| sample_writer(header.pid, fd)),
                };
                if let Some(capture) = &mut self.writer_images {
                    capture.record(self.events.len() + 1, &event, &file, pidfd.as_ref());
                }
                self.events.push(event);
            }
            if let Some(capture) = &self.writer_images {
                capture.check_bound()?;
            }
        }
        Ok(self.events.len() - before)
    }

    pub fn events(&self) -> Result<&[CloseWriteEvent], String> {
        if self.poisoned {
            Err("fanotify capture already uncertain".to_owned())
        } else {
            Ok(&self.events)
        }
    }

    /// Consume the watcher only after the independently owned producer has
    /// stopped. A final drain is required before any inode correlation.
    pub fn finish(mut self) -> Result<FinishedStagingEffectEvents, String> {
        self.drain()?;
        Ok(FinishedStagingEffectEvents {
            filesystem_device: self.filesystem_device,
            events: self.events,
            writer_images: self
                .writer_images
                .map(WriterImageCapture::finish)
                .transpose()?,
        })
    }
}

impl FinishedStagingEffectEvents {
    pub(crate) fn writer_images(&self) -> Option<&[serde_json::Value]> {
        self.writer_images.as_deref()
    }

    pub fn events(&self) -> &[CloseWriteEvent] {
        &self.events
    }

    /// Compare a retained, already-open file with every close-write event
    /// for its device/inode. The expected cgroup must come from an outside
    /// process pin. A missing event, unknown writer or foreign writer refuses;
    /// this still cannot identify deleted files or prove Guard causality.
    pub fn correlate_file(
        &self,
        file: &impl AsFd,
        expected_cgroup: &str,
    ) -> Result<CorrelatedFileEffect, String> {
        if !valid_cgroup(expected_cgroup) {
            return Err("invalid outside effect writer cgroup".to_owned());
        }
        let metadata = fstat(file).map_err(|error| error.to_string())?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_nlink != 1
            || metadata.st_dev != self.filesystem_device
        {
            return Err(
                "retained effect is not one regular file on the marked filesystem".to_owned(),
            );
        }
        let matching = self
            .events
            .iter()
            .filter(|event| event.device == metadata.st_dev && event.inode == metadata.st_ino);
        let final_handle = sample_file_handle(file)?;
        let mut count = 0;
        let mut writers = Vec::new();
        for event in matching {
            let event_handle = event
                .file_handle
                .as_ref()
                .ok_or("effect file generation was not observed")?;
            if event_handle != &final_handle {
                continue;
            }
            let writer = event
                .writer
                .as_ref()
                .ok_or("effect writer process was not observed live")?;
            if event.owner != metadata.st_uid
                || writer.pid != event.reported_pid
                || writer.cgroup != expected_cgroup
            {
                return Err("effect writer or file owner differs from outside pin".to_owned());
            }
            count += 1;
            if !writers.contains(writer) {
                writers.push(writer.clone());
            }
        }
        if count == 0 {
            return Err("retained effect has no captured close-write".to_owned());
        }
        writers.sort_by_key(|writer| (writer.pid, writer.start_ticks));
        Ok(CorrelatedFileEffect {
            device: metadata.st_dev,
            inode: metadata.st_ino,
            close_writes: count,
            writers,
            cgroup: expected_cgroup.to_owned(),
        })
    }
}

#[cfg(test)]
#[path = "staging_effect_events_tests.rs"]
mod tests;
