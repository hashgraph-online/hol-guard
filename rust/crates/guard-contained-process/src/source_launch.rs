//! The caller's authorization fence for a framed frozen-source launch.

use std::io;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use crate::{CapturedOutput, Isolation, PinnedCommand};

#[path = "source_ack.rs"]
mod acknowledgement;

pub(crate) struct SourceGate<'a> {
    pub gate: &'a mut dyn SourceLaunchGate,
    pub frame_before_commit: bool,
}

pub(crate) fn validate_deferred_outputs(
    isolation: &Isolation,
    gate: Option<&SourceGate<'_>>,
) -> io::Result<()> {
    if isolation.creation_mask.is_some_and(|mask| mask > 0o777)
        || !isolation.deferred_outputs.is_empty()
            && (isolation.creation_mask.is_none()
                || !gate.is_some_and(|gate| gate.frame_before_commit)
                || isolation.deferred_outputs.len() > 64
                || isolation.inherited_files.len() + isolation.deferred_outputs.len() > 250)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid deferred output launch",
        ));
    }
    Ok(())
}

pub trait SourceLaunchGate {
    /// Authorize the first output effect after native child initialization,
    /// before file creation/truncation and interpreter exec. A real attempt
    /// can fail after this point; it must not be automatically retried.
    fn prepare_effects(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "output effects need explicit authorization",
        ))
    }

    /// Revalidate current authority and, if not already claimed for output
    /// effects, atomically claim the grant. Keep any
    /// launch fence held until `released` or this capture returns an error.
    fn commit(&mut self) -> io::Result<()>;

    /// The kernel accepted the one-byte release marker. Record this local
    /// state before a fallible acknowledgement: an error after this point may
    /// have executed user code and must never trigger an automatic retry.
    /// This acknowledges dispatch, not user-code completion.
    fn released(&mut self) -> io::Result<()>;
}

impl PinnedCommand {
    /// A macOS system image is adopted only from the verified read-only root.
    /// Read-only modes on a private copied image do not establish this proof.
    #[cfg(target_os = "macos")]
    pub fn has_readonly_system_image(&self) -> io::Result<bool> {
        self.verify_bindings()?;
        self.image.on_readonly_system_root()
    }

    /// Feed source to a trusted framing bootstrap, then release its NUL marker
    /// only after `gate` commits. The caller must bind the interpreter/bootstrap
    /// and exact expected source length; arbitrary executables need not wait
    /// for this marker and cannot use this method as an authorization boundary.
    pub fn capture_frozen_source(
        self,
        source: &[u8],
        cap: usize,
        deadline: Instant,
        cancel: &AtomicBool,
        isolation: Isolation,
        gate: &mut dyn SourceLaunchGate,
    ) -> io::Result<CapturedOutput> {
        if cap == 0 || source.len() > 4 * 1024 * 1024 || source.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid frozen source frame",
            ));
        }
        crate::unix::capture(
            self,
            source,
            cap,
            deadline,
            cancel,
            isolation,
            crate::unix::CaptureMode::Standard(Some(SourceGate {
                gate,
                frame_before_commit: false,
            })),
        )
    }

    /// Deliver a complete NUL-terminated source frame before committing, then
    /// release a second empty frame after authorization. The trusted bootstrap
    /// must send readiness `R` and dispatch `S` to reserved fd6. The process
    /// owner waits for each acknowledgment within the deadline before calling
    /// the corresponding gate callback. Other inherited files start at fd7.
    pub fn capture_acknowledged_source(
        self,
        source: &[u8],
        cap: usize,
        deadline: Instant,
        cancel: &AtomicBool,
        mut isolation: Isolation,
        gate: &mut dyn SourceLaunchGate,
    ) -> io::Result<CapturedOutput> {
        if cap == 0 || source.len() > 4 * 1024 * 1024 || source.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid frozen source frame",
            ));
        }
        let (channel, writer) = crate::unix::control_pipe()?;
        crate::unix::control_nonblocking(&channel)?;
        isolation
            .inherited_files
            .insert(0, std::fs::File::from(writer));
        let mut acknowledged = acknowledgement::Gate {
            authority: gate,
            channel: std::fs::File::from(channel),
            deadline,
            cancel,
            outputs: isolation.deferred_outputs.clone(),
            output_base: 6 + isolation.inherited_files.len() as u32,
        };
        crate::unix::capture(
            self,
            source,
            cap,
            deadline,
            cancel,
            isolation,
            crate::unix::CaptureMode::Standard(Some(SourceGate {
                gate: &mut acknowledged,
                frame_before_commit: true,
            })),
        )
    }
}

#[cfg(test)]
#[path = "source_launch_tests.rs"]
mod tests;
