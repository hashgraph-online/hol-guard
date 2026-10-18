//! The caller's authorization fence for a framed frozen-source launch.

use std::io;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use crate::{CapturedOutput, Isolation, PinnedCommand};

pub trait SourceLaunchGate {
    /// Revalidate current authority and atomically claim the grant. Keep any
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
        crate::unix::capture(self, source, cap, deadline, cancel, isolation, Some(gate))
    }
}

#[cfg(test)]
#[path = "source_launch_tests.rs"]
mod tests;
