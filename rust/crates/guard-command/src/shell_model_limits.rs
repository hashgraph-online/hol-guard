//! Resource bounds for modeling shell text a resident worker cannot cancel.
//!
//! A bounded model fails with a typed limit instead of allocating or reading
//! the filesystem past the declared envelope; the caller turns that into a
//! fail-closed refusal.

use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShellModelLimit {
    Segments,
    Proofs,
    Deadline,
}

#[derive(Clone, Copy, Debug)]
pub struct ShellModelLimits {
    pub max_segments: usize,
    /// Path proofs (including those held on the directory stack) one segment
    /// may carry.
    pub max_segment_proofs: usize,
    /// Path proofs summed over every segment of one context.
    pub max_total_proofs: usize,
    pub deadline: Option<Instant>,
}

impl ShellModelLimits {
    pub const fn unbounded() -> Self {
        Self {
            max_segments: usize::MAX,
            max_segment_proofs: usize::MAX,
            max_total_proofs: usize::MAX,
            deadline: None,
        }
    }

    pub fn check_deadline(&self) -> Result<(), ShellModelLimit> {
        match self.deadline {
            Some(deadline) if Instant::now() >= deadline => Err(ShellModelLimit::Deadline),
            _ => Ok(()),
        }
    }

    pub fn admit_segments(&self, count: usize) -> Result<(), ShellModelLimit> {
        if count > self.max_segments {
            return Err(ShellModelLimit::Segments);
        }
        Ok(())
    }

    /// Account one segment's proofs against both bounds before they are copied.
    pub fn admit_proofs(&self, total: &mut usize, segment: usize) -> Result<(), ShellModelLimit> {
        *total = total.saturating_add(segment);
        if segment > self.max_segment_proofs || *total > self.max_total_proofs {
            return Err(ShellModelLimit::Proofs);
        }
        Ok(())
    }
}
