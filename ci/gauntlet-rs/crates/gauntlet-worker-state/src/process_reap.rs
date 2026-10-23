//! Bounded direct-child reap for fixed inert ARM probes. Production job
//! deadlines and descendant cleanup require separate worker evidence.

use crate::CgroupProbeError;
use std::process::Child;
use std::thread;
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_millis(20);
const REAP_WAIT: Duration = Duration::from_secs(3);

pub(crate) fn reap_probe_child_bounded(child: &mut Child) -> Result<(), CgroupProbeError> {
    let mut started = Instant::now();
    let mut escalated = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) if started.elapsed() < REAP_WAIT => thread::sleep(POLL),
            Ok(None) if !escalated => {
                let _ = child.kill();
                escalated = true;
                started = Instant::now();
            }
            Ok(None) => return Err(CgroupProbeError::Spawn),
            Err(_) => {
                let _ = child.kill();
                return Err(CgroupProbeError::Spawn);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn long_lived_child_is_killed_and_reaped_after_fixed_wait() {
        let mut child = Command::new("/usr/bin/sleep").arg("30").spawn().unwrap();
        let result = reap_probe_child_bounded(&mut child);
        if result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        assert_eq!(result, Ok(()));
    }
}
