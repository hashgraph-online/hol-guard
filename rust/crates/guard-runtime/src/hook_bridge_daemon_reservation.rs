//! The bounded reservation a hook bridge takes before it starts the daemon.
//!
//! A dead daemon is not met by one hook. A harness that fires a burst of
//! tool hooks meets it with all of them at once, and before this every one
//! of them ran the install-time start command itself: N hooks, N start
//! processes, each paying an interpreter start out of its own hook budget
//! for a daemon that only one of them had to start.
//!
//! One short-lived file in the Guard home bounds that. The first hook
//! creates it exclusively and owns the start; the others see it, skip their
//! own start and go straight to waiting for the daemon the owner is
//! bringing up. The reservation lasts only as long as a start command may
//! run (`START_TIMEOUT`), so a hook that is killed mid-start costs the next
//! one a bounded wait rather than a dead install, and a start that fails
//! releases it at once.
//!
//! Nothing here decides a verdict or whether a daemon is healthy: it only
//! decides which hook pays for the start. Every path that cannot reserve
//! starts the daemon exactly as it did before.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::START_TIMEOUT;

/// The reservation, beside the daemon state it is taken for. The body is
/// for whoever reads the home; the expiry is the file's own timestamp.
const RESERVATION_FILE: &str = "daemon-hook-start-reservation.json";

/// A start this hook owns.
pub(super) struct Reserved {
    marker: Option<PathBuf>,
}

impl Reserved {
    /// Give the reservation up, so the next hook starts the daemon instead
    /// of waiting for a start that is already over. A start that ran to
    /// completion keeps it: the daemon it started is up, or is still coming
    /// up for every other hook's wait, and the file expires on its own.
    pub(super) fn release(self) {
        if let Some(marker) = self.marker {
            let _ = fs::remove_file(marker);
        }
    }
}

/// `Some` when this hook may run the start command, `None` when another
/// hook began a start less than `START_TIMEOUT` ago and this one should
/// wait for that daemon instead of starting a second one.
///
/// Without a Guard home, or with a home this hook cannot write a marker in,
/// there is nowhere to reserve: the start runs as it always did.
pub(super) fn reserve(guard_home: Option<&Path>) -> Option<Reserved> {
    // A relative home is the working directory of whatever launched the
    // hook, which is not a place to leave state; a bridge that passes one
    // starts the daemon as it did before.
    let Some(marker) = guard_home
        .filter(|home| home.is_absolute())
        .map(|home| home.join(RESERVATION_FILE))
    else {
        return Some(unreserved());
    };
    match claim(&marker) {
        Ok(()) => return Some(held(marker)),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(_) => return Some(unreserved()),
    }
    if !expired(&marker) {
        return None;
    }
    // Taking an expired reservation over is a remove and a create, so two
    // hooks that both find the same expired marker can end up owning a
    // start each: either one may remove what the other just created. That
    // costs a second start command, which is what every hook did before
    // this reservation existed and what the daemon's own owner lock already
    // settles; it never costs a start, since the hook that loses the race
    // still holds a reservation and still runs the command. The alternative,
    // a lock held across the check, buys that narrow window at the price of
    // a hook the harness kills stranding every later one.
    let _ = fs::remove_file(&marker);
    match claim(&marker) {
        Ok(()) => Some(held(marker)),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => None,
        Err(_) => Some(unreserved()),
    }
}

fn held(marker: PathBuf) -> Reserved {
    Reserved {
        marker: Some(marker),
    }
}

fn unreserved() -> Reserved {
    Reserved { marker: None }
}

/// Create the marker, failing when one is already there. The body is
/// written after the create won, so a write that fails leaves the
/// reservation this hook holds in place rather than a start nobody owns.
fn claim(marker: &Path) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(marker)?;
    let claimed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let _ = write!(file, "{{\"claimed_at\": {claimed_at}}}");
    Ok(())
}

/// Whether the reservation is older than a start command may run, which a
/// reservation whose age cannot be read at all also is: one that bounds
/// nothing must not hold every later hook off the start.
fn expired(marker: &Path) -> bool {
    let Ok(claimed_at) = fs::symlink_metadata(marker).and_then(|metadata| metadata.modified())
    else {
        return true;
    };
    // A marker dated ahead of the clock has no readable age: `elapsed` fails
    // for as long as the clock stays behind it. A successful start leaves its
    // marker in place, so a backward step after one — an NTP correction, a VM
    // resume, a home written on a host whose clock runs ahead — would
    // otherwise hold every later hook off the start indefinitely, and each of
    // them would wait out a daemon nobody is bringing up. An age that cannot
    // be read is expired, whichever way it cannot be read.
    match claimed_at.elapsed() {
        Ok(age) => age >= START_TIMEOUT,
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::FileTimes;
    use std::time::Duration;

    fn home() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn age(marker: &Path, age: Duration) {
        let file = OpenOptions::new().write(true).open(marker).unwrap();
        file.set_times(FileTimes::new().set_modified(SystemTime::now() - age))
            .unwrap();
    }

    #[test]
    fn the_first_hook_reserves_the_start_and_the_next_waits_for_it() {
        let home = home();
        let first = reserve(Some(home.path())).expect("the first hook owns the start");
        assert!(home.path().join(RESERVATION_FILE).exists());
        assert!(
            reserve(Some(home.path())).is_none(),
            "a second start for the same daemon is what the reservation exists to stop"
        );
        first.release();
        assert!(!home.path().join(RESERVATION_FILE).exists());
        reserve(Some(home.path())).expect("a released reservation is free again");
    }

    #[test]
    fn a_reservation_no_start_can_still_be_running_under_is_taken_over() {
        let home = home();
        reserve(Some(home.path())).expect("the first hook owns the start");
        let marker = home.path().join(RESERVATION_FILE);
        age(&marker, START_TIMEOUT - Duration::from_secs(1));
        assert!(reserve(Some(home.path())).is_none());
        age(&marker, START_TIMEOUT + Duration::from_secs(1));
        let taken = reserve(Some(home.path())).expect("an expired reservation is taken over");
        assert!(
            reserve(Some(home.path())).is_none(),
            "the hook that took it over now owns the start"
        );
        taken.release();
    }

    #[test]
    fn the_claim_is_recorded_for_whoever_reads_the_home() {
        let home = home();
        let held = reserve(Some(home.path())).expect("the first hook owns the start");
        let body = fs::read_to_string(home.path().join(RESERVATION_FILE)).unwrap();
        let claimed_at = serde_json::from_str::<serde_json::Value>(&body).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(claimed_at["claimed_at"].as_u64().unwrap().abs_diff(now) <= 5);
        held.release();
    }

    #[test]
    fn a_home_that_cannot_hold_a_reservation_starts_the_daemon_as_before() {
        let home = home();
        let missing = home.path().join("gone");
        reserve(Some(&missing)).expect("an unreachable home reserves nothing and starts");
        assert!(!missing.exists());
        reserve(None).expect("no home reserves nothing and starts");
        reserve(Some(Path::new("relative"))).expect("a relative home reserves nothing and starts");
        assert!(!Path::new("relative").exists());
    }

    #[test]
    fn a_reservation_dated_ahead_of_the_clock_is_taken_over() {
        let home = home();
        reserve(Some(home.path())).expect("the first hook owns the start");
        let marker = home.path().join(RESERVATION_FILE);
        // What a backward clock step after a successful start leaves behind.
        let file = OpenOptions::new().write(true).open(&marker).unwrap();
        file.set_times(
            FileTimes::new().set_modified(SystemTime::now() + Duration::from_secs(3600)),
        )
        .unwrap();
        let taken = reserve(Some(home.path()))
            .expect("a reservation with no readable age bounds nothing and is taken over");
        assert!(
            reserve(Some(home.path())).is_none(),
            "the hook that took it over now owns the start"
        );
        taken.release();
    }

    #[cfg(unix)]
    #[test]
    fn a_marker_planted_as_a_symlink_is_never_written_through() {
        let home = home();
        let target = home.path().join("elsewhere");
        std::os::unix::fs::symlink(&target, home.path().join(RESERVATION_FILE)).unwrap();
        // A link is a reservation like any other: it is waited out, and
        // taken over by removing the link itself once its own timestamp
        // expires. Either way the file it points at is never created.
        assert!(reserve(Some(home.path())).is_none());
        assert!(!target.exists());
    }
}
