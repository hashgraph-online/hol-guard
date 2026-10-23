//! Data-only, outside-pinned reader for the worker-owned public key.
//! It never reads the seed or turns a controller signature into a verdict.

use super::{read_pin, ControllerKeyError, ControllerKeyPin};
use crate::{ActiveLease, RunReservationJournal, StartedMarker};
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerKeyOutsidePins {
    pub job_id: String,
    pub source_sha: String,
    pub deployment_digest: String,
    pub worker_generation: String,
    pub started_marker_sha256: String,
    pub controller_key_pin_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerKeyObservation {
    pub started_marker_sha256: String,
    pub controller_public_key_hex: String,
    pub controller_key_pin_sha256: String,
}

impl ControllerKeyObservation {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-controller-key-observation.v1",
            "started_marker_sha256":self.started_marker_sha256,
            "controller_public_key_hex":self.controller_public_key_hex,
            "controller_key_pin_sha256":self.controller_key_pin_sha256,
            "execution_eligible":false,
        })
    }
}

fn read_exact_pair(
    journal: &RunReservationJournal,
    pins: &ControllerKeyOutsidePins,
    require_root: bool,
) -> Result<(StartedMarker, ControllerKeyPin), ControllerKeyError> {
    let started = journal
        .started(
            &pins.job_id,
            &pins.source_sha,
            &pins.deployment_digest,
            &pins.worker_generation,
        )
        .map_err(ControllerKeyError::Reservation)?
        .ok_or(ControllerKeyError::InvalidPin)?;
    if started.sha256 != pins.started_marker_sha256 || started.controller_public_key_hex.is_none() {
        return Err(ControllerKeyError::InvalidPin);
    }
    let pin = read_pin(journal, &started, require_root)?;
    if pin.raw_sha256 != pins.controller_key_pin_sha256
        || started.controller_public_key_hex.as_deref() != Some(&pin.public_key_hex)
    {
        return Err(ControllerKeyError::InvalidPin);
    }
    Ok((started, pin))
}

fn observe_internal(
    journal: &RunReservationJournal,
    pins: &ControllerKeyOutsidePins,
    require_root: bool,
) -> Result<ControllerKeyObservation, ControllerKeyError> {
    let first = read_exact_pair(journal, pins, require_root)?;
    let second = read_exact_pair(journal, pins, require_root)?;
    if first != second {
        return Err(ControllerKeyError::InvalidPin);
    }
    Ok(ControllerKeyObservation {
        started_marker_sha256: first.0.sha256,
        controller_public_key_hex: first.1.public_key_hex,
        controller_key_pin_sha256: first.1.raw_sha256,
    })
}

/// Read the keyed marker and sidecar under the Root worker lease, requiring
/// both digests from outside this journal. Supplying hashes observed from the
/// same untrusted VM state does not make them independent trust anchors.
pub fn observe_controller_key_pin_root_owned(
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    pins: &ControllerKeyOutsidePins,
) -> Result<ControllerKeyObservation, ControllerKeyError> {
    if !journal.root_owned {
        return Err(ControllerKeyError::UnsafePin);
    }
    lease
        .verify(&journal.root)
        .map_err(ControllerKeyError::Reservation)?;
    let observed = observe_internal(journal, pins, true)?;
    lease
        .verify(&journal.root)
        .map_err(ControllerKeyError::Reservation)?;
    Ok(observed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller_key::write_pin;
    use gauntlet_contracts::WorkerRequest;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn independent_digest_pins_survive_restart_and_refuse_substitution() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let journal = RunReservationJournal::open(&root).unwrap();
        let request = WorkerRequest::parse(
            br#"{"action":"run","deployment_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","job_id":"a1b2c3d4e5f60718","schema":"hol-gauntlet-worker-request.v1","source_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        )
        .unwrap();
        let public = "d".repeat(64);
        let started = journal
            .reserve_internal(
                &request,
                &"a".repeat(40),
                &"b".repeat(64),
                &"c".repeat(64),
                Some(&public),
            )
            .unwrap();
        let pin = write_pin(&journal, &started, &public, false).unwrap();
        let outside = ControllerKeyOutsidePins {
            job_id: request.job_id().to_owned(),
            source_sha: started.source_sha.clone(),
            deployment_digest: started.deployment_digest.clone(),
            worker_generation: started.worker_generation.clone(),
            started_marker_sha256: started.sha256.clone(),
            controller_key_pin_sha256: pin.raw_sha256.clone(),
        };
        let first = observe_internal(&journal, &outside, false).unwrap();
        assert_eq!(first.controller_public_key_hex, public);
        assert_eq!(first.to_json()["execution_eligible"], false);
        drop(journal);
        let restarted = RunReservationJournal::open(&root).unwrap();
        assert_eq!(
            observe_internal(&restarted, &outside, false).unwrap(),
            first
        );

        let mut wrong = outside.clone();
        wrong.started_marker_sha256 = "e".repeat(64);
        assert!(observe_internal(&restarted, &wrong, false).is_err());
        wrong = outside.clone();
        wrong.controller_key_pin_sha256 = "e".repeat(64);
        assert!(observe_internal(&restarted, &wrong, false).is_err());

        let path = root.join(format!("{}.controller-key.json", request.job_id()));
        let changed = String::from_utf8(std::fs::read(&path).unwrap())
            .unwrap()
            .replace(&public, &"e".repeat(64));
        std::fs::write(&path, changed).unwrap();
        assert!(observe_internal(&restarted, &outside, false).is_err());
    }

    #[test]
    fn root_reader_requires_the_private_journal_and_exclusive_lease() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let temp = tempfile::tempdir_in("/root").unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let journal =
            RunReservationJournal::open_root_owned(&temp.path().canonicalize().unwrap()).unwrap();
        let lease = journal.acquire_active_lease().unwrap();
        let request = WorkerRequest::parse(
            br#"{"action":"run","deployment_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","job_id":"a1b2c3d4e5f60718","schema":"hol-gauntlet-worker-request.v1","source_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        )
        .unwrap();
        let public = "d".repeat(64);
        let started = journal
            .reserve_keyed_under_lease(
                &lease,
                &request,
                &"a".repeat(40),
                &"b".repeat(64),
                &"c".repeat(64),
                &public,
            )
            .unwrap();
        let pin = write_pin(&journal, &started, &public, true).unwrap();
        let outside = ControllerKeyOutsidePins {
            job_id: request.job_id().to_owned(),
            source_sha: started.source_sha.clone(),
            deployment_digest: started.deployment_digest.clone(),
            worker_generation: started.worker_generation.clone(),
            started_marker_sha256: started.sha256.clone(),
            controller_key_pin_sha256: pin.raw_sha256.clone(),
        };
        assert_eq!(
            observe_controller_key_pin_root_owned(&journal, &lease, &outside)
                .unwrap()
                .controller_public_key_hex,
            public
        );
        let mut wrong = outside.clone();
        wrong.controller_key_pin_sha256 = "e".repeat(64);
        assert!(observe_controller_key_pin_root_owned(&journal, &lease, &wrong).is_err());
    }
}
