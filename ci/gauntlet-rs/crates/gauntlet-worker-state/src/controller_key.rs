//! Worker-owned deterministic signing identity. Only the public key is
//! durable; the 32-byte seed crosses one exec in a sealed, private memfd.

use crate::{
    hex, read_bounded_regular, ActiveLease, ReservationError, RunReservationJournal, StartedMarker,
};
use gauntlet_contracts::canonicalize;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustix::fs::{fstat, fsync, openat, statat, AtFlags, FileType, Mode, OFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;

const SCHEMA: &str = "hol-gauntlet-controller-key-pin.v1";
const MAX_BYTES: u64 = 1024;
const REQUIRED_SEALS: libc::c_int =
    libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;

#[path = "controller_key_observe.rs"]
mod observe;
pub use observe::{
    observe_controller_key_pin_root_owned, ControllerKeyObservation, ControllerKeyOutsidePins,
};

#[derive(Debug)]
pub enum ControllerKeyError {
    RootRequired,
    Generate,
    Seal,
    UnsafePin,
    InvalidPin,
    Reservation(ReservationError),
}

impl fmt::Display for ControllerKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootRequired => f.write_str("Linux Root required for worker signing key"),
            Self::Generate => f.write_str("worker signing key generation failed"),
            Self::Seal => f.write_str("worker signing key memfd could not be sealed"),
            Self::UnsafePin => f.write_str("Root-owned one-use controller key pin required"),
            Self::InvalidPin => f.write_str("controller key pin differs from the started job"),
            Self::Reservation(error) => write!(f, "controller key pin lease: {error}"),
        }
    }
}

impl std::error::Error for ControllerKeyError {}

pub(crate) struct SealedControllerKey {
    descriptor: File,
    public_key_hex: String,
}

impl SealedControllerKey {
    pub(crate) fn generate() -> Result<Self, ControllerKeyError> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(ControllerKeyError::RootRequired);
        }
        let mut seed = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut seed)
            .map_err(|_| ControllerKeyError::Generate)?;
        let pair =
            Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| ControllerKeyError::Generate)?;
        let name = c"hol-gauntlet-controller-key";
        // SAFETY: the static name is NUL-terminated, and a successful syscall
        // gives this process sole ownership of the returned descriptor.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr(),
                libc::MFD_ALLOW_SEALING | libc::MFD_CLOEXEC,
            )
        };
        if !(3..=4096).contains(&raw) {
            if raw >= 0 {
                // SAFETY: raw is the descriptor returned by memfd_create.
                unsafe { libc::close(raw as libc::c_int) };
            }
            return Err(ControllerKeyError::Generate);
        }
        // SAFETY: raw was returned by memfd_create and is transferred once.
        let mut descriptor = unsafe { File::from_raw_fd(raw as libc::c_int) };
        let written = descriptor.write_all(&seed);
        seed.fill(0);
        written.map_err(|_| ControllerKeyError::Seal)?;
        descriptor
            .seek(SeekFrom::Start(0))
            .map_err(|_| ControllerKeyError::Seal)?;
        // SAFETY: fcntl receives this owned descriptor and the fixed seal mask.
        let added =
            unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_ADD_SEALS, REQUIRED_SEALS) };
        if added < 0 {
            return Err(ControllerKeyError::Seal);
        }
        // SAFETY: F_GET_SEALS and fstat only inspect the held descriptor.
        let seals = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GET_SEALS) };
        let metadata = descriptor
            .metadata()
            .map_err(|_| ControllerKeyError::Seal)?;
        if seals & REQUIRED_SEALS != REQUIRED_SEALS
            || !metadata.is_file()
            || metadata.len() != 32
            || metadata.uid() != 0
            || metadata.nlink() != 0
        {
            return Err(ControllerKeyError::Seal);
        }
        Ok(Self {
            descriptor,
            public_key_hex: pair
                .public_key()
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        })
    }

    pub(crate) fn fd(&self) -> &File {
        &self.descriptor
    }

    pub(crate) fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ControllerKeyPin {
    pub(crate) public_key_hex: String,
    pub(crate) raw_sha256: String,
}

fn pin_name(job_id: &str) -> Result<String, ControllerKeyError> {
    if !hex(job_id, 16) {
        return Err(ControllerKeyError::InvalidPin);
    }
    Ok(format!("{job_id}.controller-key.json"))
}

fn pin_bytes(started: &StartedMarker, public_key_hex: &str) -> Result<Vec<u8>, ControllerKeyError> {
    if !hex(public_key_hex, 64)
        || started.controller_public_key_hex.as_deref() != Some(public_key_hex)
    {
        return Err(ControllerKeyError::InvalidPin);
    }
    let value = json!({
        "schema": SCHEMA,
        "job_id": started.job_id,
        "source_sha": started.source_sha,
        "deployment_digest": started.deployment_digest,
        "worker_generation": started.worker_generation,
        "started_marker_sha256": started.sha256,
        "controller_public_key_hex": public_key_hex,
    });
    let bytes =
        canonicalize(value.to_string().as_bytes()).map_err(|_| ControllerKeyError::InvalidPin)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(ControllerKeyError::InvalidPin);
    }
    Ok(bytes)
}

fn require_started(
    journal: &RunReservationJournal,
    started: &StartedMarker,
) -> Result<(), ControllerKeyError> {
    let retained = journal
        .started(
            &started.job_id,
            &started.source_sha,
            &started.deployment_digest,
            &started.worker_generation,
        )
        .map_err(ControllerKeyError::Reservation)?;
    if retained.as_ref() != Some(started) {
        return Err(ControllerKeyError::InvalidPin);
    }
    Ok(())
}

pub(crate) fn write_pin(
    journal: &RunReservationJournal,
    started: &StartedMarker,
    public_key_hex: &str,
    require_root: bool,
) -> Result<ControllerKeyPin, ControllerKeyError> {
    require_started(journal, started)?;
    let bytes = pin_bytes(started, public_key_hex)?;
    let name = pin_name(&started.job_id)?;
    let descriptor = openat(
        &journal.root,
        name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| ControllerKeyError::UnsafePin)?;
    let stat = fstat(&descriptor).map_err(|_| ControllerKeyError::UnsafePin)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 1
        || stat.st_mode & 0o077 != 0
        || (require_root && stat.st_uid != 0)
    {
        return Err(ControllerKeyError::UnsafePin);
    }
    let mut file = File::from(descriptor);
    file.write_all(&bytes)
        .map_err(|_| ControllerKeyError::UnsafePin)?;
    file.sync_all().map_err(|_| ControllerKeyError::UnsafePin)?;
    fsync(&journal.root).map_err(|_| ControllerKeyError::UnsafePin)?;
    Ok(ControllerKeyPin {
        public_key_hex: public_key_hex.to_owned(),
        raw_sha256: format!("{:x}", Sha256::digest(bytes)),
    })
}

pub(crate) fn pin_controller_key_under_lease(
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    started: &StartedMarker,
    key: &SealedControllerKey,
) -> Result<ControllerKeyPin, ControllerKeyError> {
    if !journal.root_owned {
        return Err(ControllerKeyError::UnsafePin);
    }
    lease
        .verify(&journal.root)
        .map_err(ControllerKeyError::Reservation)?;
    write_pin(journal, started, key.public_key_hex(), true)
}

pub(crate) fn read_pin(
    journal: &RunReservationJournal,
    started: &StartedMarker,
    require_root: bool,
) -> Result<ControllerKeyPin, ControllerKeyError> {
    require_started(journal, started)?;
    let name = pin_name(&started.job_id)?;
    let bytes = read_bounded_regular(&journal.root, &name, MAX_BYTES)
        .map_err(ControllerKeyError::Reservation)?
        .ok_or(ControllerKeyError::InvalidPin)?;
    let stat = statat(&journal.root, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ControllerKeyError::UnsafePin)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 1
        || stat.st_mode & 0o077 != 0
        || (require_root && stat.st_uid != 0)
    {
        return Err(ControllerKeyError::UnsafePin);
    }
    let canonical = canonicalize(&bytes).map_err(|_| ControllerKeyError::InvalidPin)?;
    if canonical != bytes {
        return Err(ControllerKeyError::InvalidPin);
    }
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| ControllerKeyError::InvalidPin)?;
    let fields = value.as_object().ok_or(ControllerKeyError::InvalidPin)?;
    let public = value["controller_public_key_hex"]
        .as_str()
        .ok_or(ControllerKeyError::InvalidPin)?;
    if fields.len() != 7
        || value["schema"] != SCHEMA
        || value["job_id"] != started.job_id
        || value["source_sha"] != started.source_sha
        || value["deployment_digest"] != started.deployment_digest
        || value["worker_generation"] != started.worker_generation
        || value["started_marker_sha256"] != started.sha256
        || started.controller_public_key_hex.as_deref() != Some(public)
        || !hex(public, 64)
    {
        return Err(ControllerKeyError::InvalidPin);
    }
    Ok(ControllerKeyPin {
        public_key_hex: public.to_owned(),
        raw_sha256: format!("{:x}", Sha256::digest(bytes)),
    })
}

fn require_pin(
    journal: &RunReservationJournal,
    started: &StartedMarker,
    expected: &ControllerKeyPin,
    require_root: bool,
) -> Result<(), ControllerKeyError> {
    if read_pin(journal, started, require_root)? != *expected {
        return Err(ControllerKeyError::InvalidPin);
    }
    Ok(())
}

pub(crate) fn require_pinned_controller_key_under_lease(
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    started: &StartedMarker,
    expected: &ControllerKeyPin,
) -> Result<(), ControllerKeyError> {
    if !journal.root_owned {
        return Err(ControllerKeyError::UnsafePin);
    }
    lease
        .verify(&journal.root)
        .map_err(ControllerKeyError::Reservation)?;
    require_pin(journal, started, expected, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gauntlet_contracts::WorkerRequest;
    use serde_json::json;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    fn request() -> WorkerRequest {
        WorkerRequest::parse(
            &serde_json::to_vec(&json!({
                "schema":"hol-gauntlet-worker-request.v1",
                "action":"run",
                "job_id":"a1b2c3d4e5f60718",
                "source_sha":"a".repeat(40),
                "deployment_digest":"b".repeat(64),
            }))
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn legacy_started_marker_cannot_be_retroactively_keyed() {
        let temp = tempfile::tempdir().unwrap();
        let journal = RunReservationJournal::open(&temp.path().canonicalize().unwrap()).unwrap();
        let started = journal
            .reserve(
                &request(),
                &"a".repeat(40),
                &"b".repeat(64),
                &"c".repeat(64),
            )
            .unwrap();
        assert_eq!(started.controller_public_key_hex, None);
        assert!(matches!(
            write_pin(&journal, &started, &"d".repeat(64), false),
            Err(ControllerKeyError::InvalidPin)
        ));
    }

    #[test]
    #[ignore = "requires the pinned Root Linux ARM Python image with controller dependencies"]
    fn python_consumes_a_rust_generated_sealed_descriptor() {
        let python = std::env::var("GAUNTLET_KEY_INTEROP_PYTHON").unwrap();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .unwrap();
        let key = SealedControllerKey::generate().unwrap();
        let fd = key.fd().as_raw_fd();
        let code = "import sys;sys.path.insert(0,sys.argv[1]);from ci.gauntlet.benchmark.ci_pipeline import _rust_worker_signing_key;key=_rust_worker_signing_key('deterministic');sys.stdout.write(key.public_key().public_bytes_raw().hex())";
        let mut child = Command::new(python);
        child
            .env_clear()
            .env("HOL_GAUNTLET_RUST_SIGNING_KEY_FD", fd.to_string())
            .env("HOME", "/root")
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .args(["-I", "-B", "-c", code])
            .arg(root);
        // SAFETY: only the fixed fcntl syscall runs between fork and exec.
        unsafe {
            child.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "Python key adapter failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            key.public_key_hex()
        );
    }

    #[test]
    fn sealed_key_is_single_descriptor_and_public_pin_is_one_use() {
        if unsafe { libc::geteuid() } != 0 {
            assert!(matches!(
                SealedControllerKey::generate(),
                Err(ControllerKeyError::RootRequired)
            ));
            return;
        }
        let key = SealedControllerKey::generate().unwrap();
        assert_eq!(key.public_key_hex().len(), 64);
        assert_eq!(
            unsafe { libc::fcntl(key.fd().as_raw_fd(), libc::F_GET_SEALS) } & REQUIRED_SEALS,
            REQUIRED_SEALS
        );
        let fd = key.fd().as_raw_fd();
        let path = format!("/proc/self/fd/{fd}");
        assert!(!Command::new("/usr/bin/cat")
            .arg(&path)
            .output()
            .unwrap()
            .status
            .success());
        let mut child = Command::new("/usr/bin/cat");
        child.arg(&path);
        // SAFETY: only the fixed fcntl syscall runs between fork and exec.
        unsafe {
            child.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let passed = child.output().unwrap();
        assert!(passed.status.success());
        let read_pair = Ed25519KeyPair::from_seed_unchecked(&passed.stdout).unwrap();
        assert_eq!(
            read_pair
                .public_key()
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            key.public_key_hex()
        );
        let temp = tempfile::tempdir().unwrap();
        let journal = RunReservationJournal::open(&temp.path().canonicalize().unwrap()).unwrap();
        let started = journal
            .reserve_internal(
                &request(),
                &"a".repeat(40),
                &"b".repeat(64),
                &"c".repeat(64),
                Some(key.public_key_hex()),
            )
            .unwrap();
        assert_eq!(
            started.controller_public_key_hex.as_deref(),
            Some(key.public_key_hex())
        );
        assert!(matches!(
            read_pin(&journal, &started, false),
            Err(ControllerKeyError::InvalidPin)
        ));
        let pin = write_pin(&journal, &started, key.public_key_hex(), false).unwrap();
        assert_eq!(read_pin(&journal, &started, false).unwrap(), pin);
        let restarted = RunReservationJournal::open(&temp.path().canonicalize().unwrap()).unwrap();
        assert_eq!(read_pin(&restarted, &started, false).unwrap(), pin);
        assert!(matches!(
            write_pin(&journal, &started, key.public_key_hex(), false),
            Err(ControllerKeyError::UnsafePin)
        ));
        let mut wrong = started.clone();
        wrong.sha256 = "d".repeat(64);
        assert!(read_pin(&journal, &wrong, false).is_err());
        let path = temp.path().join(pin_name(&started.job_id).unwrap());
        let changed = String::from_utf8(std::fs::read(&path).unwrap())
            .unwrap()
            .replace(&pin.public_key_hex, &"e".repeat(64));
        std::fs::write(&path, changed).unwrap();
        assert!(matches!(
            require_pin(&journal, &started, &pin, false),
            Err(ControllerKeyError::InvalidPin)
        ));
    }
}
