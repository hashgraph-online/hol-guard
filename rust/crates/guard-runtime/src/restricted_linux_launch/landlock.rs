//! Strict ABI-3 Landlock grants anchored to verified no-follow descriptors.
use super::plan::{Plan, Result};
use ::landlock::{
    Access, AccessFs, BitFlags, CompatLevel, Compatible, PathBeneath, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetStatus, ABI,
};
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const EXECUTE: u64 = 1;
const WRITE_FILE: u64 = 1 << 1;
const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
const HANDLED: u64 = (1 << 15) - 1;
const WRITE_DIRECTORY: u64 = HANDLED & !(EXECUTE | READ_FILE | READ_DIR | (1 << 6) | (1 << 11));

struct Boundary {
    ruleset: Option<RulesetCreated>,
}
impl Boundary {
    fn grant(
        &mut self,
        path: &Path,
        access: u64,
        directory: Option<bool>,
        identity: Option<(u64, u64)>,
        device: bool,
    ) -> Result<()> {
        if !path.is_absolute() {
            return Err("Linux access plans require absolute paths.");
        }
        let descriptor = open(
            path,
            OFlag::O_PATH | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| "Could not resolve the Linux access boundary.")?;
        let file = File::from(descriptor);
        let m = file
            .metadata()
            .map_err(|_| "Could not resolve the Linux access boundary.")?;
        let evidence = super::admission::Evidence {
            mode: m.mode(),
            device: m.dev(),
            inode: m.ino(),
            links: m.nlink(),
            major: libc::major(m.rdev()),
            minor: libc::minor(m.rdev()),
        };
        let access =
            super::admission::rights(path, access, directory, identity, device, &evidence)?;
        let flags = BitFlags::<AccessFs>::from_bits(access)
            .map_err(|_| "Could not install the Linux access boundary.")?;
        let ruleset = self
            .ruleset
            .take()
            .ok_or("Could not install the Linux access boundary.")?
            .add_rule(PathBeneath::new(&file, flags))
            .map_err(|_| "Could not install the Linux access boundary.")?;
        self.ruleset = Some(ruleset);
        Ok(())
    }
}

pub(super) fn enforce(plan: &Plan) -> Result<()> {
    if !matches!(std::env::consts::ARCH, "x86_64" | "aarch64") {
        return Err("Unsupported Linux syscall architecture; execution was not started.");
    }
    // HardRequirement rejects kernels below ABI 3 instead of dropping rights.
    let ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V3))
        .map_err(|_| "Landlock ABI 3 or later is required; execution was not started.")?
        .create()
        .map_err(|_| "Could not create the Linux access boundary.")?;
    let mut boundary = Boundary {
        ruleset: Some(ruleset),
    };
    for path in &plan.read_roots {
        boundary.grant(path, READ_FILE | READ_DIR, Some(true), None, false)?;
    }
    for path in &plan.read_files {
        let identity = plan
            .read_identities
            .get(path)
            .copied()
            .ok_or("Linux read target changed after discovery.")?;
        boundary.grant(path, READ_FILE, Some(false), Some(identity), false)?;
    }
    for path in &plan.list_roots {
        boundary.grant(path, READ_DIR, Some(true), None, false)?;
    }
    for path in &plan.write_roots {
        boundary.grant(
            path,
            WRITE_DIRECTORY | READ_FILE | READ_DIR,
            Some(true),
            None,
            false,
        )?;
    }
    for path in &plan.executables {
        boundary.grant(path, EXECUTE | READ_FILE, Some(false), None, false)?;
    }
    for path in &plan.device_files {
        boundary.grant(
            path,
            READ_FILE
                | if path == Path::new("/dev/null") {
                    WRITE_FILE
                } else {
                    0
                },
            Some(false),
            None,
            true,
        )?;
    }
    let status = boundary
        .ruleset
        .take()
        .ok_or("Could not enforce the Linux access boundary.")?
        .restrict_self()
        .map_err(|_| "Could not enforce the Linux access boundary.")?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err("Could not enforce the Linux access boundary.");
    }
    Ok(())
}
