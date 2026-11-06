//! Seal executable images only after making every namespace mount noexec.
use super::mapping_copy::{identity, seal};
use super::mapping_records::validate;
use super::mounts::{targets, BIND, NODEV, NOEXEC, NOSUID, READONLY, REMOUNT};
use super::plan::{Plan, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const STORE: &str = "/guard-approved-mappings";

fn mount(source: Option<&Path>, target: &Path, flags: u64) -> Result<()> {
    nix::mount::mount(
        source,
        target,
        None::<&str>,
        nix::mount::MsFlags::from_bits_retain(flags),
        None::<&str>,
    )
    .map_err(|_| "Linux executable mapping mount failed.")
}

fn flags(path: &Path) -> Result<u64> {
    nix::sys::statvfs::statvfs(path)
        .map(|v| v.flags().bits())
        .map_err(|_| "Linux mount could not be verified.")
}

pub(super) fn enforce(plan: &Plan) -> Result<BTreeMap<PathBuf, (u64, u64)>> {
    let approved: BTreeSet<_> = plan
        .read_files
        .iter()
        .chain(&plan.executables)
        .cloned()
        .collect();
    let records = validate(&plan.mapping_records, &approved)?;
    // Disable same-UID inspection before private executable copies are created.
    nix::sys::prctl::set_dumpable(false)
        .map_err(|_| "Linux setup process inspection could not be disabled.")?;
    if nix::sys::prctl::get_dumpable()
        .map_err(|_| "Linux setup process inspection could not be disabled.")?
    {
        return Err("Linux setup process inspection could not be disabled.");
    }
    let mut raw = Vec::new();
    fs::File::open("/proc/self/mountinfo")
        .map_err(|_| "Namespace mount snapshot unavailable.")?
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "Namespace mount snapshot unavailable.")?;
    let mounts = targets(&raw)?;
    let store = Path::new(STORE);
    if !mounts.iter().any(|(p, _)| p == store)
        || !store.is_dir()
        || fs::read_dir(store)
            .map_err(|_| "The private Linux mapping store is unavailable.")?
            .next()
            .is_some()
    {
        return Err("The private Linux mapping store is unavailable.");
    }
    fs::set_permissions(store, fs::Permissions::from_mode(0o700))
        .map_err(|_| "The private Linux mapping store is unavailable.")?;
    for (target, inherited) in mounts {
        mount(None, &target, BIND | REMOUNT | inherited)?;
        if flags(&target)? & NOEXEC == 0 {
            return Err("Linux noexec mount was not enforced.");
        }
    }
    let mut identities = BTreeMap::new();
    for (index, record) in records.iter().enumerate() {
        let destination = store.join(index.to_string());
        let descriptor = seal(record, &destination)?;
        let sealed = descriptor
            .metadata()
            .map_err(|_| "Linux sealed mapping could not be verified.")?;
        for target in &record.aliases {
            let alias = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(target)
                .map_err(|_| "Executable mapping alias changed.")?;
            if identity(
                &alias
                    .metadata()
                    .map_err(|_| "Executable mapping alias changed.")?,
            )? != record.identity
            {
                return Err("Executable mapping alias changed.");
            }
            drop(alias);
            mount(Some(&destination), target, BIND)?;
            mount(None, target, BIND | REMOUNT | READONLY | NOSUID | NODEV)?;
            let actual =
                fs::metadata(target).map_err(|_| "Linux sealed mapping mount was not enforced.")?;
            if (actual.dev(), actual.ino()) != (sealed.dev(), sealed.ino())
                || flags(target)? & NOEXEC != 0
            {
                return Err("Linux sealed mapping mount was not enforced.");
            }
            identities.insert(target.clone(), (actual.dev(), actual.ino()));
        }
    }
    mount(
        None,
        store,
        BIND | REMOUNT | READONLY | NOSUID | NODEV | NOEXEC,
    )?;
    if flags(store)? & (READONLY | NOEXEC) != READONLY | NOEXEC {
        return Err("Linux immutable mapping store was not enforced.");
    }
    super::capabilities::drop_all()?;
    Ok(identities)
}
