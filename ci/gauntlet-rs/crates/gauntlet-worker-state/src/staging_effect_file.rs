//! Read-only correlation of a host-digest-pinned effect journal with a held
//! final provider-control file. The caller supplies a cgroup value;
//! matching an inode and writer does not prove a Guard decision.

use crate::linux_process::valid_cgroup;
use crate::staging_effect_journal::read_staging_effect_journal_ineligible;
use crate::staging_file_handle::sample_file_handle;
use crate::{
    hex, open_root_owned_public_directory, ActiveLease, RunReservationJournal, StartedMarker,
};
use gauntlet_contracts::{EffectFileHandle, EFFECT_IMAGE_JOURNAL_SCHEMA};
use rustix::fs::{fstat, openat2, statat, AtFlags, FileType, Mode, OFlags, ResolveFlags, Stat};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::Path;

const PROVIDER_BYTES: &[u8] = b"idmapped provider effect";
const PRODUCT_OWNER: u32 = 10001;
const PRODUCT_VIEW_OWNER: u32 = 10004;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingFixedEffectShadow {
    pub run_id: String,
    pub role: String,
    pub surface: String,
    pub final_sha256: String,
    pub device: u64,
    pub inode: u64,
    pub file_handle: Option<EffectFileHandle>,
    pub close_writes: usize,
    pub writers: Vec<(u32, u64)>,
    pub expected_cgroup: String,
    pub journal_sha256: String,
}

impl StagingFixedEffectShadow {
    pub fn to_json(&self) -> Value {
        let writers: Vec<_> = self
            .writers
            .iter()
            .map(|(pid, start_ticks)| json!({"pid":pid,"start_ticks":start_ticks}))
            .collect();
        let mut value = json!({
            "schema":"hol-gauntlet-staging-fixed-effect-shadow.v1",
            "run_id":self.run_id,
            "role":self.role,
            "surface":self.surface,
            "final_sha256":self.final_sha256,
            "final_bytes":PROVIDER_BYTES.len(),
            "device":self.device,
            "inode":self.inode,
            "close_writes":self.close_writes,
            "writers":writers,
            "caller_expected_cgroup":self.expected_cgroup,
            "outside_journal_sha256":self.journal_sha256,
            "held_final_file_checked":true,
            "physical_owner_uid":PRODUCT_OWNER,
            "event_view_owner_uid":PRODUCT_VIEW_OWNER,
            "idmap_kernel_verified":false,
            "guard_causality_verified":false,
            "execution_eligible":false,
        });
        if let Some(handle) = &self.file_handle {
            value["schema"] = json!("hol-gauntlet-staging-fixed-effect-shadow.v2");
            value["file_handle"] = handle.to_json();
            value["file_generation_verified"] = json!(true);
        }
        value
    }
}

pub(crate) fn same_file(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_mode == b.st_mode
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_nlink == b.st_nlink
        && a.st_size == b.st_size
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime
        && a.st_ctime_nsec == b.st_ctime_nsec
}

pub(crate) fn open_fixed_effect_file(
    root: &OwnedFd,
    path: &str,
    owner: u32,
    expected_bytes: &[u8],
) -> Result<(File, Stat), String> {
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let resolve = ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
    let descriptor = openat2(root, path, flags, Mode::empty(), resolve)
        .map_err(|error| format!("fixed effect file unavailable: {error}"))?;
    let before = fstat(&descriptor).map_err(|error| error.to_string())?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != owner
        || before.st_nlink != 1
        || before.st_mode & 0o7777 != 0o600
        || before.st_size != expected_bytes.len() as i64
    {
        return Err("fixed provider effect has unsafe metadata".to_owned());
    }
    let mut file = File::from(descriptor);
    let mut raw = Vec::new();
    file.by_ref()
        .take(expected_bytes.len() as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|error| error.to_string())?;
    let after = fstat(&file).map_err(|error| error.to_string())?;
    let visible =
        statat(root, path, AtFlags::SYMLINK_NOFOLLOW).map_err(|error| error.to_string())?;
    let reopened = openat2(root, path, flags, Mode::empty(), resolve)
        .map_err(|error| format!("fixed effect file changed: {error}"))?;
    let reopened_stat = fstat(&reopened).map_err(|error| error.to_string())?;
    if raw != expected_bytes
        || !same_file(&before, &after)
        || !same_file(&before, &visible)
        || !same_file(&before, &reopened_stat)
    {
        return Err("fixed provider effect bytes or inode changed".to_owned());
    }
    Ok((file, before))
}

pub(crate) fn correlate_rows(
    journal_raw: &[u8],
    file: &Stat,
    expected_event_owner: u32,
    expected_cgroup: &str,
    final_handle: Option<&EffectFileHandle>,
) -> Result<(usize, Vec<(u32, u64)>), String> {
    if !valid_cgroup(expected_cgroup) {
        return Err("outside product cgroup pin is invalid".to_owned());
    }
    let journal: Value = serde_json::from_slice(journal_raw)
        .map_err(|_| "effect journal JSON is invalid".to_owned())?;
    if (journal["schema"] == "hol-gauntlet-staging-effect-events.v2"
        || journal["schema"] == EFFECT_IMAGE_JOURNAL_SCHEMA)
        != final_handle.is_some()
    {
        return Err("effect journal and final file identity versions differ".to_owned());
    }
    let rows = journal["events"]
        .as_array()
        .ok_or("effect journal rows are unavailable")?;
    let mut count = 0;
    let mut writers = BTreeSet::new();
    for row in rows {
        if row["device"].as_u64() != Some(file.st_dev) || row["inode"].as_u64() != Some(file.st_ino)
        {
            continue;
        }
        if let Some(handle) = final_handle {
            let observed = EffectFileHandle::from_json(&row["file_handle"])
                .ok_or("matching inode has an unavailable file generation")?;
            if &observed != handle {
                // This is a different filesystem object that reused the
                // inode. Its writer cannot be attributed to the held file.
                continue;
            }
        }
        let writer = &row["writer"];
        let pid = writer["pid"].as_u64().and_then(|n| u32::try_from(n).ok());
        let start = writer["start_ticks"].as_u64();
        if row["owner"].as_u64() != Some(expected_event_owner as u64)
            || row["pidfd_available"] != true
            || pid.is_none_or(|n| n == 0 || row["reported_pid"].as_u64() != Some(n as u64))
            || start.is_none_or(|n| n == 0)
            || writer["cgroup"] != expected_cgroup
        {
            return Err("final effect has an unknown or foreign writer".to_owned());
        }
        count += 1;
        writers.insert((pid.unwrap(), start.unwrap()));
    }
    if count == 0 {
        return Err("final effect has no captured close-write".to_owned());
    }
    Ok((count, writers.into_iter().collect()))
}

fn product_service_under_run_slice(run_id: &str, cgroup: &str) -> bool {
    let Ok(slice) = crate::launch_plan::rust_job_slice_name(run_id) else {
        return false;
    };
    let prefix = format!("/{slice}/hol-product-cell-");
    cgroup
        .strip_prefix(&prefix)
        .and_then(|unit| unit.strip_suffix(".service"))
        .is_some_and(|unit_id| hex(unit_id, 32))
}

pub fn observe_staging_fixed_provider_effect_ineligible(
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    started: &StartedMarker,
    outside_journal_sha256: &str,
    role: &str,
    surface: &str,
    expected_cgroup: &str,
) -> Result<StagingFixedEffectShadow, String> {
    if !hex(&started.job_id, 16)
        || !matches!(
            role,
            "success" | "input-binding" | "injection" | "boundary" | "timeout" | "cancel"
        )
        || !valid_cgroup(expected_cgroup)
        || !product_service_under_run_slice(&started.job_id, expected_cgroup)
    {
        return Err("fixed effect outside run, role or cgroup pin is invalid".to_owned());
    }
    let relative = match surface {
        "provider-remote" => "tasks/remote/private-provider-control.txt",
        "provider-home" => "tasks/home/private-provider-control.txt",
        _ => return Err("fixed effect surface is unavailable".to_owned()),
    };
    let raw =
        read_staging_effect_journal_ineligible(journal, lease, started, outside_journal_sha256)?;
    let role_path = format!("/home/hx-{}/{role}", started.job_id);
    let role_dir = open_root_owned_public_directory(Path::new(&role_path))
        .map_err(|error| error.to_string())?;
    let role_stat = fstat(&role_dir).map_err(|error| error.to_string())?;
    if role_stat.st_uid != 0 || role_stat.st_mode & 0o7777 != 0o700 {
        return Err("fixed effect role directory is not Root-private".to_owned());
    }
    let (file, before) =
        open_fixed_effect_file(&role_dir, relative, PRODUCT_OWNER, PROVIDER_BYTES)?;
    let document: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    let file_handle = if document["schema"] == "hol-gauntlet-staging-effect-events.v2"
        || document["schema"] == EFFECT_IMAGE_JOURNAL_SCHEMA
    {
        Some(sample_file_handle(&file)?)
    } else {
        None
    };
    // The product's idmapped mount projects the physical UID 10001 as 10004.
    // Same device/inode and these fixed UIDs are a diagnostic relation until
    // Root independently attests that live mount's idmapping.
    let (close_writes, writers) = correlate_rows(
        &raw,
        &before,
        PRODUCT_VIEW_OWNER,
        expected_cgroup,
        file_handle.as_ref(),
    )?;
    let final_role_dir = open_root_owned_public_directory(Path::new(&role_path))
        .map_err(|error| error.to_string())?;
    let final_role_stat = fstat(&final_role_dir).map_err(|error| error.to_string())?;
    let final_file = openat2(
        &final_role_dir,
        relative,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|error| format!("fixed effect visible path changed: {error}"))?;
    if !same_file(&before, &fstat(&file).map_err(|error| error.to_string())?)
        || file_handle
            .as_ref()
            .is_some_and(|handle| sample_file_handle(&file).as_ref() != Ok(handle))
        || role_stat.st_dev != final_role_stat.st_dev
        || role_stat.st_ino != final_role_stat.st_ino
        || !same_file(
            &before,
            &fstat(&final_file).map_err(|error| error.to_string())?,
        )
        || read_staging_effect_journal_ineligible(journal, lease, started, outside_journal_sha256)?
            != raw
    {
        return Err("fixed effect or outside-pinned journal changed".to_owned());
    }
    Ok(StagingFixedEffectShadow {
        run_id: started.job_id.clone(),
        role: role.to_owned(),
        surface: surface.to_owned(),
        final_sha256: format!("{:x}", Sha256::digest(PROVIDER_BYTES)),
        device: before.st_dev,
        inode: before.st_ino,
        file_handle,
        close_writes,
        writers,
        expected_cgroup: expected_cgroup.to_owned(),
        journal_sha256: outside_journal_sha256.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::open;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn fixed_file_and_rows_refuse_changed_bytes_links_and_unknown_writers() {
        let run_id = "0123456789abcdef";
        let product_cgroup = format!(
            "/holgauntletrust{run_id}.slice/hol-product-cell-{}.service",
            "a".repeat(32)
        );
        assert!(product_service_under_run_slice(run_id, &product_cgroup));
        assert!(!product_service_under_run_slice(
            "fedcba9876543210",
            &product_cgroup
        ));
        assert!(!product_service_under_run_slice(
            run_id,
            &format!("{product_cgroup}/child")
        ));
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider.txt");
        std::fs::write(&path, PROVIDER_BYTES).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let root = open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let (held, stat) =
            open_fixed_effect_file(&root, "provider.txt", stat_uid(&path), PROVIDER_BYTES).unwrap();
        assert_eq!(fstat(&held).unwrap().st_ino, stat.st_ino);
        let row = json!({"events":[{"device":stat.st_dev,"inode":stat.st_ino,"owner":PRODUCT_VIEW_OWNER,
            "reported_pid":42,"pidfd_available":true,
            "writer":{"pid":42,"start_ticks":123,"cgroup":"/product-cell.service"}}]});
        assert_eq!(
            correlate_rows(
                row.to_string().as_bytes(),
                &stat,
                PRODUCT_VIEW_OWNER,
                "/product-cell.service",
                None,
            )
            .unwrap(),
            (1, vec![(42, 123)])
        );
        let mut wrong = row.clone();
        wrong["events"][0]["writer"] = Value::Null;
        assert!(correlate_rows(
            wrong.to_string().as_bytes(),
            &stat,
            PRODUCT_VIEW_OWNER,
            "/product-cell.service",
            None,
        )
        .is_err());
        let mut wrong = row.clone();
        wrong["events"][0]["writer"]["cgroup"] = json!("/foreign.service");
        assert!(correlate_rows(
            wrong.to_string().as_bytes(),
            &stat,
            PRODUCT_VIEW_OWNER,
            "/product-cell.service",
            None,
        )
        .is_err());
        assert!(correlate_rows(
            row.to_string().as_bytes(),
            &stat,
            PRODUCT_VIEW_OWNER + 1,
            "/product-cell.service",
            None,
        )
        .is_err());
        assert!(correlate_rows(
            br#"{"events":[]}"#,
            &stat,
            PRODUCT_VIEW_OWNER,
            "/product-cell.service",
            None,
        )
        .is_err());
        symlink(&path, directory.path().join("linked.txt")).unwrap();
        assert!(open_fixed_effect_file(&root, "linked.txt", stat.st_uid, PROVIDER_BYTES).is_err());
        std::fs::write(&path, b"changed").unwrap();
        assert!(
            open_fixed_effect_file(&root, "provider.txt", stat.st_uid, PROVIDER_BYTES).is_err()
        );
    }

    fn stat_uid(path: &Path) -> u32 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).unwrap().uid()
    }

    #[test]
    fn generation_match_excludes_reused_inode_but_never_unknown_matching_writer() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let stat = fstat(temp.as_file()).unwrap();
        let handle = EffectFileHandle::from_kernel(1, &[1, 2, 3, 4]).unwrap();
        let row = json!({"device":stat.st_dev,"inode":stat.st_ino,"owner":PRODUCT_VIEW_OWNER,
            "file_handle":handle.to_json(),"reported_pid":42,"pidfd_available":true,
            "writer":{"pid":42,"start_ticks":123,"cgroup":"/product-cell.service"}});
        let mut old = row.clone();
        old["file_handle"] = EffectFileHandle::from_kernel(1, &[1, 2, 3, 5])
            .unwrap()
            .to_json();
        old["writer"] = Value::Null;
        old["pidfd_available"] = json!(false);
        let journal = json!({"schema":"hol-gauntlet-staging-effect-events.v2","events":[old,row]});
        let read = |j: &Value| {
            correlate_rows(
                j.to_string().as_bytes(),
                &stat,
                PRODUCT_VIEW_OWNER,
                "/product-cell.service",
                Some(&handle),
            )
        };
        assert_eq!(read(&journal).unwrap(), (1, vec![(42, 123)]));
        let mut with_images = journal.clone();
        with_images["schema"] = json!(EFFECT_IMAGE_JOURNAL_SCHEMA);
        with_images["writer_images"] = json!([]);
        assert_eq!(read(&with_images).unwrap(), (1, vec![(42, 123)]));
        let mut unknown = journal.clone();
        unknown["events"][0]["file_handle"] = handle.to_json();
        assert!(read(&unknown).is_err());
        let mut missing = journal.clone();
        missing["events"][0]["file_handle"] = Value::Null;
        assert!(read(&missing).is_err());
        let mut no_match = journal.clone();
        no_match["events"].as_array_mut().unwrap().pop();
        assert!(read(&no_match).is_err());
        let mut downgrade = journal;
        downgrade["schema"] = json!("hol-gauntlet-staging-effect-events.v1");
        assert!(read(&downgrade).is_err());
    }
}
