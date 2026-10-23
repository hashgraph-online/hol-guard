//! Bounded kernel cgroup samples taken by the Rust staging owner while its
//! Python control is alive. Positive samples are independent of the control
//! record, but polling cannot establish every short-lived process or Guard
//! decision and never grants execution eligibility.

use crate::sdk_wire_peer::SdkWirePeerPin;
use crate::staging_machine_observer::{
    observe_sdk_executable, ContainerProcessIdentity, MachineSliceSampler, SdkExecutableIdentity,
};
use crate::staging_product_observer::{ProductObservation, StagingProductSampler};
use crate::{launch_plan::rust_job_slice_name, OwnedJobCgroup};
use rustix::fs::{fstat, open, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const MAX_CONTROL_BYTES: u64 = 4096;
const MAX_RETAINED_CONTAINER_PROCESSES: usize = 64;
const MAX_RETAINED_SDK_EXECUTABLES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SliceSample {
    tasks: u64,
    populated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveStagingKernelObservation {
    pub(crate) sample_count: u64,
    pub(crate) max_controller_tasks: u64,
    pub(crate) product_slice_observed: bool,
    pub(crate) product_slice_populated: bool,
    pub(crate) max_product_tasks: u64,
    pub(crate) container_processes: Vec<ContainerProcessIdentity>,
    pub(crate) sdk_executables: Vec<SdkExecutableIdentity>,
    pub(crate) product: Option<ProductObservation>,
}

impl LiveStagingKernelObservation {
    pub(crate) fn to_json(&self) -> Value {
        let container_processes: Vec<_> = self
            .container_processes
            .iter()
            .map(|process| {
                json!({
                    "container_id":process.container_id,
                    "pid":process.pid,
                    "start_ticks":process.start_ticks,
                    "cgroup":process.cgroup,
                })
            })
            .collect();
        let sdk_executables: Vec<_> = self
            .sdk_executables
            .iter()
            .map(|process| {
                json!({
                    "container_id":process.container_id,
                    "pid":process.pid,
                    "start_ticks":process.start_ticks,
                    "cgroup":process.cgroup,
                    "argv_sha256":process.argv_sha256,
                    "executable_sha256":process.executable_sha256,
                })
            })
            .collect();
        json!({
            "schema":"hol-gauntlet-staging-kernel-samples.v3",
            "sample_count":self.sample_count,
            "max_controller_tasks":self.max_controller_tasks,
            "product_slice_observed":self.product_slice_observed,
            "product_slice_populated":self.product_slice_populated,
            "max_product_tasks":self.max_product_tasks,
            "container_processes":container_processes,
            "sdk_executables":sdk_executables,
            "container_processes_exhaustively_observed":false,
            "control_processes_exhaustively_observed":false,
            "guard_causality_verified":false,
            "execution_eligible":false,
        })
    }
}

pub(crate) struct StagingKernelSampler {
    root: OwnedFd,
    root_stat: Stat,
    slice_name: String,
    machine: MachineSliceSampler,
    product: StagingProductSampler,
    observed_container_processes: BTreeSet<ContainerProcessIdentity>,
    observed_sdk_executables: BTreeSet<SdkExecutableIdentity>,
    observation: LiveStagingKernelObservation,
}

fn same_root_directory(first: &Stat, second: &Stat) -> bool {
    FileType::from_raw_mode(first.st_mode) == FileType::Directory
        && first.st_uid == 0
        && first.st_mode & 0o022 == 0
        && first.st_dev == second.st_dev
        && first.st_ino == second.st_ino
        && first.st_uid == second.st_uid
        && first.st_mode == second.st_mode
}

fn read_control(directory: &OwnedFd, name: &str) -> Result<Vec<u8>, String> {
    let descriptor = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("{name} unavailable: {error}"))?;
    let mut raw = Vec::new();
    File::from(descriptor)
        .take(MAX_CONTROL_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|error| format!("{name} read failed: {error}"))?;
    if raw.len() as u64 > MAX_CONTROL_BYTES {
        return Err(format!("{name} exceeds fixed bound"));
    }
    Ok(raw)
}

fn parse_tasks(raw: &[u8]) -> Result<u64, String> {
    let text = std::str::from_utf8(raw).map_err(|_| "invalid pids.current UTF-8")?;
    let digits = text
        .strip_suffix('\n')
        .ok_or("pids.current lacks final newline")?;
    if digits.is_empty() || digits.len() > 20 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid pids.current count".to_owned());
    }
    digits
        .parse()
        .map_err(|_| "pids.current overflows u64".to_owned())
}

fn parse_populated(raw: &[u8]) -> Result<bool, String> {
    let text = std::str::from_utf8(raw).map_err(|_| "invalid cgroup.events UTF-8")?;
    if !text.ends_with('\n') {
        return Err("cgroup.events lacks final newline".to_owned());
    }
    let mut populated = None;
    for line in text.lines() {
        let mut parts = line.split_ascii_whitespace();
        if parts.next() == Some("populated") {
            let value = parts.next().ok_or("missing populated value")?;
            if populated.is_some() || !matches!(value, "0" | "1") || parts.next().is_some() {
                return Err("invalid populated event".to_owned());
            }
            populated = Some(value == "1");
        }
    }
    populated.ok_or_else(|| "missing populated event".to_owned())
}

fn select_unique_sdk_ancestor<'a>(
    observed: &'a BTreeSet<SdkExecutableIdentity>,
    expected_bun_sha256: &str,
) -> Result<Option<&'a SdkExecutableIdentity>, String> {
    if expected_bun_sha256.len() != 64
        || !expected_bun_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("verified Bun asset digest required for SDK peer selection".to_owned());
    }
    let mut matches = observed
        .iter()
        .filter(|identity| identity.executable_sha256 == expected_bun_sha256);
    let one = matches.next();
    if matches.next().is_some() {
        return Err("more than one exact Bun SDK process is live in the staging sample".to_owned());
    }
    Ok(one)
}

impl StagingKernelSampler {
    /// Select exactly one sampled Bun with the independently inventoried
    /// executable bytes, then reobserve argv, executable and process identity
    /// before its cgroup can authorize accepting an SDK relay connection.
    pub(crate) fn unique_live_sdk_ancestor(
        &self,
        expected_bun_sha256: &str,
    ) -> Result<Option<SdkWirePeerPin>, String> {
        let Some(identity) =
            select_unique_sdk_ancestor(&self.observed_sdk_executables, expected_bun_sha256)?
        else {
            return Ok(None);
        };
        let process = ContainerProcessIdentity {
            container_id: identity.container_id.clone(),
            pid: identity.pid,
            start_ticks: identity.start_ticks,
            cgroup: identity.cgroup.clone(),
        };
        if observe_sdk_executable(&process).as_ref() != Some(identity) {
            return Err("sampled Bun SDK process changed before relay handoff".to_owned());
        }
        Ok(Some(SdkWirePeerPin {
            pid: identity.pid,
            start_ticks: identity.start_ticks,
            cgroup: identity.cgroup.clone(),
        }))
    }

    pub(crate) fn new(run_id: &str, role: crate::StagingRole) -> Result<Self, String> {
        let slice_name = rust_job_slice_name(run_id).map_err(|error| error.to_string())?;
        let root = open(
            CGROUP_ROOT,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| format!("cgroup root unavailable: {error}"))?;
        let root_stat = fstat(&root).map_err(|error| error.to_string())?;
        if !same_root_directory(&root_stat, &root_stat) {
            return Err("unsafe cgroup root".to_owned());
        }
        let machine = MachineSliceSampler::new()?;
        Ok(Self {
            root,
            root_stat,
            slice_name,
            machine,
            product: StagingProductSampler::new(run_id, role)?,
            observed_container_processes: BTreeSet::new(),
            observed_sdk_executables: BTreeSet::new(),
            observation: LiveStagingKernelObservation {
                sample_count: 0,
                max_controller_tasks: 0,
                product_slice_observed: false,
                product_slice_populated: false,
                max_product_tasks: 0,
                container_processes: Vec::new(),
                sdk_executables: Vec::new(),
                product: None,
            },
        })
    }

    fn sample_product_slice(&mut self) -> Result<Option<SliceSample>, String> {
        let before = fstat(&self.root).map_err(|error| error.to_string())?;
        if !same_root_directory(&self.root_stat, &before) {
            return Err("cgroup root changed before sample".to_owned());
        }
        let directory = match openat(
            &self.root,
            self.slice_name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(directory) => directory,
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => return Err(format!("product slice unavailable: {error}")),
        };
        let opened = fstat(&directory).map_err(|error| error.to_string())?;
        let visible = match statat(
            &self.root,
            self.slice_name.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(visible) => visible,
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => return Err(format!("product slice changed: {error}")),
        };
        if !same_root_directory(&opened, &visible) {
            return Err("unsafe product slice identity".to_owned());
        }
        let tasks = parse_tasks(&read_control(&directory, "pids.current")?)?;
        let populated = parse_populated(&read_control(&directory, "cgroup.events")?)?;
        if self.observation.sample_count.is_multiple_of(5) {
            self.product.sample(&directory)?;
        }
        let final_visible = match statat(
            &self.root,
            self.slice_name.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(visible) => visible,
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => return Err(format!("product slice disappeared: {error}")),
        };
        let after = fstat(&self.root).map_err(|error| error.to_string())?;
        if !same_root_directory(&opened, &final_visible)
            || !same_root_directory(&self.root_stat, &after)
        {
            return Err("product slice changed during sample".to_owned());
        }
        Ok(Some(SliceSample { tasks, populated }))
    }

    pub(crate) fn sample(&mut self, group: &OwnedJobCgroup) -> Result<(), String> {
        let controller_tasks = group.tasks().map_err(|error| error.to_string())?;
        let product = self.sample_product_slice()?;
        if self.observation.sample_count.is_multiple_of(5) {
            for process in self.machine.sample()? {
                if !self.observed_sdk_executables.iter().any(|observed| {
                    observed.container_id == process.container_id
                        && observed.pid == process.pid
                        && observed.start_ticks == process.start_ticks
                }) {
                    if let Some(executable) = observe_sdk_executable(&process) {
                        if self.observed_sdk_executables.len() == MAX_RETAINED_SDK_EXECUTABLES
                            && !self.observed_sdk_executables.contains(&executable)
                        {
                            return Err("staging SDK executable identity bound exceeded".to_owned());
                        }
                        self.observed_sdk_executables.insert(executable);
                    }
                }
                if self.observed_container_processes.len() == MAX_RETAINED_CONTAINER_PROCESSES
                    && !self.observed_container_processes.contains(&process)
                {
                    return Err("staging container process identity bound exceeded".to_owned());
                }
                self.observed_container_processes.insert(process);
            }
        }
        self.observation.sample_count += 1;
        self.observation.max_controller_tasks =
            self.observation.max_controller_tasks.max(controller_tasks);
        if let Some(product) = product {
            self.observation.product_slice_observed = true;
            self.observation.product_slice_populated |= product.populated;
            self.observation.max_product_tasks =
                self.observation.max_product_tasks.max(product.tasks);
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> LiveStagingKernelObservation {
        self.observation.product = Some(self.product.finish());
        self.observation.container_processes =
            self.observed_container_processes.into_iter().collect();
        self.observation.sdk_executables = self.observed_sdk_executables.into_iter().collect();
        self.observation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_handoff_requires_one_exact_inventoried_bun() {
        let digest = "a".repeat(64);
        let other = "b".repeat(64);
        let identity = |pid, executable_sha256: String| SdkExecutableIdentity {
            container_id: format!("container-{pid}"),
            pid,
            start_ticks: 123,
            cgroup: format!("/machine.slice/libpod-{pid}.scope"),
            argv_sha256: "c".repeat(64),
            executable_sha256,
        };
        let mut observed = BTreeSet::new();
        observed.insert(identity(10, other));
        assert!(select_unique_sdk_ancestor(&observed, &digest)
            .unwrap()
            .is_none());
        observed.insert(identity(11, digest.clone()));
        assert_eq!(
            select_unique_sdk_ancestor(&observed, &digest)
                .unwrap()
                .unwrap()
                .pid,
            11
        );
        observed.insert(identity(12, digest.clone()));
        assert!(select_unique_sdk_ancestor(&observed, &digest).is_err());
        assert!(select_unique_sdk_ancestor(&observed, &digest.to_uppercase()).is_err());
    }

    #[test]
    fn kernel_counters_require_bounded_exact_numbers_and_unique_populated_event() {
        assert_eq!(parse_tasks(b"0\n"), Ok(0));
        assert_eq!(parse_tasks(b"18\n"), Ok(18));
        for value in [
            b"-1\n".as_slice(),
            b"1",
            b"1\n2\n",
            b"18446744073709551616\n",
        ] {
            assert!(parse_tasks(value).is_err());
        }
        assert_eq!(parse_populated(b"populated 1\nfrozen 0\n"), Ok(true));
        assert_eq!(parse_populated(b"populated 0\n"), Ok(false));
        for value in [
            b"populated 1\npopulated 0\n".as_slice(),
            b"populated 2\n",
            b"frozen 0\n",
            b"populated 1",
        ] {
            assert!(parse_populated(value).is_err());
        }
    }
}
