//! Independent discovery under the one-role run's Root-owned systemd slice.
//! A successful sample identifies the live private init and its task idmaps;
//! it does not establish continuous isolation or any Guard decision.

use crate::product_cell_units::scan_at;
use crate::staging_machine_observer::parse_pids;
use crate::staging_product_process::observe_product_init;
use crate::{launch_plan::rust_job_slice_name, StagingRole};
use rustix::fs::{fstat, openat, statat, AtFlags, Mode, OFlags, Stat};
use serde_json::{json, Value};
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProductObservation {
    run_id: String,
    role: String,
    slice_samples: u64,
    process_attempts: u64,
    observation: Option<Value>,
    last_unavailable_reason: Option<String>,
}

impl ProductObservation {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-staging-product-kernel.v1",
            "run_id":self.run_id,"role":self.role,
            "slice_samples":self.slice_samples,"process_attempts":self.process_attempts,
            "observation":self.observation,"last_unavailable_reason":self.last_unavailable_reason,
            "continuously_observed":false,"guard_causality_verified":false,"execution_eligible":false,
        })
    }
}

pub(crate) struct StagingProductSampler {
    slice_name: String,
    role_path: String,
    unit_identity: Option<(String, Stat)>,
    result: ProductObservation,
}

fn same_unit(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_mode == b.st_mode
        && a.st_uid == 0
        && b.st_uid == 0
        && a.st_mode & 0o022 == 0
}

impl StagingProductSampler {
    pub(crate) fn new(run_id: &str, role: StagingRole) -> Result<Self, String> {
        Ok(Self {
            slice_name: rust_job_slice_name(run_id).map_err(|e| e.to_string())?,
            role_path: format!("/home/hx-{run_id}/{}", role.as_str()),
            unit_identity: None,
            result: ProductObservation {
                run_id: run_id.to_owned(),
                role: role.as_str().to_owned(),
                slice_samples: 0,
                process_attempts: 0,
                observation: None,
                last_unavailable_reason: None,
            },
        })
    }

    pub(crate) fn sample(&mut self, slice: &OwnedFd) -> Result<(), String> {
        self.result.slice_samples += 1;
        let units = scan_at(slice, 0).map_err(|e| e.to_string())?;
        if units.len() > 1 {
            return Err("multiple product services in single-role staging slice".to_owned());
        }
        let Some(name) = units.first() else {
            return Ok(());
        };
        let unit = openat(
            slice,
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let before = fstat(&unit).map_err(|e| e.to_string())?;
        let visible =
            statat(slice, name.as_str(), AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
        if !same_unit(&before, &visible) {
            return Err("product service changed before sample".to_owned());
        }
        if let Some((observed_name, observed)) = &self.unit_identity {
            if observed_name != name || !same_unit(observed, &before) {
                return Err("product service replaced after independent kernel sample".to_owned());
            }
            return Ok(());
        }
        let pids = openat(
            &unit,
            "cgroup.procs",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let mut raw = Vec::new();
        File::from(pids)
            .take(4097)
            .read_to_end(&mut raw)
            .map_err(|e| e.to_string())?;
        let cgroup = format!("/{}/{name}", self.slice_name);
        for pid in parse_pids(&raw)? {
            self.result.process_attempts += 1;
            match observe_product_init(pid, &cgroup, &self.role_path) {
                Ok(mut observation) => {
                    let after = statat(slice, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                        .map_err(|e| e.to_string())?;
                    if !same_unit(&before, &after) {
                        return Err("product service changed during sample".to_owned());
                    }
                    observation["service"] = json!(name);
                    observation["cgroup_device"] = json!(before.st_dev);
                    observation["cgroup_inode"] = json!(before.st_ino);
                    self.result.observation = Some(observation);
                    self.result.last_unavailable_reason = None;
                    self.unit_identity = Some((name.clone(), before));
                    break;
                }
                Err(reason) => self.result.last_unavailable_reason = Some(reason),
            }
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> ProductObservation {
        self.result
    }
}
