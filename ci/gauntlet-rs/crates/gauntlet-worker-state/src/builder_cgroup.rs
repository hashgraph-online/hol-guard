//! Separate fixed cgroup profile for a trusted builder-image construction.
//! The eventual candidate container has its own Podman limits and custody.

use crate::contained_probe::{CgroupProbeError, GroupLimits, OwnedProbeGroup};
use crate::hex;
use std::process::Command;

const LIMITS: GroupLimits = GroupLimits {
    memory: "12884901888\n",
    pids: "512\n",
    cpu: "200000 100000\n",
};

pub(crate) struct OwnedBuilderCgroup {
    inner: OwnedProbeGroup,
}

pub(crate) struct OwnedCandidateCgroup {
    inner: OwnedProbeGroup,
}

impl OwnedBuilderCgroup {
    pub(crate) fn create(job_id: &str) -> Result<Self, CgroupProbeError> {
        if !hex(job_id, 16) {
            return Err(CgroupProbeError::InvalidJobId);
        }
        let name = format!("hol-gauntlet-rust-builder-{job_id}");
        let path = format!("/system.slice/{name}");
        Ok(Self {
            inner: OwnedProbeGroup::create_named(name, path, LIMITS)?,
        })
    }

    pub(crate) fn path(&self) -> &str {
        self.inner.path()
    }

    pub(crate) fn attach_child(&self, command: &mut Command) -> Result<(), CgroupProbeError> {
        self.inner.attach_child(command)
    }

    pub(crate) fn kill(&self) -> Result<(), CgroupProbeError> {
        self.inner.kill()
    }

    pub(crate) fn drain_and_remove(&mut self) -> Result<(), CgroupProbeError> {
        self.inner.drain_and_remove()
    }
}

impl OwnedCandidateCgroup {
    pub(crate) fn create(job_id: &str) -> Result<Self, CgroupProbeError> {
        if !hex(job_id, 16) {
            return Err(CgroupProbeError::InvalidJobId);
        }
        let name = format!("hol-gauntlet-rust-candidate-{job_id}");
        let path = format!("/system.slice/{name}");
        Ok(Self {
            inner: OwnedProbeGroup::create_named(name, path, LIMITS)?,
        })
    }

    pub(crate) fn path(&self) -> &str {
        self.inner.path()
    }

    pub(crate) fn attach_child(&self, command: &mut Command) -> Result<(), CgroupProbeError> {
        self.inner.attach_child(command)
    }

    pub(crate) fn kill(&self) -> Result<(), CgroupProbeError> {
        self.inner.kill()
    }

    pub(crate) fn drain_and_remove(&mut self) -> Result<(), CgroupProbeError> {
        self.inner.drain_and_remove()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_unbounded_or_nonjob_cgroup_names() {
        assert!(matches!(
            OwnedBuilderCgroup::create("../../system.slice"),
            Err(CgroupProbeError::InvalidJobId)
        ));
    }
}
