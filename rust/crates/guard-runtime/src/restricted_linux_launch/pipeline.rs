//! Every kernel stage must succeed before the approved image is executed.
use super::plan::{Plan, Result};
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;

pub(super) trait Stages {
    fn mappings(&mut self, plan: &Plan) -> Result<BTreeMap<PathBuf, (u64, u64)>>;
    fn landlock(&mut self, plan: &Plan) -> Result<()>;
    fn socket(&mut self) -> Result<()>;
    fn execute(&mut self, plan: &Plan) -> Result<()>;
}

struct Kernel;
impl Stages for Kernel {
    fn mappings(&mut self, plan: &Plan) -> Result<BTreeMap<PathBuf, (u64, u64)>> {
        super::mappings::enforce(plan)
    }
    fn landlock(&mut self, plan: &Plan) -> Result<()> {
        super::landlock::enforce(plan)
    }
    fn socket(&mut self) -> Result<()> {
        super::socket::enforce()
    }
    fn execute(&mut self, plan: &Plan) -> Result<()> {
        let _error = std::process::Command::new(&plan.command[0])
            .args(&plan.command[1..])
            .exec();
        Err("The approved command could not be executed.")
    }
}

pub(super) fn enter(plan: Plan) -> Result<()> {
    run(plan, &mut Kernel)
}

pub(super) fn run(mut plan: Plan, stages: &mut impl Stages) -> Result<()> {
    for (path, identity) in &plan.write_identities {
        let metadata =
            std::fs::symlink_metadata(path).map_err(|_| "Linux output boundary changed.")?;
        if !metadata.is_dir() || (metadata.dev(), metadata.ino()) != *identity {
            return Err("Linux output boundary changed.");
        }
    }
    let sealed = stages.mappings(&plan)?;
    for path in &plan.read_files {
        if let Some(identity) = sealed.get(path) {
            plan.read_identities.insert(path.clone(), *identity);
        }
    }
    stages.landlock(&plan)?;
    stages.socket()?;
    stages.execute(&plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_kernel_stage_never_reaches_repository_execution() {
        struct Backend {
            failure: &'static str,
            calls: Vec<&'static str>,
        }
        impl Stages for Backend {
            fn mappings(&mut self, _: &Plan) -> Result<BTreeMap<PathBuf, (u64, u64)>> {
                self.calls.push("mappings");
                if self.failure == "mappings" {
                    Err("failed")
                } else {
                    Ok(BTreeMap::new())
                }
            }
            fn landlock(&mut self, _: &Plan) -> Result<()> {
                self.calls.push("landlock");
                if self.failure == "landlock" {
                    Err("failed")
                } else {
                    Ok(())
                }
            }
            fn socket(&mut self) -> Result<()> {
                self.calls.push("socket");
                if self.failure == "socket" {
                    Err("failed")
                } else {
                    Ok(())
                }
            }
            fn execute(&mut self, _: &Plan) -> Result<()> {
                self.calls.push("execute");
                Ok(())
            }
        }
        for (failure, expected) in [
            ("mappings", vec!["mappings"]),
            ("landlock", vec!["mappings", "landlock"]),
            ("socket", vec!["mappings", "landlock", "socket"]),
            ("none", vec!["mappings", "landlock", "socket", "execute"]),
        ] {
            let plan = Plan {
                command: vec!["/unexecuted-fixture".into()],
                read_roots: vec![],
                read_files: vec![],
                list_roots: vec![],
                write_roots: vec![],
                executables: vec![],
                device_files: vec![],
                read_identities: BTreeMap::new(),
                write_identities: BTreeMap::new(),
                mapping_records: serde_json::json!([]),
            };
            let mut backend = Backend {
                failure,
                calls: vec![],
            };
            assert_eq!(run(plan, &mut backend).is_ok(), failure == "none");
            assert_eq!(backend.calls, expected);
        }
    }
}
