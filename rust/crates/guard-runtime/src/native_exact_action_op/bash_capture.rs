//! Read-only resident capture. No approval token or admission allow is issued.

use guard_contracts::{NativeBashCaptureV1, NativeBashSubjectV1};

#[cfg(target_os = "macos")]
#[path = "bash_capture_macos.rs"]
mod platform;

pub(super) fn inspect(request: &NativeBashCaptureV1) -> Result<NativeBashSubjectV1, &'static str> {
    #[cfg(target_os = "macos")]
    return platform::inspect(request);
    #[cfg(not(target_os = "macos"))]
    {
        let _ = request;
        Err("bash_execution_binding_unavailable_platform")
    }
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use super::*;

    #[test]
    fn bash_subject_inspection_reports_unsupported_platform_without_a_subject() {
        let request = NativeBashCaptureV1 {
            harness: "omp".into(),
            command: "/bin/bash script.sh dry".into(),
            cwd: "/project".into(),
            workspace: "/project".into(),
            home_dir: "/home/tester".into(),
            guard_home: "/home/tester/guard".into(),
            execution_environment: guard_contracts::GuardExecutionEnvironmentV1::unavailable(),
            environment: Default::default(),
            file_creation_mask: Some(0o022),
            budget_ms: 1000,
        };
        assert_eq!(
            inspect(&request),
            Err("bash_execution_binding_unavailable_platform")
        );
    }
}
