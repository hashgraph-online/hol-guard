use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    PythonReportInvalid,
    PythonImplementationUnsupported,
    PythonVersionUnsupported,
    PythonBuildUnqualified,
    PythonReleaseIncompatible,
    PlatformUnsupported,
}

/// Facts from the fixed isolated probe on a host-selected executable.
/// Never accept this record from a public caller as proof of an eligible runtime.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterpreterFacts {
    pub schema: String,
    pub implementation: String,
    pub version: [u16; 3],
    pub release_level: String,
    pub free_threaded: bool,
    pub debug_build: bool,
    pub abi: String,
    pub platform: String,
}

/// Eligibility only. The supervisor must separately verify the executable,
/// qualified package and worker identity before issuing any ready capability.
pub fn check_interpreter(facts: &InterpreterFacts) -> Result<(), UnavailableReason> {
    if facts.schema != "guard-cigar-interpreter.v1" {
        return Err(UnavailableReason::PythonReportInvalid);
    }
    if facts.implementation != "cpython" {
        return Err(UnavailableReason::PythonImplementationUnsupported);
    }
    if facts.version[..2] != [3, 14] || facts.release_level != "final" {
        return Err(UnavailableReason::PythonVersionUnsupported);
    }
    if facts.free_threaded || facts.debug_build {
        return Err(UnavailableReason::PythonBuildUnqualified);
    }
    let expected_abi = match facts.platform.as_str() {
        "darwin-arm64" | "darwin-x64" => "cpython-314-darwin",
        "linux-arm64-gnu" => "cpython-314-aarch64-linux-gnu",
        "linux-x64-gnu" => "cpython-314-x86_64-linux-gnu",
        "linux-arm64-musl" => "cpython-314-aarch64-linux-musl",
        "linux-x64-musl" => "cpython-314-x86_64-linux-musl",
        "win32-x64" => "cp314-win_amd64",
        _ => return Err(UnavailableReason::PlatformUnsupported),
    };
    if facts.abi != expected_abi {
        return Err(UnavailableReason::PythonBuildUnqualified);
    }
    Ok(())
}
