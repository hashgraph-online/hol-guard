//! Inert Linux ARM proof that an already-hashed Python executable descriptor
//! can be bound to `execveat(AT_EMPTY_PATH)` while retaining its venv prefix.
//! This does not launch a controller or benchmark job.

use crate::HeldInterpreter;
use serde_json::{json, Value};
use std::fmt;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const PROBE_CODE: &str = "import sys;raise SystemExit(73 if sys.prefix==sys.argv[1] else 74)";
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const CONTAINED_PROBE_CODE: &str = "import os,time;os.fork();time.sleep(5)";
const SUCCESS_CODE: i32 = 73;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterpreterExecError {
    Platform,
    InvalidInterpreter,
    Spawn,
    TimedOut,
    VenvMismatch,
    UnexpectedExit,
}

impl fmt::Display for InterpreterExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Platform => "Linux ARM64 interpreter execution probe required",
            Self::InvalidInterpreter => "verified interpreter changed before or after probe",
            Self::Spawn => "descriptor-bound interpreter probe could not start",
            Self::TimedOut => "descriptor-bound interpreter probe exceeded its deadline",
            Self::VenvMismatch => "descriptor-bound interpreter did not retain its venv prefix",
            Self::UnexpectedExit => "descriptor-bound interpreter returned an unexpected exit",
        })
    }
}

impl std::error::Error for InterpreterExecError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterpreterExecProof {
    pub interpreter_sha256: String,
    pub python_path: String,
    pub expected_venv: String,
}

impl InterpreterExecProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-interpreter-exec-probe.v1",
            "interpreter_sha256":self.interpreter_sha256,
            "python_path":self.python_path,
            "expected_venv":self.expected_venv,
            "execveat_fd_bound":true,
            "venv_prefix_preserved":true,
            "fixed_probe_exit_code":SUCCESS_CODE,
            "controller_executed":false,
            "execution_eligible":false,
        })
    }
}

/// Execute only the fixed, inert prefix probe through the already-hashed
/// interpreter descriptor. A future dispatcher needs separate controller
/// custody, exclusive lease, cgroup isolation, deadline and outcome scoring.
pub fn probe_verified_interpreter_exec(
    interpreter: &HeldInterpreter,
) -> Result<InterpreterExecProof, InterpreterExecError> {
    #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
    {
        let _ = interpreter;
        Err(InterpreterExecError::Platform)
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        linux::probe(interpreter)
    }
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(crate) fn spawn_contained_interpreter_probe(
    interpreter: &HeldInterpreter,
    cgroup_writer: std::os::fd::OwnedFd,
) -> Result<std::process::Child, InterpreterExecError> {
    linux::spawn_contained_probe(interpreter, cgroup_writer)
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod linux {
    use super::{
        HeldInterpreter, InterpreterExecError, InterpreterExecProof, CONTAINED_PROBE_CODE,
        PROBE_CODE, SUCCESS_CODE,
    };
    use std::ffi::CString;
    use std::io;
    use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    const POLL: Duration = Duration::from_millis(10);
    const DEADLINE: Duration = Duration::from_secs(5);

    fn checked_cstring(value: &str) -> Result<CString, InterpreterExecError> {
        CString::new(value).map_err(|_| InterpreterExecError::InvalidInterpreter)
    }

    /// The child callback makes no allocations, reads or locks after fork.
    /// It either replaces the child through the verified descriptor or returns
    /// an error to `Command::spawn`; `/usr/bin/false` cannot run as a fallback.
    fn spawn_fd(
        descriptor: BorrowedFd<'_>,
        argv: &[&str],
        cgroup_writer: Option<OwnedFd>,
    ) -> Result<Child, InterpreterExecError> {
        if argv.is_empty() || argv.len() > 7 {
            return Err(InterpreterExecError::InvalidInterpreter);
        }
        let args: Vec<_> = argv
            .iter()
            .map(|value| checked_cstring(value))
            .collect::<Result<_, _>>()?;
        let environment = [
            checked_cstring("PATH=/usr/bin:/bin")?,
            checked_cstring("LANG=C.UTF-8")?,
            checked_cstring("HOME=/root")?,
        ];
        let argument_ptrs: Vec<usize> = args.iter().map(|value| value.as_ptr() as usize).collect();
        let environment_ptrs: Vec<usize> = environment
            .iter()
            .map(|value| value.as_ptr() as usize)
            .collect();
        let fd = descriptor.as_raw_fd();
        let mut command = Command::new("/usr/bin/false");
        command
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: all buffers are prepared before fork. The child uses only
        // stack digits, cgroup write, privilege-drop and execveat syscalls.
        // The CStrings remain owned by the closure through exec or failure.
        unsafe {
            command.pre_exec(move || {
                let _keep_args = &args;
                let _keep_environment = &environment;
                if let Some(writer) = &cgroup_writer {
                    let mut pid = libc::getpid() as u32;
                    let mut digits = [0u8; 10];
                    let mut start = digits.len();
                    loop {
                        start -= 1;
                        digits[start] = b'0' + (pid % 10) as u8;
                        pid /= 10;
                        if pid == 0 {
                            break;
                        }
                    }
                    let bytes = &digits[start..];
                    let written =
                        libc::write(writer.as_raw_fd(), bytes.as_ptr().cast(), bytes.len());
                    if written != bytes.len() as isize {
                        return Err(if written < 0 {
                            io::Error::last_os_error()
                        } else {
                            io::Error::from_raw_os_error(libc::EIO)
                        });
                    }
                    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                        || libc::setgroups(0, std::ptr::null()) != 0
                        || libc::setresgid(65534, 65534, 65534) != 0
                        || libc::setresuid(65534, 65534, 65534) != 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                let mut argv_ptrs = [std::ptr::null(); 8];
                for (slot, pointer) in argv_ptrs.iter_mut().zip(&argument_ptrs) {
                    *slot = *pointer as *const libc::c_char;
                }
                let mut env_ptrs = [std::ptr::null(); 4];
                for (slot, pointer) in env_ptrs.iter_mut().zip(&environment_ptrs) {
                    *slot = *pointer as *const libc::c_char;
                }
                libc::syscall(
                    libc::SYS_execveat,
                    fd,
                    c"".as_ptr(),
                    argv_ptrs.as_ptr(),
                    env_ptrs.as_ptr(),
                    libc::AT_EMPTY_PATH,
                );
                Err(io::Error::last_os_error())
            });
        }
        command.spawn().map_err(|_| InterpreterExecError::Spawn)
    }

    fn exec_fd(descriptor: BorrowedFd<'_>, argv: &[&str]) -> Result<i32, InterpreterExecError> {
        let mut child = spawn_fd(descriptor, argv, None)?;
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return status.code().ok_or(InterpreterExecError::UnexpectedExit)
                }
                Ok(None) if started.elapsed() < DEADLINE => thread::sleep(POLL),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(InterpreterExecError::TimedOut);
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(InterpreterExecError::Spawn);
                }
            }
        }
    }

    pub(super) fn spawn_contained_probe(
        interpreter: &HeldInterpreter,
        cgroup_writer: OwnedFd,
    ) -> Result<Child, InterpreterExecError> {
        let declaration = interpreter.declaration();
        let fd = interpreter
            .checked_fd()
            .map_err(|_| InterpreterExecError::InvalidInterpreter)?;
        spawn_fd(
            fd,
            &[
                &declaration.python_path,
                "-I",
                "-S",
                "-B",
                "-c",
                CONTAINED_PROBE_CODE,
            ],
            Some(cgroup_writer),
        )
    }

    pub(super) fn probe(
        interpreter: &HeldInterpreter,
    ) -> Result<InterpreterExecProof, InterpreterExecError> {
        let declaration = interpreter.declaration();
        let expected_venv = declaration
            .python_path
            .strip_suffix("/bin/python")
            .ok_or(InterpreterExecError::InvalidInterpreter)?;
        let fd = interpreter
            .checked_fd()
            .map_err(|_| InterpreterExecError::InvalidInterpreter)?;
        let code = exec_fd(
            fd,
            &[
                &declaration.python_path,
                "-I",
                "-B",
                "-c",
                PROBE_CODE,
                expected_venv,
            ],
        )?;
        interpreter
            .assert_unchanged()
            .map_err(|_| InterpreterExecError::InvalidInterpreter)?;
        match code {
            SUCCESS_CODE => Ok(InterpreterExecProof {
                interpreter_sha256: declaration.sha256.clone(),
                python_path: declaration.python_path.clone(),
                expected_venv: expected_venv.to_owned(),
            }),
            74 => Err(InterpreterExecError::VenvMismatch),
            _ => Err(InterpreterExecError::UnexpectedExit),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs::File;
        use std::os::fd::AsFd;

        #[test]
        fn fd_exec_runs_opened_binary_without_path_fallback() {
            let binary = File::open("/usr/bin/true").unwrap();
            let exit = exec_fd(binary.as_fd(), &["/usr/bin/true"]).unwrap();
            assert_eq!(exit, 0);
        }

        #[test]
        fn wrong_executable_cannot_fake_the_fixed_probe_exit() {
            let binary = File::open("/usr/bin/false").unwrap();
            let exit = exec_fd(binary.as_fd(), &["/usr/bin/false"]).unwrap();
            assert_eq!(exit, 1);
        }
    }
}
