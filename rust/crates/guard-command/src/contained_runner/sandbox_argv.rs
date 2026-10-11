//! Platform sandbox argv construction (`sandbox-exec` profile and `bwrap`).

use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::contract::Request;

const LINUX_HOSTS: &str = "127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n";
const LINUX_NSSWITCH: &str = "hosts: files\n";

fn profile_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

pub(super) fn macos_argv(
    backend: &str,
    request: &Request,
    pinned: &str,
    temp_root: &Path,
) -> Vec<String> {
    let root = temp_root.to_string_lossy();
    let mut profile: Vec<String> = [
        "(version 1)",
        "(deny default)",
        "(import \"system.sb\")",
        "(allow process*)",
        "(deny process-fork)",
        "(allow sysctl-read)",
        "(allow mach-lookup)",
        "(allow ipc-posix*)",
        "(allow file-read-metadata)",
    ]
    .iter()
    .map(|line| (*line).to_owned())
    .collect();
    profile.push(format!(
        "(allow file-map-executable (literal \"{}\"))",
        profile_escape(pinned)
    ));
    for path in ["/System", "/usr", "/bin", "/sbin", root.as_ref()] {
        profile.push(format!(
            "(allow file-read* (subpath \"{}\"))",
            profile_escape(path)
        ));
    }
    profile.push(format!(
        "(allow file-write* (subpath \"{}\"))",
        profile_escape(&root)
    ));
    profile.push("(deny network*)".to_owned());
    profile.push("(deny file-write* (subpath \"/cores\"))".to_owned());
    let mut argv = vec![
        backend.to_owned(),
        "-p".to_owned(),
        profile.join("\n"),
        pinned.to_owned(),
    ];
    argv.extend(request.argv[1..].iter().cloned());
    argv
}

pub(super) fn write_linux_name_service_files(temp_root: &Path) -> Result<PathBuf, String> {
    let linux_etc = temp_root.join("linux-etc");
    DirBuilder::new()
        .mode(0o700)
        .create(&linux_etc)
        .map_err(|error| error.to_string())?;
    for (name, text) in [("hosts", LINUX_HOSTS), ("nsswitch.conf", LINUX_NSSWITCH)] {
        let path = linux_etc.join(name);
        fs::write(&path, text).map_err(|error| error.to_string())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400))
            .map_err(|error| error.to_string())?;
    }
    Ok(linux_etc)
}

pub(super) fn linux_argv(
    backend: &str,
    request: &Request,
    temp_root: &Path,
    linux_etc: &Path,
) -> Result<Vec<String>, String> {
    let text = |path: &Path| path.to_string_lossy().into_owned();
    let mut argv: Vec<String> = [
        backend,
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--tmpfs",
        "/",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--bind",
    ]
    .iter()
    .map(|item| (*item).to_owned())
    .collect();
    argv.push(text(temp_root));
    argv.extend(["/guard", "--dir", "/etc", "--ro-bind"].map(str::to_owned));
    argv.push(text(&linux_etc.join("hosts")));
    argv.extend(["/etc/hosts", "--ro-bind"].map(str::to_owned));
    argv.push(text(&linux_etc.join("nsswitch.conf")));
    argv.push("/etc/nsswitch.conf".to_owned());
    for path in ["/usr", "/bin", "/lib", "/lib64", "/sbin"] {
        if Path::new(path).exists() {
            argv.extend(["--ro-bind", path, path].map(str::to_owned));
        }
    }
    let relative = Path::new(&request.cwd)
        .strip_prefix(&request.policy.workspace)
        .map_err(|_| "cwd must remain inside the workspace".to_owned())?;
    let sandbox_cwd = Path::new("/guard/workspace").join(relative);
    argv.extend([
        "--chdir".to_owned(),
        text(&sandbox_cwd),
        "--clearenv".to_owned(),
    ]);
    for (key, value) in &request.environment {
        argv.extend(["--setenv".to_owned(), key.clone(), value.clone()]);
    }
    argv.extend(
        [
            "--setenv",
            "HOME",
            "/guard/home",
            "--setenv",
            "TMPDIR",
            "/guard/tmp",
            "--",
            "/guard/guard-exec",
        ]
        .map(str::to_owned),
    );
    argv.extend(request.argv[1..].iter().cloned());
    Ok(argv)
}
