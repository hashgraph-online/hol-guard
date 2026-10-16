//! Windows shell launches: an ordinary native image or read-only git from a
//! POSIX-shell harness mints a token bound to what the loader reads, and every
//! launch Guard cannot pin to one file and its loader inputs stays one-time.

use std::collections::BTreeMap;
use std::path::PathBuf;

use guard_contracts::NativeExactActionQueryV1;
use serde_json::json;

use super::super::exact_action_token;
use super::{cmd, query, shell, Tree};

pub(super) type Edit<'a> = &'a dyn Fn(&mut String, &mut String, &mut BTreeMap<String, String>);

pub(super) fn launch(tree: &Tree, command: &str, edit: Edit) -> Result<String, &'static str> {
    let mut request = query(tree, "Bash", Some(command), json!(null), &tree.ws());
    if let NativeExactActionQueryV1::ExactAction {
        harness,
        tool_name,
        environment,
        ..
    } = &mut request
    {
        edit(harness, tool_name, environment);
    }
    exact_action_token(&request)
}

fn prepend_path(environment: &mut BTreeMap<String, String>, entries: &str) {
    let path = environment.get("PATH").cloned().unwrap_or_default();
    environment.insert("PATH".to_owned(), format!("{entries};{path}"));
}

fn where_exe() -> PathBuf {
    let system = std::env::var("SystemRoot").unwrap();
    PathBuf::from(system).join("System32").join("where.exe")
}

/// `text` at `relative` under the tree, creating its directory.
pub(super) fn put(tree: &Tree, relative: &str, text: &str) {
    let path = PathBuf::from(tree.path(relative));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// A native image (a copy of `where.exe`) at `relative` under the tree.
fn image(tree: &Tree, relative: &str) {
    let path = PathBuf::from(tree.path(relative));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::copy(where_exe(), path).unwrap();
}

pub(super) fn git_repository(tree: &Tree) {
    cmd(&tree.ws(), "git init -q");
    assert!(PathBuf::from(tree.path("ws\\.git")).is_dir());
}

#[test]
fn ordinary_windows_launches_mint_a_token() {
    let tree = Tree::new();
    git_repository(&tree);
    image(&tree, "ws\\bin\\probe.exe");
    for command in [
        "git status",
        "git --no-pager log -1",
        "cd src && git status",
        "./bin/probe.exe probe",
        "bin/probe probe",
    ] {
        let first = shell(&tree, command);
        assert!(first.is_ok(), "{command}: {first:?}");
        assert_eq!(first, shell(&tree, command), "{command}");
    }
    let ws_bin = tree.path("ws\\bin");
    let bare = launch(&tree, "probe probe", &|_, _, env| {
        prepend_path(env, &ws_bin)
    });
    assert!(bare.is_ok(), "{bare:?}");
    let pi = launch(&tree, "./bin/probe.exe probe", &|harness, tool, _| {
        *harness = "omp".to_owned();
        *tool = "bash".to_owned();
    });
    assert!(pi.is_ok(), "{pi:?}");
    let gitk = r"C:\Program Files\Git\cmd\gitk.exe";
    if PathBuf::from(gitk).is_file() {
        let installed = shell(&tree, "'C:/Program Files/Git/cmd/gitk.exe' --version");
        assert!(installed.is_ok(), "{installed:?}");
    }
}

#[test]
fn loader_inputs_change_the_token() {
    let tree = Tree::new();
    git_repository(&tree);
    image(&tree, "ws\\bin\\probe.exe");
    let probe = shell(&tree, "./bin/probe.exe probe").unwrap();
    let git = shell(&tree, "git status").unwrap();
    // A DLL beside a workspace image, or a manifest, loads with it.
    tree.write("ws\\bin\\version.dll", "MZ planted");
    let with_dll = shell(&tree, "./bin/probe.exe probe").unwrap();
    assert_ne!(probe, with_dll);
    tree.write("ws\\bin\\probe.exe.manifest", "<assembly/>");
    assert_ne!(with_dll, shell(&tree, "./bin/probe.exe probe").unwrap());
    // A DLL in the working directory is in the default search order even for
    // an installed image.
    tree.write("ws\\planted.dll", "MZ planted");
    assert_ne!(git, shell(&tree, "git status").unwrap());
    // The image bytes themselves.
    let before = shell(&tree, "./bin/probe.exe probe").unwrap();
    let mut bytes = std::fs::read(tree.path("ws\\bin\\probe.exe")).unwrap();
    bytes.push(0);
    std::fs::write(tree.path("ws\\bin\\probe.exe"), bytes).unwrap();
    assert_ne!(before, shell(&tree, "./bin/probe.exe probe").unwrap());
    // Repository config git reads.
    tree.write("ws\\.git\\info\\attributes", "*.txt -diff\n");
    assert_ne!(git, shell(&tree, "git status").unwrap());
}

#[test]
fn windows_launchers_and_destructive_commands_stay_one_time() {
    let tree = Tree::new();
    tree.write("ws\\script.js", "console.log(1)\n");
    tree.write("ws\\script.sh", "echo 1\n");
    for (command, expected) in [
        ("cmd /c dir", "mutable_launcher"),
        ("cmd.exe /c dir", "mutable_launcher"),
        (
            "powershell -NoProfile -Command Get-Date",
            "mutable_launcher",
        ),
        ("pwsh -c 1", "mutable_launcher"),
        ("wscript script.js", "mutable_launcher"),
        ("cscript script.js", "mutable_launcher"),
        ("mshta about:blank", "mutable_launcher"),
        ("rundll32 shell32.dll,Control_RunDLL", "mutable_launcher"),
        ("regsvr32 /s x.dll", "mutable_launcher"),
        ("msiexec /i x.msi", "mutable_launcher"),
        ("wsl ls", "mutable_launcher"),
        ("bash script.sh", "mutable_launcher"),
        ("schtasks /query", "mutable_launcher"),
        ("reg query HKCU", "mutable_launcher"),
        ("certutil -hashfile script.js", "mutable_launcher"),
        ("bitsadmin /list", "mutable_launcher"),
        ("node script.js", "mutable_launcher"),
        ("winpty node script.js", "mutable_launcher"),
        ("winpty.exe node script.js", "mutable_launcher"),
        ("cygstart script.js", "mutable_launcher"),
        ("tclsh script.js", "mutable_launcher"),
        ("tclsh86 script.js", "mutable_launcher"),
        ("TCLSH86.EXE script.js", "mutable_launcher"),
        ("wish script.js", "mutable_launcher"),
        ("wish86 script.js", "mutable_launcher"),
        ("npm test", "mutable_launcher"),
        ("npx vitest", "mutable_launcher"),
        ("python -m pytest", "mutable_launcher"),
        ("py -m pytest", "mutable_launcher"),
        ("taskkill /im x.exe", "destructive_command"),
        ("icacls script.js", "destructive_command"),
        ("del script.js", "destructive_command"),
        ("robocopy a b", "destructive_command"),
        ("netsh wlan show profiles", "destructive_command"),
    ] {
        assert_eq!(shell(&tree, command), Err(expected), "{command}");
    }
    // System32 images load from a directory no proof can bind.
    for command in ["where where", "where.exe where", "cd src && where where"] {
        let reason = shell(&tree, command);
        assert!(
            matches!(reason, Err("unproven_launch" | "compound_command")),
            "{command}: {reason:?}"
        );
    }
}

#[test]
fn launches_guard_cannot_pin_stay_one_time() {
    let tree = Tree::new();
    image(&tree, "ws\\bin\\probe.exe");
    tree.write("ws\\bin\\tool.cmd", "@echo off\r\necho hi\r\n");
    tree.write("ws\\bin\\tool.bat", "@echo off\r\necho hi\r\n");
    image(&tree, "ws\\twins\\probe.exe");
    tree.write("ws\\twins\\probe", "#!/bin/sh\necho shadow\n");
    image(&tree, "ws\\com\\probe.exe");
    image(&tree, "ws\\com\\probe.com");
    image(&tree, "ws\\shims\\probe.exe");
    tree.write("ws\\shims\\probe.shim", "path = C:\\elsewhere\\real.exe\n");
    image(&tree, "ws\\local\\probe.exe");
    std::fs::create_dir_all(tree.path("ws\\local\\probe.exe.local")).unwrap();
    image(&tree, "ws\\many\\probe.exe");
    for index in 0..17 {
        tree.write(&format!("ws\\many\\lib{index}.dll"), "MZ");
    }
    let ws = tree.ws();
    let msys = format!(
        "/{}/bin/probe.exe probe",
        ws.replacen(":\\", "/", 1).replace('\\', "/")
    );
    let unc = format!(
        "//localhost/{}/bin/probe.exe probe",
        ws.replacen(':', "$", 1).replace('\\', "/")
    );
    for (command, expected) in [
        ("./bin/tool.cmd", "unproven_launch"),
        ("./bin/tool.bat", "unproven_launch"),
        ("bin/tool", "unproven_launch"),
        ("twins/probe probe", "unproven_launch"),
        ("com/probe probe", "unproven_launch"),
        ("./shims/probe.exe probe", "mutable_launcher"),
        ("./local/probe.exe probe", "unproven_launch"),
        ("./many/probe.exe probe", "unproven_launch"),
        ("./bin/probe.exe. probe", "unproven_launch"),
        ("./bin/probe.exe::$DATA probe", "unproven_launch"),
        ("bin/../bin/probe.exe probe", "unproven_launch"),
        ("./bin/prob?.exe probe", "unproven_launch"),
        (msys.as_str(), "unproven_launch"),
        (unc.as_str(), "unproven_launch"),
    ] {
        assert_eq!(shell(&tree, command), Err(expected), "{command}");
    }
    let apps = std::env::var("LOCALAPPDATA")
        .map(|base| PathBuf::from(base).join("Microsoft\\WindowsApps"))
        .ok();
    let alias = apps
        .and_then(|dir| std::fs::read_dir(dir).ok())
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "exe"));
    if let Some(alias) = alias {
        let spelled = alias.to_str().unwrap().replace('\\', "/");
        let reason = shell(&tree, &format!("'{spelled}' --version"));
        assert!(reason.is_err(), "{spelled}: {reason:?}");
    }
}

#[test]
fn search_path_and_harness_ambiguity_stays_one_time() {
    let tree = Tree::new();
    image(&tree, "ws\\bin\\probe.exe");
    put(&tree, "ws\\early\\probe", "#!/bin/sh\necho shadow\n");
    put(&tree, "ws\\cmdshim\\probe.cmd", "@echo shadow\r\n");
    let bin = tree.path("ws\\bin");
    let early = format!("{};{bin}", tree.path("ws\\early"));
    let cmdshim = format!("{};{bin}", tree.path("ws\\cmdshim"));
    let empty = format!(";{bin}");
    let relative = format!("bin;{bin}");
    let quoted = format!("\"{bin}\"");
    for entries in [&early, &cmdshim, &empty, &relative, &quoted] {
        let reason = launch(&tree, "probe probe", &|_, _, env| {
            prepend_path(env, entries)
        });
        assert_eq!(reason, Err("unproven_launch"), "{entries}");
    }
    let doubled = launch(&tree, "probe probe", &|_, _, env| {
        prepend_path(env, &bin);
        env.insert("Path".to_owned(), bin.clone());
    });
    assert_eq!(doubled, Err("unproven_launch"));
    // Git Bash searches `~/bin` ahead of PATH.
    put(&tree, "home\\bin\\probe", "#!/bin/sh\necho shadow\n");
    let home_bin = launch(&tree, "probe probe", &|_, _, env| prepend_path(env, &bin));
    assert_eq!(home_bin, Err("unproven_launch"));
    // PowerShell harnesses and tools are not modeled.
    for (harness, tool) in [
        ("codex", "shell"),
        ("codex", "Bash"),
        ("claude-code", "PowerShell"),
    ] {
        let reason = launch(&tree, "./bin/probe.exe probe", &|name, tool_name, _| {
            *name = harness.to_owned();
            *tool_name = tool.to_owned();
        });
        assert_eq!(reason, Err("unproven_launch"), "{harness} {tool}");
    }
}

#[test]
fn git_helpers_on_windows_stay_one_time() {
    let tree = Tree::new();
    git_repository(&tree);
    assert!(shell(&tree, "git status").is_ok());
    let lowercase = launch(&tree, "git status", &|_, _, env| {
        env.insert("git_pager".to_owned(), "less".to_owned());
    });
    assert_eq!(lowercase, Err("git_helper_config"));
    for config in [
        "[diff \"x\"]\n\ttextconv = cat\n",
        "[include]\n\tpath = ~/extra.cfg\n",
        "[include]\n\tpath = /etc/extra.cfg\n",
        "[include]\n\tpath = %(prefix)/etc/extra.cfg\n",
        "[core]\n\thooksPath = ~/hooks\n",
    ] {
        tree.write("ws\\.git\\config", config);
        assert_eq!(
            shell(&tree, "git status"),
            Err("git_helper_config"),
            "{config}"
        );
    }
    tree.write("ws\\.git\\config", "[core]\n\tbare = false\n");
    let unpinned_home = launch(&tree, "git status", &|_, _, env| {
        env.insert("HOME".to_owned(), "/c/Users/someone".to_owned());
    });
    assert_eq!(unpinned_home, Err("unproven_launch"));
    let unc = format!("\\\\localhost\\{}", tree.ws().replacen(':', "$", 1));
    let request = query(&tree, "Bash", Some("git status"), json!(null), &unc);
    assert_eq!(exact_action_token(&request), Err("unproven_launch"));
    let mut request = query(&tree, "Bash", Some("git status"), json!(null), &tree.ws());
    if let NativeExactActionQueryV1::ExactAction { workspace, .. } = &mut request {
        *workspace = Some(unc);
    }
    assert_eq!(exact_action_token(&request), Err("unproven_launch"));
}

#[test]
fn dlls_the_search_path_reaches_are_bound() {
    let tree = Tree::new();
    git_repository(&tree);
    image(&tree, "ws\\bin\\probe.exe");
    put(&tree, "tools\\readme.txt", "no libraries\n");
    let tools = tree.path("tools");
    let commands = ["git status", "./bin/probe.exe probe"];
    let tokens = |tree: &Tree| {
        commands.map(|command| launch(tree, command, &|_, _, env| prepend_path(env, &tools)))
    };
    let clean = tokens(&tree);
    assert!(clean.iter().all(Result::is_ok), "{clean:?}");
    // A DLL planted where the loader search ends, or in the `~/bin` Git Bash
    // searches first, changes the token.
    put(&tree, "tools\\libwinpthread-1.dll", "MZ planted");
    let planted = tokens(&tree);
    for (before, after) in clean.iter().zip(&planted) {
        assert_ne!(before, after);
    }
    // A spelling that only starts inside Program Files is bound by where it
    // leads.
    let program_files = std::env::var("ProgramFiles").unwrap();
    let detour = format!("{program_files}\\..{}", &tools[2..]);
    let through = |tree: &Tree| launch(tree, "git status", &|_, _, env| prepend_path(env, &detour));
    let before = through(&tree);
    put(&tree, "tools\\detour.dll", "MZ planted");
    assert!(before.is_ok());
    assert_ne!(before, through(&tree));
    let git = shell(&tree, "git status");
    put(&tree, "home\\bin\\version.dll", "MZ planted");
    assert_ne!(git, shell(&tree, "git status"));
    assert!(shell(&tree, "git status").is_ok());
    // More DLLs than the binding caps cover stay once-only.
    for index in 0..17 {
        put(&tree, &format!("tools\\extra{index}.dll"), "MZ planted");
    }
    for reason in tokens(&tree) {
        assert_eq!(reason, Err("unproven_launch"));
    }
}

#[test]
fn unresolved_path_entries_are_bound_instead_of_refusing_the_launch() {
    let tree = Tree::new();
    git_repository(&tree);
    let tools = tree.path("tools");
    std::fs::create_dir_all(&tools).unwrap();
    // A trailing dot is not a pinned spelling, so `resolve` is None, but
    // Windows still opens the directory. A missing short-shaped tail fails
    // the same way and must not refuse every launch.
    let dotted = format!("{tools}.");
    let missing = format!("{}\\missing~1", tree.ws());
    let entries = format!("{dotted};{missing}");
    let launch_entries = |tree: &Tree| {
        launch(tree, "git status", &|_, _, env| {
            prepend_path(env, &entries);
        })
    };
    let clean = launch_entries(&tree).expect("unresolved entries stay reusable");
    put(&tree, "tools\\libwinpthread-1.dll", "MZ planted");
    assert_ne!(clean, launch_entries(&tree).unwrap());
    // The same directory, spelled as a walk out of Program Files plus a
    // trailing dot, is not an install root just because the text starts there.
    let program_files = std::env::var("ProgramFiles").unwrap();
    let detour = format!("{program_files}\\..{}.", &tools[2..]);
    let before = launch(&tree, "git status", &|_, _, env| prepend_path(env, &detour)).unwrap();
    put(&tree, "tools\\detour.dll", "MZ planted");
    assert_ne!(
        before,
        launch(&tree, "git status", &|_, _, env| prepend_path(env, &detour)).unwrap()
    );
}

#[test]
fn loader_steering_and_sibling_programs_are_bound_or_refused() {
    let tree = Tree::new();
    git_repository(&tree);
    image(&tree, "ws\\bin\\probe.exe");
    for name in [
        "COR_ENABLE_PROFILING",
        "cor_profiler_path",
        "CORECLR_PROFILER",
        "DOTNET_STARTUP_HOOKS",
        "DOTNET_ROOT(x86)",
        "DOTNET_ADDITIONAL_DEPS",
        "QT_PLUGIN_PATH",
        "OPENSSL_MODULES",
    ] {
        for command in ["git status", "./bin/probe.exe probe"] {
            let reason = launch(&tree, command, &|_, _, env| {
                env.insert(name.to_owned(), "1".to_owned());
            });
            assert_eq!(reason, Err("unproven_launch"), "{name} {command}");
        }
    }
    // .NET reads `runtimeconfig.dev.json` probing paths beside the image.
    let probe = shell(&tree, "./bin/probe.exe probe").unwrap();
    tree.write("ws\\bin\\probe.runtimeconfig.dev.json", "{}");
    assert_ne!(probe, shell(&tree, "./bin/probe.exe probe").unwrap());
    // A bare-name child launch finds the working directory's programs first.
    let git = shell(&tree, "git status").unwrap();
    image(&tree, "ws\\git-lfs.exe");
    assert_ne!(git, shell(&tree, "git status").unwrap());
}
