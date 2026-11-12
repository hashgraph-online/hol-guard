use super::names_system_file;

#[test]
fn account_kernel_and_log_files_are_system_files() {
    for code in [
        "file_name = '/etc/passwd'\nwith open(file_name) as f:\n    print(f.read())",
        "open(\"/etc/shadow\").read()",
        "open('/root/.bashrc', 'a').write('alias sudo=\"rm -rf /\"')",
        "print(open('/proc/cpuinfo').read())",
        "open('/sys/kernel/vmcoreinfo').read()",
        "open('/var/lib/pam/auth').read()",
        "open('/var/log/dpkg.log').read()",
        "open('/usr/share/base-passwd/passwd.master').read()",
        "open('/usr/usrfile.txt').read()",
        "fs.readFileSync('/etc/group', 'utf8')",
        "open('/private/etc/master.passwd').read()",
        "open('/usr/bin/../../etc/passwd').read()",
        "open('/var/tmp/../../etc/shadow').read()",
    ] {
        assert!(names_system_file(code), "{code}");
    }
}

#[test]
fn programs_scratch_space_and_workspace_paths_are_not_system_files() {
    for code in [
        "subprocess.run(['/usr/bin/git', 'status'])",
        "subprocess.run(['/usr/local/bin/node', '--version'])",
        "open('/var/folders/xy/T/report.json').read()",
        "open('/tmp/out.txt', 'w').write('ok')",
        "open('src/etc/config.json').read()",
        "print('/etcetera')",
        "print(1 + 1)",
        "import json\nprint(json.dumps({'a': 1}))",
    ] {
        assert!(!names_system_file(code), "{code}");
    }
}

#[test]
fn a_program_fed_on_a_heredoc_is_read_for_system_files() {
    let home = std::env::temp_dir();
    let home = home.to_str().unwrap();
    let context = crate::pretool::PathContext {
        home_dir: Some(home),
        cwd: Some(home),
        ..Default::default()
    };
    let named = "python3 - <<'PYEOF'\nwith open('/etc/passwd') as f:\n    print(f.read())\nPYEOF";
    assert!(super::text_names_system_file(named, context));
    let local = "python3 - <<'PYEOF'\nwith open('data.csv') as f:\n    print(f.read())\nPYEOF";
    assert!(!super::text_names_system_file(local, context));
}
