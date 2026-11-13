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
        "open('/./etc/passwd').read()",
        "open('/tmp/../etc/passwd').read()",
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
        "open('/tmp/./out/../report.txt').read()",
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

#[test]
fn template_literals_and_bare_scratch_directories_are_read_by_quote_kind() {
    assert!(names_system_file(
        "require('fs').readFileSync(`/etc/passwd`, 'utf8')"
    ));
    for code in [
        "tempfile.mkdtemp(dir='/var/tmp/')",
        "os.listdir('/usr/local/')",
        "os.listdir('/usr/bin/')",
        "fs.readdirSync(`/var/tmp`)",
    ] {
        assert!(!names_system_file(code), "{code}");
    }
}

#[test]
fn ruby_perl_and_php_inline_source_is_read_for_system_files() {
    let home = std::env::temp_dir();
    let home = home.to_str().unwrap();
    let context = crate::pretool::PathContext {
        home_dir: Some(home),
        cwd: Some(home),
        ..Default::default()
    };
    for named in [
        "ruby -e 'puts File.read(\"/etc/passwd\")'",
        "perl -e 'open(my $f, \"<\", \"/etc/shadow\"); print <$f>'",
        "php -r 'echo file_get_contents(\"/etc/passwd\");'",
    ] {
        assert!(super::text_names_system_file(named, context), "{named}");
    }
    let local = "ruby -e 'puts File.read(\"Gemfile\")'";
    assert!(!super::text_names_system_file(local, context));
}

#[test]
fn comment_markers_inside_strings_or_the_other_language_do_not_hide_a_path() {
    let home = std::env::temp_dir();
    let home = home.to_str().unwrap();
    let context = crate::pretool::PathContext {
        home_dir: Some(home),
        cwd: Some(home),
        ..Default::default()
    };
    for named in [
        "python3 -c 'label = \"note # comment\"; print(open(\"/etc/passwd\").read())'",
        "python3 -c 'n = 7 // 2; print(open(\"/etc/passwd\").read())'",
        // The `#` sits inside a triple-quoted string that opened a line above.
        "python3 -c 's = \"\"\"\n#\"\"\"; print(open(\"/etc/passwd\").read())'",
        "node -e 'const s = `\n //`; console.log(require(\"fs\").readFileSync(\"/etc/passwd\", \"utf8\"))'",
    ] {
        assert!(super::text_names_system_file(named, context), "{named}");
    }
    let commented = "python3 -c 'print(1)  # open(\"/etc/passwd\")'";
    assert!(!super::text_names_system_file(commented, context));
}
