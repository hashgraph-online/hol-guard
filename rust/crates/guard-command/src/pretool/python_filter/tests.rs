use super::{interpreter_options, names, path_outside_workspace, program};

fn words(text: &str) -> Vec<String> {
    text.split(' ').map(str::to_owned).collect()
}

#[test]
fn programs_that_only_reshape_their_input_pass() {
    for source in [
        "import json,sys; d=json.load(sys.stdin); print(d['state'])",
        "import sys,json; d=json.load(sys.stdin); print(json.dumps({k:d.get(k) for k in ('a','b')}, indent=2))",
        "\nimport json,sys\nfor c in json.load(sys.stdin):\n    if c['state'] not in ('SUCCESS','SKIPPED'): print(c['state'], c['name'], c['link'])",
        "import json,sys; rs=json.load(sys.stdin); [print(r.get('id'), str(r.get('command',''))[:70].replace(chr(10),' ')) for r in rs]",
        "import json, sys\nfrom collections import Counter\nprint(Counter(x['kind'] for x in json.load(sys.stdin)).most_common(5))",
        "import json,sys\nprint(f\"{len(json.load(sys.stdin))} rows, first {sys.argv[1]!r:>10}\")",
        "import re,sys\nfor line in sys.stdin:\n    m = re.compile(r'(\\d+)').search(line)\n    if m: print(m.group(1), file=sys.stderr)",
        "from json import (\n    load,\n    dumps,\n)\nimport sys\nprint(dumps(load(sys.stdin)))",
        "import json,sys\ndef walk(o):\n    if isinstance(o, dict):\n        for k, v in o.items(): walk(v)\nwalk(json.load(sys.stdin))",
        "import json,sys; print(f'{\"x\" if 1 else \"y\"}')",
    ] {
        assert!(program::screened(source), "{source}");
    }
}

#[test]
fn programs_that_reach_past_their_input_fail() {
    for source in [
        "import os; print(os.listdir('.'))",
        "import subprocess; subprocess.run(['ls'])",
        "import json as j; print(j)",
        "import os.path",
        "from os import system",
        "from json import *",
        "from . import x",
        "import json; print(json.decoder)",
        "import sys; print(sys.modules)",
        "import sys; m = sys; print(m)",
        "print(open('/etc/hosts').read())",
        "print(eval('1+1'))",
        "exec('print(1)')",
        "print(getattr(print, 'x'))",
        "print(globals())",
        "print(().__class__)",
        "g = (x for x in []); print(g.gi_frame.f_globals)",
        "import sys; print(sys._getframe())",
        "x = input()",
        "help(print)",
        "breakpoint()",
        "print(type(1))",
        "print(f'{open(\"x\")}')",
        "print(f\"{f'{open(1)}'}\")",
        "print(f\"{x[\"k\"]}\")",
        "print(f'{x\\n}')",
        "print('unterminated)",
        "# -*- coding: rot13 -*-\nprint(1)",
        "print('caf\u{e9}')",
        "import shlex; s = shlex.shlex('x'); s.source = 'source'",
        "import re; c = compile('1', 'x', 'eval')",
        "x = 1 \\ 2",
        "if True: import os",
        "import\njson",
        "import fractions; fractions.sys.stdout.write('x')",
        "from fractions import sys",
        "import textwrap; print(textwrap.re)",
        "import statistics; print(statistics.math.pi)",
        "import json; print('{0.x}'.format(json.load))",
        "import json; print('{0.x}' '{1}'.format_map({}))",
        "import string; string.Formatter().vformat('{0}', (), {})",
    ] {
        assert!(!program::screened(source), "{source}");
    }
}

#[test]
fn carriage_return_ends_a_comment_before_a_hidden_import() {
    // CPython treats bare CR and CRLF as line boundaries; a scanner must
    // not discard executable code after a comment on either spelling.
    let unsafe_source = "import json; print(json.dumps([1])) #\rimport os; print(os.name)";
    assert!(!program::screened(unsafe_source), "{unsafe_source:?}");

    let crlf_source = "import json; print(json.dumps([1])) #\r\nimport subprocess";
    assert!(!program::screened(crlf_source), "{crlf_source:?}");

    let harmless_source = "import json; print(json.dumps([1])) #\rprint('done')";
    assert!(program::screened(harmless_source), "{harmless_source:?}");
}

#[test]
fn only_quiet_interpreter_switches_lead_to_the_program() {
    for (arguments, isolated, program) in [
        ("-c X", false, 1),
        ("-I -c X", true, 2),
        ("-Ic X arg", true, 1),
        ("-u -B -c X", false, 3),
        ("-S -c X", false, 2),
    ] {
        let options = interpreter_options(&words(arguments)).expect(arguments);
        assert_eq!(options.ignores_environment, isolated, "{arguments}");
        assert_eq!(options.safe_path, isolated, "{arguments}");
        assert_eq!(options.program, program, "{arguments}");
        assert_eq!(options.no_site, arguments.starts_with("-S"), "{arguments}");
    }
    for arguments in [
        "-c",
        "script.py",
        "-m json.tool",
        "-i -c X",
        "-X dev -c X",
        "-cX",
        "--c X",
        "-W error -c X",
    ] {
        assert!(
            interpreter_options(&words(arguments)).is_none(),
            "{arguments}"
        );
    }
}

#[test]
fn only_variables_that_steer_the_interpreter_count() {
    for name in [
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONHOME",
        "pythonpath",
        "PYTHONWARNINGS",
        "PYTHONUSERBASE",
    ] {
        assert!(names::steering_variable(name), "{name}");
    }
    for name in [
        "PYTHONUNBUFFERED",
        "PYTHONIOENCODING",
        "PYTHONDONTWRITEBYTECODE",
        "PATH",
        "PY",
        "\u{e9}PYTHON",
    ] {
        assert!(!names::steering_variable(name), "{name}");
    }
}

#[test]
fn standard_library_names_shadow_whatever_their_case() {
    for stem in ["json", "JSON", "traceback", "_colorize", "sitecustomize"] {
        assert!(names::shadows_standard_library(stem), "{stem}");
    }
    for stem in ["pkg", "scripts", "", "tests", "README"] {
        assert!(!names::shadows_standard_library(stem), "{stem}");
    }
}

#[test]
fn only_unquoted_glob_characters_expand() {
    for text in ["python3 -c *", "python3 -c 'x' ?.json", "python3 -c [ab]"] {
        assert!(super::unquoted_glob(text), "{text}");
    }
    for text in [
        "python3 -c 'print([1])'",
        "python3 -c \"print([1])\"",
        "python3 -c print\\[1\\]",
        "python3 -c 'a\" * \"b'",
    ] {
        assert!(!super::unquoted_glob(text), "{text}");
    }
}

#[test]
fn a_workspace_interpreter_is_inside_however_its_path_is_spelled() {
    let root = std::env::temp_dir().join(format!("guard-pyfilter-path-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let bin = root.join("project/.venv/bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(bin.join("python3"), "").unwrap();
    let root = std::fs::canonicalize(&root).unwrap();
    let cwd = root.join("project");
    let cwd = cwd.to_str();
    let name = root.file_name().unwrap().to_str().unwrap();
    // Climbs before it reaches the working directory, so a plain prefix
    // check would read it as outside.
    let climbed = format!("{}/../{name}/project/.venv/bin/python3", root.display());
    assert!(!path_outside_workspace(&climbed, cwd), "{climbed}");
    let direct = format!("{}/project/.venv/bin/python3", root.display());
    assert!(!path_outside_workspace(&direct, cwd), "{direct}");
    #[cfg(unix)]
    {
        let link = root.join("python3");
        std::os::unix::fs::symlink(bin.join("python3"), &link).unwrap();
        assert!(!path_outside_workspace(link.to_str().unwrap(), cwd));
    }
    assert!(!path_outside_workspace("/no/such/python3", cwd));
    assert!(path_outside_workspace("python3", cwd));
    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn a_venv_launcher_symlink_to_system_python_still_counts_as_workspace_python() {
    let root =
        std::env::temp_dir().join(format!("guard-pyfilter-venv-link-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let bin = root.join("project/.venv/bin");
    std::fs::create_dir_all(&bin).unwrap();
    let outside = root.join("system-python3");
    std::fs::write(&outside, "").unwrap();
    let launcher = bin.join("python3");
    std::os::unix::fs::symlink(&outside, &launcher).unwrap();

    let workspace = root.join("project");
    let workspace = workspace.to_str().unwrap();
    // Resolving the final symlink gives a system path; Python nevertheless
    // uses the invoked .venv path to load startup .pth files without -S.
    assert!(!path_outside_workspace(
        launcher.to_str().unwrap(),
        Some(workspace)
    ));
    assert!(path_outside_workspace(
        outside.to_str().unwrap(),
        Some(workspace)
    ));
    std::fs::remove_dir_all(&root).unwrap();
}
