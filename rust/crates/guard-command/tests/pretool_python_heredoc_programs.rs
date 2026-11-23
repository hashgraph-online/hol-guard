//! A Python program fed on standard input from a quoted heredoc.
//!
//! `python3 probe.py` runs in the workspace sandbox once its source needs
//! neither the network nor a credential store. Agents write the same probe
//! inline far more often, as `python3 << 'EOF'` or `python3 - << 'EOF'`, and
//! that spelling was held for review as soon as the program imported a
//! module, the project's own or the standard library's. The heredoc is now
//! held to the bar the script file meets. A program that needs the network,
//! names a credential store (itself or through a local module it imports),
//! declares its own source encoding, is fed to an
//! interpreter that also runs other code, or is chained to other commands,
//! keeps its review.

use crate::git_helper_fixture as fixture;
use fixture::FixtureCleanup;
use serde_json::json;
use std::path::{Path, PathBuf};

const CONTAINED: (&str, &str) = ("sandbox-required", "native_workspace_containment_required");

fn checkout(label: &str) -> (PathBuf, FixtureCleanup) {
    let root = std::env::temp_dir().join(format!(
        "guard-python-heredoc-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("project");
    std::fs::create_dir_all(project.join("pkg")).unwrap();
    std::fs::write(project.join("pkg/__init__.py"), "X = 1\n").unwrap();
    std::fs::write(project.join("pkg/remote.py"), "import requests\n").unwrap();
    std::fs::write(
        project.join("pkg/stopper.py"),
        "import os as proc\nproc.kill(4242, 15)\n",
    )
    .unwrap();
    for (name, source) in [
        (
            "lazy",
            "class Pool:\n    def __init__(self):\n        self._module = __import__('concurrent.futures').futures\n",
        ),
        ("lazystop", "p = __import__('os')\np.kill(4242, 15)\n"),
        ("lazyremote", "m = __import__('socket')\n"),
        ("lazylocal", "m = __import__('pkg.stopper')\n"),
        (
            "documented",
            "\"\"\"Tools.\n\n.. [1] See the guide.\n\"\"\"\n\ndef chunked(it):\n    \"\"\"Split it.\n\n    .. deprecated:: 1.0\n    \"\"\"\n    return it\n",
        ),
        ("docpath", "\"\"\"/home/user/.aws/credentials\"\"\"\n"),
    ] {
        std::fs::write(project.join(format!("pkg/{name}.py")), source).unwrap();
    }
    // A package whose initializer signals, under a harmless module.
    std::fs::create_dir_all(project.join("nested/inner")).unwrap();
    std::fs::write(
        project.join("nested/__init__.py"),
        "import os as proc\nproc.kill(4242, 15)\n",
    )
    .unwrap();
    std::fs::write(project.join("nested/inner/leaf.py"), "X = 1\n").unwrap();
    // A package and a same-named module: Python loads the package.
    std::fs::create_dir_all(project.join("shadow")).unwrap();
    std::fs::write(
        project.join("shadow/__init__.py"),
        "import os as proc\nproc.kill(4242, 15)\n",
    )
    .unwrap();
    std::fs::write(project.join("shadow.py"), "X = 1\n").unwrap();
    std::fs::write(
        project.join("caf\u{e9}.py"),
        "import os as proc\nproc.kill(4242, 15)\n",
    )
    .unwrap();
    std::fs::create_dir_all(project.join("wide")).unwrap();
    for index in 0..40 {
        std::fs::write(project.join(format!("wide/m{index}.py")), "X = 1\n").unwrap();
    }
    std::fs::write(
        project.join("keys.py"),
        "print(open('/home/user/.aws/credentials').read())\n",
    )
    .unwrap();
    std::fs::write(
        project.join("pyproject.toml"),
        "[project]\nname = \"pkg\"\n",
    )
    .unwrap();
    fixture::git(&root, &project, &["init", "--quiet", "-b", "main"]);
    let root = fixture::canonical_spelling(&root);
    (root.clone(), FixtureCleanup(root))
}

fn outcome(root: &Path, command: &str) -> (String, String) {
    let result = fixture::evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name":"Bash","tool_input":{"command":command}}),
        Some(&fixture::local_admin_controls(Vec::new())),
        None,
        root.to_str(),
        root.join("project").to_str(),
    );
    (result.minimum_action, result.reason_code)
}

#[test]
fn a_probe_that_imports_modules_runs_in_the_workspace_sandbox() {
    let (root, _cleanup) = checkout("imports");
    for command in [
        "python3 << 'EOF'\nimport pkg\nprint(pkg.X)\nEOF",
        "python3 - << 'PYEOF'\nimport inspect\nimport pkg\n\nprint(inspect.getmembers(pkg))\nPYEOF",
        "python3 << 'EOF'\nfrom collections import OrderedDict\n\nd = OrderedDict([('a', 1)])\nd.move_to_end('a')\nprint(list(d))\nEOF",
        "python <<'EOF'\nimport json\nprint(json.dumps({}))\nEOF",
        "python3 << 'EOF'\nprint(1)\nEOF",
        "python3 << 'EOF'\nmarker = \" #\"; print(marker) # safe trailing comment\nEOF",
        // A continued ordinary string can still run inside the workspace.
        "python3 <<'EOF'\nmarker = \"a\\\nb\"; print(marker)\nEOF",
        "python3 <<'EOF'\nimport \\\n json\nprint(json.dumps({}))\nEOF",
        "python3 <<'EOF' | tee out.txt\nimport pkg\nprint(pkg.X)\nEOF",
        "python3 -I << 'EOF'\nimport glob\nimport re\nprint(sorted(glob.glob('pkg/*.py')))\nEOF",
        "python3 -I - <<'EOF'\nimport json\nprint(json.dumps([]))\nEOF",
        // CRLF inside a quoted heredoc is a physical newline, not a bare CR.
        "python3 <<'EOF'\nimport json\r\nprint(json.dumps({}))\r\nEOF",
        // Builtins-only code takes a separate fast path and must accept CRLF.
        "python3 <<'EOF'\nprint(1)\r\nprint(2)\r\nEOF",
        // `coding` past the second line is not an encoding declaration.
        "python3 <<'EOF'\nimport json\nprint(open('pyproject.toml', encoding='utf-8').read())\nEOF",
        "python3 <<'EOF'\nimport json\nimport sys\n# decoding note\nsys.stdout.reconfigure(encoding='utf-8')\nEOF",
        // Separators, method calls named like builtins and the shared
        // temporary directory stay inside what the sandbox allows.
        "python3 <<'EOF'\nimport json\nprint('/'.join(['a', 'b']), 'a/b'.split('/'))\nEOF",
        "python3 <<'EOF'\nimport re\nprint(re.compile(r'a+').findall('aa'))\nEOF",
        "python3 <<'EOF'\nimport json\nopen('/tmp/probe.json', 'w').write(json.dumps({}))\nEOF",
        "python3 <<'EOF'\nimport json\nprint(open('.gitignore').read())\nEOF",
        // Starting a program is bounded by the same sandbox.
        "python3 - <<'EOF'\nimport subprocess\nsubprocess.run(['git', 'status'])\nEOF",
        "python3 <<'EOF'\nimport signal\nsignal.signal(signal.SIGINT, signal.SIG_DFL)\nprint(1)\nEOF",
        // Text that only mentions an import is not one.
        "python3 <<'EOF'\nimport json\nprint(\"import psutil\")\nEOF",
        "python3 <<'EOF'\nimport subprocess\nsubprocess.run(['git', 'config', '--get', 'user.name'])\nEOF",
    ] {
        let (action, reason) = outcome(&root, command);
        assert_eq!((action.as_str(), reason.as_str()), CONTAINED, "{command}");
    }
}

#[test]
fn a_probe_whose_modules_import_by_a_constant_name_runs_in_the_workspace_sandbox() {
    let (root, _cleanup) = checkout("constant");
    for command in [
        "python3 - <<'PY'\nfrom pkg import lazy\nprint(lazy.Pool)\nPY",
        "python3 - <<'PY'\nimport importlib\njson = importlib.import_module('json')\nprint(json.dumps({}))\nPY",
        "python3 - <<'EOF'\nimport importlib\njson = importlib.import_module('json')\nprint(json.dumps({'lazy': True}))\nEOF",
    ] {
        let (action, reason) = outcome(&root, command);
        assert_eq!((action.as_str(), reason.as_str()), CONTAINED, "{command}");
    }
}

#[test]
fn a_probe_whose_modules_document_themselves_runs_in_the_workspace_sandbox() {
    let (root, _cleanup) = checkout("documented");
    for command in [
        "python3 - <<'PY'\nfrom pkg import documented\nprint(documented.chunked([1]))\nPY",
        "python3 - <<'EOF'\ndef chunk(items):\n    \"\"\"Split items into one batch.\n\n    .. note:: see the guide\n    \"\"\"\n    return [items]\n\nprint(chunk([1, 2]))\nEOF",
    ] {
        let (action, reason) = outcome(&root, command);
        assert_eq!((action.as_str(), reason.as_str()), CONTAINED, "{command}");
    }
}

#[test]
fn a_probe_that_would_not_fit_the_sandbox_keeps_its_review() {
    let (root, _cleanup) = checkout("misfits");
    for command in [
        "python3 - <<'EOF'\nimport requests\nprint(requests.get('https://example.invalid'))\nEOF",
        "python3 - <<'EOF'\nimport urllib.request\nprint(urllib.request.urlopen('https://example.invalid'))\nEOF",
        "python3 <<'EOF'\nimport os\nprint(open(os.path.expanduser('~/.aws/credentials')).read())\nEOF",
        "python3 <<'EOF'\n# -*- coding: utf-7 -*-\nimport json\nEOF",
        "python3 <<'EOF'\n#!/usr/bin/env python3\n  # vim: set fileencoding=utf-7 :\nimport json\nEOF",
        "python3 -c 'import os' <<'EOF'\nimport pkg\nEOF",
        "python3 -i <<'EOF'\nimport pkg\nEOF",
        "python3 -I -c 'import os' <<'EOF'\nimport json\nEOF",
        // Chained to other commands, a program that imports keeps its review.
        "python3 <<'EOF'\nimport pkg\nEOF\ngit add -A",
        "python3 - <<'EOF'\nimport subprocess\nEOF\nls",
        "python3 <<'EOF' | tee out.txt; sh out.txt\nimport pkg\nEOF",
        "python3 <<'EOF' | tee $OUT\nimport pkg\nEOF",
        // A local module that needs what the sandbox withholds counts too.
        "python3 <<'EOF'\nfrom pkg import remote\nEOF",
        "python3 - <<'EOF'\nimport pkg.remote\nEOF",
        "python3 <<'EOF'\nimport keys\nEOF",
        "python3 <<'EOF'\nif True: import socket\nEOF",
        // A hash inside a string must not erase the executable suffix.
        "python3 <<'EOF'\nmarker = \" #\"; import socket\nEOF",
        "python3 <<'EOF'\nprint(1) #\rimport socket\nEOF",
        // A bare CR can reframe the encoding declaration as Python's second
        // physical line even when the heredoc parser split only on LF.
        "python3 <<'EOF'\n# first comment\r# coding: utf-7\n+AGk-mport socket\nEOF",
        // Source scanning and the interpreter must agree on line boundaries.
        "python3 - <<'EOF'\nimport json\rprint(json.dumps({}))\nEOF",
        // A builtins-only probe must not bypass the physical-line check.
        "python3 <<'EOF'\nprint(1)\rprint(2)\nEOF",
        "python3 <<'EOF'\nmarker = \" #\"; from urllib import request\nEOF",
        // Python joins this continued string before interpreting the semicolon.
        // The comment's unmatched quote must not hide the network import.
        "python3 <<'EOF'\nmarker = \"a\\\nb\"; import socket # \"\nEOF",
        "python3 <<'EOF'\nimport \\\n socket\nEOF",
        "python3 <<'EOF'\nimport so\\\ncket\nEOF",
        "python3 <<'EOF'\nfrom \\\n socket import create_connection\nEOF",
        "python3 <<'EOF'\nprint(1) #\\\nimport socket\nEOF",
        "python3 <<'EOF'\nmarker = \" #\"; print(open('/home/user/.aws/credentials').read())\nEOF",
        // The sandbox still exposes the rest of the host: other processes,
        // the clipboard and screen, system directories and the checkout's
        // own Git configuration.
        "python3 - <<'PYEOF'\nimport psutil\nfor proc in psutil.process_iter():\n    proc.kill()\nPYEOF",
        "python3 - <<'PYEOF'\nimport pyperclip\nprint(pyperclip.paste())\nPYEOF",
        "python3 - <<'PYEOF'\nfrom PIL import ImageGrab\nImageGrab.grab().save('shot.png')\nPYEOF",
        "python3 - <<'PYEOF'\nimport os\nos.system('ls -a /app/')\nPYEOF",
        "python3 - <<'PYEOF'\nimport json\nprint(eval(\"__import__('os').getcwd()\"))\nPYEOF",
        "python3 - <<'PYEOF'\nimport glob\nprint(glob.glob('/app/*'))\nPYEOF",
        "python3 - <<'PYEOF'\nimport os\nbase = \"/usr\"\nprint(open(os.path.join(base, \"../etc/passwd\")).read())\nPYEOF",
        "python3 - <<'PYEOF'\nimport os\nprint(os.listdir('..'))\nPYEOF",
        "python3 - <<'PY'\nfrom pathlib import Path\nPath('.git/config').write_text('[core]\\n\\thooksPath = /dev/null\\n')\nPY",
        // The same reach through a command line, an alias or the root.
        "python3 - <<'PY'\nimport os\nos.system('git config core.hooksPath /dev/null')\nPY",
        "python3 - <<'PY'\nimport subprocess\nsubprocess.run(['kill', '-9', '1'])\nPY",
        "python3 - <<'PY'\nimport os\nos.system('cat /etc/passwd /tmp/out')\nPY",
        "python3 - <<'PY'\nimport os as proc\nproc.kill(4242, 15)\nPY",
        "python3 - <<'PY'\nimport os\nprint(os.listdir('/'))\nPY",
        // A local module the program imports counts too.
        "python3 - <<'PY'\nimport pkg.stopper\nPY",
        // So does a module it imports by a constant name, and one whose
        // name reaches signals through an alias.
        "python3 - <<'PY'\nimport pkg.lazylocal\nPY",
        "python3 - <<'PY'\nimport pkg.lazystop\nPY",
        "python3 - <<'PY'\nimport pkg.lazyremote\nPY",
        // A docstring the program reads back is a string like any other.
        "python3 - <<'PY'\nimport pkg.docpath\nprint(open(pkg.docpath.__doc__).read())\nPY",
        "python3 - <<'EOF'\n\"\"\"/etc/passwd\"\"\"\nprint(open(__doc__).read())\nEOF",
        "python3 - <<'EOF'\nimport importlib\nsock = importlib.import_module('socket')\nprint(sock.gethostname())\nEOF",
        // Every command of a command line, past wrapper option values and
        // nested shells, and paths spelled with escapes, joined literals or
        // formatted strings.
        "python3 - <<'PY'\nimport os\nos.system('true; pkill gdm')\nPY",
        "python3 - <<'PY'\nprint(open(\"\\x2fetc/passwd\").read())\nPY",
        "python3 - <<'PY'\nimport os\nprint(os.listdir('pkg/../..'))\nPY",
        "python3 - <<'PY'\nimport os\nos.system('env -u DISPLAY kill -TERM 4242')\nPY",
        "python3 - <<'PY'\nimport os\nos.system('sh -c \"kill 1\"')\nPY",
        "python3 - <<'PY'\np = '/' 'etc/passwd'\nprint(open(p).read())\nPY",
        "python3 - <<'PY'\npart = 'etc'\nprint(open(f'/{part}/passwd').read())\nPY",
        // A dotted import runs each enclosing package's `__init__.py` first.
        "python3 - <<'PY'\nimport nested.inner.leaf\nPY",
        "python3 - <<'PY'\nfrom nested.inner import leaf\nPY",
        "python3 - <<'PY'\nm = __import__('nested.inner.leaf')\nPY",
        "python3 - <<'PY'\nimport shadow\nPY",
        "python3 - <<'PY'\nm = __import__('shadow')\nPY",
        "python3 - <<'PY'\nm = __import__('caf\u{e9}')\nPY",
        "python3 - <<'PY'\np = __import__('subprocess').os\np.kill(4242, 15)\nPY",
        "python3 - <<'PY'\nfrom importlib import import_module as load\nimport_module = lambda _: load('o' + 's')\np = import_module('json')\np.kill(4242, 15)\nPY",
        "python3 - <<'PY'\ndef f():\n    '../secret.txt'\nprint(open(f.__code__.co_consts[0]).read())\nPY",
        "python3 - <<'PY'\ndef f():\n    '../secret.txt'\nprint(open(getattr(f, '__d' 'oc__')).read())\nPY",
    ] {
        let (action, _) = outcome(&root, command);
        assert!(
            action != "allow" && action != "sandbox-required",
            "{command}: {action}"
        );
    }
}

#[test]
fn a_probe_whose_local_imports_are_not_all_read_keeps_its_review() {
    let (root, _cleanup) = checkout("wide");
    let imports: String = (0..40)
        .map(|index| format!("import wide.m{index}\n"))
        .collect();
    let command = format!("python3 - <<'PY'\n{imports}print(1)\nPY");
    let (action, _) = outcome(&root, &command);
    assert!(
        action != "allow" && action != "sandbox-required",
        "{command}: {action}"
    );
}
