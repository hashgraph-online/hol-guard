use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, UNIX_EPOCH};

use serde_json::{json, Value};

use super::super::context::{Ctx, Engines, LocalExecution};
use super::super::launch::launch_identity;
use super::python_script;

/// The interpreter a project's `py` directory holds, launched as `name`.
fn interpreter(cwd: &str, name: &str) -> Value {
    json!({
        "file_format": "native",
        "launch_path": format!("{cwd}/py/bin/{name}"),
        "path": format!("{cwd}/py/bin/python3.12"),
    })
}

struct Fixed;

impl Engines for Fixed {
    fn launch_identity(
        &self,
        executable: &str,
        args: &[String],
        cwd: &str,
        _home: Option<&str>,
        _env: &BTreeMap<String, String>,
    ) -> Value {
        let name = Path::new(executable).file_name().unwrap().to_str().unwrap();
        json!({"executable": interpreter(cwd, name), "args": args})
    }

    fn launch_reusable(&self, _identity: &Value) -> bool {
        true
    }

    fn local_executions(
        &self,
        _command: &str,
        _cwd: &str,
        _home: Option<&str>,
        _env: &BTreeMap<String, String>,
    ) -> Option<Vec<LocalExecution>> {
        None
    }
}

/// A project below the target directory: macOS `$TMPDIR` resolves under
/// `/private/var`, which the sensitive-path screen rejects. It holds an
/// interpreter installation in `py` and an empty home in `home`.
struct Project(PathBuf);

impl Project {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/python-script-tests")
            .join(format!(
                "p-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(&root).unwrap();
        let project = Self(root.canonicalize().unwrap());
        project.write("py/bin/python3.12", "");
        // Explicit source stubs for this synthetic interpreter, not a claim
        // that a standard module name proves an installed implementation.
        for name in [
            "__future__",
            "functools",
            "json",
            "os",
            "pathlib",
            "textwrap",
        ] {
            project.write(&format!("py/lib/python3.12/{name}.py"), "");
        }
        std::fs::create_dir_all(project.0.join(SITE)).unwrap();
        std::fs::create_dir_all(project.0.join("home")).unwrap();
        project
    }

    fn write(&self, relative: &str, text: &str) {
        self.write_bytes(relative, text.as_bytes());
    }

    fn write_bytes(&self, relative: &str, bytes: &[u8]) {
        let path = self.0.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn cwd(&self) -> &str {
        self.0.to_str().unwrap()
    }

    fn home(&self) -> String {
        format!("{}/home", self.cwd())
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const SITE: &str = "py/lib/python3.12/site-packages";

fn bind(project: &Project, args: &[&str], env: &[(&str, &str)]) -> Result<Value, &'static str> {
    bind_with(project, args, env, &interpreter(project.cwd(), "python3"))
}

fn bind_with(
    project: &Project,
    args: &[&str],
    env: &[(&str, &str)],
    executable: &Value,
) -> Result<Value, &'static str> {
    let env: BTreeMap<String, String> = env
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect();
    let home = project.home();
    let ctx = Ctx {
        home: Some(&home),
        env: &env,
        deadline: Instant::now() + Duration::from_secs(10),
        engines: &Fixed,
    };
    let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    python_script(&args, project.cwd(), &ctx, executable, &[])
}

fn launch(project: &Project, command: &str) -> Result<Value, &'static str> {
    let env = BTreeMap::new();
    let home = project.home();
    let ctx = Ctx {
        home: Some(&home),
        env: &env,
        deadline: Instant::now() + Duration::from_secs(10),
        engines: &Fixed,
    };
    launch_identity(command, project.cwd(), &ctx)
}

/// A 16-byte `.pyc` header with `flags`, then the source's modification
/// second and size for a timestamp file.
fn pyc(flags: u32, seconds: u32, size: u32, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::from(*b"\xcb\r\r\n");
    for word in [flags, seconds, size] {
        bytes.extend(word.to_le_bytes());
    }
    bytes.extend(body);
    bytes
}

fn report_project() -> Project {
    let project = Project::new();
    project.write(
        "scripts/report.py",
        "#!/usr/bin/env python3\n\"\"\"Summarize rows; the system never evaluates input.\"\"\"\nfrom __future__ import annotations\n\nimport json, os\nfrom pathlib import Path\n\nimport helpers\nfrom lib import fmt\nfrom lib.totals import total\n\n\ndef main() -> None:\n    rows = json.loads(Path(os.path.join('data', 'rows.json')).read_text())\n    print(f\"{fmt.label(rows['name'])}: {total(rows['values'])}\", helpers.VERSION)\n\n\nif __name__ == '__main__':\n    main()\n",
    );
    project.write("scripts/helpers.py", "VERSION = '1.0'\n");
    project.write("scripts/lib/__init__.py", "");
    project.write(
        "scripts/lib/fmt.py",
        "import textwrap\n\n\ndef label(name):\n    return textwrap.shorten(name, 20)\n",
    );
    project.write(
        "scripts/lib/totals.py",
        "from .fmt import label\n\n\ndef total(values):\n    return sum(values)\n",
    );
    project
}

fn module_paths(bound: &Value) -> Vec<String> {
    bound["modules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|module| module["path"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn a_script_binds_local_and_standard_modules_by_content() {
    let project = report_project();
    let bound = bind(&project, &["scripts/report.py"], &[]).unwrap();
    let root = project.cwd();
    assert_eq!(bound["script"], format!("{root}/scripts/report.py"));
    assert_eq!(
        module_paths(&bound),
        [
            format!("{root}/scripts/helpers.py"),
            format!("{root}/scripts/lib/__init__.py"),
            format!("{root}/scripts/lib/fmt.py"),
            format!("{root}/scripts/lib/totals.py"),
            format!("{root}/scripts/report.py"),
        ]
    );
    assert_eq!(
        bound["standard"],
        json!(["__future__", "json", "os", "pathlib", "textwrap"])
    );
    assert_eq!(bound["runtime_modules"].as_array().unwrap().len(), 5);
    project.write("py/lib/python3.12/json.py", "VERSION = 2\n");
    let runtime_changed = bind(&project, &["scripts/report.py"], &[]).unwrap();
    assert_ne!(runtime_changed["runtime_modules"], bound["runtime_modules"]);
    project.write("py/lib/python3.12/json.py", "");
    // A standard alias is not a source package. Preserve the old form as
    // explicit uncertainty until its runtime alias can be proved.
    project.write("alias.py", "import os.path\n");
    assert_eq!(
        bind(&project, &["alias.py"], &[]),
        Err("python_runtime_module_unproven")
    );
    assert_eq!(
        bind(&project, &["-u", "-B", "scripts/report.py"], &[]).unwrap()["modules"],
        bound["modules"]
    );

    project.write("scripts/helpers.py", "VERSION = '2.0'\n");
    let edited = bind(&project, &["scripts/report.py"], &[]).unwrap();
    assert_ne!(edited["modules"], bound["modules"]);
}

#[test]
fn runtime_imports_bind_both_startup_and_project_shadow_candidates() {
    let project = Project::new();
    project.write("tool.py", "import colorsys\n");
    project.write("calendar.py", "VALUE = 'local'\n");
    project.write("py/lib/python3.12/colorsys.py", "import calendar\n");
    project.write("py/lib/python3.12/calendar.py", "VALUE = 'first'\n");
    let before = bind(&project, &["tool.py"], &[]).unwrap();
    assert!(module_paths(&before)
        .iter()
        .any(|path| path.ends_with("/calendar.py")));
    assert_eq!(before["runtime_modules"].as_array().unwrap().len(), 2);
    project.write("py/lib/python3.12/calendar.py", "VALUE = 'other'\n");
    let installed_changed = bind(&project, &["tool.py"], &[]).unwrap();
    assert_ne!(
        before["runtime_modules"],
        installed_changed["runtime_modules"]
    );
    project.write("calendar.py", "VALUE = 'other'\n");
    let local_changed = bind(&project, &["tool.py"], &[]).unwrap();
    assert_ne!(installed_changed["modules"], local_changed["modules"]);
}

#[test]
fn bytecode_python_runs_in_place_of_a_local_module_is_bound() {
    let project = report_project();
    let before = bind(&project, &["scripts/report.py"], &[]).unwrap();
    assert_eq!(before["bytecode"], json!([]));
    let source = std::fs::metadata(project.0.join("scripts/helpers.py")).unwrap();
    let seconds = source
        .modified()
        .unwrap()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let size = source.len() as u32;
    let cached = "scripts/__pycache__/helpers.cpython-312.pyc";

    // Python skips a short file and a stale timestamp, and writes a fresh one.
    project.write(cached, "one");
    assert_eq!(bind(&project, &["scripts/report.py"], &[]).unwrap(), before);
    project.write_bytes(cached, &pyc(0, seconds.wrapping_add(1), size, b"one"));
    assert_eq!(bind(&project, &["scripts/report.py"], &[]).unwrap(), before);

    project.write_bytes(cached, &pyc(0, seconds, size, b"one"));
    let current = bind(&project, &["scripts/report.py"], &[]).unwrap();
    assert_eq!(current["bytecode"].as_array().unwrap().len(), 1);
    project.write_bytes(cached, &pyc(0, seconds, size, b"two"));
    let replaced = bind(&project, &["scripts/report.py"], &[]).unwrap();
    assert_ne!(replaced["bytecode"], current["bytecode"]);
    // Bit 1 alone still marks a timestamp file.
    project.write_bytes(cached, &pyc(2, seconds, size, b"two"));
    let flagged = bind(&project, &["scripts/report.py"], &[]).unwrap();
    assert_eq!(flagged["bytecode"].as_array().unwrap().len(), 1);
    project.write_bytes(cached, &pyc(1, 0, 0, b"two"));
    let hashed = bind(&project, &["scripts/report.py"], &[]).unwrap();
    assert_eq!(hashed["bytecode"].as_array().unwrap().len(), 1);
    assert_ne!(hashed["bytecode"], replaced["bytecode"]);
}

#[test]
fn a_module_beside_the_script_shadows_the_standard_one() {
    let project = Project::new();
    project.write("tool.py", "import json\nprint(json.dumps(1))\n");
    project.write("json.py", "def dumps(value):\n    return str(value)\n");
    let bound = bind(&project, &["tool.py"], &[]).unwrap();
    assert_eq!(module_paths(&bound).len(), 2);
    assert_eq!(bound["standard"], json!([]));
    // Without the script's directory on the module path, the standard one loads.
    let isolated = bind(&project, &["-I", "tool.py"], &[]).unwrap();
    assert_eq!(module_paths(&isolated).len(), 1);
    assert_eq!(isolated["standard"], json!(["json"]));
    // `PYTHONSAFEPATH` does the same, unless `-E` makes Python ignore it.
    let safe = bind(&project, &["tool.py"], &[("PYTHONSAFEPATH", "1")]).unwrap();
    assert_eq!(safe["standard"], json!(["json"]));
    let ignored = bind(&project, &["-E", "tool.py"], &[("PYTHONSAFEPATH", "1")]).unwrap();
    assert_eq!(module_paths(&ignored).len(), 2);
    assert_eq!(ignored["standard"], json!([]));
}

#[test]
fn a_symlinked_script_imports_beside_its_target() {
    let project = Project::new();
    let root = project.cwd();
    project.write("real/tool.py", "import json\nprint(json.dumps(1))\n");
    project.write("real/json.py", "def dumps(value):\n    return str(value)\n");
    project.write(
        "link/json.py",
        "def dumps(value):\n    return repr(value)\n",
    );
    std::os::unix::fs::symlink("../real/tool.py", project.0.join("link/run.py")).unwrap();
    let bound = bind(&project, &["link/run.py"], &[]).unwrap();
    assert_eq!(bound["script"], format!("{root}/real/tool.py"));
    assert_eq!(
        module_paths(&bound),
        [
            format!("{root}/real/json.py"),
            format!("{root}/real/tool.py")
        ]
    );
}

#[test]
fn writes_cannot_replace_bound_runtime_modules() {
    let project = Project::new();
    project.write(
        "gen.py",
        "import json\nfrom pathlib import Path\n\nPath('out').mkdir(exist_ok=True)\nwith open('out/data.json', 'w') as handle:\n    json.dump({'ok': True}, handle)\n",
    );
    // A script whose directory is on the module path could create a module
    // there that shadows a standard one.
    assert_eq!(bind(&project, &["gen.py"], &[]), Err("mutable_launcher"));
    // Safe-path mode removes project shadowing, but cannot stop a write
    // replacing a bound installed implementation before it is imported.
    assert_eq!(
        bind(&project, &["-P", "gen.py"], &[]),
        Err("mutable_launcher")
    );
    // Reading files is not writing them.
    project.write(
        "read.py",
        "import json\nfrom pathlib import Path\n\nwith open('in.json') as a, open('in.json', 'rb') as b, Path('x').open(encoding='utf-8') as c:\n    print(json.load(a), b.read(), c.read())\n",
    );
    assert!(bind(&project, &["read.py"], &[]).is_ok());
    // A path class reached in one module moves a file through a
    // two-argument `replace` in another.
    project.write("paths.py", "from pathlib import Path as P\n");
    project.write("swap.py", "from paths import P\nP.replace(a, b)\n");
    assert_eq!(bind(&project, &["swap.py"], &[]), Err("mutable_launcher"));
    project.write(
        "names.py",
        "from pathlib import Path\n\nname = 'a-b'.replace('-', '_')\nprint(Path(name))\n",
    );
    assert!(bind(&project, &["names.py"], &[]).is_ok());
}

#[test]
fn code_the_graph_cannot_bind_keeps_the_launch_once_only() {
    for (files, args) in [
        (vec![("t.py", "import requests\n")], vec!["t.py"]),
        (vec![("t.py", "import subprocess\n")], vec!["t.py"]),
        (
            vec![("t.py", "from importlib import import_module\n")],
            vec!["t.py"],
        ),
        (vec![("t.py", "import os\nos.system('ls')\n")], vec!["t.py"]),
        (vec![("t.py", "exec(input())\n")], vec!["t.py"]),
        (vec![("t.py", "from . import x\n")], vec!["t.py"]),
        (vec![("t.py", "import helpers\n")], vec!["-I", "t.py"]),
        (
            vec![("t.py", "import helpers\n"), ("helpers.py", "eval('1')\n")],
            vec!["t.py"],
        ),
        (
            vec![
                ("t.py", "import helpers\n"),
                ("helpers.py", "X = 1\n"),
                ("helpers.cpython-312-darwin.so", ""),
            ],
            vec!["t.py"],
        ),
        (
            vec![("t.py", "import json\n"), ("json.pyc", "")],
            vec!["t.py"],
        ),
        (
            vec![
                (
                    "t.py",
                    "import helpers\nopen('helpers.py', 'w').write('X = 2')\n",
                ),
                ("helpers.py", "X = 1\n"),
            ],
            vec!["t.py"],
        ),
        (
            vec![("t.py", "import pkg\n"), ("pkg/mod.py", "")],
            vec!["t.py"],
        ),
        (
            vec![
                ("t.py", "import pkg.sub\n"),
                ("pkg/__init__.py", "from .. import t\n"),
                ("pkg/sub.py", ""),
            ],
            vec!["t.py"],
        ),
        (vec![("t.py", "print(1)\n")], vec!["-c", "print(1)"]),
        // `-x` skips the first line, so a literal the scan reads becomes code.
        (
            vec![(
                "t.py",
                "s = \"\"\"\nexec(open('payload').read())\n#\"\"\"\n",
            )],
            vec!["-x", "t.py"],
        ),
        (vec![("t.py", "from logging import config\n")], vec!["t.py"]),
        (vec![("t.py", "import logging.config\n")], vec!["t.py"]),
        (vec![("t.py", "from unittest import mock\n")], vec!["t.py"]),
        (vec![("t.py", "import unittest.mock as m\n")], vec!["t.py"]),
        (vec![("t.py", "print(1)\n")], vec!["-m", "t"]),
        (vec![("t.py", "print(1)\n")], vec!["-W", "error", "t.py"]),
        (vec![("t.py", "print(1)\n")], vec!["-X", "dev", "t.py"]),
        (vec![("t.py", "print(1)\n")], vec!["-i", "t.py"]),
        (vec![("t.py", "print(1)\n")], vec!["--", "t.py"]),
        (vec![("t.py", "print(1)\n")], vec!["-"]),
        (vec![("t.py", "print(1)\n")], vec![]),
        (vec![("t.py", "print(1)\n")], vec!["missing.py"]),
        (vec![("t.txt", "print(1)\n")], vec!["t.txt"]),
    ] {
        let project = Project::new();
        for (path, text) in &files {
            project.write(path, text);
        }
        assert_eq!(
            bind(&project, &args, &[]),
            Err("mutable_launcher"),
            "{files:?} {args:?}"
        );
    }
    let project = Project::new();
    project.write("t.py", "print(1)\n");
    for name in [
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONWARNINGS",
        "PYTHONPYCACHEPREFIX",
        "pythonpath",
    ] {
        assert_eq!(
            bind(&project, &["t.py"], &[(name, "x")]),
            Err("mutable_launcher"),
            "{name}"
        );
    }
    assert!(bind(&project, &["t.py"], &[("PYTHONPATH", "")]).is_ok());
    assert!(bind(&project, &["-OO", "-uB", "t.py", "--flag"], &[]).is_ok());
}

#[test]
fn metadata_only_python_images_cannot_get_a_closed_launch_identity() {
    let project = report_project();
    for command in [
        "python3 scripts/report.py",
        "python scripts/report.py",
        "python3.12 scripts/report.py",
    ] {
        assert_eq!(
            launch(&project, command),
            Err("python_runtime_bootstrap_unproven")
        );
    }
    assert_eq!(launch(&project, "python3 -c 1"), Err("mutable_launcher"));
    assert_eq!(
        launch(&project, "cd scripts && python3 report.py"),
        Err("compound_command")
    );
}

#[path = "python_startup_tests.rs"]
mod startup;
