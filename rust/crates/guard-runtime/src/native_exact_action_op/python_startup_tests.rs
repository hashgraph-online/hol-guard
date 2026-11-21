//! Binding the code Python's `site` module runs before a script.

use serde_json::{json, Value};

use super::{bind, bind_with, Project, SITE};

fn startup_paths(bound: &Value) -> Vec<String> {
    bound["startup"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| file["path"].as_str().unwrap().to_owned())
        .collect()
}

/// A site directory with setuptools' `.pth` hook, its package, a path
/// entry and a `sitecustomize`.
fn site_project() -> Project {
    let project = Project::new();
    project.write("tool.py", "import json\nprint(json.dumps(1))\n");
    project.write(
        &format!("{SITE}/distutils-precedence.pth"),
        "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \n",
    );
    project.write(
        &format!("{SITE}/_distutils_hack/__init__.py"),
        "def add_shim():\n    pass\n",
    );
    project.write(&format!("{SITE}/_distutils_hack/override.py"), "");
    project.write(&format!("{SITE}/extra.pth"), "# comment\nextra\n");
    project.write(&format!("{SITE}/extra/sitecustomize.py"), "X = 1\n");
    project
}

#[test]
fn code_site_runs_before_the_script_is_bound() {
    let project = site_project();
    let site = format!("{}/{SITE}", project.cwd());
    let bound = bind(&project, &["tool.py"], &[]).unwrap();
    assert_eq!(
        startup_paths(&bound),
        [
            format!("{site}/_distutils_hack/__init__.py"),
            format!("{site}/distutils-precedence.pth"),
            format!("{site}/extra.pth"),
            format!("{site}/extra/sitecustomize.py"),
        ]
    );

    project.write(&format!("{SITE}/extra/sitecustomize.py"), "X = 2\n");
    let customized = bind(&project, &["tool.py"], &[]).unwrap();
    assert_ne!(customized["startup"], bound["startup"]);
    project.write(&format!("{SITE}/extra.pth"), "extra\n");
    let extended = bind(&project, &["tool.py"], &[]).unwrap();
    assert_ne!(extended["startup"], customized["startup"]);

    // `-S` skips `site`, so nothing in a site directory runs.
    project.write(&format!("{SITE}/sitecustomize.pyc"), "");
    assert_eq!(
        bind(&project, &["-S", "tool.py"], &[]).unwrap()["startup"],
        json!([])
    );
}

#[test]
fn startup_sources_bind_what_they_import() {
    let project = Project::new();
    let site = format!("{}/{SITE}", project.cwd());
    project.write("tool.py", "print(1)\n");
    project.write(&format!("{SITE}/sitecustomize.py"), "import helper\n");
    project.write(&format!("{SITE}/helper.py"), "X = 1\n");
    project.write(&format!("{SITE}/hook.pth"), "import pkg.sub\n");
    project.write(&format!("{SITE}/pkg/__init__.py"), "");
    project.write(
        &format!("{SITE}/pkg/sub/__init__.py"),
        "from . import leaf\n",
    );
    project.write(&format!("{SITE}/pkg/sub/leaf.py"), "");
    let bound = bind(&project, &["tool.py"], &[]).unwrap();
    assert_eq!(
        startup_paths(&bound),
        [
            format!("{site}/helper.py"),
            format!("{site}/hook.pth"),
            format!("{site}/pkg/__init__.py"),
            format!("{site}/pkg/sub/__init__.py"),
            format!("{site}/pkg/sub/leaf.py"),
            format!("{site}/sitecustomize.py"),
        ]
    );
    project.write(&format!("{SITE}/helper.py"), "X = 2\n");
    let edited = bind(&project, &["tool.py"], &[]).unwrap();
    assert_ne!(edited["startup"], bound["startup"]);

    // Startup code that evaluates or writes is not bound by its text.
    for text in [
        "exec(open('x').read())\n",
        "open('x', 'w').write('')\n",
        "import missing\n",
    ] {
        project.write(&format!("{SITE}/sitecustomize.py"), text);
        assert_eq!(
            bind(&project, &["tool.py"], &[]),
            Err("mutable_launcher"),
            "{text}"
        );
    }
}

#[test]
fn a_virtualenv_shim_is_bound_by_content() {
    let project = Project::new();
    let site = format!("{}/{SITE}", project.cwd());
    project.write("tool.py", "print(1)\n");
    project.write(&format!("{SITE}/_virtualenv.pth"), "import _virtualenv\n");
    let shim = concat!(
        "import sys\nfrom functools import partial\n\n",
        "_DISTUTILS_PATCH = 'distutils.dist', 'setuptools.dist'\n\n",
        "class _Finder:\n",
        "    def find_spec(self, fullname, path, target=None):\n",
        "        if fullname in _DISTUTILS_PATCH:\n",
        "            from importlib.util import find_spec\n",
        "            spec = find_spec(fullname, path)\n",
        "            old = getattr(spec.loader, 'exec_module')\n",
        "            setattr(spec.loader, 'exec_module', partial(self.exec_module, old))\n",
        "            return spec\n\n",
        "    @staticmethod\n",
        "    def exec_module(old, module):\n",
        "        old(module)\n\n",
        "sys.meta_path.insert(0, _Finder())\n",
    );
    project.write(&format!("{SITE}/_virtualenv.py"), shim);
    let bound = bind(&project, &["tool.py"], &[]).unwrap();
    assert_eq!(
        startup_paths(&bound),
        [
            format!("{site}/_virtualenv.pth"),
            format!("{site}/_virtualenv.py"),
        ]
    );

    // The shim redirects distutils, so a local copy is not what runs.
    project.write("tool.py", "import distutils\n");
    project.write("distutils.py", "");
    assert_eq!(bind(&project, &["tool.py"], &[]), Err("mutable_launcher"));
    project.write(&format!("{SITE}/_virtualenv.pth"), "# off\n");
    assert!(bind(&project, &["tool.py"], &[]).is_ok());
    project.write(&format!("{SITE}/_virtualenv.pth"), "import _virtualenv\n");

    project.write("tool.py", "print(1)\n");
    // A function may load a redirected package; code that runs on import
    // binds what it loads.
    let loader =
        "import importlib\ndef load():\n    importlib.import_module('setuptools._distutils')\n";
    let method = "def spec_for(self, name):\n    return 'spec_for_{name}'.format(**locals())\n";
    project.write(
        &format!("{SITE}/_virtualenv.py"),
        &format!("{shim}{loader}{method}"),
    );
    assert!(bind(&project, &["tool.py"], &[]).is_ok());
    // A method named for a redirected package runs only when that package
    // is imported, so a finder may dispatch to it by name.
    let dispatched = |name: &str, call: &str, target: &str| {
        format!(
            "{shim}import importlib\nclass Finder:\n    def find_spec(self, fullname, path, target=None):\n        {name}\n        return getattr(self, {call})()\n    def {target}(self):\n        importlib.import_module('setuptools')\n"
        )
    };
    let finder = |name: &str, target: &str| dispatched(name, "method_name", target);
    let formed = "method_name = 'spec_for_{fullname}'.format(**locals())";
    project.write(
        &format!("{SITE}/_virtualenv.py"),
        &finder(formed, "spec_for_distutils"),
    );
    assert!(bind(&project, &["tool.py"], &[]).is_ok());
    project.write(
        &format!("{SITE}/_virtualenv.py"),
        &format!("{shim}import importlib\nimportlib.import_module('setuptools._distutils')\n"),
    );
    assert_eq!(bind(&project, &["tool.py"], &[]), Err("mutable_launcher"));
    project.write(&format!("{SITE}/setuptools/__init__.py"), "");
    project.write(&format!("{SITE}/setuptools/_distutils.py"), "X = 1\n");
    let bound = bind(&project, &["tool.py"], &[]).unwrap();
    assert!(startup_paths(&bound).contains(&format!("{site}/setuptools/_distutils.py")));
    // Nothing but the shim may call a loader.
    project.write(
        &format!("{SITE}/_virtualenv.py"),
        &format!("{shim}{loader}"),
    );
    project.write(
        &format!("{SITE}/_virtualenv.pth"),
        "import _virtualenv; _virtualenv.load()\n",
    );
    assert_eq!(bind(&project, &["tool.py"], &[]), Err("mutable_launcher"));
    project.write(&format!("{SITE}/_virtualenv.pth"), "import _virtualenv\n");
    // Names that could load code the proof does not bind.
    for text in [
        format!("{shim}open('x').read()\n"),
        format!("{shim}import subprocess\n"),
        format!("{shim}__import__('helper')\n"),
        format!("{shim}import importlib\nimportlib.import_module('payload')\n"),
        format!("{shim}import importlib\nload = importlib.import_module\n"),
        format!("{shim}from importlib.util import find_spec\nfind_spec('payload').loader.exec_module(None)\n"),
        format!("{shim}import builtins\n"),
        format!("{shim}getattr(sys, 'modules')\n"),
        format!("{shim}import os\nos.rename('a.py', 'b.py')\n"),
        format!("{shim}import os\nos.execv('/bin/sh', ['sh'])\n"),
        format!("{shim}sys.path.insert(0, 'payload')\n"),
        format!("{shim}names = locals()\n"),
        format!("{shim}import importlib\ndef load():\n    importlib.import_module('payload')\n"),
        format!("{shim}import importlib\ndef load():\n    importlib.import_module('setuptools')\nload()\n"),
        format!(
            "{shim}import importlib\nclass Finder:\n    def find_spec(self, name, path, target=None):\n        return self.load()\n    def load(self):\n        importlib.import_module('setuptools')\n"
        ),
        finder("method_name = 'load'", "load"),
        finder("method_name = 'spec_for_distutils'", "spec_for_distutils"),
        finder(formed, "spec_for_payload"),
        finder("method_name = f'spec_for_{fullname}'", "spec_for_payload"),
        finder(&format!("{formed}; fullname = 'payload'"), "spec_for_distutils"),
        finder(&format!("\"\"\"{formed}\"\"\"; method_name = 'load'"), "spec_for_x"),
        dispatched(formed, "method_name.replace('json', 'distutils')", "spec_for_distutils"),
        dispatched(formed, "method_name[:-1]", "spec_for_distutils"),
        dispatched(formed, "method_name + 's'", "spec_for_distutils"),
    ] {
        project.write(&format!("{SITE}/_virtualenv.py"), &text);
        assert_eq!(
            bind(&project, &["tool.py"], &[]),
            Err("mutable_launcher"),
            "{text}"
        );
    }
}

#[test]
fn a_shim_binds_the_modules_it_imports() {
    let project = site_project();
    let site = format!("{}/{SITE}", project.cwd());
    project.write(
        &format!("{SITE}/_distutils_hack/__init__.py"),
        "import _distutils_hack.payload\n\ndef add_shim():\n    pass\n",
    );
    project.write(&format!("{SITE}/_distutils_hack/payload.py"), "X = 1\n");
    let bound = bind(&project, &["tool.py"], &[]).unwrap();
    assert!(startup_paths(&bound).contains(&format!("{site}/_distutils_hack/payload.py")));
    project.write(&format!("{SITE}/_distutils_hack/payload.py"), "X = 2\n");
    let edited = bind(&project, &["tool.py"], &[]).unwrap();
    assert_ne!(edited["startup"], bound["startup"]);
    project.write(
        &format!("{SITE}/_distutils_hack/payload.py"),
        "exec(open('x').read())\n",
    );
    assert_eq!(bind(&project, &["tool.py"], &[]), Err("mutable_launcher"));
}

#[test]
fn a_virtual_environment_reads_its_own_site_directory() {
    let project = Project::new();
    let root = project.cwd();
    project.write("tool.py", "print(1)\n");
    project.write(
        "venv/pyvenv.cfg",
        &format!("home = {root}/py/bin\ninclude-system-site-packages = false\n"),
    );
    project.write("venv/bin/python", "");
    project.write(
        "venv/lib/python3.12/site-packages/sitecustomize.py",
        "X = 1\n",
    );
    // The base site directory is outside this environment.
    project.write(&format!("{SITE}/sitecustomize.so"), "");
    let executable = json!({
        "file_format": "native",
        "launch_path": format!("{root}/venv/bin/python"),
        "path": format!("{root}/py/bin/python3.12"),
    });
    let bound = bind_with(&project, &["tool.py"], &[], &executable).unwrap();
    assert_eq!(
        startup_paths(&bound),
        [format!(
            "{root}/venv/lib/python3.12/site-packages/sitecustomize.py"
        )]
    );
    project.write(
        "venv/pyvenv.cfg",
        &format!("home = {root}/py/bin\ninclude-system-site-packages = true\n"),
    );
    assert_eq!(
        bind_with(&project, &["tool.py"], &[], &executable),
        Err("mutable_launcher")
    );
}

#[test]
fn startup_code_the_proof_cannot_bind_keeps_the_launch_once_only() {
    for (path, text) in [
        (format!("{SITE}/sitecustomize.pyc"), ""),
        (format!("{SITE}/sitecustomize/__init__.py"), ""),
        (format!("{SITE}/hook.pth"), "import missing_hook\n"),
        (format!("{SITE}/hook.pth"), "import subprocess\n"),
        (format!("{SITE}/hook.pth"), "import os; os.system('id')\n"),
        (
            format!("{SITE}/hook.pth"),
            "import os\rimport missing_hook\n",
        ),
        (format!("{SITE}/json.py"), ""),
        ("py/lib/python3.12/usercustomize.pyc".to_owned(), ""),
        (
            "home/.local/lib/python3.12/site-packages/usercustomize.so".to_owned(),
            "",
        ),
    ] {
        let project = Project::new();
        project.write("tool.py", "import json\n");
        project.write(&path, text);
        assert_eq!(
            bind(&project, &["tool.py"], &[]),
            Err("mutable_launcher"),
            "{path}"
        );
    }

    // The user site is skipped with `-s` or `PYTHONNOUSERSITE`.
    let project = Project::new();
    project.write("tool.py", "import json\n");
    project.write(
        "home/.local/lib/python3.12/site-packages/usercustomize.so",
        "",
    );
    assert!(bind(&project, &["-s", "tool.py"], &[]).is_ok());
    assert!(bind(&project, &["tool.py"], &[("PYTHONNOUSERSITE", "1")]).is_ok());
    assert!(bind(&project, &["-E", "tool.py"], &[("PYTHONNOUSERSITE", "1")]).is_err());

    // An interpreter whose standard library the proof cannot place.
    let root = project.cwd();
    for executable in [
        json!({"file_format": "script", "launch_path": format!("{root}/py/bin/python3"), "path": format!("{root}/py/bin/python3.12")}),
        json!({"file_format": "native", "launch_path": "python3", "path": format!("{root}/py/bin/python3.12")}),
        json!({"file_format": "unverified", "launch_path": format!("{root}/py/bin/python3"), "path": format!("{root}/py/bin/python3.12")}),
    ] {
        assert_eq!(
            bind_with(&project, &["-s", "tool.py"], &[], &executable),
            Err("python_runtime_module_unproven"),
            "{executable}"
        );
    }
}
