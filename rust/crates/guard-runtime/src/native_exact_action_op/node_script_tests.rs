use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::super::context::{Ctx, Engines, LocalExecution};
use super::super::launch::launch_identity;
use super::node_script;
#[path = "node_installed_tests.rs"]
mod installed_tests;

struct Fixed;

impl Engines for Fixed {
    fn launch_identity(
        &self,
        executable: &str,
        args: &[String],
        _cwd: &str,
        _home: Option<&str>,
        _env: &BTreeMap<String, String>,
    ) -> Value {
        json!({"executable": executable, "args": args})
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
/// `/private/var`, which the sensitive-path screen rejects.
struct Project(PathBuf);

impl Project {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/node-script-tests")
            .join(format!(
                "p-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(&root).unwrap();
        Self(root.canonicalize().unwrap())
    }

    fn write(&self, relative: &str, text: &str) {
        let path = self.0.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn cwd(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn bind(project: &Project, args: &[&str], env: &[(&str, &str)]) -> Result<Value, &'static str> {
    let env: BTreeMap<String, String> = env
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect();
    let ctx = Ctx {
        home: None,
        env: &env,
        deadline: Instant::now() + Duration::from_secs(10),
        engines: &Fixed,
    };
    let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    node_script(&args, project.cwd(), &ctx)
}

fn launch(project: &Project, command: &str) -> Result<Value, &'static str> {
    let env = BTreeMap::new();
    let ctx = Ctx {
        home: None,
        env: &env,
        deadline: Instant::now() + Duration::from_secs(10),
        engines: &Fixed,
    };
    launch_identity(command, project.cwd(), &ctx)
}

fn report_project() -> Project {
    let project = Project::new();
    project.write("package.json", r#"{"type": "module"}"#);
    project.write(
        "scripts/report.mjs",
        "#!/usr/bin/env node\nimport { readFile } from 'node:fs/promises';\nimport path from \"path\";\nimport { total } from './lib/sum.mjs';\nimport config from './config.json' with { type: 'json' };\nimport { parse } from 'csv-lite';\nconst { format } = await import('./lib/format.mjs');\nconsole.log(import.meta.url, format(total([1, 2])), config, parse, path, readFile);\n",
    );
    project.write(
        "scripts/lib/sum.mjs",
        "export const total = (xs) => xs.reduce((a, b) => a + b, 0);\nexport class Tally {\n  constructor(rows) { this.rows = rows; }\n  at(i) { return this.rows[i + 1]; }\n}\n",
    );
    project.write(
        "scripts/lib/format.mjs",
        "export * from './sum.mjs';\nexport const format = String;\n",
    );
    project.write("scripts/config.json", "{\"limit\": 5}\n");
    // A package named after a builtin never stands in for it.
    project.write("node_modules/vm/package.json", r#"{"name": "vm"}"#);
    project.write(
        "node_modules/csv-lite/package.json",
        r#"{"name":"csv-lite","version":"1.0.0","type":"module","main":"index.js"}"#,
    );
    project.write(
        "node_modules/csv-lite/index.js",
        "export const parse = String;\n",
    );
    project
}

#[test]
fn a_script_binds_its_whole_module_graph() {
    let project = report_project();
    let bound = bind(&project, &["scripts/report.mjs", "--limit", "5"], &[]).unwrap();
    let modules: Vec<&str> = bound["modules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["path"].as_str().unwrap())
        .collect();
    assert_eq!(modules.len(), 4, "{bound}");
    assert!(modules.iter().any(|path| path.ends_with("lib/format.mjs")));
    assert_eq!(bound["builtins"], json!(["fs/promises", "path"]));
    assert_eq!(bound["packages"].as_array().unwrap().len(), 1);
    // The package scope and the imported JSON are both bound as data.
    assert_eq!(bound["data"].as_array().unwrap().len(), 3);

    // Editing a transitively imported module changes the identity.
    project.write("scripts/lib/sum.mjs", "export const total = () => 0;\n");
    let edited = bind(&project, &["scripts/report.mjs", "--limit", "5"], &[]).unwrap();
    assert_ne!(bound, edited);
    // So does reinstalling the package.
    project.write(
        "node_modules/csv-lite/package.json",
        r#"{"name": "csv-lite", "version": "1.0.1"}"#,
    );
    assert_ne!(
        edited,
        bind(&project, &["scripts/report.mjs", "--limit", "5"], &[]).unwrap()
    );
}

#[test]
fn installed_package_code_changes_identity_with_unchanged_manifest_size_and_mtime() {
    let project = Project::new();
    project.write("package.json", r#"{"type":"module"}"#);
    project.write(
        "report.mjs",
        "import value from 'local-report'; console.log(value);\n",
    );
    project.write(
        "node_modules/local-report/package.json",
        r#"{"name":"local-report","version":"1.0.0","type":"module","main":"index.js"}"#,
    );
    project.write(
        "node_modules/local-report/index.js",
        "export default 'safe';\n",
    );
    let before = bind(&project, &["report.mjs"], &[]).unwrap();
    let installed = project.0.join("node_modules/local-report/index.js");
    let metadata = std::fs::metadata(&installed).unwrap();
    project.write(
        "node_modules/local-report/index.js",
        "export default 'evil';\n",
    );
    std::fs::File::options()
        .write(true)
        .open(&installed)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(metadata.modified().unwrap()))
        .unwrap();
    assert_eq!(std::fs::metadata(&installed).unwrap().len(), metadata.len());
    assert_eq!(
        std::fs::metadata(&installed).unwrap().modified().unwrap(),
        metadata.modified().unwrap()
    );
    let after = bind(&project, &["report.mjs"], &[]).unwrap();
    assert_ne!(
        before, after,
        "installed executable bytes are part of the reviewed version"
    );
}

#[test]
fn a_commonjs_require_resolves_like_node() {
    let project = Project::new();
    project.write("tool.cjs", "const util = require('./util');\nconst os = require('os');\nconsole.log(util, os, require.main === module);\n");
    project.write("util.js", "module.exports = 1;\n");
    let bound = bind(&project, &["tool.cjs"], &[]).unwrap();
    assert_eq!(bound["modules"].as_array().unwrap().len(), 2, "{bound}");

    // A directory import resolves through its own manifest, which is not bound.
    project.write("dir.cjs", "require('./lib');\n");
    project.write("lib/index.js", "module.exports = 1;\n");
    assert_eq!(bind(&project, &["dir.cjs"], &[]), Err("mutable_launcher"));
}

#[test]
fn launches_that_load_unbound_code_stay_once_only() {
    let project = report_project();
    for (name, source) in [
        (
            "computed-import",
            "const name = process.argv[2];\nawait import(name);\n",
        ),
        ("template-import", "await import(`./lib/${x}.mjs`);\n"),
        ("template-from", "import x from `./a.mjs`;\n"),
        ("computed-require", "const r = require;\nr('./x');\n"),
        ("require-variable", "require(process.env.PLUGIN);\n"),
        ("eval", "eval(readFileSync('payload.js', 'utf8'));\n"),
        ("indirect-eval", "(0, globalThis.eval)('1');\n"),
        ("function", "new Function('return 1')();\n"),
        ("constructor", "(() => {}).constructor('return 1')();\n"),
        (
            "create-require",
            "import { createRequire } from 'node:module';\n",
        ),
        ("vm", "import vm from 'node:vm';\n"),
        ("module", "import 'module';\n"),
        ("shadowed-builtin", "import vm from 'vm';\n"),
        ("spawn", "import { execSync } from 'node:child_process';\n"),
        ("spawn-bare", "require('child_process');\n"),
        ("computed-global", "globalThis['ev' + 'al']('1');\n"),
        ("global-object", "global['ev' + 'al']('1');\n"),
        ("reflect", "Reflect.apply(f, null, []);\n"),
        ("constructor-property", "const C = f.constructor;\n"),
        ("wasm", "WebAssembly.instantiate(bytes);\n"),
        ("computed-index", "const C = f['constr' + 'uctor'];\n"),
        ("char-codes", "f[String.fromCharCode(99)];\n"),
        ("node-only-builtin", "import test from 'node:test';\n"),
        ("worker", "import { Worker } from 'node:worker_threads';\n"),
        ("worker-new", "new Worker('./w.js');\n"),
        ("builtin-module", "process.getBuiltinModule('vm');\n"),
        ("escape", "const r = \\u0072equire;\n"),
        ("arguments", "arguments[1]('./x');\n"),
        ("missing-relative", "import './gone.mjs';\n"),
        ("missing-package", "import 'not-installed';\n"),
        ("package-imports", "import x from '#internal';\n"),
        ("data-url", "import 'data:text/javascript,1';\n"),
        ("addon", "require('./native.node');\n"),
        ("from-comment", "import x from /* c */ './payload.mjs';\n"),
        (
            "from-line-comment",
            "export * from // c\n'./payload.mjs';\n",
        ),
        (
            "computed-module",
            "module[\"re\".concat(\"quire\")](\"./p.js\");\n",
        ),
        ("computed-process", "process['dlopen'](module, 'p.node');\n"),
        ("optional-process", "process?.binding('spawn_sync');\n"),
        ("comment-process", "process/**/.dlopen(m, 'p.node');\n"),
        ("execve", "process.execve('/bin/sh');\n"),
        ("process-alias", "const p = process;\np[name]('x');\n"),
        ("process-destructure", "const { binding } = process;\n"),
        ("process-argument", "run(process);\n"),
        ("module-alias", "const m = module;\nm[key]('./p.js');\n"),
        (
            "renamed-process",
            "import p from 'node:process';\np[key]();\n",
        ),
        ("required-process", "const p = require('node:process');\n"),
        (
            "sloppy-this",
            "(function () { return this; })().process[key]();\n",
        ),
        (
            "compared-process",
            "const k = ['dl', 'open'].join('');\n0 !== process[k]({ exports: {} }, 'x.node');\n",
        ),
        ("typeof-call-process", "typeof process[key](m, 'p.node');\n"),
        ("negated-process", "-process[key](m, 'p.node');\n"),
        (
            "divided-process",
            "const n = 1 / process[key](m, 'p.node');\n",
        ),
        ("labelled-process", "node:process[key](m, 'p.node');\n"),
        ("typeof-call-module", "typeof module[key]('./p.js');\n"),
        ("quoted-member", "const key = 'binding';\n"),
        ("template-key", "x[`${a}b`]();\n"),
        ("call-key", "x['re'.concat('quire')]('./p');\n"),
    ] {
        project.write(&format!("bad/{name}.mjs"), source);
        project.write("bad/native.node", "binary");
        assert_eq!(
            bind(&project, &[&format!("bad/{name}.mjs")], &[]),
            Err(if name == "missing-package" {
                "node_package_entrypoint_unproven"
            } else {
                "mutable_launcher"
            }),
            "{name}"
        );
    }
}

#[test]
fn ordinary_process_and_module_use_still_binds() {
    let project = report_project();
    project.write(
        "scripts/cli.mjs",
        "import process from 'node:process';\nimport { writeFileSync } from 'node:fs';\nimport { total } from './lib/sum.mjs';\n// process each row, then exit\nif (typeof process !== 'undefined' && process.argv[2]) {\n  const rows = [1, 2, Number(process.env.EXTRA ?? 0)];\n  writeFileSync('out.json', JSON.stringify([total(rows), rows[rows.length - 1]]));\n  console.log(['done', String(rows.length)]);\n  process.exit(0);\n}\n",
    );
    project.write(
        "scripts/tool.cjs",
        "const fs = require('fs');\nconst { parse } = require('csv-lite');\nconst job = { process: (rows) => rows };\nfunction main() { fs.writeFileSync('out.json', String(job.process(parse))); }\nif (require.main === module) main();\nmodule.exports = { main };\n",
    );
    assert!(bind(&project, &["scripts/cli.mjs"], &[]).is_ok());
    // Installed package code is mutable too. This conservative proof cannot
    // establish that every imperative load precedes every possible write.
    assert_eq!(
        bind(&project, &["scripts/tool.cjs"], &[]),
        Err("node_runtime_package_mutation_unproven")
    );
    let source = std::fs::read_to_string(project.0.join("scripts/tool.cjs")).unwrap();
    project.write(
        "scripts/tool.cjs",
        &source.replace("writeFileSync", "readFileSync"),
    );
    assert!(bind(&project, &["scripts/tool.cjs"], &[]).is_ok());
}

#[test]
fn a_graph_that_writes_files_cannot_bind_modules_it_loads_later() {
    let project = report_project();
    project.write("scripts/plugin.mjs", "export default 1;\n");
    project.write("scripts/plugin.js", "module.exports = 1;\n");
    project.write(
        "scripts/lib/save.mjs",
        "import { writeFile } from 'node:fs/promises';\nexport const save = (body) => writeFile(new URL('../plugin.mjs', import.meta.url), body);\n",
    );
    for (name, source) in [
        (
            "rewrite-then-import",
            "import { writeFileSync } from 'node:fs';\nwriteFileSync(new URL('./plugin.mjs', import.meta.url), process.env.BODY);\nawait import('./plugin.mjs');\n",
        ),
        (
            "rewrite-then-require",
            "const fs = require('fs');\nfs.writeFileSync(__dirname + '/plugin.js', process.env.BODY);\nrequire('./plugin.js');\n",
        ),
        (
            "rewrite-in-another-module",
            "import { save } from './lib/save.mjs';\nawait save(process.env.BODY);\nawait import('./plugin.mjs');\n",
        ),
        // Deleting the bound file lets the require fall through to another
        // extension, so deletion counts as a write.
        (
            "delete-then-require",
            "const fs = require('fs');\nfs.rmSync(__dirname + '/plugin.js');\nrequire('./plugin');\n",
        ),
        (
            "unlink-then-require",
            "const fs = require('fs');\nfs.unlinkSync(__dirname + '/plugin.js');\nrequire('./plugin');\n",
        ),
    ] {
        project.write(&format!("scripts/{name}.mjs"), source);
        assert_eq!(
            bind(&project, &[&format!("scripts/{name}.mjs")], &[]),
            Err("mutable_launcher"),
            "{name}"
        );
    }
    // Static imports load before the script runs, so a write cannot reach them.
    project.write(
        "scripts/static.mjs",
        "import { writeFileSync } from 'node:fs';\nimport value from './plugin.mjs';\nwriteFileSync('out.json', String(value));\n",
    );
    assert!(bind(&project, &["scripts/static.mjs"], &[]).is_ok());
}

#[test]
fn options_environment_and_entrypoints_that_load_other_code_stay_once_only() {
    let project = report_project();
    let script = "scripts/report.mjs";
    assert!(bind(&project, &["--no-warnings", script], &[]).is_ok());
    assert!(bind(&project, &["--", script], &[]).is_ok());
    for args in [
        vec!["-e", "1"],
        vec!["-r", "./x.js", script],
        vec!["--import", "./x.mjs", script],
        vec!["--require=./x.js", script],
        vec!["--loader", "./x.mjs", script],
        vec!["-"],
        vec![],
        vec!["missing.mjs"],
        vec!["scripts"],
        vec!["package.json"],
    ] {
        assert_eq!(
            bind(&project, &args, &[]),
            Err("mutable_launcher"),
            "{args:?}"
        );
    }
    for name in ["NODE_OPTIONS", "NODE_PATH"] {
        assert_eq!(
            bind(&project, &[script], &[(name, "x")]),
            Err("mutable_launcher")
        );
    }
    assert!(bind(&project, &[script], &[("NODE_OPTIONS", "")]).is_ok());
}

#[test]
fn only_a_single_node_launch_gets_a_script_identity() {
    let project = report_project();
    let launched = launch(&project, "node scripts/report.mjs").unwrap();
    assert_eq!(launched["kind"], "node-script");
    assert!(launch(&project, "nodejs scripts/report.mjs").is_ok());
    assert_eq!(launch(&project, "node -e 1"), Err("mutable_launcher"));
    assert_eq!(
        launch(&project, "cd scripts && node report.mjs"),
        Err("compound_command")
    );
    assert_eq!(
        launch(&project, "bun scripts/report.mjs"),
        Err("mutable_launcher")
    );
}
