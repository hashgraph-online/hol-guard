use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::paths::normpath;
use super::{is_python_name, pure, run_command, Host};

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = fs::canonicalize(dir.path()).expect("canonical tempdir");
    let home = root.join("home");
    fs::create_dir_all(home.join(".local").join("bin")).expect("bin dir");
    Fixture {
        _dir: dir,
        root,
        home,
    }
}

impl Fixture {
    fn bin(&self) -> PathBuf {
        self.home.join(".local").join("bin")
    }

    fn environment(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("HOME".to_owned(), text(&self.home)),
            (
                "XDG_DATA_HOME".to_owned(),
                text(&self.home.join(".local").join("share")),
            ),
        ])
    }

    fn host(&self, environment: BTreeMap<String, String>) -> Host {
        Host {
            home: self.home.clone(),
            cwd: self.root.clone(),
            environment,
        }
    }

    fn inventory(&self, protected: &[PathBuf]) -> Value {
        self.host(self.environment())
            .inventory(&text(&self.bin()), protected)
    }

    fn pipx_venv(&self, name: &str) -> PathBuf {
        let venv = self
            .home
            .join(".local")
            .join("pipx")
            .join("venvs")
            .join(name);
        let scripts = venv.join("bin");
        fs::create_dir_all(&scripts).expect("scripts");
        write(
            &scripts.join("hol-guard"),
            &format!(
                "#!{}/python\nfrom codex_plugin_scanner import main\n",
                scripts.display()
            ),
        );
        let native = venv
            .join("lib")
            .join("python3.12")
            .join("site-packages")
            .join("codex_plugin_scanner")
            .join("guard")
            .join("_native");
        fs::create_dir_all(&native).expect("native dir");
        write(&native.join("hol-guard-runtime"), "runtime");
        venv
    }
}

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn write(path: &Path, content: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("parent dir");
    fs::write(path, content).expect("write");
}

fn empty() -> Value {
    json!({"venvs": [], "stale_entries": [], "user_site": []})
}

#[test]
fn reports_a_pipx_venv_with_its_entry_and_runtime() {
    let fixture = fixture();
    let venv = fixture.pipx_venv("hol-guard");
    let entry = fixture.bin().join("hol-guard");
    write(
        &entry,
        &format!(
            "#!{}/bin/python\nimport codex_plugin_scanner\n",
            venv.display()
        ),
    );

    let runtime = venv
        .join("lib/python3.12/site-packages/codex_plugin_scanner/guard/_native/hol-guard-runtime");
    assert_eq!(
        fixture.inventory(&[]),
        json!({
            "venvs": [{
                "kind": "pipx",
                "root": text(&venv),
                "entries": [text(&entry)],
                "runtimes": [text(&runtime)],
            }],
            "stale_entries": [],
            "user_site": [],
        })
    );
}

#[test]
fn a_sibling_venv_path_does_not_claim_an_entry() {
    let fixture = fixture();
    let venv = fixture.pipx_venv("hol-guard");
    let sibling = venv.with_file_name("hol-guard-dev");
    write(
        &fixture.bin().join("hol-guard"),
        &format!("#!/bin/sh\nexec {}/bin/hol-guard\n", sibling.display()),
    );

    let inventory = fixture.inventory(&[]);

    assert_eq!(inventory["venvs"][0]["entries"], json!([]));
    assert_eq!(inventory["user_site"], json!([]));
}

#[test]
fn a_protected_venv_is_left_out() {
    let fixture = fixture();
    let venv = fixture.pipx_venv("hol-guard");

    assert_eq!(
        fixture.inventory(&[venv.join("bin").join("python")]),
        empty()
    );
}

#[test]
fn uv_tool_dir_from_the_environment_is_read() {
    let fixture = fixture();
    let tools = fixture.root.join("uv-tools");
    fs::create_dir_all(tools.join("hol_guard")).expect("uv venv");
    let mut environment = fixture.environment();
    environment.insert("UV_TOOL_DIR".to_owned(), text(&tools));

    let inventory = fixture
        .host(environment)
        .inventory(&text(&fixture.bin()), &[]);

    assert_eq!(inventory["venvs"][0]["kind"], "uv");
    assert_eq!(
        inventory["venvs"][0]["root"],
        text(&tools.join("hol_guard"))
    );
}

#[test]
fn a_users_own_shell_wrapper_is_ignored() {
    let fixture = fixture();
    write(
        &fixture.bin().join("hol-guard"),
        "#!/bin/sh\nexec python3 -m codex_plugin_scanner.cli \"$@\"\n",
    );

    assert_eq!(fixture.inventory(&[]), empty());
}

#[test]
fn a_pip_user_script_names_its_system_interpreter() {
    let fixture = fixture();
    let python = fixture.root.join("system").join("bin").join("python3.12");
    write(&python, "");
    let script = fixture.bin().join("hol-guard");
    write(
        &script,
        &format!(
            "#!{}\nfrom codex_plugin_scanner.cli import main\n",
            python.display()
        ),
    );
    let eval = fixture.bin().join("hol-guard-eval");
    write(
        &eval,
        &format!(
            "#!{}\nfrom codex_plugin_scanner.eval import main\n",
            python.display()
        ),
    );

    assert_eq!(
        fixture.inventory(&[])["user_site"],
        json!([{"interpreter": text(&python), "entries": [text(&script), text(&eval)]}])
    );
}

#[test]
fn a_venv_interpreter_is_not_a_pip_user_install() {
    let fixture = fixture();
    let python = fixture.root.join("venv").join("bin").join("python3");
    write(&python, "");
    write(
        &fixture.root.join("venv").join("pyvenv.cfg"),
        "home = /usr\n",
    );
    write(
        &fixture.bin().join("hol-guard"),
        &format!(
            "#!{}\nfrom codex_plugin_scanner.cli import main\n",
            python.display()
        ),
    );

    assert_eq!(fixture.inventory(&[]), empty());
}

#[test]
fn a_desktop_path_shim_is_left_alone() {
    let fixture = fixture();
    let python = fixture.root.join("system").join("bin").join("python3");
    write(&python, "");
    write(
        &fixture.bin().join("hol-guard"),
        &format!(
            "#!{}\n# HOL_GUARD_DESKTOP_USER_PATH_SHIM\nimport codex_plugin_scanner\n",
            python.display()
        ),
    );

    assert_eq!(fixture.inventory(&[]), empty());
}

#[test]
fn path_entries_outside_home_are_not_searched() {
    let fixture = fixture();
    let python = fixture.root.join("system").join("bin").join("python3");
    write(&python, "");
    let outside = fixture.root.join("outside");
    write(
        &outside.join("hol-guard"),
        &format!("#!{}\nimport codex_plugin_scanner\n", python.display()),
    );
    let inside = fixture.home.join("tools");
    let script = inside.join("hol-guard");
    write(
        &script,
        &format!("#!{}\nimport codex_plugin_scanner\n", python.display()),
    );
    let path = format!("{}:{}: ", outside.display(), inside.display());

    let inventory = fixture.host(fixture.environment()).inventory(&path, &[]);

    assert_eq!(
        inventory["user_site"],
        json!([{"interpreter": text(&python), "entries": [text(&script)]}])
    );
}

#[test]
fn a_tilde_bin_dir_expands_against_home() {
    let fixture = fixture();
    let python = fixture.root.join("system").join("bin").join("python3");
    write(&python, "");
    let script = fixture.home.join("pipx-bin").join("hol-guard");
    write(
        &script,
        &format!("#!{}\nimport codex_plugin_scanner\n", python.display()),
    );
    let mut environment = fixture.environment();
    environment.insert("PIPX_BIN_DIR".to_owned(), " ~/pipx-bin/ ".to_owned());

    let inventory = fixture.host(environment).inventory("", &[]);

    assert_eq!(inventory["user_site"][0]["entries"], json!([text(&script)]));
}

#[test]
fn is_python_name_matches_the_interpreter_pattern() {
    for name in ["python", "python3", "python3.12", "python3.12.1"] {
        assert!(is_python_name(name), "{name}");
    }
    for name in [
        "python3.",
        "python.3",
        "pythonw",
        "py",
        "python3.x",
        "hol-guard",
    ] {
        assert!(!is_python_name(name), "{name}");
    }
}

#[test]
fn pure_and_normpath_follow_pathlib() {
    assert_eq!(pure("/a//b/./c/"), PathBuf::from("/a/b/c"));
    assert_eq!(pure("./a"), PathBuf::from("a"));
    assert_eq!(pure(""), PathBuf::from("."));
    assert_eq!(normpath(Path::new("/a/b/../../../c")), PathBuf::from("/c"));
    assert_eq!(normpath(Path::new("a/../../b")), PathBuf::from("../b"));
    assert_eq!(normpath(Path::new("a/..")), PathBuf::from("."));
}

#[test]
fn requests_are_validated() {
    let request = |value: Value| run_command(value.to_string().as_bytes());
    let valid = json!({
        "schema": "desktop-foreign-inventory.v1",
        "home": "/nonexistent-home",
        "cwd": "/",
        "path": "",
        "environment": {},
        "protected": [],
    });
    let answer: Value =
        serde_json::from_slice(&request(valid.clone()).expect("valid request")).expect("json");
    assert_eq!(answer, empty());

    let mut wrong_schema = valid.clone();
    wrong_schema["schema"] = json!("desktop-foreign-inventory.v0");
    let mut relative_cwd = valid.clone();
    relative_cwd["cwd"] = json!("relative");
    let mut unknown_field = valid;
    unknown_field["extra"] = json!(true);
    for rejected in [wrong_schema, relative_cwd, unknown_field] {
        assert_eq!(
            request(rejected),
            Err("desktop_foreign_inventory_request_invalid".to_owned())
        );
    }
    assert_eq!(
        run_command(vec![b' '; 1024 * 1024 + 1].as_slice()),
        Err("desktop_foreign_inventory_request_too_large".to_owned())
    );
}

#[cfg(unix)]
mod links {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    use serde_json::json;

    use super::{fixture, text, write};

    #[test]
    fn a_relative_link_left_by_a_deleted_venv_is_stale() {
        let fixture = fixture();
        let link = fixture.bin().join("hol-guard");
        symlink(Path::new("../pipx/venvs/hol-guard/bin/hol-guard"), &link).expect("link");

        let inventory = fixture.inventory(&[]);

        assert_eq!(inventory["stale_entries"], json!([text(&link)]));
        assert_eq!(inventory["venvs"], json!([]));
    }

    #[test]
    fn a_link_into_a_live_venv_belongs_to_it() {
        let fixture = fixture();
        let venv = fixture.pipx_venv("hol-guard");
        let link = fixture.bin().join("hol-guard");
        symlink(venv.join("bin").join("hol-guard"), &link).expect("link");

        assert_eq!(
            fixture.inventory(&[])["venvs"][0]["entries"],
            json!([text(&link)])
        );
    }

    #[test]
    fn a_symlinked_venv_is_not_removed() {
        let fixture = fixture();
        let real = fixture.root.join("elsewhere");
        fs::create_dir_all(&real).expect("real venv");
        let venvs = fixture.home.join(".local").join("pipx").join("venvs");
        fs::create_dir_all(&venvs).expect("venvs");
        symlink(&real, venvs.join("hol-guard")).expect("link");

        assert_eq!(fixture.inventory(&[])["venvs"], json!([]));
    }

    #[test]
    fn an_entry_inside_the_desktop_data_dir_is_left_alone() {
        let fixture = fixture();
        let launcher = fixture
            .home
            .join(".local/share/org.hol.guard.desktop/core/current-hol-guard");
        write(
            &launcher,
            "#!/usr/bin/python3\nimport codex_plugin_scanner\n",
        );
        symlink(&launcher, fixture.bin().join("hol-guard")).expect("link");

        assert_eq!(fixture.inventory(&[]), super::empty());
    }

    #[test]
    fn resolve_follows_links_and_keeps_a_missing_tail() {
        let fixture = fixture();
        let real = fixture.root.join("real");
        fs::create_dir_all(real.join("inner")).expect("real");
        symlink(&real, fixture.root.join("alias")).expect("alias");
        symlink(Path::new("alias/inner"), fixture.root.join("relative")).expect("relative");
        symlink(fixture.root.join("loop"), fixture.root.join("loop")).expect("loop");
        let host = fixture.host(fixture.environment());

        assert_eq!(
            host.resolve(&fixture.root.join("relative/missing/../x")),
            real.join("inner/x")
        );
        assert_eq!(host.resolve(Path::new("alias")), real);
        assert_eq!(
            host.resolve(&fixture.root.join("loop/x")),
            fixture.root.join("loop/x")
        );
        assert_eq!(host.resolve(Path::new("/")), PathBuf::from("/"));
    }
}
