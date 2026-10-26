use super::outside_script;
use crate::{parse_command, CommandModelRequestV1};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/outside-script-unit")
            .join(format!(
                "run-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        std::fs::create_dir_all(root.join("scratch")).unwrap();
        Self {
            root: root.canonicalize().unwrap(),
        }
    }

    fn workspace(&self) -> PathBuf {
        self.root.join("workspace")
    }

    fn write(&self, relative: &str, text: &str) -> PathBuf {
        let path = self.root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        path
    }

    fn grant(&self, command: &str) -> Option<PathBuf> {
        let model = parse_command(&CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".into(),
            transport: "shell_string".into(),
            extraction_provenance: "pre-tool-generic".into(),
        })
        .unwrap();
        outside_script(&model.segments[0], &self.workspace()).map(|(_, path)| path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn a_plain_script_outside_the_workspace_is_granted_by_its_canonical_path() {
    let scratch = Scratch::new();
    let python = scratch.write("scratch/check.py", "import json\nprint(json.dumps([1]))\n");
    let node = scratch.write("scratch/build.mjs", "console.log(1);\n");
    assert_eq!(
        scratch.grant(&format!("python3 {}", python.display())),
        Some(python.clone())
    );
    assert_eq!(
        scratch.grant(&format!("python3 -u {} --flag", python.display())),
        Some(python)
    );
    assert_eq!(
        scratch.grant(&format!("node {}", node.display())),
        Some(node)
    );
}

#[test]
fn a_script_inside_the_workspace_needs_no_grant() {
    let scratch = Scratch::new();
    let inside = scratch.write("workspace/tally.py", "print(1)\n");
    assert_eq!(
        scratch.grant(&format!("python3 {}", inside.display())),
        None
    );
}

#[test]
fn network_credential_and_module_scripts_are_not_granted() {
    let scratch = Scratch::new();
    let network = scratch.write("scratch/fetch.py", "import requests\nrequests.get('x')\n");
    let keys = scratch.write(
        "scratch/keys.py",
        "print(open('/home/u/.aws/credentials').read())\n",
    );
    let module = scratch.write("scratch/main.py", "import helper\nhelper.run()\n");
    scratch.write("scratch/helper.py", "def run():\n    pass\n");
    let fetch = scratch.write("scratch/fetch.mjs", "await fetch('https://x.invalid');\n");
    let stream = scratch.write(
        "scratch/stream.py",
        "import asyncio\nasyncio.run(asyncio.open_connection('h', 1))\n",
    );
    for path in [network, keys, module, stream] {
        assert_eq!(
            scratch.grant(&format!("python3 {}", path.display())),
            None,
            "{}",
            path.display()
        );
    }
    assert_eq!(scratch.grant(&format!("node {}", fetch.display())), None);
}

#[test]
fn only_a_regular_non_hidden_script_with_a_script_extension_is_granted() {
    let scratch = Scratch::new();
    let text = scratch.write("scratch/notes.txt", "print(1)\n");
    let hidden = scratch.write("scratch/.cache/run.py", "print(1)\n");
    let real = scratch.write("scratch/real.py", "print(1)\n");
    let link = scratch.root.join("scratch/link.py");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let directory = scratch.root.join("scratch/dir.py");
    std::fs::create_dir_all(&directory).unwrap();
    let parent = format!("{}/scratch/../scratch/real.py", scratch.root.display());
    for command in [
        format!("python3 {}", text.display()),
        format!("python3 {}", hidden.display()),
        format!("python3 {}", link.display()),
        format!("python3 {}", directory.display()),
        format!("python3 {parent}"),
        "python3 scratch/real.py".to_owned(),
        "python3 $TMPDIR/real.py".to_owned(),
        format!(
            "python3 {}/missing.py",
            scratch.root.join("scratch").display()
        ),
    ] {
        assert_eq!(scratch.grant(&command), None, "{command}");
    }
}

#[test]
fn a_symlinked_directory_never_redirects_the_grant() {
    let scratch = Scratch::new();
    let real = scratch.write("elsewhere/run.py", "print(1)\n");
    let alias = scratch.root.join("scratch/alias");
    std::os::unix::fs::symlink(real.parent().unwrap(), &alias).unwrap();
    assert_eq!(
        scratch.grant(&format!("python3 {}/run.py", alias.display())),
        None
    );
}

#[test]
fn secret_named_scripts_are_not_granted() {
    let scratch = Scratch::new();
    let secret = scratch.write("scratch/.env.py", "print(1)\n");
    let ssh = scratch.write("scratch/.ssh/id_rsa.py", "print(1)\n");
    for path in [secret, ssh] {
        assert_eq!(scratch.grant(&format!("python3 {}", path.display())), None);
    }
}
