use super::{
    command_reads_environment_secrets, command_reads_environment_secrets_with_caller_cwd,
    printer_expands_secret, without_node_port_reads,
};
use serde_json::Value;

struct Cleanup(std::path::PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn link_file(target: &std::path::Path, link: &std::path::Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(target, link).unwrap();
}

#[test]
fn old_python_vectors_match_native_classification() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/environment_secret_dump/parity_vectors.json"
    ))
    .unwrap();
    let temporary =
        std::env::temp_dir().join(format!("environment-secret-parity-{}", std::process::id()));
    let root = temporary.join("workspace");
    std::fs::create_dir(&temporary).unwrap();
    let _cleanup = Cleanup(temporary.clone());
    std::fs::create_dir(&root).unwrap();
    for (name, content) in vectors["fixtures"].as_object().unwrap() {
        let target = root.join(name);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(target, content.as_str().unwrap()).unwrap();
    }
    link_file(&root.join("reader.py"), &root.join("linked.py"));
    let outside = temporary.join("outside.py");
    std::fs::write(&outside, vectors["fixtures"]["reader.py"].as_str().unwrap()).unwrap();
    link_file(&outside, &root.join("linked-outside.py"));
    std::fs::write(root.join("invalid.py"), [0xff, 0xfe]).unwrap();
    std::fs::write(root.join("huge.py"), vec![b'#'; 256 * 1024 + 1]).unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let command = case["command"].as_str().unwrap();
        let cwd = if case.get("cwd").is_some_and(Value::is_null) {
            None
        } else {
            Some(root.as_path())
        };
        assert_eq!(
            command_reads_environment_secrets_with_caller_cwd(
                command,
                cwd,
                Some(&root),
                Some(&root)
            )
            .unwrap(),
            case["matched"].as_bool().unwrap(),
            "command={command:?}"
        );
    }
}

#[test]
fn local_script_changes_are_observed_on_each_call() {
    let root =
        std::env::temp_dir().join(format!("environment-secret-drift-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let _cleanup = Cleanup(root.clone());
    let script = root.join("reader.py");
    std::fs::write(&script, "print('hello')").unwrap();
    assert!(
        !command_reads_environment_secrets("python reader.py", Some(&root), Some(&root)).unwrap()
    );
    std::fs::write(&script, "import os; print(os.environ)").unwrap();
    assert!(
        command_reads_environment_secrets("python reader.py", Some(&root), Some(&root)).unwrap()
    );
}

#[test]
fn printing_a_credential_variable_is_a_secret_read() {
    for text in [
        "echo \"$GITHUB_TOKEN\" > p.txt",
        "printf '%s' ${NPM_TOKEN}",
        "echo Bearer $OPENAI_API_KEY",
    ] {
        assert!(printer_expands_secret(text), "{text}");
    }
    for text in ["echo \"$PATH\" > p.txt", "echo ${HOME}/x", "printf hello"] {
        assert!(!printer_expands_secret(text), "{text}");
    }
}

#[test]
fn only_dotted_port_variables_are_blanked_from_the_node_environment() {
    for (text, kept) in [
        ("listen(process.env.port||3000)", "listen( ||3000)"),
        (
            "listen(number(process.env.port ?? 3000))",
            "listen(number(  ?? 3000))",
        ),
        (
            "listen(process.env.dev_port, process.env.vite_port)",
            "listen( ,  )",
        ),
        ("listen(process.env . port)", "listen( )"),
    ] {
        assert_eq!(without_node_port_reads(text), kept, "{text}");
    }
    for text in [
        "r.end(json.stringify(process.env))",
        "listen(process.env.port);r.end(process.env.github_token)",
        "process.env['port']",
        "process.env[name]",
        "process.env.port_token",
        "process.env.passport",
        "process.env.port$x",
        "process.env.port/u005ftoken",
        "process.env.port/u0041iner_token",
        "process.env.port\\u005ftoken",
        "process.env.porté",
        "process.env?.port",
        "{...process.env}",
        "object.keys(process.env)",
    ] {
        assert!(
            without_node_port_reads(text).contains("process.env"),
            "{text}"
        );
    }
}
