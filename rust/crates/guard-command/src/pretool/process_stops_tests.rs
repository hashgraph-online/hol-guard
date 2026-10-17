use super::safe_pkill_arguments;
use crate::pretool::PathContext;

struct Project(std::path::PathBuf);

impl Drop for Project {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn project() -> Project {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/process-stops-tests")
        .join(format!(
            "run-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
    for file in ["server.js", "app/main.py", "guard-server.js"] {
        let path = root.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "\n").unwrap();
    }
    std::fs::create_dir_all(root.join("served")).unwrap();
    Project(root.canonicalize().unwrap())
}

fn allowed(project: &Project, arguments: &[&str]) -> bool {
    let arguments: Vec<String> = arguments.iter().map(|word| (*word).to_owned()).collect();
    let context = PathContext {
        cwd: project.0.to_str(),
        ..PathContext::default()
    };
    safe_pkill_arguments(&arguments, context)
}

#[test]
fn a_workspace_server_stops_on_term_or_int() {
    let project = project();
    for arguments in [
        &["-f", "node server.js"][..],
        &["-TERM", "-f", "node server.js"],
        &["-f", "-INT", "node server.js"],
        &["-15", "-f", "python3 app/main.py"],
        &["-SIGINT", "-f", "bun server.js"],
    ] {
        assert!(allowed(&project, arguments), "{arguments:?}");
    }
}

#[test]
fn broad_patterns_other_signals_and_options_keep_the_review() {
    let project = project();
    for arguments in [
        // Bare programs and broad patterns.
        &["node"][..],
        &["-f", "node"],
        &["-f", "python"],
        &["-f", "server.js"],
        &["-f", "node .*"],
        &["-f", "node server.js extra"],
        &["-f", "node  server.js"],
        &["node server.js"],
        // Other signals and options.
        &["-9", "-f", "node server.js"],
        &["-KILL", "-f", "node server.js"],
        &["-HUP", "-f", "node server.js"],
        &["-TERM", "-INT", "-f", "node server.js"],
        &["-u", "root", "-f", "node server.js"],
        &["-f", "-u", "root", "node server.js"],
        &["-fx", "node server.js"],
        &["-f", "-n", "node server.js"],
        &["-f", "-f", "node server.js"],
        // Scripts outside the workspace, missing, or not a file.
        &["-f", "node /tmp/server.js"],
        &["-f", "node ../server.js"],
        &["-f", "node ./server.js"],
        &["-f", "node missing.js"],
        &["-f", "node served"],
        &["-f", "node app//main.py"],
        // Interpreters and scripts that name Guard or a harness.
        &["-f", "sh server.js"],
        &["-f", "node guard-server.js"],
        &["-f", "node claude.js"],
        &["-f", "node omp/cli.js"],
    ] {
        assert!(!allowed(&project, arguments), "{arguments:?}");
    }
}

#[test]
fn no_working_directory_keeps_the_review() {
    let arguments = vec!["-f".to_owned(), "node server.js".to_owned()];
    assert!(!safe_pkill_arguments(&arguments, PathContext::default()));
}
