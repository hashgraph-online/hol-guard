//! Native preparation for direct inline evaluation (`python -c`, `node -e`).
use super::*;

pub(super) fn prepare_inline(input: &Input) -> Result<Value, RestrictedPytestError> {
    let argv = normalized_command(&input.command)?;
    if !inline_eval(&argv)? {
        return Err(RestrictedPytestError::new(
            "inline_eval_invalid_command",
            "Protected evaluation requires direct inline argv.",
        ));
    }
    let name = Path::new(&argv[0]).file_name().and_then(OsStr::to_str);
    if name == Some("bun") {
        return bun::prepare_eval(input, &argv);
    }
    let node = matches!(name, Some("node" | "nodejs"));
    let runtime = if node {
        node_runtime_args(&argv)?
    } else {
        python_runtime_args(&argv).unwrap_or_default()
    };
    let index = 1 + runtime.len();
    let script_index = if node {
        node_script_index(&argv, index)
    } else if !matches!(argv[index].as_str(), "-c" | "-m") {
        Some(index)
    } else {
        None
    };
    if let Some(script_index) = script_index {
        let script = input.cwd.join(&argv[script_index]).canonicalize().ok();
        let root = input.workspace.canonicalize().ok();
        if !script
            .as_ref()
            .zip(root.as_ref())
            .is_some_and(|(script, root)| script.is_file() && path_is_within(script, root))
        {
            return Err(RestrictedPytestError::new(
                "inline_eval_invalid_command",
                "Test script is not in the workspace.",
            ));
        }
    }
    let mut plan = if node {
        prepare_node(&Input {
            command: vec![argv[0].clone(), "--test".to_owned()],
            workspace: input.workspace.clone(),
            cwd: input.cwd.clone(),
            platform: input.platform.clone(),
            backend_executable: input.backend_executable.clone(),
            search_path: input.search_path.clone(),
            home: input.home.clone(),
            ..Input::default()
        })?
    } else {
        validation::resolve_workspace_with_home(&input.workspace, input.home.as_deref())?;
        let response = super::authority::evaluate(
            "prepare",
            &json!({"command":[argv[0],"-m","pytest"],
            "workspace":input.workspace,"cwd":input.cwd,"platform":input.platform,
            "home":input.home,"backend_executable":input.backend_executable,
            "search_path":input.search_path,"read_only_workspace":true}),
        );
        if let Some(value) = response.get("value") {
            value.clone()
        } else {
            return Err(RestrictedPytestError::new(
                response["reason_code"]
                    .as_str()
                    .unwrap_or(PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE),
                response["message"]
                    .as_str()
                    .unwrap_or("Native inline preparation is unavailable."),
            ));
        }
    };
    // A program that runs Git can read the repository through it; the plan
    // names that Git so the sandbox can exec it and the run finds it on PATH.
    super::super::inline_git::grant(&mut plan, &argv[index..], &input.search_path);
    let mut command = vec![plan["executable"].as_str().unwrap().to_owned()];
    command.extend(runtime);
    command.extend_from_slice(&argv[index..]);
    plan["profile_version"] = json!(if node {
        "node-eval-readonly-v1"
    } else {
        "python-eval-readonly-v1"
    });
    plan["command"] = json!(command);
    Ok(plan)
}
