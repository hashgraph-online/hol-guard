//! Native preparation for contained Vitest and tsx test runs.
use super::*;

pub(super) fn readonly_config_arguments(args: &[String], manifest: &Path) -> Vec<String> {
    let mut result = args.to_vec();
    if args
        .iter()
        .any(|v| v == "--configLoader" || v.starts_with("--configLoader="))
    {
        return result;
    }
    let Ok(file) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(manifest)
    else {
        return result;
    };
    if !file.metadata().is_ok_and(|m| m.is_file()) {
        return result;
    }
    let mut bytes = Vec::new();
    if file.take(65537).read_to_end(&mut bytes).is_err() || bytes.len() > 65536 {
        return result;
    }
    let Ok(package) = serde_json::from_slice::<Value>(&bytes) else {
        return result;
    };
    let major = package
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("")
        .split('.')
        .next()
        .unwrap_or("");
    // Only the comparison is needed; Python's unbounded int may be much larger.
    let digits = major.trim_start_matches('0');
    if package.get("name").and_then(Value::as_str) == Some("vitest")
        && !major.is_empty()
        && major.bytes().all(|v| v.is_ascii_digit())
        && (digits.len() > 1 || digits.parse::<u8>().is_ok_and(|v| v >= 4))
    {
        result.extend(["--configLoader".to_owned(), "runner".to_owned()]);
    }
    result
}

pub(super) fn prepare_vitest(input: &Input) -> Result<Value, RestrictedPytestError> {
    let argv = normalized_command(&input.command)?;
    if let Some((script, arguments)) = tsx_test_invocation(&argv)? {
        return prepare_tsx(input, &argv, script.as_deref(), &arguments);
    }
    let (tool, args) = contained_runner_invocation(&input.command)?;
    let runtime = node_runtime_args(&input.command)?;
    let mut workspace = input.workspace.clone();
    let mut cwd = input.cwd.clone();
    if let Some((Some(directory), _)) = bun_vitest_invocation(&input.command) {
        let target = expand_user(Path::new(&directory));
        let target = if target.is_absolute() {
            target
        } else {
            cwd.join(target)
        };
        let original = workspace.canonicalize().ok();
        let resolved = target.canonicalize().ok().filter(|p| p.is_dir());
        let valid = original
            .as_ref()
            .zip(resolved.as_ref())
            .is_some_and(|(root, path)| {
                Path::new(&input.command[0]).file_name() != Some(OsStr::new("bunx"))
                    || path_is_within(path, root)
            });
        if !valid {
            return Err(RestrictedPytestError::new(
                "vitest_restricted_invalid_command",
                "Vitest working directory is unavailable.",
            ));
        }
        cwd = resolved.unwrap();
        if !path_is_within(&cwd, original.as_ref().unwrap()) {
            workspace = cwd.clone();
        }
    }
    let base = Input {
        command: vec!["node".to_owned(), "--test".to_owned()],
        workspace,
        cwd,
        platform: input.platform.clone(),
        backend_executable: input.backend_executable.clone(),
        search_path: input.search_path.clone(),
        home: input.home.clone(),
        ..Input::default()
    };
    let mut plan = prepare_node(&base)?;
    let workspace = Path::new(plan["workspace"].as_str().unwrap());
    let cwd = Path::new(plan["cwd"].as_str().unwrap());
    // Each contained runner is the workspace's own installed entry point.
    // Mocha publishes two spellings of its `bin` shim across the releases
    // this route reads: `bin/mocha.js` from Mocha 10 on, and the
    // extensionless `bin/mocha` of Mocha 8 and 9. The installed one decides
    // which the run executes, so a project on either release runs rather than
    // reporting the package it holds as missing, and the walk up to the
    // project root looks for the manifest both spellings ship beside rather
    // than for one of them.
    let (installed, package_entries): (&str, &[&str]) = match tool {
        "jest" => ("jest/bin/jest.js", &["jest/bin/jest.js"]),
        "mocha" => (
            "mocha/package.json",
            &["mocha/bin/mocha.js", "mocha/bin/mocha"],
        ),
        // AVA moved its entry twice without renaming the package, so the
        // manifest is the one spelling every release ships and the entries
        // are read in the order the releases introduced them.
        "ava" => (
            "ava/package.json",
            &[
                "ava/entrypoints/cli.js",
                "ava/entrypoints/cli.mjs",
                "ava/cli.js",
            ],
        ),
        "jasmine" => ("jasmine/package.json", &["jasmine/bin/jasmine.js"]),
        "qunit" => ("qunit/package.json", &["qunit/bin/qunit.js"]),
        "uvu" => ("uvu/package.json", &["uvu/bin.js"]),
        "tape" => ("tape/package.json", &["tape/bin/tape"]),
        "tsd" => ("tsd/package.json", &["tsd/dist/cli.js"]),
        // tap moved its entry once without renaming the package: tap 21 ships
        // the ESM runner, tap 16 through 20 the CommonJS one. The manifest is
        // the spelling every release ships and the entries are read in the
        // order the releases introduced them.
        "tap" => (
            "tap/package.json",
            &["tap/dist/esm/run.mjs", "tap/bin/run.js"],
        ),
        "borp" => ("borp/package.json", &["borp/borp.js"]),
        "poku" => ("poku/package.json", &["poku/lib/bin/index.js"]),
        "lab" => ("@hapi/lab/package.json", &["@hapi/lab/bin/lab"]),
        "cucumber-js" => (
            "@cucumber/cucumber/package.json",
            &["@cucumber/cucumber/bin/cucumber.js"],
        ),
        _ => ("vitest/vitest.mjs", &["vitest/vitest.mjs"]),
    };
    let modules = nearest_project_root(cwd, workspace, &format!("node_modules/{installed}"))?
        .join("node_modules");
    let entry = package_entries.iter().find_map(|package_entry| {
        modules
            .join(package_entry)
            .canonicalize()
            .ok()
            .filter(|p| p.is_file() && path_is_within(p, &modules))
    });
    // A call that spelled the entry point has to run the file it spelled, so
    // the resolved installed entry is checked against it. Bun spells one the
    // same way Node does.
    let node = matches!(
        Path::new(&input.command[0])
            .file_name()
            .and_then(OsStr::to_str),
        Some("node" | "nodejs")
    ) || bun_runner_entry_launch(&argv);
    // Vitest's `bin` shim and the CLI module that shim imports name the same
    // installed runner, so either spelling resolves to the entry point Guard
    // runs; the plan below still executes the package's own `bin` entry.
    let spelled: Vec<PathBuf> = entry
        .iter()
        .cloned()
        .chain(
            (tool == "vitest")
                .then(|| {
                    modules
                        .join("vitest/dist/cli.js")
                        .canonicalize()
                        .ok()
                        .filter(|p| p.is_file() && path_is_within(p, &modules))
                })
                .flatten(),
        )
        .collect();
    let matching = !node
        || input
            .command
            .get(1 + runtime.len())
            .and_then(|p| cwd.join(p).canonicalize().ok())
            .is_some_and(|p| spelled.contains(&p));
    if entry.is_none() || !matching {
        return Err(RestrictedPytestError::new(
            "vitest_restricted_dependency_unavailable",
            match tool {
                "jest" => "Jest is not installed inside this workspace. Guard did not download or execute a replacement.",
                "mocha" => "Mocha is not installed inside this workspace. Guard did not download or execute a replacement.",
                "ava" => "AVA is not installed inside this workspace. Guard did not download or execute a replacement.",
                "jasmine" => "Jasmine is not installed inside this workspace. Guard did not download or execute a replacement.",
                "qunit" => "QUnit is not installed inside this workspace. Guard did not download or execute a replacement.",
                "uvu" => "uvu is not installed inside this workspace. Guard did not download or execute a replacement.",
                "tape" => "tape is not installed inside this workspace. Guard did not download or execute a replacement.",
                "tsd" => "tsd is not installed inside this workspace. Guard did not download or execute a replacement.",
                "tap" => "tap is not installed inside this workspace. Guard did not download or execute a replacement.",
                "borp" => "borp is not installed inside this workspace. Guard did not download or execute a replacement.",
                "poku" => "poku is not installed inside this workspace. Guard did not download or execute a replacement.",
                "lab" => "lab is not installed inside this workspace. Guard did not download or execute a replacement.",
                "cucumber-js" => "cucumber-js is not installed inside this workspace. Guard did not download or execute a replacement.",
                _ => "Vitest is not installed inside this workspace. Guard did not download or execute a replacement.",
            },
        ));
    }
    let entry = entry.unwrap();
    // The config loader argument is Vitest's own. Mocha reads a watch mode
    // out of a workspace `.mocharc` or `package.json` that the call itself
    // never names, and a watching run never finishes inside the sink, so the
    // run states the mode its admission was read as; Mocha's command line
    // beats its configuration file. Jest takes its arguments as given.
    let args = match tool {
        "vitest" => readonly_config_arguments(&args, &entry.parent().unwrap().join("package.json")),
        "mocha" => std::iter::once("--watch=false".to_owned())
            .chain(args)
            .collect(),
        _ => args,
    };
    let mut command = vec![plan["executable"].as_str().unwrap().to_owned()];
    command.extend(runtime);
    command.push(entry.to_string_lossy().into_owned());
    command.extend(args);
    plan["profile_version"] = json!("vitest-readonly-v1");
    plan["command"] = json!(command);
    Ok(plan)
}

fn prepare_tsx(
    input: &Input,
    argv: &[String],
    script: Option<&str>,
    arguments: &[String],
) -> Result<Value, RestrictedPytestError> {
    let mut plan = prepare_node(&Input {
        command: vec!["node".to_owned(), "--test".to_owned()],
        workspace: input.workspace.clone(),
        cwd: input.cwd.clone(),
        platform: input.platform.clone(),
        backend_executable: input.backend_executable.clone(),
        search_path: input.search_path.clone(),
        home: input.home.clone(),
        ..Input::default()
    })?;
    let workspace = Path::new(plan["workspace"].as_str().unwrap());
    let cwd = Path::new(plan["cwd"].as_str().unwrap());
    let modules = nearest_project_root(cwd, workspace, "node_modules/tsx/dist/loader.mjs")?
        .join("node_modules");
    let loader = modules
        .join("tsx/dist/loader.mjs")
        .canonicalize()
        .ok()
        .filter(|path| path.is_file() && path_is_within(path, &modules));
    let name = Path::new(&argv[0]).file_name().and_then(OsStr::to_str);
    if name == Some("bun") {
        return bun::prepare_eval(input, argv);
    }
    let node = matches!(name, Some("node" | "nodejs"));
    let runtime = if node {
        node_runtime_args(argv)?
    } else {
        vec![]
    };
    let matching = !node
        || argv
            .get(1 + runtime.len())
            .and_then(|value| cwd.join(value).canonicalize().ok())
            == loader
                .as_ref()
                .map(|path| path.parent().unwrap().join("cli.mjs"));
    let Some(loader) = loader.filter(|_| matching) else {
        return Err(RestrictedPytestError::new("vitest_restricted_dependency_unavailable", "tsx is not installed inside this workspace. Guard did not download or execute a replacement."));
    };
    let flags = tsx_test_runner_flags(argv)?;
    let test_mode = tsx_runner_test_mode(&flags);
    // In test-runner mode every word after the flags is another path Node
    // loads, so each one has to resolve inside the workspace. A run that names
    // none leaves the discovery to Node, inside the same workspace.
    let mut files: Vec<String> = script.map(ToOwned::to_owned).into_iter().collect();
    if test_mode {
        files.extend_from_slice(arguments);
    }
    if !files.iter().all(|file| {
        cwd.join(file).canonicalize().is_ok_and(|path| {
            // The test runner walks a directory for the files it runs; a
            // script it is handed outside that mode has to be the file.
            (path.is_file() || (test_mode && path.is_dir())) && path_is_within(&path, workspace)
        })
    }) {
        return Err(RestrictedPytestError::new(
            "vitest_restricted_invalid_command",
            "Test script is not in the workspace.",
        ));
    }
    let uri = url::Url::from_file_path(loader)
        .map_err(|_| invalid_node("Test loader is unavailable."))?;
    let mut command = vec![plan["executable"].as_str().unwrap().to_owned()];
    command.extend(runtime);
    command.extend(["--import".to_owned(), uri.into()]);
    // Node reads its test-runner flags before the first file; behind it they
    // are a word the run loads, so they go back in front of it.
    command.extend(flags);
    command.extend(script.map(ToOwned::to_owned));
    command.extend_from_slice(arguments);
    plan["profile_version"] = json!("vitest-readonly-v1");
    plan["command"] = json!(command);
    Ok(plan)
}
