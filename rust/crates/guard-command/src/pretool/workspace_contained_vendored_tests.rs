//! Composer and Bundler read a dependency tree the project owns, so the verbs
//! that read it run inside the workspace sandbox the way `npm run` does.
//! Everything that reaches a registry keeps the admission it has today, as
//! does a project whose dependencies live outside the workspace. A host
//! without the sandbox, such as Windows, keeps the admission for every one.
use super::local_vendored_work;
use crate::pretool::workspace_contained_tests::{controls, host, workspace, CONTAINED};
use std::path::Path;

fn outcome(harness: &str, command: &str, cwd: &std::path::Path) -> (String, String) {
    let controls = controls();
    let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
        Some(&controls),
        None,
        Some("/Users/nobody"),
        cwd.to_str(),
    );
    (result.reason_code, result.minimum_action)
}

/// A PHP project whose packages are installed beside the manifest.
fn php_project(name: &str) -> std::path::PathBuf {
    let ws = workspace(name, true);
    std::fs::write(
        ws.join("composer.json"),
        "{\"name\": \"app/portal\", \"require\": {}}\n",
    )
    .unwrap();
    std::fs::write(ws.join("composer.lock"), "{\"packages\": []}\n").unwrap();
    std::fs::create_dir_all(ws.join("vendor/bin")).unwrap();
    std::fs::write(ws.join("vendor/autoload.php"), "<?php\n").unwrap();
    ws
}

/// A Ruby project whose gems are installed beside the manifest.
fn ruby_project(name: &str) -> std::path::PathBuf {
    let ws = workspace(name, true);
    std::fs::write(ws.join("Gemfile"), "source \"https://rubygems.invalid\"\n").unwrap();
    std::fs::write(
        ws.join("Gemfile.lock"),
        "DEPENDENCIES\n\nBUNDLED WITH\n   2.5.9\n",
    )
    .unwrap();
    std::fs::create_dir_all(ws.join("vendor/bundle/ruby/3.3.0/bin")).unwrap();
    std::fs::create_dir_all(ws.join(".bundle")).unwrap();
    std::fs::write(
        ws.join(".bundle/config"),
        "BUNDLE_PATH: \"vendor/bundle\"\n",
    )
    .unwrap();
    ws
}

#[test]
fn a_composer_verb_reads_the_vendor_tree_inside_the_sandbox() {
    let ws = php_project("php-reads");
    for command in [
        "composer validate",
        "composer validate --strict",
        "composer show",
        "composer show monolog/monolog",
        "composer info",
        "composer licenses",
        "composer check-platform-reqs",
        "composer dump-autoload",
        "composer run-script test",
        "composer run test",
        "composer exec phpunit",
        "composer --no-interaction run-script lint",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_eq!(reason == CONTAINED, host(), "{reason} {harness}: {command}");
        }
    }
}

#[test]
fn a_bundler_verb_reads_the_bundle_inside_the_sandbox() {
    let ws = ruby_project("ruby-reads");
    for command in [
        "bundle exec rspec",
        "bundle exec rspec spec/models",
        "bundle exec rubocop",
        "bundler exec rake",
        "bundle list",
        "bundle show",
        "bundle check",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_eq!(reason == CONTAINED, host(), "{reason} {harness}: {command}");
        }
    }
}

#[test]
fn everything_that_reaches_a_registry_keeps_its_review() {
    let php = php_project("php-installs");
    for command in [
        "composer install",
        "composer update",
        "composer require monolog/monolog",
        "composer remove monolog/monolog",
        "composer create-project laravel/laravel app",
        "composer global require friendsofphp/php-cs-fixer",
        "composer diagnose",
        "composer self-update",
        // Composer status may download a dist comparison copy; keep it reviewed.
        "composer status",
        // `show` reports the registry once one of these is attached.
        "composer show --latest",
        "composer show --all",
        "composer show --available",
        "composer show -o",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &php);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
    let ruby = ruby_project("ruby-installs");
    for command in [
        "bundle install",
        "bundle update",
        "bundle add rails",
        "bundle outdated",
        "bundle lock",
        "bundle config set path vendor/bundle",
        "gem install rails",
        "gem update",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ruby);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

#[test]
fn a_project_without_its_tree_beside_the_manifest_keeps_its_review() {
    // Without `vendor` the packages resolve through Composer's own home, and
    // without `vendor/bundle` the gems resolve through the caller's gem home;
    // the sandbox replaces both.
    let php = workspace("php-bare", true);
    std::fs::write(php.join("composer.json"), "{\"name\": \"app/portal\"}\n").unwrap();
    let ruby = workspace("ruby-bare", true);
    std::fs::write(
        ruby.join("Gemfile"),
        "source \"https://rubygems.invalid\"\n",
    )
    .unwrap();
    for (ws, command) in [
        (&php, "composer show"),
        (&php, "composer run-script test"),
        (&ruby, "bundle exec rspec"),
        (&ruby, "bundle list"),
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
    // A manifest alone is not the tree: `composer validate` reads only the
    // manifest, so it stays local even here.
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, _) = outcome(harness, "composer validate", &php);
        assert_eq!(reason == CONTAINED, host(), "{reason} {harness}");
    }
}

#[test]
fn a_verb_the_lists_do_not_hold_keeps_its_review() {
    let php = php_project("php-unknown");
    for command in [
        "composer",
        "composer archive",
        "composer exec --list",
        "composer run-script",
        "composer bump",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &php);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
    // A lone version query records no package observation: a plain program.
    for harness in ["codex", "claude-code", "omp"] {
        let contained = outcome(harness, "composer --version", &php).0 == CONTAINED;
        assert_eq!(contained, host(), "{harness}");
    }
    let ruby = ruby_project("ruby-unknown");
    for command in [
        "bundle",
        "bundle exec",
        "bundle exec --help",
        "bundle doctor",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ruby);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

// The checks below call the decision directly, so they hold on every host,
// including the ones that have no sandbox to route into.

fn run(name: &str, ws: &Path, words: &[&str]) -> bool {
    let words: Vec<String> = words.iter().map(|word| (*word).to_owned()).collect();
    local_vendored_work(name, &words, &[], ws, ws)
}

fn configure_composer(ws: &Path, config: serde_json::Value) {
    let manifest = serde_json::json!({"name": "app/portal", "config": config});
    std::fs::write(ws.join("composer.json"), manifest.to_string()).unwrap();
}

fn configure_bundle(ws: &Path, config: &str) {
    std::fs::write(ws.join(".bundle/config"), config).unwrap();
}

#[test]
fn composer_reads_its_working_directory_from_anywhere_on_the_line() {
    let ws = php_project("php-working-dir");
    assert!(run("composer", &ws, &["run-script", "test"]));
    assert!(run(
        "composer",
        &ws,
        &["exec", "phpunit", "--filter", "testOne"]
    ));
    let moved: [&[&str]; 9] = [
        &["run-script", "test", "-d", "packages/other"],
        &["run-script", "test", "--working-dir=packages/other"],
        &["exec", "phpunit", "--working-dir", "packages/other"],
        &["exec", "phpunit", "--", "-d", "packages/other"],
        &["run", "test", "--", "--working-dir=packages/other"],
        &["-d", "packages/other", "run-script", "test"],
        &["show", "-dpackages/other"],
        &["show", "-qd", "packages/other"],
        &["exec", "phpunit", "-d", "packages/other"],
    ];
    for words in moved {
        assert!(!run("composer", &ws, words), "{words:?}");
    }
}

#[test]
fn a_verb_that_hands_the_line_to_a_package_manager_keeps_its_review() {
    let php = php_project("php-delegated");
    let ruby = ruby_project("ruby-delegated");
    // Names that only resemble a package tool are still project tools.
    assert!(run(
        "composer",
        &php,
        &["exec", "phpunit", "tests/Unit/ComposerTest.php"]
    ));
    assert!(run("bundle", &ruby, &["exec", "rspec", "spec/gem_spec.rb"]));
    assert!(run("bundle", &ruby, &["exec", "rake", "db:migrate"]));
    let composer: [&[&str]; 7] = [
        &["exec", "composer", "install"],
        &["exec", "vendor/bin/composer", "update"],
        &["exec", "php", "composer.phar", "install"],
        &["exec", "env", "npm", "install"],
        &["exec", "sh", "-c", "npm install"],
        &["exec", "pip", "install", "requests"],
        &["run-script", "pip", "install", "requests"],
    ];
    for words in composer {
        assert!(!run("composer", &php, words), "{words:?}");
    }
    let bundle: [&[&str]; 7] = [
        &["exec", "gem", "install", "rails"],
        &["exec", "bundle", "install"],
        &["exec", "bundler", "update"],
        &["exec", "ruby", "-S", "gem", "install", "rails"],
        &["exec", "sh", "-c", "gem install rails"],
        &["exec", "pip", "install", "requests"],
        &["exec", "npm", "install"],
    ];
    for words in bundle {
        assert!(!run("bundle", &ruby, words), "{words:?}");
    }
}

#[test]
fn a_variable_that_moves_the_project_or_its_tree_keeps_its_review() {
    let php = php_project("php-variables");
    let ruby = ruby_project("ruby-variables");
    let show = ["show".to_owned()];
    let exec = ["exec".to_owned(), "rspec".to_owned()];
    let with = |variable: &str| [variable.to_owned()];
    for variable in [
        "COMPOSER",
        "COMPOSER_HOME",
        "COMPOSER_VENDOR_DIR",
        "COMPOSER_BIN_DIR",
    ] {
        assert!(!local_vendored_work(
            "composer",
            &show,
            &with(variable),
            &php,
            &php
        ));
    }
    for variable in [
        "BUNDLE_PATH",
        "BUNDLE_GEMFILE",
        "BUNDLE_APP_CONFIG",
        "GEM_HOME",
        "GEM_PATH",
        "RUBYOPT",
        "RUBYLIB",
    ] {
        assert!(!local_vendored_work(
            "bundle",
            &exec,
            &with(variable),
            &ruby,
            &ruby
        ));
    }
    assert!(local_vendored_work(
        "composer",
        &show,
        &with("CI"),
        &php,
        &php
    ));
    assert!(local_vendored_work(
        "bundle",
        &exec,
        &with("CI"),
        &ruby,
        &ruby
    ));
}

#[test]
fn composer_reads_the_tree_its_manifest_names() {
    let ws = php_project("php-configured");
    for vendor in [
        "../shared-vendor",
        "/opt/vendor",
        "~/vendor",
        "{$home}/vendor",
        "$HOME/vendor",
        "libs/../../vendor",
        "",
    ] {
        configure_composer(&ws, serde_json::json!({ "vendor-dir": vendor }));
        assert!(!run("composer", &ws, &["show"]), "{vendor:?}");
        assert!(!run("composer", &ws, &["run-script", "test"]), "{vendor:?}");
        // `validate` reads the manifest alone, wherever the tree is.
        assert!(run("composer", &ws, &["validate"]), "{vendor:?}");
    }
    // A tree the manifest names is the one that has to exist, not `vendor`.
    configure_composer(&ws, serde_json::json!({ "vendor-dir": "libs" }));
    assert!(!run("composer", &ws, &["show"]));
    std::fs::create_dir_all(ws.join("libs")).unwrap();
    assert!(run("composer", &ws, &["show"]));
    // The binary directory follows the same rule.
    for bin in ["/usr/local/bin", "../bin", "~/bin"] {
        configure_composer(
            &ws,
            serde_json::json!({ "vendor-dir": "libs", "bin-dir": bin }),
        );
        assert!(!run("composer", &ws, &["exec", "phpunit"]), "{bin:?}");
    }
    for bin in ["{$vendor-dir}/bin", "tools/bin"] {
        configure_composer(
            &ws,
            serde_json::json!({ "vendor-dir": "libs", "bin-dir": bin }),
        );
        assert!(run("composer", &ws, &["exec", "phpunit"]), "{bin:?}");
    }
    // A setting that is not a path, or a manifest that is not JSON, is not
    // read as the conventional tree.
    configure_composer(&ws, serde_json::json!({ "vendor-dir": 7 }));
    assert!(!run("composer", &ws, &["show"]));
    configure_composer(&ws, serde_json::json!({ "bin-dir": ["bin"] }));
    assert!(!run("composer", &ws, &["show"]));
    std::fs::write(ws.join("composer.json"), "{ not json").unwrap();
    assert!(!run("composer", &ws, &["show"]));
}

#[test]
fn bundler_reads_the_bundle_its_configuration_names() {
    let ws = ruby_project("ruby-configured");
    let exec = ["exec", "rspec"];
    assert!(run("bundle", &ws, &exec));
    for path in [
        "/opt/gems",
        "../gems",
        "~/gems",
        "$HOME/gems",
        "a/../../gems",
    ] {
        configure_bundle(&ws, &format!("---\nBUNDLE_PATH: \"{path}\"\n"));
        assert!(!run("bundle", &ws, &exec), "{path}");
        assert!(!run("bundle", &ws, &["list"]), "{path}");
    }
    // The path the configuration names is the one that has to exist, not
    // `vendor/bundle`.
    configure_bundle(&ws, "---\nBUNDLE_PATH: \".bundle/gems\"\n");
    assert!(!run("bundle", &ws, &exec));
    std::fs::create_dir_all(ws.join(".bundle/gems")).unwrap();
    assert!(run("bundle", &ws, &exec));
    // A deployment bundle lives in `vendor/bundle`.
    configure_bundle(&ws, "---\nBUNDLE_DEPLOYMENT: \"true\"\n");
    assert!(run("bundle", &ws, &exec));
    configure_bundle(&ws, "---\nBUNDLE_DEPLOYMENT: \"false\"\n");
    assert!(!run("bundle", &ws, &exec));
    // A directory with the conventional name is not a bundle until the
    // project's configuration says so.
    std::fs::remove_file(ws.join(".bundle/config")).unwrap();
    assert!(!run("bundle", &ws, &exec));
    // A Gemfile or configuration kept elsewhere is not this project's.
    for moved in [
        "BUNDLE_GEMFILE: \"../Gemfile\"",
        "BUNDLE_APP_CONFIG: \"/etc/bundle\"",
    ] {
        configure_bundle(
            &ws,
            &format!("---\nBUNDLE_PATH: \"vendor/bundle\"\n{moved}\n"),
        );
        assert!(!run("bundle", &ws, &exec), "{moved}");
    }
    // Bundler keeps the last of a repeated key, so a file that sets one twice
    // names no tree; `BUNDLE_PATH__SYSTEM` selects the caller's gem home.
    for config in [
        "BUNDLE_PATH: \"vendor/bundle\"\nBUNDLE_PATH: \"/opt/gems\"\n",
        "BUNDLE_PATH: \"/opt/gems\"\nBUNDLE_PATH: \"vendor/bundle\"\n",
        "BUNDLE_PATH: \"vendor/bundle\"\nBUNDLE_PATH: \"vendor/bundle\"\n",
        "BUNDLE_DEPLOYMENT: \"true\"\nBUNDLE_DEPLOYMENT: \"false\"\n",
        "BUNDLE_PATH: \"vendor/bundle\"\nBUNDLE_PATH__SYSTEM: \"true\"\n",
        // Bundler does not read these spellings as the setting they resemble.
        "BUNDLE_DEPLOYMENT: \"false\"\nBUNDLE_PATH:vendor/bundle\n",
        " BUNDLE_PATH: \"vendor/bundle\"\n",
        "BUNDLE_PATH : \"vendor/bundle\"\n",
        "BUNDLE_PATH: \"vendor/bundle\"\nBUNDLE_GEMFILE:../Gemfile\n",
    ] {
        configure_bundle(&ws, &format!("---\n{config}"));
        assert!(!run("bundle", &ws, &exec), "{config}");
        assert!(!run("bundle", &ws, &["list"]), "{config}");
    }
}

#[cfg(unix)]
#[test]
fn a_tree_that_is_a_link_out_of_the_workspace_keeps_its_review() {
    let outside = std::env::temp_dir().join(format!("guard-out-{}-vendored", std::process::id()));
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir_all(outside.join("bundle")).unwrap();
    let php = php_project("php-linked");
    assert!(run("composer", &php, &["show"]));
    std::fs::remove_dir_all(php.join("vendor")).unwrap();
    std::os::unix::fs::symlink(&outside, php.join("vendor")).unwrap();
    assert!(!run("composer", &php, &["show"]));
    let ruby = ruby_project("ruby-linked");
    assert!(run("bundle", &ruby, &["list"]));
    std::fs::remove_dir_all(ruby.join("vendor/bundle")).unwrap();
    std::os::unix::fs::symlink(outside.join("bundle"), ruby.join("vendor/bundle")).unwrap();
    assert!(!run("bundle", &ruby, &["list"]));
}

#[test]
fn a_moved_project_a_delegated_install_or_an_outside_tree_keeps_its_review() {
    let php = php_project("php-routed");
    configure_composer(
        &php,
        serde_json::json!({ "vendor-dir": "../shared-vendor" }),
    );
    let ruby = ruby_project("ruby-routed");
    configure_bundle(&ruby, "---\nBUNDLE_PATH: \"/opt/gems\"\n");
    let php_ok = php_project("php-routed-ok");
    let ruby_ok = ruby_project("ruby-routed-ok");
    for (ws, command) in [
        (&php_ok, "composer run-script test -d packages/other"),
        (
            &php_ok,
            "composer exec phpunit --working-dir=packages/other",
        ),
        (&php_ok, "composer exec composer install"),
        (&ruby_ok, "bundle exec gem install rails"),
        (&ruby_ok, "bundle exec bundle install"),
        (&php, "composer show"),
        (&php, "composer run-script test"),
        (&ruby, "bundle exec rspec"),
        (&ruby, "bundle list"),
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_ne!(minimum, "allow", "{harness}: {command} ({reason})");
        }
    }
}
