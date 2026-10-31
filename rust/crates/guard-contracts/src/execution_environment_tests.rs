use super::*;

#[test]
fn heap_and_diagnostic_flags_are_inert() {
    for value in [
        "--max-old-space-size=8192",
        " --max_old_space_size=4096  --no-warnings ",
        "--enable-source-maps --stack-trace-limit=50",
        "--max-semi-space-size=64 --trace-deprecation",
    ] {
        assert!(node_options_inert(value), "{value:?}");
    }
}

#[test]
fn loaders_files_and_odd_spellings_are_not_inert() {
    for value in [
        "",
        "   ",
        "--require ./hook.js",
        "--require=./hook.js",
        "-r ./hook.js",
        "--import=data:text/javascript,0",
        "--loader ./loader.mjs",
        "--experimental-loader=./loader.mjs",
        "--inspect=0.0.0.0:9229",
        "--max-old-space-size=8192 --require=./hook.js",
        "--max-old-space-size=",
        "--max-old-space-size=8g",
        "--max-old-space-size 8192",
        "--env-file=.env",
        "--max-old-space-size=8192\t--require=x",
        "\"--max-old-space-size=8192\"",
        "--no-warnings=1",
    ] {
        assert!(!node_options_inert(value), "{value:?}");
    }
}

#[test]
fn the_flag_is_omitted_when_false() {
    let stamp = GuardExecutionEnvironmentV1::unavailable();
    let text = serde_json::to_string(&stamp).unwrap();
    assert!(!text.contains("node_options_inert"), "{text}");
    let stamp = GuardExecutionEnvironmentV1 {
        node_options_inert: true,
        ..stamp
    };
    let text = serde_json::to_string(&stamp).unwrap();
    let read: GuardExecutionEnvironmentV1 = serde_json::from_str(&text).unwrap();
    assert!(read.node_options_inert, "{text}");
}
