//! Uninstalled, read-only Root diagnostic over one retained six-control job.

#[cfg(target_os = "linux")]
fn main() {
    use gauntlet_evidence::observe_six_control_openings_root_owned_ineligible;
    use std::collections::BTreeMap;
    use std::path::Path;

    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 13 {
        eprintln!("usage: gauntlet-six-control-openings-shadow JOB_ID SOURCE_SHA ABSOLUTE_CONFIG_JSON EXTERNAL_CONFIG_SHA256 EXTERNAL_REPORT_SHA256 EXPECTED_EXIT_CODE KEY_SUCCESS KEY_INPUT_BINDING KEY_INJECTION KEY_BOUNDARY KEY_TIMEOUT KEY_CANCEL");
        std::process::exit(2);
    }
    let fields: Option<Vec<&str>> = args
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(index, _)| *index != 3)
        .map(|(_, value)| value.to_str())
        .collect();
    let Some(fields) = fields else {
        eprintln!("outside identities must be UTF-8");
        std::process::exit(2);
    };
    if fields.len() != 11 {
        eprintln!("invalid outside identities");
        std::process::exit(2);
    }
    let Ok(exit_code) = fields[4].parse::<i32>() else {
        eprintln!("expected exit code must be an integer");
        std::process::exit(2);
    };
    let roles = [
        "success",
        "input-binding",
        "injection",
        "boundary",
        "timeout",
        "cancel",
    ];
    let keys: BTreeMap<String, String> = roles
        .into_iter()
        .zip(&fields[5..11])
        .map(|(role, key)| (role.to_owned(), (*key).to_owned()))
        .collect();
    let result = observe_six_control_openings_root_owned_ineligible(
        fields[0],
        fields[1],
        Path::new(&args[3]),
        fields[2],
        fields[3],
        exit_code,
        &keys,
    );
    match result {
        Ok(shadow) => println!("{}", shadow.to_json()),
        Err(error) => {
            eprintln!("six-control openings shadow refused: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Linux Root required for six-control openings shadow");
    std::process::exit(2);
}
