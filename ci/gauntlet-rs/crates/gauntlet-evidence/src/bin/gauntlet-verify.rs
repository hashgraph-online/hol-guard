use gauntlet_evidence::{read_external_pins, verify_bundle};
use std::path::Path;

fn main() {
    let arguments: Vec<_> = std::env::args_os().collect();
    if arguments.len() != 3 {
        eprintln!("usage: gauntlet-verify ABSOLUTE_BUNDLE_DIRECTORY ABSOLUTE_EXTERNAL_PINS_JSON");
        std::process::exit(2);
    }
    let bundle = Path::new(&arguments[1]);
    let pins_path = Path::new(&arguments[2]);
    if !bundle.is_absolute() || !pins_path.is_absolute() || pins_path.starts_with(bundle) {
        eprintln!("bundle and external pins must be separate absolute paths");
        std::process::exit(2);
    }
    let result = read_external_pins(pins_path).and_then(|pins| verify_bundle(bundle, &pins));
    match result {
        Ok(report) => println!("{}", report.to_json()),
        Err(error) => {
            eprintln!("gauntlet evidence invalid: {error}");
            std::process::exit(1);
        }
    }
}
