use super::filetime_ns;

#[test]
fn filetime_ticks_read_as_cpython_reads_them() {
    assert_eq!(filetime_ns(116_444_736_000_000_000), Some(0));
    assert_eq!(filetime_ns(116_444_736_000_000_001), Some(100));
    assert_eq!(filetime_ns(116_444_736_012_345_678), Some(1_234_567_800));
    assert_eq!(filetime_ns(116_444_735_999_999_999), Some(-100));
    assert_eq!(filetime_ns(u64::MAX), None);
}

/// The publisher records `Path.stat()`, so the resident must read the
/// same four fields from the same file.
#[cfg(windows)]
#[test]
fn windows_input_observation_matches_cpython_stat() {
    let path = std::env::temp_dir().join(format!(
        "guard-direct-lane-input-{}-{}",
        std::process::id(),
        super::now_ms().unwrap_or_default()
    ));
    std::fs::write(&path, b"policy").unwrap();
    let path_text = path.to_str().unwrap();
    let stat = super::observe_input(path_text).unwrap();
    let output = std::process::Command::new("python")
        .args([
            "-c",
            "import os, sys; s = os.stat(sys.argv[1]); \
             print(s.st_mtime_ns, s.st_size, s.st_ino, s.st_ctime_ns)",
            path_text,
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let fields: Vec<i128> = String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .map(|field| field.parse().unwrap())
        .collect();
    assert_eq!(
        fields,
        [
            i128::from(stat.mtime_ns),
            i128::from(stat.size),
            i128::from(stat.ino),
            i128::from(stat.ctime_ns),
        ]
    );
    std::fs::write(&path, b"policy changed").unwrap();
    assert_ne!(super::observe_input(path_text), Some(stat));
    std::fs::remove_file(&path).unwrap();
    assert_eq!(super::observe_input(path_text), None);
}
