use super::safe_headless_browser_read;

fn arguments(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn a_headless_dump_of_a_loopback_page_on_a_temporary_profile_is_admitted() {
    for (browser, text) in [
        (
            "chromium",
            "--headless=new --user-data-dir=/tmp/guard-run --dump-dom http://127.0.0.1:3000",
        ),
        (
            "google-chrome",
            "--headless --disable-gpu --user-data-dir=/tmp/preview/profile --dump-dom http://localhost:5173/items?page=2",
        ),
        (
            "chromium-browser",
            "--headless=new --no-first-run --window-size=1280,800 --virtual-time-budget=5000 --user-data-dir=/private/tmp/run-1/ --dump-dom https://[::1]:8443/",
        ),
        (
            "microsoft-edge",
            "--dump-dom --headless --user-data-dir=/tmp/x http://127.0.0.1",
        ),
    ] {
        assert!(safe_headless_browser_read(browser, &arguments(text)), "{browser} {text}");
    }
}

#[test]
fn control_channels_and_real_profiles_are_refused() {
    for text in [
        "--headless --remote-debugging-port=9222 --user-data-dir=/tmp/run --dump-dom http://127.0.0.1:3000",
        "--headless --remote-debugging-pipe --user-data-dir=/tmp/run --dump-dom http://127.0.0.1:3000",
        "--headless -remote-debugging-port=9222 --user-data-dir=/tmp/run --dump-dom http://127.0.0.1:3000",
        "--headless --profile-directory=Default --user-data-dir=/tmp/run --dump-dom http://127.0.0.1:3000",
        "--headless --load-extension=/tmp/ext --user-data-dir=/tmp/run --dump-dom http://127.0.0.1:3000",
        "--headless --proxy-server=http://127.0.0.1:8080 --user-data-dir=/tmp/run --dump-dom http://127.0.0.1:3000",
        "--headless --no-sandbox --user-data-dir=/tmp/run --dump-dom http://127.0.0.1:3000",
        "--headless --user-data-dir=/home/dev/.config/chromium --dump-dom http://127.0.0.1:3000",
        "--headless --user-data-dir=/tmp/../home/dev/.config/chromium --dump-dom http://127.0.0.1:3000",
        "--headless --user-data-dir=/tmp/ --dump-dom http://127.0.0.1:3000",
        "--headless --user-data-dir=/tmp/$HOME --dump-dom http://127.0.0.1:3000",
        "--headless --user-data-dir /tmp/run --dump-dom http://127.0.0.1:3000",
        "--headless --user-data-dir=/tmp/a --user-data-dir=/tmp/b --dump-dom http://127.0.0.1:3000",
        "--headless --dump-dom http://127.0.0.1:3000",
    ] {
        assert!(!safe_headless_browser_read("chromium", &arguments(text)), "{text}");
    }
}

#[test]
fn a_window_a_file_or_another_host_is_refused() {
    for text in [
        "--user-data-dir=/tmp/run --dump-dom http://127.0.0.1:3000",
        "--headless --user-data-dir=/tmp/run http://127.0.0.1:3000",
        "--headless --user-data-dir=/tmp/run --screenshot http://127.0.0.1:3000",
        "--headless --user-data-dir=/tmp/run --print-to-pdf=out.pdf http://127.0.0.1:3000",
        "--headless --user-data-dir=/tmp/run --dump-dom https://example.com/",
        "--headless --user-data-dir=/tmp/run --dump-dom http://127.0.0.1@example.com/",
        "--headless --user-data-dir=/tmp/run --dump-dom http://localhost:80@example.com/",
        "--headless --user-data-dir=/tmp/run --dump-dom http://localhost.example.com/",
        "--headless --user-data-dir=/tmp/run --dump-dom http://127.0.0.1:3000/a@b",
        "--headless --user-data-dir=/tmp/run --dump-dom file:///etc/hosts",
        "--headless --user-data-dir=/tmp/run --dump-dom http://127.0.0.1:3000 http://127.0.0.1:3001",
        "--headless --user-data-dir=/tmp/run --dump-dom",
        "--headless --user-data-dir=/tmp/run --dump-dom --window-size=wide http://127.0.0.1:3000",
    ] {
        assert!(!safe_headless_browser_read("chromium", &arguments(text)), "{text}");
    }
}

#[test]
fn only_chromium_family_browsers_are_read() {
    let text = arguments("--headless --user-data-dir=/tmp/run --dump-dom http://127.0.0.1:3000");
    for browser in ["firefox", "chromedriver", "node", "curl"] {
        assert!(!safe_headless_browser_read(browser, &text), "{browser}");
    }
}

#[cfg(unix)]
#[test]
fn an_existing_profile_must_be_a_private_directory_of_this_user() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let name = format!(
        "guard-headless-profile-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let root = std::path::Path::new("/tmp").join(&name);
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let launch = |profile: &str| {
        arguments(&format!(
            "--headless --user-data-dir={profile} --dump-dom http://127.0.0.1:3000"
        ))
    };

    let owned = root.join("owned");
    std::fs::create_dir(&owned).unwrap();
    assert!(safe_headless_browser_read(
        "chromium",
        &launch(&format!("/tmp/{name}/owned"))
    ));
    assert!(safe_headless_browser_read(
        "chromium",
        &launch(&format!("/tmp/{name}/missing/profile"))
    ));

    let linked = root.join("linked");
    symlink(&owned, &linked).unwrap();
    assert!(!safe_headless_browser_read(
        "chromium",
        &launch(&format!("/tmp/{name}/linked"))
    ));
    assert!(!safe_headless_browser_read(
        "chromium",
        &launch(&format!("/tmp/{name}/linked/inner"))
    ));

    let shared = root.join("shared");
    std::fs::create_dir(&shared).unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(!safe_headless_browser_read(
        "chromium",
        &launch(&format!("/tmp/{name}/shared"))
    ));

    std::fs::write(root.join("file"), "synthetic\n").unwrap();
    assert!(!safe_headless_browser_read(
        "chromium",
        &launch(&format!("/tmp/{name}/file"))
    ));

    std::fs::remove_dir_all(&root).unwrap();
}
