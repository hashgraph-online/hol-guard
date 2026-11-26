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
