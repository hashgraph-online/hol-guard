# HOL Guard Tray Icon

The HOL Guard tray icon provides a persistent menu bar (macOS) or system tray
(Windows/Linux) icon that lets you open the dashboard without using the terminal.

## Quick start

```bash
# Check if your platform supports the tray icon
hol-guard guard tray status

# Start the tray icon now
hol-guard guard tray start

# Install it to start automatically at login
hol-guard guard tray install

# Stop the running tray icon
hol-guard guard tray stop

# Remove the login startup registration
hol-guard guard tray uninstall
```

## Platform support

| Platform | Backend | Registration | Notes |
|----------|---------|-------------|-------|
| macOS | AppKit (pystray) | LaunchAgent plist | Requires pyobjc-framework-Quartz |
| Windows | Win32 (pystray) | Run key (registry) | No extra deps |
| Linux | AppIndicator (pystray) | XDG autostart | Requires python-xlib on x86_64 |

If `pystray` or `Pillow` is not installed, `tray status` will report
`dependency_missing`. Install with:

```bash
pip install pystray pillow
# macOS:
pip install pyobjc-framework-Quartz
# Linux (x86_64 only):
pip install python-xlib
```

## Menu items

The tray icon menu has three items:

- **Open HOL Guard** (default action — click the icon) — opens the dashboard
  in your default browser. Repeated clicks within 2 seconds are coalesced.
- **Start at Login** — toggle whether the tray starts automatically at login.
- **Quit HOL Guard** — stops the tray icon process.

## How it works

### Architecture

```
hol-guard tray start
    └── lifecycle.start_tray()
        └── _start_subprocess()
            └── python -m codex_plugin_scanner.guard.tray.runtime
                └── TrayRuntime.run()
                    ├── write_locator()  (signals readiness)
                    ├── pystray.Icon.run()  (main thread)
                    └── remove_locator()  (on exit)
```

The tray process runs independently of the terminal. It writes a locator
file to `<guard_home>/tray/locator.json` that records its PID, start
time, and backend. The CLI uses this file to detect whether the tray is
running, stale, or in a crash loop.

### Dashboard launcher

Both `hol-guard dashboard` and the tray's "Open HOL Guard" menu item call
the same canonical `open_dashboard()` function in
`dashboard_launcher.py`. This ensures:

- The daemon is started if needed
- The auth token is loaded and placed in the browser URL fragment (never
  sent to a server)
- The browser URL returned to callers is redacted (token stripped)
- Repeated opens are coalesced

### Crash recovery

If the tray process exits unexpectedly, the lifecycle records a crash in
the locator file. After `MAX_CRASH_RETRIES` (3) crashes, `tray start`
will refuse to start and suggest `tray repair`:

```bash
hol-guard guard tray repair
hol-guard guard tray start
```

### Stale process detection

The locator file records the process's start time fingerprint. If the
PID is reused by a different process (e.g., after a reboot), the locator
is detected as stale and the tray can be restarted cleanly.

## Security

- **No auth tokens in logs, process arguments, or diagnostics.** The
  tray process receives only `--guard-home` and reads tokens itself at
  runtime via the canonical launcher.
- **Browser URLs are redacted.** The `guard-token` fragment is stripped
  from any URL returned to CLI output, logs, or dashboard UI.
- **Error messages are sanitized.** The shared `sanitize_secret()`
  utility strips token, key, secret, password, auth, bearer, and
  credential patterns from all error messages before display.
- **Locator files use 0o600 permissions** on POSIX.
- **Platform adapters refuse to overwrite foreign registrations.** If a
  same-named LaunchAgent, Run key, or desktop entry exists but is not
  verifiably HOL Guard-owned, the install will fail with
  `startup_registration_collision`.

## Troubleshooting

### `tray status` shows `unsupported`

Your platform is not supported. The tray icon requires macOS, Windows, or
Linux with a graphical session.

### `tray status` shows `dependency_missing`

Install `pystray` and `Pillow`:

```bash
pip install pystray pillow
```

### `tray status` shows `stale`

A previous tray process died without cleaning up. Run:

```bash
hol-guard guard tray repair
hol-guard guard tray start
```

### `tray start` shows `crash_loop_detected`

The tray has crashed too many times. Run `tray repair` to reset the crash
counter, then check the logs at `<guard_home>/tray/stderr.log`.

### `tray start` shows `already_running`

A tray is already running. Use `--force` to stop it and start a new one:

```bash
hol-guard guard tray start --force
```

### Tray icon doesn't appear

On Linux, ensure your desktop environment supports AppIndicator
(GNOME requires the AppIndicator extension). On macOS, ensure you're
not running in a headless session.

## Integration with `hol-guard init`

The `hol-guard init` command includes an optional tray icon step. Skip
it with `--skip-tray`:

```bash
hol-guard guard init --skip-tray
```

## Native platform evidence

The tray icon has been verified on the following platforms:

### macOS (AppKit backend)

The tray runs via pystray's AppKit backend. Process inspection with
`sample <pid>` confirms:

- `-[NSApplication run]` is active (AppKit event loop)
- `_NSEventThread` is running (event processing)
- `CFRunLoopRunSpecific` / `__CFRunLoopRun` servicing Mach ports
- `com.apple.AppKit` framework loaded

Lifecycle verified: `tray install` creates a per-user LaunchAgent at
`~/Library/LaunchAgents/org.hol.guard.tray.plist` (RunAtLoad, absolute
arguments). `tray start` launches the process on the main thread.
`tray stop` terminates it. `tray uninstall` removes the LaunchAgent.

### Linux (AppIndicator backend, Xorg)

The tray runs via pystray's AppIndicator backend under Xorg. Tested
in a Docker container with Xvfb providing a virtual display:

```bash
export DISPLAY=:99
Xvfb :99 -screen 0 1024x768x24 &
```

`detect_capability()` returns `LINUX` / `APPINDICATOR` / `supported=True`.
Full lifecycle verified:

- `tray install` creates XDG autostart file at
  `~/.config/autostart/org.hol.guard.tray.desktop` (`Terminal=false`,
  `X-GNOME-Autostart-enabled=true`)
- `tray start` launches the process (confirmed via `ps` and `tray status`)
- `tray status` reports `running` with correct PID and backend
- `tray stop` terminates the process
- `tray uninstall` removes the XDG autostart file

### Windows (Win32 backend)

The tray runs via pystray's Win32 backend. The Windows adapter uses a
per-user Task Scheduler task with `pythonw.exe` (no console flash).
Cross-platform CI passes on `windows-latest`.

### Wayland sessions

The tray runs under Wayland via the AppIndicator backend with XWayland.
Verified using Weston (reference Wayland compositor) in a Docker container:

- `detect_capability()` returns `LINUX` / `APPINDICATOR` / `supported=True`
  with `WAYLAND_DISPLAY=wayland-0` set
- Full lifecycle verified: `tray install` (XDG autostart), `tray start`
  (process running), `tray status` (running/appindicator), `tray stop`,
  `tray uninstall`

GNOME Wayland requires the AppIndicator extension. KDE Plasma Wayland
supports AppIndicator natively.
