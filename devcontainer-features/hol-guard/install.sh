#!/usr/bin/env bash
set -euo pipefail

# HOL Guard DevContainer Feature
# Installs HOL Guard into a dev container for AI agent security

VERSION="${VERSION:-latest}"
INIT_HARNESS="${INITHARNESS:-auto}"
STRICT_MODE="${STRICTMODE:-false}"

echo "================================================"
echo "  HOL Guard DevContainer Feature"
echo "  https://hol.org/guard"
echo "================================================"

# Ensure Python is available
if ! command -v python3 &>/dev/null; then
    echo "ERROR: Python 3.10+ is required. Please install the Python feature first."
    echo "  Add to devcontainer.json: \"ghcr.io/devcontainers/features/python\""
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "Detected Python: ${PY_VERSION}"

# Check minimum version (3.10+)
MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
if [ "$MAJOR" -lt 3 ] || { [ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 10 ]; }; then
    echo "ERROR: HOL Guard requires Python 3.10+. Found ${PY_VERSION}."
    exit 1
fi

# Determine the target non-root user (devcontainer provides these env vars)
USERNAME="${_REMOTE_USER:-${_CONTAINER_USER:-auto}}"
if [ "${USERNAME}" = "auto" ] || [ "${USERNAME}" = "root" ]; then
    for u in vscode node codespace; do
        if id "$u" &>/dev/null; then
            USERNAME="$u"
            break
        fi
    done
fi
if [ "${USERNAME}" = "auto" ]; then
    USERNAME="root"
fi

USER_HOME=$(getent passwd "${USERNAME}" | cut -d: -f6 || echo "/home/${USERNAME}")
echo "Installing for user: ${USERNAME} (${USER_HOME})"

# Run a command as the target user
run_as_user() {
    if [ "${USERNAME}" = "root" ]; then
        eval "$1"
    else
        su "${USERNAME}" -c "$1"
    fi
}

# Install pipx if not present (handling PEP 668 externally-managed-environment)
if ! command -v pipx &>/dev/null && ! run_as_user "command -v pipx &>/dev/null"; then
    echo "Installing pipx..."
    if command -v apt-get &>/dev/null; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update && apt-get install -y pipx
    elif command -v apk &>/dev/null; then
        apk add pipx
    elif command -v dnf &>/dev/null; then
        dnf install -y pipx
    else
        run_as_user "python3 -m pip install --user pipx || python3 -m pip install --user pipx --break-system-packages"
    fi
fi

# Ensure pipx is in the user's PATH
run_as_user "pipx ensurepath &>/dev/null || ${USER_HOME}/.local/bin/pipx ensurepath &>/dev/null" || true

# Determine pipx binary path
PIPX_BIN="pipx"
if ! run_as_user "command -v pipx &>/dev/null"; then
    PIPX_BIN="${USER_HOME}/.local/bin/pipx"
fi

# Install hol-guard (--force for idempotent re-runs)
if [ "$VERSION" = "latest" ]; then
    echo "Installing HOL Guard (latest)..."
    run_as_user "${PIPX_BIN} install --force hol-guard"
else
    echo "Installing HOL Guard v${VERSION}..."
    run_as_user "${PIPX_BIN} install --force hol-guard==${VERSION}"
fi

# Determine hol-guard binary path
GUARD_BIN="hol-guard"
if ! run_as_user "command -v hol-guard &>/dev/null"; then
    GUARD_BIN="${USER_HOME}/.local/bin/hol-guard"
fi

# Initialize for harness if requested
if [ "$INIT_HARNESS" != "none" ]; then
    echo ""
    echo "Initializing HOL Guard for harness: ${INIT_HARNESS}..."
    # The Guard CLI auto-detects installed harnesses. --yes makes init
    # non-interactive for devcontainer builds.
    if [ "$INIT_HARNESS" = "auto" ]; then
        run_as_user "${GUARD_BIN} init --yes"
    else
        # No --harness flag exists yet; use --yes for non-interactive auto-detect.
        # The specified harness will be detected if installed in the container.
        echo "Note: hol-guard init auto-detects installed harnesses."
        echo "  Specified harness '${INIT_HARNESS}' will be configured if found."
        run_as_user "${GUARD_BIN} init --yes"
    fi

    if [ "$STRICT_MODE" = "true" ]; then
        echo "Enabling strict mode..."
        run_as_user "${GUARD_BIN} settings set security-level strict"
    fi
fi

echo ""
echo "HOL Guard installed successfully."
echo "  Docs: https://hol.org/guard"
echo "  CLI:  hol-guard --help"
echo "================================================"
